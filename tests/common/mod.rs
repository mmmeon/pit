//! Test harness: ptys read through a vt100 parser, the pinentry binary spoken
//! to over Assuan, and an isolated tmux server.
#![allow(dead_code)]

use std::env;
use std::ffi::CStr;
use std::fs::{self, File};
use std::io::{BufRead, BufReader, Read, Write};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::process::CommandExt;
use std::path::PathBuf;
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::mpsc::{self, Receiver};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

pub const BIN: &str = env!("CARGO_BIN_EXE_pinentry-tmux");
pub const WAIT: Duration = Duration::from_secs(10);

/// gpg-error codes as the pinentry reports them (source 5 = pinentry).
pub const ERR_TIMEOUT: u32 = (5 << 24) | 62;
pub const ERR_NO_PIN_ENTRY: u32 = (5 << 24) | 85;
pub const ERR_CANCELED: u32 = (5 << 24) | 99;
pub const ERR_NOT_CONFIRMED: u32 = (5 << 24) | 114;

/// Skips the test when tmux isn't installed.
#[macro_export]
macro_rules! require_tmux {
    () => {
        if !$crate::common::have("tmux") {
            eprintln!("skipping: tmux not found");
            return;
        }
    };
}

pub fn have(cmd: &str) -> bool {
    Command::new(cmd).arg("--version").stdout(Stdio::null()).stderr(Stdio::null()).status().is_ok()
}

/// Polls `f` until it returns Some, or panics with `what` and `dump()`.
pub fn wait_until<T>(what: &str, mut f: impl FnMut() -> Option<T>, dump: impl Fn() -> String) -> T {
    let start = Instant::now();
    loop {
        if let Some(v) = f() {
            return v;
        }
        if start.elapsed() > WAIT {
            panic!("timed out waiting for {what}\n{}", dump());
        }
        thread::sleep(Duration::from_millis(20));
    }
}

/// A scratch directory that also isolates tmux and TMPDIR for whatever runs
/// in it. Removed on drop.
pub struct Sandbox {
    pub root: PathBuf,
}

impl Sandbox {
    pub fn new() -> Sandbox {
        static N: AtomicUsize = AtomicUsize::new(0);
        let n = N.fetch_add(1, Ordering::Relaxed);
        let root = env::temp_dir().join(format!("pt{}-{n}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(root.join("tmux")).unwrap();
        fs::create_dir_all(root.join("tmp")).unwrap();
        Sandbox { root }
    }

    /// TMPDIR for the pinentry, where its fifo directories go.
    pub fn tmp(&self) -> PathBuf {
        self.root.join("tmp")
    }

    /// Points `cmd` at this sandbox's tmux server and TMPDIR.
    pub fn apply<'a>(&self, cmd: &'a mut Command) -> &'a mut Command {
        cmd.env_remove("TMUX")
            .env_remove("TMUX_PANE")
            .env("TMUX_TMPDIR", self.root.join("tmux"))
            .env("TMPDIR", self.tmp())
    }

    pub fn leftovers(&self) -> Vec<String> {
        fs::read_dir(self.tmp())
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect()
    }
}

impl Drop for Sandbox {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

/// A pseudo-terminal whose output is fed to a vt100 screen.
pub struct Pty {
    master: File,
    slave: File,
    path: String,
    parser: Arc<Mutex<vt100::Parser>>,
}

impl Pty {
    pub fn new(rows: u16, cols: u16) -> Pty {
        let (mut m, mut s) = (0, 0);
        let ws = libc::winsize { ws_row: rows, ws_col: cols, ws_xpixel: 0, ws_ypixel: 0 };
        let ok = unsafe { libc::openpty(&mut m, &mut s, std::ptr::null_mut(), std::ptr::null(), &ws) };
        assert_eq!(ok, 0, "openpty: {}", std::io::Error::last_os_error());
        // Other tests spawn processes concurrently: don't leak into them.
        for fd in [m, s] {
            unsafe { libc::fcntl(fd, libc::F_SETFD, libc::FD_CLOEXEC) };
        }
        let (master, slave) = unsafe { (File::from_raw_fd(m), File::from_raw_fd(s)) };
        // ttyname() uses a static buffer, so it isn't safe across test threads.
        let mut buf = [0 as libc::c_char; 128];
        assert_eq!(unsafe { libc::ttyname_r(s, buf.as_mut_ptr(), buf.len()) }, 0);
        let path = unsafe { CStr::from_ptr(buf.as_ptr()) }.to_str().unwrap().to_string();

        let parser = Arc::new(Mutex::new(vt100::Parser::new(rows, cols, 0)));
        let mut reader = master.try_clone().unwrap();
        let p = parser.clone();
        thread::spawn(move || {
            let mut buf = [0; 4096];
            while let Ok(n @ 1..) = reader.read(&mut buf) {
                p.lock().unwrap().process(&buf[..n]);
            }
        });
        Pty { master, slave, path, parser }
    }

    pub fn path(&self) -> &str {
        &self.path
    }

    /// Types `keys` as if at the keyboard.
    pub fn send(&self, keys: &str) {
        (&self.master).write_all(keys.as_bytes()).unwrap();
    }

    /// Writes `s` as program output, e.g. a shell prompt before the pinentry.
    pub fn print(&self, s: &str) {
        (&self.slave).write_all(s.as_bytes()).unwrap();
    }

    pub fn screen(&self) -> vt100::Screen {
        self.parser.lock().unwrap().screen().clone()
    }

    pub fn text(&self) -> String {
        self.screen().contents()
    }

    pub fn row(&self, row: u16) -> String {
        let screen = self.screen();
        let (_, cols) = screen.size();
        screen.rows(0, cols).nth(row as usize).unwrap_or_default()
    }

    /// Waits until the screen satisfies `pred`, and returns it.
    pub fn wait(&self, what: &str, pred: impl Fn(&vt100::Screen) -> bool) -> vt100::Screen {
        wait_until(
            what,
            || {
                let screen = self.screen();
                pred(&screen).then_some(screen)
            },
            || format!("screen:\n{}", self.text()),
        )
    }

    pub fn wait_text(&self, needle: &str) -> vt100::Screen {
        self.wait(&format!("{needle:?} on screen"), |s| s.contents().contains(needle))
    }

    pub fn wait_gone(&self, needle: &str) -> vt100::Screen {
        self.wait(&format!("{needle:?} to go"), |s| !s.contents().contains(needle))
    }

    /// The terminal modes that the pinentry must put back.
    pub fn modes(&self) -> [libc::tcflag_t; 4] {
        let mut t: libc::termios = unsafe { std::mem::zeroed() };
        assert_eq!(unsafe { libc::tcgetattr(self.slave.as_raw_fd(), &mut t) }, 0);
        [t.c_iflag, t.c_oflag, t.c_cflag, t.c_lflag]
    }

    /// A Command that runs on this pty as its controlling terminal.
    pub fn command(&self, program: &str) -> Command {
        let mut cmd = Command::new(program);
        let fd = || Stdio::from(OwnedFd::from(self.slave.try_clone().unwrap()));
        cmd.stdin(fd()).stdout(fd()).stderr(fd()).env("TERM", "xterm-256color");
        unsafe {
            cmd.pre_exec(|| {
                if libc::setsid() < 0 || libc::ioctl(0, libc::TIOCSCTTY, 0) < 0 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
        cmd
    }
}

/// The pinentry binary, spoken to over Assuan.
pub struct Pinentry {
    child: Child,
    stdin: Option<ChildStdin>,
    lines: Receiver<String>,
}

impl Pinentry {
    pub fn spawn(sb: &Sandbox, args: &[&str]) -> Pinentry {
        let mut cmd = Command::new(BIN);
        sb.apply(&mut cmd).args(args).stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::null());
        let mut child = cmd.spawn().unwrap();
        let stdin = child.stdin.take().unwrap();
        let stdout = BufReader::new(child.stdout.take().unwrap());
        let (tx, lines) = mpsc::channel();
        thread::spawn(move || {
            for line in stdout.lines() {
                let Ok(line) = line else { break };
                if tx.send(line).is_err() {
                    break;
                }
            }
        });
        let mut p = Pinentry { child, stdin: Some(stdin), lines };
        let hello = p.line().expect("no greeting");
        assert!(hello.starts_with("OK Pleased to meet you, process "), "{hello}");
        p
    }

    /// The next output line, or None at EOF.
    pub fn line(&mut self) -> Option<String> {
        match self.lines.recv_timeout(WAIT) {
            Ok(line) => Some(line),
            Err(mpsc::RecvTimeoutError::Disconnected) => None,
            Err(mpsc::RecvTimeoutError::Timeout) => panic!("pinentry said nothing for {WAIT:?}"),
        }
    }

    /// Sends a line without waiting for the answer.
    pub fn start(&mut self, line: &str) {
        let stdin = self.stdin.as_mut().unwrap();
        writeln!(stdin, "{line}").unwrap();
        stdin.flush().unwrap();
    }

    /// Collects output up to and including the OK or ERR line.
    pub fn finish(&mut self) -> Vec<String> {
        let mut out = Vec::new();
        loop {
            let line = self.line().unwrap_or_else(|| panic!("EOF after {out:?}"));
            let done = line == "OK" || line.starts_with("OK ") || line.starts_with("ERR ");
            out.push(line);
            if done {
                return out;
            }
        }
    }

    pub fn cmd(&mut self, line: &str) -> Vec<String> {
        self.start(line);
        self.finish()
    }

    /// Sends several commands, expecting OK from each.
    pub fn setup(&mut self, lines: &[&str]) {
        for line in lines {
            assert_eq!(self.cmd(line), ["OK"], "{line}");
        }
    }

    pub fn pid(&self) -> u32 {
        self.child.id()
    }

    pub fn kill(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }

    /// Closes stdin and waits for the process to exit.
    pub fn close(&mut self) -> std::process::ExitStatus {
        self.stdin = None;
        self.child.wait().unwrap()
    }
}

impl Drop for Pinentry {
    fn drop(&mut self) {
        self.kill();
    }
}

/// The ERR code in a reply, if it's an error.
pub fn err_code(reply: &[String]) -> Option<u32> {
    reply.last()?.strip_prefix("ERR ")?.split(' ').next()?.parse().ok()
}

/// The `D` payload of a reply, unescaped.
pub fn data(reply: &[String]) -> Vec<u8> {
    let mut out = Vec::new();
    for line in reply.iter().filter_map(|l| l.strip_prefix("D ")) {
        let b = line.as_bytes();
        let mut i = 0;
        while i < b.len() {
            if b[i] == b'%' && i + 2 < b.len() {
                out.push(u8::from_str_radix(&line[i + 1..i + 3], 16).unwrap());
                i += 3;
            } else {
                out.push(b[i]);
                i += 1;
            }
        }
    }
    out
}

/// An isolated tmux server, killed on drop.
pub struct Tmux<'a> {
    sb: &'a Sandbox,
}

/// A tmux client attached from its own pty.
pub struct Client {
    pub pty: Pty,
    child: Child,
}

impl Drop for Client {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

impl<'a> Tmux<'a> {
    pub fn start(sb: &'a Sandbox) -> Tmux<'a> {
        let t = Tmux { sb };
        t.run(&["-f", "/dev/null", "new-session", "-d", "-x", "100", "-y", "30", "sleep 1d"]);
        t
    }

    pub fn command(&self) -> Command {
        let mut cmd = Command::new("tmux");
        self.sb.apply(&mut cmd);
        cmd
    }

    /// Runs a tmux command, panicking if it fails.
    pub fn run(&self, args: &[&str]) -> String {
        let out = self.command().args(args).stdin(Stdio::null()).output().unwrap();
        assert!(out.status.success(), "tmux {args:?}: {}", String::from_utf8_lossy(&out.stderr));
        String::from_utf8(out.stdout).unwrap()
    }

    pub fn attach(&self, rows: u16, cols: u16) -> Client {
        let pty = Pty::new(rows, cols);
        let mut cmd = pty.command("tmux");
        self.sb.apply(&mut cmd).arg("attach");
        let child = cmd.spawn().unwrap();
        let tty = pty.path().to_string();
        wait_until(
            "client to attach",
            || self.run(&["list-clients", "-F", "#{client_tty}"]).lines().any(|l| l == tty).then_some(()),
            || pty.text(),
        );
        // The status line is the last thing drawn.
        pty.wait("status line", |s| s.contents().contains("[0] 0:"));
        Client { pty, child }
    }

    pub fn set(&self, option: &str, value: &str) {
        self.run(&["set", "-g", option, value]);
    }

    pub fn pane_tty(&self) -> String {
        self.run(&["display", "-p", "#{pane_tty}"]).trim().to_string()
    }

    pub fn capture(&self) -> String {
        self.run(&["capture-pane", "-p"])
    }

    pub fn send_keys(&self, keys: &[&str]) {
        let mut args = vec!["send-keys"];
        args.extend(keys);
        self.run(&args);
    }

    /// Opens an unrelated popup on `client`, in the background.
    pub fn busy_popup(&self, client: &Client) -> Child {
        self.command()
            .args(["display-popup", "-c", client.pty.path(), "-E", "-T", "busy", "sleep 1d"])
            .stdin(Stdio::null())
            .spawn()
            .unwrap()
    }

    pub fn close_popup(&self, client: &Client) {
        self.run(&["display-popup", "-C", "-c", client.pty.path()]);
    }
}

impl Drop for Tmux<'_> {
    fn drop(&mut self) {
        let _ = self.command().arg("kill-server").stderr(Stdio::null()).status();
    }
}
