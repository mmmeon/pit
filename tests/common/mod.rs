//! Test harness: ptys read through a vt100 parser, the pinentry binary spoken
//! to over Assuan, and an isolated tmux server.
//!
//! Each time a test waits on a screen it prints a snapshot of it, which
//! cargo shows for failed tests. To watch the tests:
//!   cargo test -- --nocapture
//!     prints the snapshots of passing tests too
//!   PIT_TEST_LIVE=1 cargo test
//!     replays every pty on this terminal as it's drawn, one test at a time,
//!     typing slowly (PIT_TEST_SLOW=ms per key, default 120). Ptys take this
//!     terminal's size, and its echo is off until the tests exit.
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
use std::sync::{Arc, Mutex, MutexGuard, OnceLock};
use std::thread;
use std::time::{Duration, Instant};

pub const BIN: &str = env!("CARGO_BIN_EXE_pit");
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

fn flag(name: &str) -> bool {
    env::var(name).is_ok_and(|v| !v.is_empty() && v != "0")
}

/// This terminal's modes before live replay turned echo off.
static SAVED: OnceLock<(libc::c_int, libc::termios)> = OnceLock::new();

extern "C" fn restore_tty() {
    if let Some((fd, t)) = SAVED.get() {
        unsafe {
            libc::tcflush(*fd, libc::TCIFLUSH);
            libc::tcsetattr(*fd, libc::TCSANOW, t);
        }
    }
}

/// Restores the terminal on Ctrl-C too, then dies of the signal as usual.
extern "C" fn restore_tty_and_die(sig: libc::c_int) {
    restore_tty();
    unsafe {
        libc::signal(sig, libc::SIG_DFL);
        libc::raise(sig);
    }
}

/// The terminal to replay ptys on (PIT_TEST_LIVE), if any.
fn live() -> Option<&'static Mutex<File>> {
    static TTY: OnceLock<Option<Mutex<File>>> = OnceLock::new();
    TTY.get_or_init(|| {
        if !flag("PIT_TEST_LIVE") {
            return None;
        }
        match File::options().read(true).write(true).open("/dev/tty") {
            Ok(tty) => {
                // tmux queries the terminal, and the replies arrive as input.
                // Don't let them echo over the replay.
                let fd = tty.as_raw_fd();
                let mut t: libc::termios = unsafe { std::mem::zeroed() };
                if unsafe { libc::tcgetattr(fd, &mut t) } == 0 && SAVED.set((fd, t)).is_ok() {
                    let mut quiet = t;
                    quiet.c_lflag &= !libc::ECHO;
                    unsafe {
                        libc::tcsetattr(fd, libc::TCSANOW, &quiet);
                        libc::atexit(restore_tty);
                        let die = restore_tty_and_die as extern "C" fn(libc::c_int) as libc::sighandler_t;
                        libc::signal(libc::SIGINT, die);
                        libc::signal(libc::SIGTERM, die);
                    }
                }
                Some(Mutex::new(tty))
            }
            Err(e) => {
                eprintln!("PIT_TEST_LIVE: can't open /dev/tty ({e}), not replaying");
                None
            }
        }
    })
    .as_ref()
}

fn live_write(bytes: &[u8]) {
    if let Some(tty) = live() {
        let mut tty = tty.lock().unwrap_or_else(|e| e.into_inner());
        let _ = tty.write_all(bytes);
        let _ = tty.flush();
    }
}

/// Delay per key when replaying live.
fn slow() -> Duration {
    let dflt = if live().is_some() { 120 } else { 0 };
    let ms = env::var("PIT_TEST_SLOW").ok().and_then(|v| v.parse().ok()).unwrap_or(dflt);
    Duration::from_millis(ms)
}

fn test_name() -> String {
    thread::current().name().unwrap_or("?").rsplit("::").next().unwrap().to_string()
}

/// Draws `body` in a box headed with `title`.
pub fn frame(title: &str, body: &str) -> String {
    use unicode_width::UnicodeWidthStr;
    let lines: Vec<&str> = body.lines().collect();
    let inner = lines.iter().map(|l| l.width()).max().unwrap_or(0).max(title.width() + 4);
    let mut out = format!("┌─ {title} {}┐\n", "─".repeat(inner - title.width() - 3));
    for l in &lines {
        out += &format!("│{l}{}│\n", " ".repeat(inner - l.width()));
    }
    out + &format!("└{}┘\n", "─".repeat(inner))
}

pub fn have(cmd: &str) -> bool {
    Command::new(cmd).arg("--version").stdout(Stdio::null()).stderr(Stdio::null()).status().is_ok()
}

/// Polls `f` until it returns Some, or panics with `what` and `dump()`.
/// Prints `dump()` once it's satisfied.
pub fn wait_until<T>(what: &str, f: impl FnMut() -> Option<T>, dump: impl Fn() -> String) -> T {
    poll(what, f, dump, true)
}

fn poll<T>(what: &str, mut f: impl FnMut() -> Option<T>, dump: impl Fn() -> String, show: bool) -> T {
    let start = Instant::now();
    loop {
        if let Some(v) = f() {
            if show {
                eprint!("{}", frame(&format!("{} · {what}", test_name()), &dump()));
            }
            return v;
        }
        if start.elapsed() > WAIT {
            panic!("timed out waiting for {what}\n{}", frame("screen", &dump()));
        }
        thread::sleep(Duration::from_millis(20));
    }
}

/// A scratch directory that also isolates tmux and TMPDIR for whatever runs
/// in it. Removed on drop.
pub struct Sandbox {
    pub root: PathBuf,
    /// Held while replaying live, so tests take turns on the terminal.
    _turn: Option<MutexGuard<'static, ()>>,
}

const SANDBOX_PREFIX: &str = "pit-test-";

/// Removes sandboxes left by test runs that were killed.
fn remove_stale_sandboxes() {
    let Ok(entries) = fs::read_dir(env::temp_dir()) else { return };
    for entry in entries.flatten() {
        let name = entry.file_name();
        let Some(rest) = name.to_str().and_then(|n| n.strip_prefix(SANDBOX_PREFIX)) else { continue };
        let pid = rest.split('-').next().and_then(|p| p.parse::<u32>().ok());
        if pid.is_some_and(|pid| !PathBuf::from(format!("/proc/{pid}")).exists()) {
            let _ = fs::remove_dir_all(entry.path());
        }
    }
}

impl Sandbox {
    pub fn new() -> Sandbox {
        static TURN: Mutex<()> = Mutex::new(());
        let turn = live().map(|_| TURN.lock().unwrap_or_else(|e| e.into_inner()));
        static CLEAN: OnceLock<()> = OnceLock::new();
        CLEAN.get_or_init(remove_stale_sandboxes);
        static N: AtomicUsize = AtomicUsize::new(0);
        let n = N.fetch_add(1, Ordering::Relaxed);
        let root = env::temp_dir().join(format!("{SANDBOX_PREFIX}{}-{n}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(root.join("tmux")).unwrap();
        fs::create_dir_all(root.join("tmp")).unwrap();
        fs::create_dir_all(root.join("run")).unwrap();
        Sandbox { root, _turn: turn }
    }

    /// TMPDIR for the pinentry, where its fifo directories go.
    pub fn tmp(&self) -> PathBuf {
        self.root.join("tmp")
    }

    /// Points `cmd` at this sandbox's tmux server, TMPDIR, runtime dir and
    /// config, with no display.
    pub fn apply<'a>(&self, cmd: &'a mut Command) -> &'a mut Command {
        cmd.env_remove("TMUX")
            .env_remove("TMUX_PANE")
            .env_remove("DISPLAY")
            .env_remove("WAYLAND_DISPLAY")
            .env_remove("PIT_HANDOFF")
            .env("TMUX_TMPDIR", self.root.join("tmux"))
            .env("TMPDIR", self.tmp())
            .env("XDG_RUNTIME_DIR", self.root.join("run"))
            .env("XDG_CONFIG_HOME", self.root.join("config"))
    }

    /// Writes the pinentry's config file.
    pub fn config(&self, toml: &str) {
        let dir = self.root.join("config/pit");
        fs::create_dir_all(&dir).unwrap();
        fs::write(dir.join("config.toml"), toml).unwrap();
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
    /// A pty for a terminal-sized test: `rows` x `cols`, or this terminal's
    /// size when replaying live.
    pub fn term(rows: u16, cols: u16) -> Pty {
        let size = live().and_then(|tty| {
            let mut ws: libc::winsize = unsafe { std::mem::zeroed() };
            let fd = tty.lock().unwrap_or_else(|e| e.into_inner()).as_raw_fd();
            let ok = unsafe { libc::ioctl(fd, libc::TIOCGWINSZ, &mut ws) } == 0 && ws.ws_col > 0;
            ok.then_some((ws.ws_row, ws.ws_col))
        });
        let (rows, cols) = size.unwrap_or((rows, cols));
        Pty::new(rows, cols)
    }

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
                live_write(&buf[..n]);
            }
        });
        // Start each pty on a clean screen, with the test in the window title.
        live_write(format!("\x1b]2;{}\x07\x1b[0m\x1b[2J\x1b[H", test_name()).as_bytes());
        Pty { master, slave, path, parser }
    }

    pub fn path(&self) -> &str {
        &self.path
    }

    /// (rows, cols)
    pub fn size(&self) -> (usize, usize) {
        let (rows, cols) = self.screen().size();
        (rows.into(), cols.into())
    }

    /// Types `keys` as if at the keyboard. Escape sequences go in one write
    /// so they aren't mistaken for a lone Esc.
    pub fn send(&self, keys: &str) {
        let delay = slow();
        if delay.is_zero() || keys.contains('\x1b') {
            (&self.master).write_all(keys.as_bytes()).unwrap();
            thread::sleep(delay);
            return;
        }
        for c in keys.chars() {
            (&self.master).write_all(c.encode_utf8(&mut [0; 4]).as_bytes()).unwrap();
            thread::sleep(delay);
        }
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
            || self.dump(),
        )
    }

    /// The screen's rows, without trailing blank ones.
    pub fn dump(&self) -> String {
        let screen = self.screen();
        let (_, cols) = screen.size();
        let mut rows: Vec<String> = screen.rows(0, cols).map(|r| r.trim_end().to_string()).collect();
        while rows.last().is_some_and(String::is_empty) {
            rows.pop();
        }
        rows.join("\n")
    }

    pub fn wait_text(&self, needle: &str) -> vt100::Screen {
        self.wait(&format!("{needle:?} on screen"), |s| s.contents().contains(needle))
    }

    pub fn wait_gone(&self, needle: &str) -> vt100::Screen {
        self.wait(&format!("{needle:?} to go"), |s| !s.contents().contains(needle))
    }

    fn termios(&self) -> libc::termios {
        let mut t: libc::termios = unsafe { std::mem::zeroed() };
        assert_eq!(unsafe { libc::tcgetattr(self.slave.as_raw_fd(), &mut t) }, 0);
        t
    }

    /// The terminal modes that the pinentry must put back.
    pub fn modes(&self) -> [libc::tcflag_t; 4] {
        let t = self.termios();
        [t.c_iflag, t.c_oflag, t.c_cflag, t.c_lflag]
    }

    /// Turns off line mode, as a full-screen program does.
    pub fn raw(&self) {
        let mut t = self.termios();
        t.c_lflag &= !(libc::ICANON | libc::ECHO);
        assert_eq!(unsafe { libc::tcsetattr(self.slave.as_raw_fd(), libc::TCSANOW, &t) }, 0);
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

impl Drop for Pty {
    fn drop(&mut self) {
        if live().is_none() {
            return;
        }
        // Linger on the final screen, then undo whatever modes the replayed
        // programs set, and drop any replies the terminal sent to their queries.
        thread::sleep(slow() * 5);
        live_write(b"\x1b[0m\x1b[r\x1b[?1049l\x1b[?25h\x1b[?1l\x1b>\x1b[?1000l\x1b[?1002l\x1b[?1006l\x1b[?2004l\x1b[2J\x1b[H");
        if let Ok(tty) = File::open("/dev/tty") {
            unsafe { libc::tcflush(tty.as_raw_fd(), libc::TCIFLUSH) };
        }
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
        Pinentry::spawn_env(sb, args, &[])
    }

    /// Spawns it with `vars` added to its environment.
    pub fn spawn_env(sb: &Sandbox, args: &[&str], vars: &[(&str, &str)]) -> Pinentry {
        let mut cmd = Command::new(BIN);
        sb.apply(&mut cmd).args(args).envs(vars.iter().copied()).stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::null());
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

/// A process listening on a gpg-agent socket, as a proxy in front of the
/// agent does (yubikey-touch-detector): it accepts connections and holds
/// them. Killed on drop.
pub struct Proxy {
    pub pid: u32,
    path: PathBuf,
}

impl Proxy {
    pub fn start(sb: &Sandbox) -> Proxy {
        // A space in the path, as in some home directories.
        let dir = sb.root.join("gnupg home");
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("S.gpg-agent.extra");
        let mut addr: libc::sockaddr_un = unsafe { std::mem::zeroed() };
        addr.sun_family = libc::AF_UNIX as _;
        let bytes = path.as_os_str().as_encoded_bytes();
        assert!(bytes.len() < addr.sun_path.len(), "{path:?}");
        for (d, s) in addr.sun_path.iter_mut().zip(bytes) {
            *d = *s as _;
        }
        // Listening from a child only: this process isn't a proxy, even for
        // a moment, to tests running beside it. The child makes only system
        // calls, which is all that's safe after forking a threaded process.
        let pid = unsafe { libc::fork() };
        assert!(pid >= 0, "fork: {}", std::io::Error::last_os_error());
        if pid == 0 {
            unsafe {
                // Nothing of the tests' held open (pipes to a pinentry would
                // never see EOF), and gone with the test.
                libc::syscall(libc::SYS_close_range, 0, u32::MAX, 0);
                libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL);
                let fd = libc::socket(libc::AF_UNIX, libc::SOCK_STREAM, 0);
                let len = std::mem::size_of::<libc::sockaddr_un>() as libc::socklen_t;
                if fd < 0 || libc::bind(fd, (&raw const addr).cast(), len) < 0 || libc::listen(fd, 16) < 0 {
                    libc::_exit(1);
                }
                // Each connection is held, and told it was accepted.
                loop {
                    let c = libc::accept(fd, std::ptr::null_mut(), std::ptr::null_mut());
                    if c >= 0 {
                        libc::write(c, b"!".as_ptr().cast(), 1);
                    }
                }
            }
        }
        Proxy { pid: pid as u32, path }
    }

    /// Spawns `cmd` as a client of the proxy: connected, once accepted, on
    /// its fd 3, and held by it alone.
    pub fn spawn(&self, cmd: &mut Command) -> Killed {
        let conn = wait_until("proxy to listen", || std::os::unix::net::UnixStream::connect(&self.path).ok(), String::new);
        (&conn).read_exact(&mut [0]).unwrap();
        let fd = conn.as_raw_fd();
        unsafe {
            cmd.pre_exec(move || {
                if libc::dup2(fd, 3) < 0 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
        Killed(cmd.spawn().unwrap())
    }
}

/// A child killed on drop, with its process group if it leads one, so
/// nothing is left holding the tests' output.
pub struct Killed(pub Child);

impl Drop for Killed {
    fn drop(&mut self) {
        unsafe { libc::kill(-(self.0.id() as i32), libc::SIGKILL) };
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

impl Drop for Proxy {
    fn drop(&mut self) {
        unsafe {
            libc::kill(self.pid as i32, libc::SIGKILL);
            libc::waitpid(self.pid as i32, std::ptr::null_mut(), 0);
        }
    }
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
        // The pane lives as long as the test process, so the server goes away
        // even if the tests are killed before Drop runs.
        let pane = format!("while kill -0 {} 2>/dev/null; do sleep 1; done", std::process::id());
        t.run(&["-f", "/dev/null", "new-session", "-d", "-x", "100", "-y", "30", &pane]);
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
        let pty = Pty::term(rows, cols);
        let mut cmd = pty.command("tmux");
        self.sb.apply(&mut cmd).arg("attach");
        let child = cmd.spawn().unwrap();
        let tty = pty.path().to_string();
        let attached = || self.run(&["list-clients", "-F", "#{client_tty}"]).lines().any(|l| l == tty);
        // The status line is the last thing drawn.
        let drawn = || pty.screen().contents().contains("[0] 0:");
        poll("client to attach", || (attached() && drawn()).then_some(()), || pty.dump(), false);
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
