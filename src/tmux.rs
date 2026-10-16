//! Finding the tmux client and running the prompt in a popup on it.

use std::env;
use std::fs::{self, OpenOptions};
use std::io::{self, Read, Write};
use std::os::fd::AsRawFd;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use crate::origin;
use crate::sys;
use crate::ui::{self, Layout, Outcome, Request, Secret, Style};

/// How long the popup gets to come up before we fall back.
const POPUP_TIMEOUT: Duration = Duration::from_secs(5);

fn tmux(args: &[&str]) -> Option<String> {
    let out = Command::new("tmux")
        .args(args)
        .stdin(Stdio::null())
        .stderr(Stdio::null())
        .output()
        .ok()?;
    out.status.success().then(|| String::from_utf8_lossy(&out.stdout).into_owned())
}

/// A line in `format` for each pane of every session.
fn panes(format: &str) -> Option<String> {
    tmux(&["list-panes", "-a", "-F", format])
}

pub struct Client {
    pub tty: String,
    pub width: usize,
}

/// Whether `tty` belongs to tmux: one of its panes, or a terminal a client
/// is attached from.
pub fn owns_tty(tty: &str) -> bool {
    let panes = panes("#{pane_tty}");
    let clients = tmux(&["list-clients", "-F", "#{client_tty}"]);
    [panes, clients].into_iter().flatten().any(|out| out.lines().any(|l| l == tty))
}

/// The most recently active tmux client.
///
/// That's the client you just typed the gpg/ssh/git command into, so the
/// popup lands on the window you're looking at. A pane's tty doesn't say
/// which client is looking at it, and several can be.
pub fn find_client() -> Option<Client> {
    clients().into_iter().max_by_key(|(activity, _)| *activity).map(|(_, c)| c)
}

/// All attached clients, with their last activity time.
fn clients() -> Vec<(u64, Client)> {
    let Some(out) = tmux(&["list-clients", "-F", "#{client_activity}\t#{client_tty}\t#{client_width}"]) else {
        return Vec::new();
    };
    out.lines()
        .filter_map(|l| {
            let mut f = l.split('\t');
            let activity: u64 = f.next()?.parse().ok()?;
            let tty = f.next()?.to_string();
            let width = f.next()?.parse().ok()?;
            Some((activity, Client { tty, width }))
        })
        .collect()
}

/// Each pane's process, with the pane as `session:window.pane`.
pub fn pane_pids() -> Vec<(u32, String)> {
    let Some(out) = panes("#{pane_pid}\t#{session_name}:#{window_index}.#{pane_index}") else {
        return Vec::new();
    };
    out.lines()
        .filter_map(|l| {
            let (pid, pane) = l.split_once('\t')?;
            Some((pid.parse().ok()?, origin::clean(pane)))
        })
        .collect()
}

/// Whether the pane on `tty` shows its terminal as is: no full-screen
/// program on the alternate screen, and not in copy mode.
pub fn pane_idle(tty: &str) -> bool {
    let Some(out) = panes("#{pane_tty}\t#{alternate_on}\t#{pane_in_mode}") else {
        return false;
    };
    out.lines().any(|l| l.split_once('\t').is_some_and(|(t, modes)| t == tty && modes == "0\t0"))
}

/// Keeps tmux from expanding `#` in text we pass as a format.
fn literal(s: &str) -> String {
    s.replace('#', "##")
}

/// Tells every other client where the prompt went, so whoever's looking
/// at another terminal knows gpg is waiting.
fn notify_others(client: &Client, title: &str) {
    let msg = literal(&format!("pinentry: {title} - prompt open on {}", client.tty));
    for (_, other) in clients().iter().filter(|(_, c)| c.tty != client.tty) {
        let _ = tmux(&["display-message", "-c", &other.tty, &msg]);
    }
}

/// The user's `@pit-hook` command, run for a prompt opening and then, once
/// this is dropped or the process dies, closing.
pub struct Hook(Option<Child>);

impl Hook {
    /// Runs `@pit-hook`, if set, for a prompt opening at `place`. In the
    /// background: it never holds up the prompt. One shell runs both events,
    /// so close never comes before open is done.
    pub fn open(req: &Request, place: &str) -> Hook {
        let Some(cmd) = option("@pit-hook") else { return Hook(None) };
        const BOTH: &str = r#"PIT_EVENT=open sh -c "$1" </dev/null; read -r x; PIT_EVENT=close exec sh -c "$1" </dev/null"#;
        let child = Command::new("sh")
            .args(["-c", BOTH, "sh", &cmd])
            .env("PIT_TITLE", &req.title)
            .env("PIT_ORIGIN", &req.origin)
            .env("PIT_WHERE", place)
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn();
        Hook(child.ok())
    }
}

impl Drop for Hook {
    fn drop(&mut self) {
        // The end of its stdin says the prompt closed.
        if let Some(mut child) = self.0.take() {
            drop(child.stdin.take());
            std::thread::spawn(move || child.wait());
        }
    }
}

/// A global tmux user option, e.g. `@pinentry-style`.
pub fn option(name: &str) -> Option<String> {
    let v = tmux(&["show-options", "-gqv", name])?;
    let v = v.trim();
    (!v.is_empty()).then(|| v.to_string())
}

fn shell_quote(s: &[u8]) -> String {
    format!("'{}'", String::from_utf8_lossy(s).replace('\'', r"'\''"))
}

/// Asks in a popup on `client`. None means the popup couldn't be shown.
pub fn prompt(client: &Client, req: &Request, lay: &Layout) -> io::Result<Option<Outcome>> {
    let dir = sys::mkdtemp()?;
    let outcome = popup(client, req, lay, &dir);
    let _ = fs::remove_dir_all(&dir);
    outcome
}

fn popup(client: &Client, req: &Request, lay: &Layout, dir: &Path) -> io::Result<Option<Outcome>> {
    fs::write(dir.join("req"), req.encode())?;
    sys::mkfifo(&dir.join("resp"))?;
    sys::mkfifo(&dir.join("ctl"))?;
    // Read-write so the opens don't block. The popup gives up once ctl has
    // no writers left: when we return, or if this process dies.
    let rw = || OpenOptions::new().read(true).write(true).clone();
    let mut resp = rw().open(dir.join("resp"))?;
    let ctl = rw().open(dir.join("ctl"))?;
    sys::set_nonblocking(resp.as_raw_fd(), true)?;

    let (x, y, w) = match req.style {
        Style::Bar => ("0", "S", client.width),
        Style::Box | Style::Line => ("C", "C", lay.width + 4),
    };
    let exe = env::current_exe()?;
    let cmd = [exe.as_os_str().as_bytes(), b"--ui", dir.as_os_str().as_bytes()].map(shell_quote);
    let mut popup = Command::new("tmux")
        .args(["display-popup", "-E", "-c", &client.tty, "-x", x, "-y", y])
        .args(["-w", &w.to_string(), "-h", &(lay.rows + 2).to_string(), "-T", &literal(&lay.title)])
        .arg(cmd.join(" "))
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()?;

    // The popup answers "READY" once it's up, then one Outcome line.
    let start = Instant::now();
    let mut buf = Secret::new();
    let mut ready = false;
    let mut hook = None;
    let outcome = loop {
        let exited = !matches!(popup.try_wait(), Ok(None));
        let readable = match sys::poll(&[resp.as_raw_fd()], Some(Duration::from_millis(100))) {
            Ok(r) => r[0] != 0,
            Err(e) => {
                let _ = popup.kill();
                break Err(e);
            }
        };
        if exited || readable {
            let mut chunk = [0; 256];
            while let Ok(n @ 1..) = resp.read(&mut chunk) {
                buf.0.extend_from_slice(&chunk[..n]);
            }
            chunk.fill(0);
        }
        if let Some(i) = buf.0.iter().position(|&b| b == b'\n') {
            let line = Secret(buf.0.drain(..=i).collect());
            if line.0 != b"READY\n" {
                break Ok(Some(Outcome::decode(&line.0)));
            }
            if !ready {
                // Only once it's really up, and without the origin: other
                // clients may be other people, and command lines can hold
                // secrets.
                notify_others(client, &req.title);
                hook = Some(Hook::open(req, &format!("popup {}", client.tty)));
            }
            ready = true;
            continue;
        }
        if exited {
            // Closed from tmux before answering: treat it as cancel. Never
            // came up at all (e.g. the client already has a popup): fall back.
            break Ok(ready.then_some(Outcome::Cancel));
        }
        if !ready && start.elapsed() > POPUP_TIMEOUT {
            let _ = popup.kill();
            break Ok(None);
        }
    };
    drop(ctl);
    let _ = popup.wait();
    drop(hook);
    outcome
}

/// Runs inside the popup: show the prompt and send back the answer.
pub fn ui_main(dir: &Path) -> io::Result<()> {
    sys::ignore_interrupts();
    // Non-blocking opens fail instead of hanging if the wrapper is gone.
    let open = |write: bool| {
        OpenOptions::new()
            .read(!write)
            .write(write)
            .custom_flags(libc::O_NONBLOCK)
            .clone()
    };
    let mut resp = open(true).open(dir.join("resp"))?;
    let ctl = open(false).open(dir.join("ctl"))?;
    let req = fs::read_to_string(dir.join("req"))?;
    let req = Request::decode(&req).ok_or(io::ErrorKind::InvalidData)?;
    // Everything's open, so the files aren't needed. Cleaning up here means
    // the directory goes away even if the wrapper is killed.
    let _ = fs::remove_dir_all(dir);
    sys::set_nonblocking(resp.as_raw_fd(), false)?;
    resp.write_all(b"READY\n")?;

    let tty = OpenOptions::new().read(true).write(true).open("/dev/tty")?;
    let outcome = ui::run(&tty, &req, Some(&ctl), false)?;
    resp.write_all(&outcome.encode().0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shell_quote_cases() {
        assert_eq!(shell_quote(b"plain"), "'plain'");
        assert_eq!(shell_quote(b"with space"), "'with space'");
        assert_eq!(shell_quote(b"it's"), r"'it'\''s'");
        assert_eq!(shell_quote(b"$(x) `y` \"z\""), "'$(x) `y` \"z\"'");
        assert_eq!(shell_quote(b""), "''");
    }

    #[test]
    fn shell_quote_survives_sh() {
        for s in ["it's", "a'b'c", "$HOME", "x\\y", "tab\there", "'"] {
            let out = Command::new("sh").arg("-c").arg(format!("printf %s {}", shell_quote(s.as_bytes()))).output().unwrap();
            assert_eq!(String::from_utf8(out.stdout).unwrap(), s);
        }
    }
}
