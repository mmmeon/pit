//! Text screenshots of each mode, kept in tests/screenshots/ for the readme.
//! A test fails when its screenshots change, and writes the new ones there:
//! look them over with git diff, and run it again.

mod common;

use std::fs;
use std::path::PathBuf;
use std::thread;
use std::time::Duration;

use common::*;

const ROWS: u16 = 14;
const COLS: u16 = 72;
const DESC: &str = "SETDESC Please enter the passphrase to unlock the OpenPGP secret key:%0A\
    \"User <user@example.org>\"%0A255-bit EDDSA key, ID 3AA5C34371567BD2,%0Acreated 2024-03-01.";

fn rows(screen: &vt100::Screen) -> Vec<String> {
    let (_, cols) = screen.size();
    screen.rows(0, cols).map(|r| r.trim_end().to_string()).collect()
}

/// One test's screenshots, checked against tests/screenshots/<test>.txt.
struct Shots {
    test: &'static str,
    text: String,
}

impl Shots {
    fn new(test: &'static str) -> Shots {
        Shots { test, text: String::new() }
    }

    fn add(&mut self, name: &str, lines: &[String]) {
        self.text += &format!("--- {name}\n");
        for l in lines {
            self.text += &steady(l);
            self.text += "\n";
        }
        self.text += "\n";
    }

    /// Fails if the screenshots changed, writing the new ones.
    fn check(self) {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(format!("tests/screenshots/{}.txt", self.test));
        let old = fs::read_to_string(&path).ok();
        if old.as_deref() == Some(&self.text) {
            return;
        }
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(&path, &self.text).unwrap();
        assert!(old.is_none(), "{} changed: look it over with git diff, and run again\n{}", path.display(), self.text);
    }
}

/// The marker echo changes at random on each key: show any typed-in one as
/// the same.
fn steady(line: &str) -> String {
    let mut chars: Vec<char> = line.chars().collect();
    for i in 0..chars.len().saturating_sub(5) {
        let marker = &chars[i + 1..i + 5];
        if chars[i] == '[' && chars[i + 5] == ']' && marker.iter().all(|c| "•·".contains(*c)) && marker.contains(&'•') {
            chars.splice(i + 1..i + 5, "•·•·".chars());
        }
    }
    chars.into_iter().collect()
}

/// The popup's rows, and with `status` everything below it too.
fn popup(screen: &vt100::Screen, status: bool) -> Vec<String> {
    let rows = rows(screen);
    let top = rows.iter().position(|r| r.contains('┌')).expect("no popup");
    let bottom = top + rows[top..].iter().position(|r| r.contains('└')).unwrap();
    let end = if status { rows.len() } else { bottom + 1 };
    let left = rows[top].chars().position(|c| c == '┌').unwrap();
    let right = rows[top].chars().position(|c| c == '┐').unwrap();
    rows[top..end]
        .iter()
        .enumerate()
        .map(|(i, r)| {
            let r: String = r.chars().skip(left).collect();
            if i <= bottom - top { r.chars().take(right - left + 1).collect() } else { r }
        })
        .map(|r| r.trim_end().to_string())
        .collect()
}

/// A server with a `work` session whose window 2 runs what looks like
/// `git commit -S`, attached from one client.
struct Desk<'a> {
    sb: &'a Sandbox,
    tmux: Tmux<'a>,
    client: Client,
    owner: String,
}

impl<'a> Desk<'a> {
    fn new(sb: &'a Sandbox) -> Desk<'a> {
        let tmux = Tmux::start(sb);
        // Attached before the rename, which attach() waits on the old name of.
        let client = tmux.attach(ROWS, COLS);
        tmux.run(&["rename-session", "work"]);
        tmux.run(&["rename-window", "zsh"]);
        // No hostname or clock in the screenshots.
        tmux.set("status-right", "");
        // perl standing in for git, run as `git commit -S` with its script
        // in a file named commit; sleep is the requester.
        std::fs::write(sb.tmp().join("commit"), "system('sleep', 999)").unwrap();
        let fake = format!("cd {} && perl -e 'exec {{\"perl\"}} qw(git commit -S)'; :", sb.tmp().display());
        let out = tmux.run(&["new-window", "-t", "work:2", "-n", "git", "-P", "-F", "#{pane_pid}", &fake]);
        let shell: u32 = out.trim().parse().unwrap();
        let comm = |p: u32| std::fs::read_to_string(format!("/proc/{p}/comm")).unwrap_or_default();
        let pid = wait_until("sleep", || descendants(shell).into_iter().find(|&p| comm(p).trim() == "sleep"), String::new);
        let uid = unsafe { libc::getuid() };
        let host = std::fs::read_to_string("/proc/sys/kernel/hostname").unwrap();
        Desk { sb, tmux, client, owner: format!("OPTION owner={pid}/{uid} {}", host.trim()), }
    }

    fn pinentry(&self) -> Pinentry {
        let mut p = Pinentry::spawn(self.sb, &[]);
        p.setup(&[&self.owner]);
        p
    }
}

fn descendants(pid: u32) -> Vec<u32> {
    let children = std::fs::read_to_string(format!("/proc/{pid}/task/{pid}/children")).unwrap_or_default();
    children.split_whitespace().filter_map(|c| c.parse().ok()).flat_map(|c| [vec![c], descendants(c)].concat()).collect()
}

/// Waits for the screen to stop changing, and returns it.
fn still(pty: &Pty) -> vt100::Screen {
    let mut last = pty.screen();
    wait_until("screen to settle", || {
        thread::sleep(Duration::from_millis(200));
        let now = pty.screen();
        let same = now.contents() == last.contents();
        last = now.clone();
        same.then_some(now)
    }, || pty.dump())
}

/// Waits for typed keys to show in the marker echo.
fn typed(pty: &Pty) -> vt100::Screen {
    pty.wait_gone("[····]");
    still(pty)
}

#[test]
fn styles() {
    require_tmux!();
    let mut shots = Shots::new("styles");
    for style in ["bar", "box", "line"] {
        let sb = Sandbox::new();
        let d = Desk::new(&sb);
        sb.config(&format!("[tmux]\nstyle = \"{style}\""));
        let mut p = d.pinentry();
        p.setup(&[DESC, "SETPROMPT Passphrase:"]);
        p.start("GETPIN");
        d.client.pty.wait_text("Passphrase:");
        d.client.pty.send("hunter2");
        shots.add(&format!("style {style}"), &popup(&typed(&d.client.pty), style == "bar"));
        d.client.pty.send("\x1b");
        p.finish();
    }
    shots.check();
}

#[test]
fn echoes() {
    require_tmux!();
    let mut shots = Shots::new("echoes");
    for echo in ["marker", "dots", "none"] {
        let sb = Sandbox::new();
        let d = Desk::new(&sb);
        sb.config(&format!("echo = \"{echo}\"\n[tmux]\nstyle = \"box\""));
        let mut p = d.pinentry();
        p.setup(&["SETDESC Unlock \"User <user@example.org>\"", "SETPROMPT Passphrase:"]);
        p.start("GETPIN");
        d.client.pty.wait_text("Passphrase:");
        d.client.pty.send("hunter2");
        let screen = match echo {
            "marker" => typed(&d.client.pty),
            "dots" => {
                d.client.pty.wait_text("•••••••");
                still(&d.client.pty)
            }
            _ => still(&d.client.pty),
        };
        shots.add(&format!("echo {echo}"), &popup(&screen, false));
        d.client.pty.send("\x1b");
        p.finish();
    }
    shots.check();
}

#[test]
fn dialogs() {
    require_tmux!();
    let sb = Sandbox::new();
    let d = Desk::new(&sb);
    sb.config("[tmux]\nstyle = \"box\"");
    let pty = &d.client.pty;
    let mut shots = Shots::new("dialogs");
    let mut shot = |name: &str| shots.add(name, &popup(&still(pty), false));

    let mut p = d.pinentry();
    p.setup(&[DESC, "SETPROMPT Passphrase:", "SETERROR Bad Passphrase (try 2 of 3)"]);
    p.start("GETPIN");
    pty.wait_text("Passphrase:");
    shot("wrong passphrase");
    pty.send("\x1b");
    p.finish();
    pty.wait_gone("Passphrase:");

    let mut p = d.pinentry();
    p.setup(&[
        "SETDESC Please enter a passphrase to protect the new key",
        "SETPROMPT Passphrase:",
        "SETREPEAT Repeat:",
        "SETREPEATERROR does not match - try again",
    ]);
    p.start("GETPIN");
    pty.wait_text("Passphrase:");
    pty.send("hunter2\r");
    pty.wait_text("Repeat:");
    pty.send("hunter3");
    pty.wait_gone("Repeat: [····]");
    shot("new passphrase, repeat");
    pty.send("\r");
    pty.wait_text("does not match");
    shot("new passphrase, mismatch");
    pty.send("\x1b");
    p.finish();
    pty.wait_gone("Repeat:");

    let mut p = d.pinentry();
    p.setup(&[
        "SETDESC An ssh process requested the use of key%0A\
         SHA256:Xg5lV0wHqR6c8eZ9o1C3pJ2bDkF4aT7nYyLmQsUvWiE%0A\
         (user@laptop)%0ADo you want to allow this?",
        "SETOK _Allow",
        "SETNOTOK _Deny",
    ]);
    p.start("CONFIRM");
    pty.wait_text("Allow");
    shot("confirm");
    pty.send("\x1b");
    p.finish();
    pty.wait_gone("Allow");

    let mut p = d.pinentry();
    p.setup(&["SETDESC No card found. Insert your OpenPGP card."]);
    p.start("MESSAGE");
    pty.wait_text("No card");
    shot("message");
    pty.send("\r");
    p.finish();
    shots.check();
}

#[test]
fn other_client() {
    require_tmux!();
    let sb = Sandbox::new();
    let d = Desk::new(&sb);
    d.tmux.set("display-time", "10000");
    d.tmux.run(&["rename-session", "0"]);
    let other = d.tmux.attach(ROWS, COLS);
    d.tmux.run(&["rename-session", "work"]);
    // Activity is tracked in whole seconds.
    thread::sleep(Duration::from_millis(1100));
    d.client.pty.send("x");
    let mut p = d.pinentry();
    p.setup(&[DESC]);
    p.start("GETPIN");
    other.pty.wait_text("prompt open on");
    let rows = rows(&still(&other.pty));
    // The client's tty differs from run to run.
    let (msg, _) = rows[rows.len() - 1].split_once("/dev/pts/").unwrap();
    let mut shots = Shots::new("other_client");
    shots.add("other client", &[format!("{msg}/dev/pts/N")]);
    shots.check();
    d.client.pty.send("\x1b");
    p.finish();
}

#[test]
fn inline() {
    let sb = Sandbox::new();
    let pty = Pty::new(8, COLS);
    pty.print("~/src/notes $ git commit -S -m 'Fix typo'\r\n");
    let mut p = Pinentry::spawn(&sb, &["--ttyname", pty.path()]);
    p.setup(&[DESC, "SETPROMPT Passphrase:"]);
    p.start("GETPIN");
    pty.wait_text("Passphrase:");
    pty.send("hunter2");
    let mut rows = rows(&typed(&pty));
    while rows.last().is_some_and(String::is_empty) {
        rows.pop();
    }
    let mut shots = Shots::new("inline");
    shots.add("inline", &rows);
    shots.check();
    pty.send("\x1b");
    p.finish();
}
