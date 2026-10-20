//! Prompting in place on an ordinary terminal (no tmux server running).

mod common;

use std::time::{Duration, Instant};

use common::*;

const ESC: &str = "\x1b";

/// A pinentry pointed at a fresh 80x24 pty, with a shell line already on it.
fn setup() -> (Sandbox, Pty, Pinentry) {
    let sb = Sandbox::new();
    let pty = Pty::term(24, 80);
    pty.print("$ gpg --sign file\r\n");
    let p = Pinentry::spawn(&sb, &["--ttyname", pty.path()]);
    (sb, pty, p)
}

/// The row the input line is drawn on, once it shows `prompt`.
fn input_row(pty: &Pty, prompt: &str) -> u16 {
    let screen = pty.wait_text(prompt);
    let (rows, cols) = screen.size();
    (0..rows).find(|&r| screen.contents_between(r, 0, r, cols).contains(prompt)).unwrap()
}

fn input_text(pty: &Pty, row: u16) -> String {
    pty.row(row).trim_end().to_string()
}

#[test]
fn draws_in_place_and_erases_after() {
    let (_sb, pty, mut p) = setup();
    let modes = pty.modes();
    p.setup(&["SETDESC Please enter the passphrase for%0A\"User <a@x>\"", "SETPROMPT Passphrase:"]);
    p.start("GETPIN");

    let screen = pty.wait_text("Passphrase:");
    assert_eq!(pty.row(0), "$ gpg --sign file");
    assert_eq!(pty.row(1).trim(), "Please enter the passphrase for \"User <a@x>\"");
    assert_eq!(pty.row(2).trim(), "Passphrase: [····]");
    assert!(screen.hide_cursor());
    assert_ne!(pty.modes(), modes, "terminal should be raw while prompting");

    pty.send("hunter2\r");
    assert_eq!(p.finish(), ["D hunter2", "OK"]);
    let screen = pty.wait_gone("Passphrase:");
    assert_eq!(screen.contents().trim_end(), "$ gpg --sign file");
    assert_eq!(screen.cursor_position(), (1, 0));
    assert!(!screen.hide_cursor());
    assert_eq!(pty.modes(), modes);
}

#[test]
fn backspace_removes_whole_characters() {
    let (_sb, pty, mut p) = setup();
    p.start("GETPIN");
    pty.wait_text("PIN:");
    pty.send("pässwörd");
    pty.send("\x7f\x7f\x08");
    pty.send("\r");
    assert_eq!(data(&p.finish()), "pässw".as_bytes());
}

#[test]
fn ctrl_u_clears_and_ctrl_d_only_cancels_when_empty() {
    let (_sb, pty, mut p) = setup();
    p.start("GETPIN");
    pty.wait_text("PIN:");
    pty.send("wrong\x15ab\x04c\r");
    assert_eq!(p.finish(), ["D abc", "OK"]);
    // Otherwise the old prompt matches, and ^D can arrive before raw mode,
    // whose flush drops it.
    pty.wait_gone("PIN:");

    p.start("GETPIN");
    pty.wait_text("PIN:");
    pty.send("\x04");
    assert_eq!(err_code(&p.finish()), Some(ERR_CANCELED));
}

#[test]
fn escape_sequences_are_ignored() {
    let (_sb, pty, mut p) = setup();
    p.start("GETPIN");
    pty.wait_text("PIN:");
    for seq in ["a", "\x1b[A", "\x1bOB", "b", "\x1b[1;5C", "\x1b[200~", "c", "\x01\t", "\r"] {
        pty.send(seq);
    }
    assert_eq!(p.finish(), ["D abc", "OK"]);
}

#[test]
fn lone_escape_and_ctrl_c_cancel() {
    for key in [ESC, "\x03"] {
        let (_sb, pty, mut p) = setup();
        let modes = pty.modes();
        p.start("GETPIN");
        pty.wait_text("PIN:");
        pty.send("secret");
        pty.send(key);
        assert_eq!(err_code(&p.finish()), Some(ERR_CANCELED), "{key:?}");
        pty.wait_gone("PIN:");
        assert_eq!(pty.modes(), modes);
    }
}

#[test]
fn awkward_bytes_are_escaped_in_data() {
    let (_sb, pty, mut p) = setup();
    p.start("GETPIN");
    pty.wait_text("PIN:");
    pty.send("100% ~ ü 漢 🔑\r");
    let reply = p.finish();
    assert_eq!(reply, ["D 100%25 ~ ü 漢 🔑", "OK"]);
}

#[test]
fn marker_hides_length() {
    let (_sb, pty, mut p) = setup();
    p.start("GETPIN");
    let row = input_row(&pty, "PIN:");
    let mut prev = input_text(&pty, row);
    assert_eq!(prev, " PIN: [····]");
    for _ in 0..12 {
        pty.send("x");
        let before = prev.clone();
        pty.wait("marker to change", |_| input_text(&pty, row) != before);
        prev = input_text(&pty, row);
        assert_eq!(prev.chars().count(), " PIN: [····]".chars().count(), "{prev:?}");
        assert!(prev.matches('•').count() >= 2, "{prev:?}");
    }
    pty.send("\r");
    assert_eq!(data(&p.finish()), b"xxxxxxxxxxxx");
}

#[test]
fn echo_setting_applies() {
    let (sb, pty, mut p) = setup();
    sb.config("echo = \"dots\"");
    p.start("GETPIN");
    let row = input_row(&pty, "PIN:");
    pty.send("abc");
    pty.wait("dots", |_| input_text(&pty, row) == " PIN: •••");
    pty.send("\r");
    assert_eq!(data(&p.finish()), b"abc");
}

#[test]
fn error_shown_in_red_for_one_dialog() {
    let (_sb, pty, mut p) = setup();
    p.setup(&["SETDESC Unlock", "SETERROR Bad passphrase (try 2 of 3)"]);
    p.start("GETPIN");
    let screen = pty.wait_text("Bad passphrase");
    let row = (0..24).find(|&r| pty.row(r).contains("Bad passphrase")).unwrap();
    let col = pty.row(row).find('B').unwrap() as u16;
    let cell = screen.cell(row, col).unwrap();
    assert_eq!(cell.fgcolor(), vt100::Color::Idx(1));
    assert!(cell.bold());
    pty.send("x\r");
    p.finish();
    pty.wait_gone("Bad passphrase");

    p.start("GETPIN");
    pty.wait_text("PIN:");
    assert!(!pty.text().contains("Bad passphrase"));
    pty.send("\x03");
    p.finish();
}

#[test]
fn repeat_and_mismatch() {
    let (_sb, pty, mut p) = setup();
    p.setup(&["SETPROMPT New:", "SETREPEAT Again:", "SETREPEATERROR no match"]);
    p.start("GETPIN");
    pty.wait_text("New:");
    pty.send("one\r");
    pty.wait_text("Again:");
    pty.send("two\r");
    pty.wait_text("no match");
    pty.wait_text("New:");
    pty.send("same\r");
    pty.wait_text("Again:");
    pty.send("same\r");
    assert_eq!(p.finish(), ["S PIN_REPEATED", "D same", "OK"]);
    pty.wait_gone("New:");

    // The repeat applies to one GETPIN only.
    p.start("GETPIN");
    pty.wait_text("New:");
    pty.send("solo\r");
    assert_eq!(p.finish(), ["D solo", "OK"]);
}

#[test]
fn confirm_buttons() {
    for (keys, code) in [("\r", None), ("n", Some(ERR_NOT_CONFIRMED)), ("N", Some(ERR_NOT_CONFIRMED)), ("y", None), (ESC, Some(ERR_CANCELED)), ("c", Some(ERR_CANCELED))] {
        let (_sb, pty, mut p) = setup();
        p.setup(&["SETDESC Really?", "SETOK _Yes", "SETNOTOK _No", "SETCANCEL _Cancel"]);
        p.start("CONFIRM");
        pty.wait_text("⏎ Yes   n No   esc Cancel");
        pty.send("q");
        pty.send(keys);
        assert_eq!(err_code(&p.finish()), code, "{keys:?}");
        pty.wait_gone("Really?");
    }
}

#[test]
fn message_and_one_button_confirm_always_ok() {
    for cmd in ["MESSAGE", "CONFIRM --one-button"] {
        for key in ["\r", ESC, "\x03"] {
            let (_sb, pty, mut p) = setup();
            p.setup(&["SETDESC Card removed", "SETNOTOK _No"]);
            p.start(cmd);
            pty.wait_text("Card removed");
            assert!(!pty.text().contains("No"), "message dialogs have one button");
            pty.send(key);
            assert_eq!(p.finish(), ["OK"], "{cmd} {key:?}");
        }
    }
}

#[test]
fn timeout() {
    let (_sb, pty, mut p) = setup();
    let modes = pty.modes();
    p.setup(&["SETTIMEOUT 1"]);
    let start = Instant::now();
    p.start("GETPIN");
    pty.wait_text("PIN:");
    assert_eq!(err_code(&p.finish()), Some(ERR_TIMEOUT));
    assert!(start.elapsed() < Duration::from_secs(3));
    pty.wait_gone("PIN:");
    assert_eq!(pty.modes(), modes);
}

#[test]
fn ttyname_from_option() {
    let sb = Sandbox::new();
    let pty = Pty::term(24, 80);
    let mut p = Pinentry::spawn(&sb, &[]);
    p.setup(&[&format!("OPTION ttyname={}", pty.path())]);
    p.start("GETPIN");
    pty.wait_text("PIN:");
    pty.send("ok\r");
    assert_eq!(p.finish(), ["D ok", "OK"]);
}

#[test]
fn narrow_terminal_wraps_description() {
    let sb = Sandbox::new();
    let pty = Pty::new(10, 30);
    let mut p = Pinentry::spawn(&sb, &["--ttyname", pty.path()]);
    p.setup(&["SETDESC Please enter the passphrase to unlock the OpenPGP secret key"]);
    p.start("GETPIN");
    pty.wait_text("PIN:");
    let rows: Vec<String> = (0..10).map(|r| pty.row(r)).take_while(|r| !r.contains("PIN:")).collect();
    assert!(rows.len() > 1, "{rows:?}");
    assert!(rows.iter().all(|r| r.chars().count() < 30), "{rows:?}");
    pty.send("\x03");
    p.finish();
    let screen = pty.wait_gone("PIN:");
    assert_eq!(screen.contents().trim(), "");
}

#[test]
fn terminal_in_raw_mode_is_not_asked() {
    // A full-screen program there would take some of the keys.
    let (_sb, pty, mut p) = setup();
    pty.raw();
    p.start("GETPIN");
    assert_eq!(err_code(&p.finish()), Some(ERR_NO_PIN_ENTRY));
    assert!(!pty.text().contains("PIN:"));
}

#[test]
fn another_reader_in_the_foreground_is_not_asked() {
    // gpg asked from elsewhere, and cat has the terminal: it would take
    // some of the keys.
    let (_sb, pty, mut p) = setup();
    let mut cat = pty.command("cat").spawn().unwrap();
    let uid = unsafe { libc::getuid() };
    p.setup(&[&format!("OPTION owner={}/{uid}", std::process::id())]);
    p.start("GETPIN");
    assert_eq!(err_code(&p.finish()), Some(ERR_NO_PIN_ENTRY));
    assert!(!pty.text().contains("PIN:"));
    let _ = cat.kill();
    let _ = cat.wait();
}

fn ask_through(p: &mut Pinentry, proxy: &Proxy) -> Vec<String> {
    let uid = unsafe { libc::getuid() };
    p.setup(&[&format!("OPTION owner={}/{uid}", proxy.pid)]);
    p.start("GETPIN");
    p.finish()
}

#[test]
fn client_behind_a_proxy_is_asked_on_its_terminal() {
    // gpg-agent names the proxy, but the command it passes on for runs here
    // in the foreground: it's the one reading, not another command.
    let (sb, pty, mut p) = setup();
    let proxy = Proxy::start(&sb);
    let _client = proxy.spawn(pty.command("sleep").arg("999"));
    let uid = unsafe { libc::getuid() };
    p.setup(&[&format!("OPTION owner={}/{uid}", proxy.pid)]);
    p.start("GETPIN");
    pty.wait_text("PIN:");
    pty.send("ok\r");
    assert_eq!(p.finish(), ["D ok", "OK"]);
}

#[test]
fn client_behind_a_proxy_elsewhere_is_not_asked_over_a_reader() {
    let (sb, pty, mut p) = setup();
    let proxy = Proxy::start(&sb);
    let null = std::process::Stdio::null;
    let _client = proxy.spawn(std::process::Command::new("sleep").arg("999").stdout(null()).stderr(null()));
    let _cat = Killed(pty.command("cat").spawn().unwrap());
    let reply = ask_through(&mut p, &proxy);
    assert_eq!(err_code(&reply), Some(ERR_NO_PIN_ENTRY));
    assert!(reply[0].contains("in use by") && !reply[0].contains("proxy"), "{reply:?}");
    assert!(!pty.text().contains("PIN:"));
}

#[test]
fn unknown_client_behind_a_proxy_is_not_asked_and_says_why() {
    // With no client to tell from it, sleep could be another reader.
    let (sb, pty, mut p) = setup();
    let proxy = Proxy::start(&sb);
    let _sleep = Killed(pty.command("sleep").arg("999").spawn().unwrap());
    let reply = ask_through(&mut p, &proxy);
    assert_eq!(err_code(&reply), Some(ERR_NO_PIN_ENTRY));
    assert!(reply[0].contains("proxy in front of gpg-agent"), "{reply:?}");
    assert!(!pty.text().contains("PIN:"));
}
