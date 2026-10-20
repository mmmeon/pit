//! When there's no popup and no terminal: another pinentry on a display, and
//! prompts left waiting for `pit answer`.

mod common;

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::process::Stdio;

use common::*;

/// A display that's taken as reachable without a socket to check.
const DISPLAY: (&str, &str) = ("DISPLAY", "remote.example:0");

/// A stand-in graphical pinentry: logs what it's sent to `gui.log`, and
/// answers GETPIN with $FAKE_PIN and CONFIRM with $FAKE_CONFIRM.
fn fake_gui(sb: &Sandbox) -> PathBuf {
    let path = sb.root.join("fake-gui");
    let log = sb.root.join("gui.log");
    let script = format!(
        r#"#!/bin/sh
echo "OK fake pinentry"
while IFS= read -r line; do
  printf '%s\n' "$line" >> '{}'
  case "$line" in
    GETPIN) printf 'D %s\nOK\n' "${{FAKE_PIN:-hunter2}}" ;;
    CONFIRM*) echo "${{FAKE_CONFIRM:-OK}}" ;;
    BYE) echo OK; exit 0 ;;
    *) echo OK ;;
  esac
done
"#,
        log.display()
    );
    fs::write(&path, script).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).unwrap();
    path
}

fn gui_log(sb: &Sandbox) -> Vec<String> {
    fs::read_to_string(sb.root.join("gui.log")).unwrap_or_default().lines().map(String::from).collect()
}

fn gui_config(sb: &Sandbox, order: &str) {
    let gui = fake_gui(sb);
    sb.config(&format!("[gui]\npinentry = '{}'\norder = \"{order}\"\n", gui.display()));
}

#[test]
fn gui_when_nowhere_else() {
    let sb = Sandbox::new();
    gui_config(&sb, "last");
    let mut p = Pinentry::spawn_env(&sb, &[], &[DISPLAY]);
    p.setup(&["OPTION ttyname=/dev/pts/99", "OPTION lc-ctype=C.UTF-8", "SETDESC Unlock%0A\"User\"", "SETPROMPT Passphrase:"]);
    assert_eq!(p.cmd("GETPIN"), ["D hunter2", "OK"]);
    let log = gui_log(&sb);
    assert!(log.contains(&"OPTION lc-ctype=C.UTF-8".into()), "{log:?}");
    assert!(!log.iter().any(|l| l.contains("ttyname")), "it mustn't fall back to a terminal: {log:?}");
    for line in ["SETTITLE gpg", "SETDESC Unlock%0A\"User\"", "SETPROMPT Passphrase:", "GETPIN", "BYE"] {
        assert!(log.contains(&line.into()), "{line} in {log:?}");
    }
}

#[test]
fn gui_answers_are_final() {
    let sb = Sandbox::new();
    gui_config(&sb, "last");
    let cancelled = format!("ERR {ERR_CANCELED} Operation cancelled");
    let mut p = Pinentry::spawn_env(&sb, &[], &[DISPLAY, ("FAKE_CONFIRM", &cancelled)]);
    assert_eq!(err_code(&p.cmd("CONFIRM")), Some(ERR_CANCELED));
    let not = format!("ERR {ERR_NOT_CONFIRMED} Not confirmed");
    let mut p = Pinentry::spawn_env(&sb, &[], &[DISPLAY, ("FAKE_CONFIRM", &not)]);
    assert_eq!(err_code(&p.cmd("CONFIRM")), Some(ERR_NOT_CONFIRMED));
    let mut p = Pinentry::spawn_env(&sb, &[], &[DISPLAY]);
    assert_eq!(p.cmd("MESSAGE"), ["OK"]);
    assert!(gui_log(&sb).contains(&"CONFIRM --one-button".into()));
}

#[test]
fn gui_that_cant_show_falls_through() {
    let sb = Sandbox::new();
    sb.config("[gui]\npinentry = '/nonexistent/pinentry-qt'\n");
    let mut p = Pinentry::spawn_env(&sb, &[], &[DISPLAY]);
    let reply = p.cmd("GETPIN");
    assert_eq!(err_code(&reply), Some(ERR_NO_PIN_ENTRY));
    assert!(reply[0].contains("and /nonexistent/pinentry-qt couldn't show it"), "{reply:?}");
}

#[test]
fn gui_needs_a_display() {
    let sb = Sandbox::new();
    gui_config(&sb, "last");
    let mut p = Pinentry::spawn_env(&sb, &[], &[("DISPLAY", ":4242")]);
    assert_eq!(err_code(&p.cmd("GETPIN")), Some(ERR_NO_PIN_ENTRY));
    assert!(gui_log(&sb).is_empty());
    // gpg-agent's --display counts too.
    let mut p = Pinentry::spawn_env(&sb, &["--display", "remote.example:0"], &[]);
    assert_eq!(p.cmd("GETPIN"), ["D hunter2", "OK"]);
}

#[test]
fn no_handing_off_twice() {
    let sb = Sandbox::new();
    gui_config(&sb, "first");
    let mut p = Pinentry::spawn_env(&sb, &[], &[DISPLAY, ("PIT_HANDOFF", "1")]);
    assert_eq!(err_code(&p.cmd("GETPIN")), Some(ERR_NO_PIN_ENTRY));
    assert!(gui_log(&sb).is_empty());
}

#[test]
fn gui_first_comes_before_the_terminal() {
    let sb = Sandbox::new();
    gui_config(&sb, "first");
    let pty = Pty::term(24, 80);
    let mut p = Pinentry::spawn_env(&sb, &["--ttyname", pty.path()], &[DISPLAY]);
    assert_eq!(p.cmd("GETPIN"), ["D hunter2", "OK"]);
    assert_eq!(pty.text().trim(), "");

    // Without a display, the terminal it is.
    let mut p = Pinentry::spawn(&sb, &["--ttyname", pty.path()]);
    p.start("GETPIN");
    pty.wait_text("PIN:");
    pty.send("abc\r");
    assert_eq!(p.finish(), ["D abc", "OK"]);
}

#[test]
fn gui_last_comes_after_the_terminal() {
    let sb = Sandbox::new();
    gui_config(&sb, "last");
    let pty = Pty::term(24, 80);
    let mut p = Pinentry::spawn_env(&sb, &["--ttyname", pty.path()], &[DISPLAY]);
    p.start("GETPIN");
    pty.wait_text("PIN:");
    pty.send("abc\r");
    assert_eq!(p.finish(), ["D abc", "OK"]);
    assert!(gui_log(&sb).is_empty());
}

/// Runs `pit answer` on `pty`.
fn answer(sb: &Sandbox, pty: &Pty) -> Killed {
    let mut cmd = pty.command(BIN);
    sb.apply(&mut cmd).arg("answer");
    Killed(cmd.spawn().unwrap())
}

fn sockets(sb: &Sandbox) -> Vec<String> {
    fs::read_dir(sb.root.join("run/pit"))
        .map(|d| d.flatten().map(|e| e.file_name().to_string_lossy().into_owned()).collect())
        .unwrap_or_default()
}

#[test]
fn pending_prompt_is_answered_elsewhere() {
    let sb = Sandbox::new();
    sb.config("pending = \"wait\"\n");
    let mut p = Pinentry::spawn(&sb, &[]);
    p.setup(&["SETDESC Unlock the key", "SETPROMPT Passphrase:"]);
    p.start("GETPIN");
    wait_until("the socket", || (!sockets(&sb).is_empty()).then_some(()), || format!("{:?}", sockets(&sb)));

    let pty = Pty::term(24, 80);
    pty.print("$ pit answer\r\n");
    let mut a = answer(&sb, &pty);
    pty.wait_text("Passphrase:");
    assert_eq!(pty.row(1).trim(), "gpg");
    assert_eq!(pty.row(2).trim(), "Unlock the key");
    pty.send("s3cret\r");
    assert_eq!(p.finish(), ["D s3cret", "OK"]);
    assert!(a.0.wait().unwrap().success());
    assert_eq!(pty.text().trim_end(), "$ pit answer");
    assert!(sockets(&sb).is_empty(), "{:?}", sockets(&sb));
}

#[test]
fn pending_prompt_outlives_an_answer_that_went_away() {
    let sb = Sandbox::new();
    sb.config("pending = \"wait\"\n");
    let mut p = Pinentry::spawn(&sb, &[]);
    p.start("CONFIRM");
    wait_until("the socket", || (!sockets(&sb).is_empty()).then_some(()), || format!("{:?}", sockets(&sb)));

    let pty = Pty::term(24, 80);
    let mut a = answer(&sb, &pty);
    pty.wait_text("Cancel");
    let _ = a.0.kill();
    let _ = a.0.wait();

    let pty = Pty::term(24, 80);
    let _a = answer(&sb, &pty);
    pty.wait_text("Cancel");
    pty.send("\r");
    assert_eq!(p.finish(), ["OK"]);
}

#[test]
fn pending_prompt_times_out() {
    let sb = Sandbox::new();
    sb.config("pending = \"wait\"\n");
    let mut p = Pinentry::spawn(&sb, &[]);
    p.setup(&["SETTIMEOUT 1"]);
    assert_eq!(err_code(&p.cmd("GETPIN")), Some(ERR_TIMEOUT));
    assert!(sockets(&sb).is_empty());
}

#[test]
fn answer_with_nothing_waiting() {
    let sb = Sandbox::new();
    // One left by a pinentry that was killed, which goes.
    fs::create_dir_all(sb.root.join("run/pit")).unwrap();
    fs::set_permissions(sb.root.join("run/pit"), fs::Permissions::from_mode(0o700)).unwrap();
    drop(std::os::unix::net::UnixListener::bind(sb.root.join("run/pit/1.sock")).unwrap());
    let mut cmd = std::process::Command::new(BIN);
    let out = sb.apply(&mut cmd).arg("answer").stdin(Stdio::null()).output().unwrap();
    assert!(!out.status.success());
    assert_eq!(String::from_utf8_lossy(&out.stderr), "pit: nothing is waiting for an answer\n");
    assert!(sockets(&sb).is_empty());
}
