//! The Assuan side, with no tmux server and no terminal to prompt on.

mod common;

use common::*;

#[test]
fn greeting_comments_and_bye() {
    let sb = Sandbox::new();
    let mut p = Pinentry::spawn(&sb, &[]);
    p.start("");
    p.start("# a comment");
    assert_eq!(p.cmd("NOP"), ["OK"]);
    assert_eq!(p.cmd("nop"), ["OK"]);
    assert_eq!(p.cmd("BYE"), ["OK closing connection"]);
    assert!(p.close().success());
}

#[test]
fn eof_exits_cleanly() {
    let sb = Sandbox::new();
    let mut p = Pinentry::spawn(&sb, &[]);
    assert!(p.close().success());
}

#[test]
fn errors_are_formatted_like_pinentry() {
    let sb = Sandbox::new();
    let mut p = Pinentry::spawn(&sb, &[]);
    assert_eq!(p.cmd("FROB"), ["ERR 83886355 Unknown IPC command <Pinentry>"]);
    assert_eq!(p.cmd("GETINFO nope"), ["ERR 83886360 IPC parameter error <Pinentry>"]);
}

#[test]
fn ttyname_flags() {
    for args in [&["--ttyname", "/dev/pts/7", "--ttytype", "vt220"][..], &["--ttyname=/dev/pts/7", "--ttytype=vt220"], &["-T", "/dev/pts/7", "-N", "vt220"]] {
        let sb = Sandbox::new();
        let mut p = Pinentry::spawn(&sb, args);
        assert_eq!(p.cmd("GETINFO ttyinfo"), ["D /dev/pts/7 vt220 -", "OK"], "{args:?}");
    }
}

#[test]
fn getinfo_basics() {
    let sb = Sandbox::new();
    let mut p = Pinentry::spawn(&sb, &[]);
    assert_eq!(p.cmd("GETINFO flavor"), ["D tmux", "OK"]);
    assert_eq!(p.cmd("GETINFO version"), [format!("D {}", env!("CARGO_PKG_VERSION")), "OK".into()]);
    assert_eq!(p.cmd("GETINFO pid"), [format!("D {}", p.pid()), "OK".into()]);
    assert_eq!(p.cmd("GETINFO ttyinfo"), ["D - - -", "OK"]);
}

#[test]
fn long_data_is_split_into_lines() {
    let sb = Sandbox::new();
    let mut p = Pinentry::spawn(&sb, &[]);
    let name = format!("/dev/{}", "x%".repeat(600));
    let escaped = name.replace('%', "%25");
    p.setup(&[&format!("OPTION ttyname={escaped}")]);
    let reply = p.cmd("GETINFO ttyinfo");
    assert!(reply.len() > 2, "{reply:?}");
    assert!(reply.iter().all(|l| l.len() < 1000));
    assert_eq!(data(&reply), format!("{name} - -").as_bytes());
}

#[test]
fn nowhere_to_ask() {
    let sb = Sandbox::new();
    let mut p = Pinentry::spawn(&sb, &[]);
    for cmd in ["GETPIN", "CONFIRM", "CONFIRM --one-button", "MESSAGE"] {
        assert_eq!(p.cmd(cmd), ["ERR 83886165 No pinentry (no tmux client for a popup, and no terminal to ask on) <Pinentry>"], "{cmd}");
    }
}

#[test]
fn unopenable_tty() {
    let sb = Sandbox::new();
    let mut p = Pinentry::spawn(&sb, &["--ttyname", "/nonexistent/tty"]);
    let reply = p.cmd("GETPIN");
    assert_eq!(err_code(&reply), Some(ERR_NO_PIN_ENTRY), "{reply:?}");
    assert!(reply[0].contains("No pinentry (") && reply[0].contains("No such file"), "{reply:?}");
}
