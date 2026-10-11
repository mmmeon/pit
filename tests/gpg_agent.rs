//! End to end through a real gpg-agent: `cargo test --test gpg_agent -- --ignored`.

mod common;

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::process::{Command, Stdio};

use common::*;

struct Agent<'a> {
    sb: &'a Sandbox,
}

impl Agent<'_> {
    fn command(&self, program: &str) -> Command {
        let mut cmd = Command::new(program);
        self.sb.apply(&mut cmd).env("GNUPGHOME", self.sb.root.join("gnupg"));
        cmd
    }
}

impl Drop for Agent<'_> {
    fn drop(&mut self) {
        let _ = self.command("gpgconf").args(["--kill", "gpg-agent"]).status();
    }
}

#[test]
#[ignore = "starts a real gpg-agent"]
fn get_passphrase_through_popup() {
    require_tmux!();
    if !have("gpg-connect-agent") {
        eprintln!("skipping: gpg-connect-agent not found");
        return;
    }
    let sb = Sandbox::new();
    let home = sb.root.join("gnupg");
    fs::create_dir(&home).unwrap();
    fs::set_permissions(&home, fs::Permissions::from_mode(0o700)).unwrap();
    fs::write(home.join("gpg-agent.conf"), format!("pinentry-program {BIN}\n")).unwrap();

    let tmux = Tmux::start(&sb);
    let client = tmux.attach(30, 100);
    let agent = Agent { sb: &sb };
    let child = agent
        .command("gpg-connect-agent")
        .env("GPG_TTY", tmux.pane_tty())
        .args(["GET_PASSPHRASE --data pinentry-tmux-test X Passphrase: Unlock%20the%20test%20key", "/bye"])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();

    client.pty.wait_text("Unlock the test key");
    client.pty.wait_text("Passphrase:");
    client.pty.send("correct horse%\r");
    let out = child.wait_with_output().unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(out.status.success(), "{stdout}\n{}", String::from_utf8_lossy(&out.stderr));
    assert_eq!(stdout.lines().collect::<Vec<_>>(), ["D correct horse%25", "OK"]);
    client.pty.wait_gone("Passphrase:");
    assert_eq!(sb.leftovers(), Vec::<String>::new());
}
