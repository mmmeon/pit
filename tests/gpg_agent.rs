//! End to end through a real gpg-agent: `cargo test --test gpg_agent -- --ignored`.

mod common;

use std::fs;
use std::io;
use std::net::Shutdown;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::thread;

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
        .args(["GET_PASSPHRASE --data pit-test X Passphrase: Unlock%20the%20test%20key", "/bye"])
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

#[test]
#[ignore = "starts a real gpg-agent"]
fn ssh_request_names_command_and_pane() {
    require_tmux!();
    if !have("gpg-connect-agent") || !have("ssh-add") || !have("ssh-keygen") {
        eprintln!("skipping: gpg-connect-agent or ssh tools not found");
        return;
    }
    let sb = Sandbox::new();
    let home = sb.root.join("gnupg");
    fs::create_dir(&home).unwrap();
    fs::set_permissions(&home, fs::Permissions::from_mode(0o700)).unwrap();
    fs::write(home.join("gpg-agent.conf"), format!("pinentry-program {BIN}\nenable-ssh-support\n")).unwrap();
    let key = sb.root.join("id");
    let status = Command::new("ssh-keygen").args(["-q", "-t", "ed25519", "-N", "", "-f"]).arg(&key).status().unwrap();
    assert!(status.success());

    let tmux = Tmux::start(&sb);
    let client = tmux.attach(30, 100);
    let agent = Agent { sb: &sb };
    assert!(agent.command("gpg-connect-agent").arg("/bye").stdout(Stdio::null()).status().unwrap().success());
    let out = agent.command("gpgconf").args(["--list-dirs", "agent-ssh-socket"]).output().unwrap();
    let sock = String::from_utf8(out.stdout).unwrap();

    // Adding a key makes the agent ask for a passphrase to protect it with.
    let cmd = format!("SSH_AUTH_SOCK={} ssh-add {}; :", sock.trim(), key.display());
    let pane = tmux.run(&["new-window", "-d", "-P", "-F", "#S:#I.#P", &cmd]);
    let screen = client.pty.wait_text(&format!(" @ {} ", pane.trim()));
    assert!(screen.contents().contains("· ssh-add "), "{}", screen.contents());
    client.pty.send("\x1b");
    client.pty.wait_gone("ssh-add");
    assert_eq!(sb.leftovers(), Vec::<String>::new());
}

/// Forwards each connection on a socket named `name` to the agent socket
/// `to`, as yubikey-touch-detector does: the agent sees this process as the
/// one asking. Returns the socket's path.
fn forward(sb: &Sandbox, name: &str, to: &str) -> PathBuf {
    let dir = sb.root.join("proxy");
    fs::create_dir_all(&dir).unwrap();
    let path = dir.join(name);
    let listener = UnixListener::bind(&path).unwrap();
    let to = to.to_string();
    thread::spawn(move || {
        for client in listener.incoming().flatten() {
            let Ok(agent) = UnixStream::connect(&to) else { continue };
            for (mut from, mut into) in [(client.try_clone().unwrap(), agent.try_clone().unwrap()), (agent, client)] {
                thread::spawn(move || {
                    let _ = io::copy(&mut from, &mut into);
                    let _ = into.shutdown(Shutdown::Both);
                });
            }
        }
    });
    path
}

#[test]
#[ignore = "starts a real gpg-agent"]
fn ssh_from_a_terminal_outside_tmux_is_asked_there() {
    ssh_from_a_terminal_outside_tmux(false);
}

#[test]
#[ignore = "starts a real gpg-agent"]
fn ssh_through_a_proxy_from_a_terminal_outside_tmux_is_asked_there() {
    ssh_from_a_terminal_outside_tmux(true);
}

fn ssh_from_a_terminal_outside_tmux(proxied: bool) {
    require_tmux!();
    if !have("gpg-connect-agent") || !have("ssh-add") || !have("ssh-keygen") {
        eprintln!("skipping: gpg-connect-agent or ssh tools not found");
        return;
    }
    let sb = Sandbox::new();
    let home = sb.root.join("gnupg");
    fs::create_dir(&home).unwrap();
    fs::set_permissions(&home, fs::Permissions::from_mode(0o700)).unwrap();
    let conf = format!("pinentry-program {BIN}\nenable-ssh-support\ndefault-cache-ttl-ssh 0\nmax-cache-ttl-ssh 0\n");
    fs::write(home.join("gpg-agent.conf"), conf).unwrap();
    let key = sb.root.join("id");
    let status = Command::new("ssh-keygen").args(["-q", "-t", "ed25519", "-N", "", "-f"]).arg(&key).status().unwrap();
    assert!(status.success());
    let data = sb.root.join("data");
    fs::write(&data, "x").unwrap();

    let tmux = Tmux::start(&sb);
    let _client = tmux.attach(30, 100);
    let agent = Agent { sb: &sb };
    let out = agent.command("gpgconf").args(["--list-dirs", "agent-ssh-socket"]).output().unwrap();
    let mut sock = String::from_utf8(out.stdout).unwrap().trim().to_string();
    if proxied {
        sock = forward(&sb, "S.gpg-agent.ssh", &sock).display().to_string();
    }

    let pty = Pty::new(20, 100);
    // As ssh's Match exec in the readme does, then ssh asking the agent.
    let script = format!(
        "GPG_TTY=$(tty) gpg-connect-agent UPDATESTARTUPTTY /bye >/dev/null; \
         export SSH_AUTH_SOCK={sock}; ssh-add {key} && ssh-keygen -Y sign -n file -f {key}.pub {data} && echo signed; sleep 9",
        key = key.display(),
        data = data.display(),
    );
    let mut sh = pty.command("sh");
    agent_env(&agent, &mut sh);
    let _sh = Killed(sh.args(["-c", &script]).spawn().unwrap());

    // Adding it asks for a passphrase to protect it with, twice.
    pty.wait_text("Passphrase:");
    pty.send("pw\r");
    pty.wait_text("Repeat:");
    pty.send("pw\r");
    // Using it asks for that passphrase.
    pty.wait_text("Passphrase:");
    pty.send("wrong\r");
    pty.wait_text("Bad Passphrase");
    pty.send("pw\r");
    pty.wait_text("signed");
}

fn agent_env(agent: &Agent, cmd: &mut Command) {
    agent.sb.apply(cmd).env("GNUPGHOME", agent.sb.root.join("gnupg"));
}
