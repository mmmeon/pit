//! Handing the prompt to another pinentry, a graphical one, when there's a
//! display it can show on.

use std::env;
use std::fs;
use std::io::{self, Read, Write};
use std::os::unix::fs::FileTypeExt;
use std::os::unix::process::CommandExt;
use std::path::Path;
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use crate::assuan::{escape, unescape};
use crate::config::Hook;
use crate::sys;
use crate::ui::{Kind, Outcome, Request, Secret};

/// Set for the pinentry we hand off to, so a pit behind it (a `pinentry`
/// symlink, a wrapper script) doesn't hand off again.
pub const HANDOFF: &str = "PIT_HANDOFF";

/// What a graphical program needs to find the display and the session.
const VARS: [&str; 6] =
    ["DISPLAY", "WAYLAND_DISPLAY", "XDG_SESSION_TYPE", "XDG_RUNTIME_DIR", "XAUTHORITY", "DBUS_SESSION_BUS_ADDRESS"];

/// How long the pinentry gets to exit after BYE.
const BYE_WAIT: Duration = Duration::from_secs(1);

const ERR_TIMEOUT: u32 = 62;
const ERR_CANCELED: u32 = 99;
const ERR_NOT_CONFIRMED: u32 = 114;

/// The display variables for the pinentry: as gpg-agent passes them, with
/// `display` from its --display or OPTION display. With neither display
/// set, the agent's environment is likely thin, and `owner`'s is used.
pub fn env(display: Option<&str>, owner: Option<u32>) -> Vec<(String, String)> {
    let mut vars: Vec<(String, String)> =
        VARS.iter().filter_map(|&k| Some((k.to_string(), env::var(k).ok().filter(|v| !v.is_empty())?))).collect();
    if let Some(d) = display.filter(|d| !d.is_empty()) {
        vars.retain(|(k, _)| k != "DISPLAY");
        vars.push(("DISPLAY".into(), d.into()));
    }
    let has_display = |vars: &[(String, String)]| vars.iter().any(|(k, _)| k == "DISPLAY" || k == "WAYLAND_DISPLAY");
    if !has_display(&vars)
        && let Some(theirs) = owner.and_then(|pid| fs::read(format!("/proc/{pid}/environ")).ok())
    {
        let theirs: Vec<(String, String)> = theirs
            .split(|&b| b == 0)
            .filter_map(|kv| {
                let (k, v) = std::str::from_utf8(kv).ok()?.split_once('=')?;
                (VARS.contains(&k) && !v.is_empty()).then(|| (k.to_string(), v.to_string()))
            })
            .collect();
        if has_display(&theirs) {
            vars = theirs;
        }
    }
    // gpg-agent passes WAYLAND_DISPLAY but not XDG_RUNTIME_DIR, where its
    // socket is: systemd's default stands in.
    if !vars.iter().any(|(k, _)| k == "XDG_RUNTIME_DIR") {
        let run = format!("/run/user/{}", sys::uid());
        if Path::new(&run).is_dir() {
            vars.push(("XDG_RUNTIME_DIR".into(), run));
        }
    }
    vars
}

/// Whether a window could be shown with `vars`: a Wayland or local X socket
/// that's there, or a remote X display (e.g. forwarded over ssh), which
/// can't be checked from here.
pub fn reachable(vars: &[(String, String)]) -> bool {
    let var = |name: &str| vars.iter().find(|(k, _)| k == name).map(|(_, v)| v.as_str());
    let socket = |p: &Path| fs::metadata(p).is_ok_and(|m| m.file_type().is_socket());
    let wayland = var("WAYLAND_DISPLAY").is_some_and(|w| match Path::new(w) {
        p if p.is_absolute() => socket(p),
        p => var("XDG_RUNTIME_DIR").is_some_and(|dir| socket(&Path::new(dir).join(p))),
    });
    wayland || var("DISPLAY").is_some_and(x_reachable)
}

/// `[host]:number[.screen]`, or a launchd-style path ending in one.
fn x_reachable(display: &str) -> bool {
    let Some((host, rest)) = display.rsplit_once(':') else { return false };
    let number = rest.split('.').next().unwrap_or_default();
    if number.is_empty() || !number.bytes().all(|b| b.is_ascii_digit()) {
        return false;
    }
    match host {
        "" | "unix" => Path::new(&format!("/tmp/.X11-unix/X{number}")).exists(),
        h if h.starts_with('/') => Path::new(h).exists(),
        _ => true,
    }
}

/// Asks with `program`, a pinentry on stdin/stdout, after replaying the
/// agent's `options`. None if it couldn't start or show the prompt; an
/// answer, cancel included, is an Outcome.
pub fn prompt(program: &str, vars: &[(String, String)], options: &[String], req: &Request, hook: Option<&str>) -> Option<Outcome> {
    let mut cmd = Command::new(program);
    cmd.envs(vars.iter().map(|(k, v)| (k, v)))
        .env(HANDOFF, "1")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    // If gpg-agent kills us, the dialog goes too.
    unsafe {
        cmd.pre_exec(|| {
            libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGTERM);
            Ok(())
        });
    }
    let mut p = Pinentry::new(cmd.spawn().ok()?);
    // Gone mid-way, it couldn't show it either.
    let outcome = p.ask(program, options, req, hook).unwrap_or(None);
    p.close();
    outcome
}

/// A reply: its data, whether it said PIN_REPEATED, and OK or the ERR code.
struct Reply {
    data: Secret,
    repeated: bool,
    result: Result<(), u32>,
}

struct Pinentry {
    child: Child,
    stdin: Option<ChildStdin>,
    stdout: ChildStdout,
    /// Read but not yet taken: may hold a passphrase.
    buf: Secret,
}

impl Pinentry {
    fn new(mut child: Child) -> Pinentry {
        let stdin = child.stdin.take();
        let stdout = child.stdout.take().expect("piped");
        Pinentry { child, stdin, stdout, buf: Secret::new() }
    }

    /// The next line, without its newline; None at EOF.
    fn line(&mut self) -> io::Result<Option<Secret>> {
        loop {
            if let Some(i) = self.buf.0.iter().position(|&b| b == b'\n') {
                let mut line = Secret::from(self.buf.0.drain(..=i).collect::<Vec<u8>>());
                line.0.pop();
                return Ok(Some(line));
            }
            let mut chunk = [0; 256];
            let n = self.stdout.read(&mut chunk)?;
            self.buf.extend(&chunk[..n]);
            chunk.fill(0);
            if n == 0 {
                return Ok(None);
            }
        }
    }

    /// Sends `line` and reads the reply. None at EOF.
    fn cmd(&mut self, line: &str) -> io::Result<Option<Reply>> {
        let stdin = self.stdin.as_mut().ok_or(io::ErrorKind::BrokenPipe)?;
        writeln!(stdin, "{line}")?;
        stdin.flush()?;
        let mut data = Secret::new();
        let mut repeated = false;
        while let Some(reply) = self.line()? {
            let r = &reply.0;
            if r == b"OK" || r.starts_with(b"OK ") {
                return Ok(Some(Reply { data, repeated, result: Ok(()) }));
            }
            if let Some(err) = r.strip_prefix(b"ERR ") {
                let code = std::str::from_utf8(err).ok().and_then(|e| e.split(' ').next()?.parse::<u32>().ok());
                return Ok(Some(Reply { data, repeated, result: Err(code.unwrap_or(0) & 0xffff) }));
            }
            if let Some(d) = r.strip_prefix(b"D ") {
                data.extend(&Secret::from(unescape(d)).0);
            } else if r == b"S PIN_REPEATED" {
                repeated = true;
            }
        }
        Ok(None)
    }

    fn ask(&mut self, program: &str, options: &[String], req: &Request, hook: Option<&str>) -> io::Result<Option<Outcome>> {
        match self.line() {
            Ok(Some(hello)) if hello.0.starts_with(b"OK") => {}
            _ => return Ok(None),
        }
        let mut setup: Vec<String> = options.iter().map(|o| format!("OPTION {o}")).collect();
        let mut set = |cmd: &str, value: &str| setup.push(format!("{cmd} {}", escape(value.as_bytes())));
        set("SETTITLE", &req.heading());
        set("SETDESC", &req.desc);
        set("SETPROMPT", &req.prompt);
        if !req.error.is_empty() {
            set("SETERROR", &req.error);
        }
        set("SETOK", &req.ok);
        set("SETCANCEL", &req.cancel);
        if let Some(notok) = &req.notok {
            set("SETNOTOK", notok);
        }
        if let (Kind::Pin, Some(repeat)) = (req.kind, &req.repeat) {
            set("SETREPEAT", repeat);
            set("SETREPEATERROR", &req.repeat_error);
        }
        if req.timeout > 0 {
            setup.push(format!("SETTIMEOUT {}", req.timeout));
        }
        // Like gpg-agent, carry on past what it doesn't take: an option it
        // doesn't know is no reason not to ask.
        for line in &setup {
            if self.cmd(line)?.is_none() {
                return Ok(None);
            }
        }

        let _hook = Hook::open(hook, req, &format!("gui {program}"));
        let ask = match req.kind {
            Kind::Pin => "GETPIN",
            Kind::Confirm => "CONFIRM",
            Kind::Message => "CONFIRM --one-button",
        };
        let Some(reply) = self.cmd(ask)? else { return Ok(None) };
        Ok(match reply.result {
            Ok(()) if req.kind == Kind::Pin => Some(Outcome::Pin { pin: reply.data, repeated: reply.repeated }),
            Ok(()) => Some(Outcome::Ok),
            Err(ERR_CANCELED) => Some(Outcome::Cancel),
            Err(ERR_TIMEOUT) => Some(Outcome::Timeout),
            Err(ERR_NOT_CONFIRMED) if req.kind == Kind::Confirm => Some(Outcome::NotOk),
            // Anything else, it couldn't show the prompt (no display after
            // all, a tty fallback with no tty).
            _ => None,
        })
    }

    /// Says goodbye, and gives it a moment to go before it's killed.
    fn close(&mut self) {
        if let Some(mut stdin) = self.stdin.take() {
            let _ = writeln!(stdin, "BYE");
        }
        let start = Instant::now();
        while matches!(self.child.try_wait(), Ok(None)) && start.elapsed() < BYE_WAIT {
            thread::sleep(Duration::from_millis(10));
        }
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::net::UnixListener;

    fn vars(kv: &[(&str, &str)]) -> Vec<(String, String)> {
        kv.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect()
    }

    #[test]
    fn remote_x_displays_count_as_reachable() {
        for d in ["localhost:10", "localhost:10.0", "remote.example:0"] {
            assert!(reachable(&vars(&[("DISPLAY", d)])), "{d}");
        }
        for d in ["", "nonsense", "host:", ":x", "/nonexistent/org.xquartz:0"] {
            assert!(!reachable(&vars(&[("DISPLAY", d)])), "{d}");
        }
    }

    #[test]
    fn wayland_needs_its_socket() {
        let dir = std::env::temp_dir().join(format!("pit-gui-test-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let run = dir.to_str().unwrap();
        assert!(!reachable(&vars(&[("WAYLAND_DISPLAY", "wayland-9"), ("XDG_RUNTIME_DIR", run)])));
        let _l = UnixListener::bind(dir.join("wayland-9")).unwrap();
        assert!(reachable(&vars(&[("WAYLAND_DISPLAY", "wayland-9"), ("XDG_RUNTIME_DIR", run)])));
        assert!(!reachable(&vars(&[("WAYLAND_DISPLAY", "wayland-9")])));
        let abs = dir.join("wayland-9");
        assert!(reachable(&vars(&[("WAYLAND_DISPLAY", abs.to_str().unwrap())])));
        fs::write(dir.join("plain"), "").unwrap();
        let plain = dir.join("plain");
        assert!(!reachable(&vars(&[("WAYLAND_DISPLAY", plain.to_str().unwrap())])));
        let _ = fs::remove_dir_all(&dir);
    }
}
