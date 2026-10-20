//! The pinentry side of the Assuan protocol that gpg-agent speaks.

use std::env;
use std::fs::{File, OpenOptions};
use std::io::{self, BufRead, Write};
use std::os::fd::AsRawFd;
use std::os::unix::fs::MetadataExt;
use std::process;

use crate::answer;
use crate::config::{Config, Hook};
use crate::gpg;
use crate::gui;
use crate::origin;
use crate::sys;
use crate::tmux;
use crate::ui::{self, Echo, Kind, Outcome, Request, Secret, Style};

const ERR_TIMEOUT: u32 = 62;
const ERR_NO_PIN_ENTRY: u32 = 85;
const ERR_CANCELED: u32 = 99;
const ERR_NOT_CONFIRMED: u32 = 114;
const ERR_ASS_UNKNOWN_CMD: u32 = 275;
const ERR_ASS_PARAMETER: u32 = 280;

/// Appends `data` with `%`, CR, LF and other control bytes percent-escaped.
pub fn escape_into(out: &mut Vec<u8>, data: &[u8]) {
    for &b in data {
        if b == b'%' || b < 0x20 {
            out.extend_from_slice(format!("%{b:02X}").as_bytes());
        } else {
            out.push(b);
        }
    }
}

pub fn escape(data: &[u8]) -> String {
    let mut out = Vec::new();
    escape_into(&mut out, data);
    String::from_utf8_lossy(&out).into_owned()
}

pub fn unescape(s: impl AsRef<[u8]>) -> Vec<u8> {
    let b = s.as_ref();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        let hex = b.get(i + 1..i + 3).and_then(|h| std::str::from_utf8(h).ok());
        match (b[i], hex.and_then(|h| u8::from_str_radix(h, 16).ok())) {
            (b'%', Some(v)) => {
                out.push(v);
                i += 3;
            }
            (c, _) => {
                out.push(c);
                i += 1;
            }
        }
    }
    out
}

fn text(arg: &str) -> String {
    String::from_utf8_lossy(&unescape(arg)).into_owned()
}

/// What gpg-agent has told us so far.
#[derive(Default)]
struct State {
    desc: Option<String>,
    prompt: Option<String>,
    error: Option<String>,
    title: Option<String>,
    ok: Option<String>,
    cancel: Option<String>,
    notok: Option<String>,
    repeat: Option<String>,
    repeat_error: Option<String>,
    keyinfo: Option<String>,
    timeout: u64,
    // OPTIONs survive RESET.
    ttyname: Option<String>,
    /// The process that connected to the agent, from `owner`, when it's on
    /// this host.
    owner: Option<u32>,
    /// `owner` is a proxy in front of the agent, not who asked.
    proxied: bool,
    ttytype: Option<String>,
    default_ok: Option<String>,
    default_cancel: Option<String>,
    default_prompt: Option<String>,
    /// The X display, from --display or `display`.
    display: Option<String>,
    /// Every OPTION as sent, for a pinentry we hand the prompt to, but
    /// those naming a terminal: it mustn't fall back to one.
    options: Vec<String>,
}

impl State {
    fn option(&mut self, arg: &str) {
        let arg = arg.trim();
        let (name, value) = arg.split_once(['=', ' ']).unwrap_or((arg, ""));
        let value = Some(text(value.trim_start_matches([' ', '='])));
        let name = name.to_ascii_lowercase();
        if !name.starts_with("tty") {
            self.options.push(arg.to_string());
        }
        match name.as_str() {
            "ttyname" => self.ttyname = value,
            "owner" => {
                self.owner = value.as_deref().and_then(origin::owner_pid);
                self.proxied = self.owner.is_some_and(origin::is_agent_proxy);
            }
            "ttytype" => self.ttytype = value,
            "default-ok" => self.default_ok = value,
            "default-cancel" => self.default_cancel = value,
            "default-prompt" => self.default_prompt = value,
            "display" => self.display = value,
            _ => {}
        }
    }

    /// Who asked, when the agent's client says: it, or behind a proxy in
    /// front of the agent, the proxy's client, if that's clear.
    fn requester(&self) -> Option<u32> {
        match self.owner {
            Some(proxy) if self.proxied => origin::proxy_client(proxy, self.ttyname.as_deref()),
            owner => owner,
        }
    }

    fn request(&self, kind: Kind) -> Request {
        let pick = |v: &Option<String>, dflt: &Option<String>, fallback: &str| {
            v.clone().or_else(|| dflt.clone()).unwrap_or_else(|| fallback.into())
        };
        Request {
            kind,
            style: Style::default(),
            echo: Echo::default(),
            title: self.title.clone().unwrap_or_else(|| "gpg".into()),
            origin: String::new(),
            guess: false,
            desc: self.desc.clone().unwrap_or_default(),
            prompt: pick(&self.prompt, &self.default_prompt, "PIN:"),
            error: self.error.clone().unwrap_or_default(),
            repeat: self.repeat.clone(),
            repeat_error: pick(&self.repeat_error, &None, "does not match - try again"),
            ok: pick(&self.ok, &self.default_ok, "_OK"),
            cancel: pick(&self.cancel, &self.default_cancel, "_Cancel"),
            notok: self.notok.clone(),
            timeout: self.timeout,
            width: 0,
        }
    }

    /// Asks the user. Err says why there's nowhere to ask.
    fn ask(&mut self, kind: Kind) -> io::Result<Result<Outcome, String>> {
        let cfg = Config::load();
        let mut req = self.request(kind);
        req.echo = cfg.echo;
        // gpg's own descriptions quote the user ID; ssh's may only give the
        // fingerprint.
        // Card PIN prompts give neither, only the card's number.
        if !req.desc.contains('"')
            && let Some(name) = match self.keyinfo.as_deref() {
                Some(k) => gpg::key_name(k),
                None => gpg::card_name(&req.desc),
            }
        {
            req.desc = gpg::add_name(&req.desc, &name);
        }
        let owner = self.requester();
        let mut tried_gui = false;
        // The popup can land far from the command that asked; say which.
        // The hook is told too, wherever it's asked. The owner is who asked
        // even off the terminal gpg names, which may be stale ("not a tty",
        // or ssh's last UPDATESTARTUPTTY).
        // Behind a proxy whose client isn't clear, where it likely is is a
        // guess, and only the pane is named.
        req.guess = self.proxied && owner.is_none();
        req.origin = match (owner, self.ttyname.as_deref()) {
            (Some(pid), _) => origin::find(pid, cfg.full_origin).label(),
            // The terminal gpg names, if there is one, though it may be stale.
            (None, Some(t)) if req.guess && origin::is_tty(t) => origin::find_tty(t).label(),
            // Otherwise the pane the popup's client is looking at.
            (None, _) if req.guess => tmux::find_client()
                .and_then(|c| tmux::active_pane_tty(&c))
                .and_then(|t| origin::find_tty(&t).label()),
            (None, _) => None,
        }
        .unwrap_or_default();
        // Like pinentry: the error and repeat prompt apply to one dialog only.
        self.error = None;
        self.repeat = None;

        // Another pinentry, if there's a display for it. Never from a pit
        // that was handed the prompt: it would only hand it on again.
        let gui = cfg.gui.as_deref().filter(|_| env::var_os(gui::HANDOFF).is_none()).and_then(|program| {
            let vars = gui::env(self.display.as_deref(), owner.or(self.owner));
            gui::reachable(&vars).then_some((program, vars))
        });
        let hand_off = |req: &Request| gui.as_ref().and_then(|(program, vars)| gui::prompt(program, vars, &self.options, req, cfg.hook.as_deref()));
        if cfg.gui_first && gui.is_some() {
            match hand_off(&req) {
                Some(outcome) => return Ok(Ok(outcome)),
                None => tried_gui = true,
            }
        }

        // gpg sends GPG_TTY on every call, and ssh's tty is kept current with
        // UPDATESTARTUPTTY. If that's an ordinary terminal, the user is
        // there, not in tmux, even if a tmux client is attached elsewhere.
        let open = |t: &str| OpenOptions::new().read(true).write(true).open(t);
        // Something else reading keys there would get some of them, and
        // they're a passphrase: a full-screen program, or another command.
        // A proxy whose client isn't clear still counts here: it isn't in
        // the terminal's foreground, so whatever is reading there is taken
        // for another reader, and giving away keys is the worse mistake.
        let asker = owner.or(self.owner);
        let free = |t: &File| {
            sys::line_mode(t.as_raw_fd()) && t.metadata().is_ok_and(|m| !origin::other_reader(m.rdev(), asker))
        };
        let outside = self.ttyname.as_deref().filter(|t| !tmux::owns_tty(t));
        // Only if nothing else has it, though: then the popup is better, and
        // it falls back to here.
        let mut tty = outside.and_then(|t| open(t).ok()).filter(free);
        // In a pane, the command that asked may still have it to itself:
        // nothing else in the foreground, nothing on the screen. Then ask in
        // place, right under it, as on an ordinary terminal.
        if tty.is_none()
            && let (Some(t), Some(pid)) = (self.ttyname.as_deref(), owner)
            && cfg.inline
            && origin::in_foreground(pid, t)
            && tmux::pane_idle(t)
        {
            tty = open(t).ok().filter(free);
        }

        if tty.is_none()
            && let Some(client) = tmux::find_client()
        {
            req.style = cfg.style;
            let lay = ui::layout(&req, client.width.saturating_sub(4));
            req.width = lay.width;
            if let Some(outcome) = tmux::prompt(&client, &req, &lay, cfg.hook.as_deref())? {
                return Ok(Ok(outcome));
            }
        }

        // Outside tmux, no tmux client, or the popup failed: ask on the
        // terminal itself, if we know it and nothing else has it. Better to
        // not ask at all than to give away some of the passphrase.
        let tty: Result<File, String> = match tty {
            Some(tty) => Ok(tty),
            None => 'tty: {
                let Some(ttyname) = &self.ttyname else {
                    break 'tty Err("no tmux client for a popup, and no terminal to ask on".into());
                };
                // A pane only on the terms above, short of the command being
                // in the foreground: never when inline prompts are off, nor
                // over something full-screen.
                if outside.is_none() && !(cfg.inline && tmux::pane_idle(ttyname)) {
                    break 'tty Err("no popup, and the pane is busy or inline prompts are off".into());
                }
                let tty = match open(ttyname) {
                    Ok(tty) => tty,
                    Err(e) => break 'tty Err(e.to_string()),
                };
                if !free(&tty) {
                    let why = "the terminal is in use by a full-screen program or another command";
                    break 'tty Err(if self.proxied && owner.is_none() {
                        format!("{why}, which can't be told apart from who asked through the proxy in front of gpg-agent")
                    } else {
                        why.into()
                    });
                }
                Ok(tty)
            }
        };
        // Nowhere on a terminal: a window, unless that was tried first,
        // then waiting for `pit answer`.
        let tty = match tty {
            Ok(tty) => tty,
            Err(mut why) => {
                if !tried_gui && gui.is_some() {
                    if let Some(outcome) = hand_off(&req) {
                        return Ok(Ok(outcome));
                    }
                    tried_gui = true;
                }
                if let (true, Some((program, _))) = (tried_gui, &gui) {
                    why = format!("{why}, and {program} couldn't show it");
                }
                if cfg.pending {
                    return answer::wait(&req, cfg.hook.as_deref()).map(Ok);
                }
                return Ok(Err(why));
            }
        };
        req.style = Style::Bar;
        req.width = sys::winsize(tty.as_raw_fd()).map_or(78, |(cols, _)| cols).saturating_sub(2);
        let place = format!("inline {}", self.ttyname.as_deref().unwrap_or_default());
        let hook = Hook::open(cfg.hook.as_deref(), &req, &place);
        let outcome = ui::run(&tty, &req, None, true);
        drop(hook);
        outcome.map(Ok)
    }
}

type Failure = (u32, String);

fn fail(code: u32, msg: &str) -> Result<(), Failure> {
    Err((code, msg.to_string()))
}

fn data(out: &mut impl Write, value: &[u8]) -> io::Result<()> {
    // Assuan lines max out at 1000 bytes.
    let mut line = Secret::new();
    for &b in value {
        if line.0.len() > 990 {
            line.0.push(b'\n');
            out.write_all(&line.0)?;
            line.0.clear();
        }
        if line.0.is_empty() {
            line.0.extend_from_slice(b"D ");
        }
        escape_into(&mut line.0, &[b]);
    }
    if !line.0.is_empty() {
        line.0.push(b'\n');
        out.write_all(&line.0)?;
    }
    Ok(())
}

fn no_pinentry(why: impl std::fmt::Display) -> Result<(), Failure> {
    fail(ERR_NO_PIN_ENTRY, &format!("No pinentry ({why})"))
}

/// Serves gpg-agent on stdin/stdout. `args` are our command-line flags,
/// which may carry --ttyname/--ttytype.
pub fn serve(args: &[String]) -> io::Result<()> {
    let mut st = State::default();
    let mut it = args.iter();
    while let Some(a) = it.next() {
        let (flag, inline) = a.split_once('=').map_or((a.as_str(), None), |(f, v)| (f, Some(v.to_string())));
        let value = || inline.clone().or_else(|| it.clone().next().cloned());
        match flag {
            "--ttyname" | "-T" => st.ttyname = value(),
            "--ttytype" | "-N" => st.ttytype = value(),
            "--display" | "-D" => st.display = value(),
            _ => {}
        }
    }

    let mut inp = io::stdin().lock();
    let mut out = io::stdout().lock();
    writeln!(out, "OK Pleased to meet you, process {}", process::id())?;
    out.flush()?;

    let mut buf = Vec::new();
    loop {
        buf.clear();
        if inp.read_until(b'\n', &mut buf)? == 0 {
            return Ok(());
        }
        let line = String::from_utf8_lossy(&buf);
        let line = line.trim_end_matches(['\n', '\r']);
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let (cmd, arg) = line.split_once(' ').unwrap_or((line, ""));
        let cmd = cmd.to_ascii_uppercase();
        if cmd == "BYE" {
            writeln!(out, "OK closing connection")?;
            out.flush()?;
            return Ok(());
        }
        match handle(&mut st, &cmd, arg, &mut out)? {
            Ok(()) => writeln!(out, "OK")?,
            Err((code, msg)) => writeln!(out, "ERR {} {msg} <Pinentry>", (5 << 24) | code)?,
        }
        out.flush()?;
    }
}

/// Runs one command, writing any status and data lines to `out`.
fn handle(st: &mut State, cmd: &str, arg: &str, out: &mut impl Write) -> io::Result<Result<(), Failure>> {
    let set = |v: &mut Option<String>| *v = Some(text(arg));
    match cmd {
        "OPTION" => st.option(arg),
        "SETDESC" => set(&mut st.desc),
        "SETPROMPT" => set(&mut st.prompt),
        "SETERROR" => set(&mut st.error),
        "SETTITLE" => set(&mut st.title),
        "SETOK" => set(&mut st.ok),
        "SETCANCEL" => set(&mut st.cancel),
        "SETNOTOK" => set(&mut st.notok),
        "SETREPEAT" => st.repeat = Some(Some(text(arg)).filter(|s| !s.is_empty()).unwrap_or("Repeat:".into())),
        "SETREPEATERROR" => set(&mut st.repeat_error),
        "SETKEYINFO" => st.keyinfo = Some(arg.trim().to_string()).filter(|k| k != "--clear"),
        "SETTIMEOUT" => st.timeout = arg.trim().parse().unwrap_or(0),
        "RESET" => {
            *st = State {
                ttyname: st.ttyname.take(),
                ttytype: st.ttytype.take(),
                default_ok: st.default_ok.take(),
                default_cancel: st.default_cancel.take(),
                default_prompt: st.default_prompt.take(),
                display: st.display.take(),
                options: std::mem::take(&mut st.options),
                ..State::default()
            }
        }
        // Accepted but not shown.
        "SETREPEATOK" | "SETQUALITYBAR" | "SETQUALITYBAR_TT" | "SETGENPIN"
        | "SETGENPIN_TT" | "CLEARPASSPHRASE" | "NOP" => {}
        "GETINFO" => {
            let dash = |v: &Option<String>| v.clone().unwrap_or_else(|| "-".into());
            let value = match arg.trim() {
                "flavor" => "tmux".to_string(),
                "version" => env!("CARGO_PKG_VERSION").to_string(),
                "pid" => process::id().to_string(),
                "ttyinfo" => format!("{} {} -", dash(&st.ttyname), dash(&st.ttytype)),
                _ => return Ok(fail(ERR_ASS_PARAMETER, "IPC parameter error")),
            };
            data(out, value.as_bytes())?;
        }
        "GETPIN" => {
            return Ok(match st.ask(Kind::Pin) {
                Ok(Ok(Outcome::Pin { pin, repeated })) => {
                    if repeated {
                        writeln!(out, "S PIN_REPEATED")?;
                    }
                    data(out, &pin.0)?;
                    Ok(())
                }
                Ok(Ok(Outcome::Timeout)) => fail(ERR_TIMEOUT, "Timeout"),
                Ok(Ok(_)) => fail(ERR_CANCELED, "Operation cancelled"),
                Ok(Err(why)) => no_pinentry(why),
                Err(e) => no_pinentry(e),
            });
        }
        "CONFIRM" | "MESSAGE" => {
            let kind = match cmd {
                "CONFIRM" if !arg.contains("--one-button") => Kind::Confirm,
                _ => Kind::Message,
            };
            return Ok(match st.ask(kind) {
                Ok(Ok(Outcome::Timeout)) => fail(ERR_TIMEOUT, "Timeout"),
                Ok(Ok(_)) if kind == Kind::Message => Ok(()),
                Ok(Ok(Outcome::Ok)) => Ok(()),
                Ok(Ok(Outcome::NotOk)) => fail(ERR_NOT_CONFIRMED, "Not confirmed"),
                Ok(Ok(_)) => fail(ERR_CANCELED, "Operation cancelled"),
                Ok(Err(why)) => no_pinentry(why),
                Err(e) => no_pinentry(e),
            });
        }
        _ => return Ok(fail(ERR_ASS_UNKNOWN_CMD, "Unknown IPC command")),
    }
    Ok(Ok(()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run(st: &mut State, line: &str) -> (String, Result<(), Failure>) {
        let (cmd, arg) = line.split_once(' ').unwrap_or((line, ""));
        let mut out = Vec::new();
        let res = handle(st, cmd, arg, &mut out).unwrap();
        (String::from_utf8(out).unwrap(), res)
    }

    fn ok(st: &mut State, line: &str) {
        assert_eq!(run(st, line), (String::new(), Ok(())), "{line}");
    }

    #[test]
    fn owner_is_who_asked_off_its_terminal() {
        let mut st = State::default();
        let me = std::process::id();
        ok(&mut st, "OPTION ttyname=not a tty");
        ok(&mut st, &format!("OPTION owner={me}/{}", sys::uid()));
        assert!(!st.proxied);
        assert_eq!(st.requester(), Some(me));
        // A proxy is still the owner for the reader check, but not who asked.
        st.proxied = true;
        assert_eq!(st.owner, Some(me));
        assert_eq!(st.requester(), None);
    }

    #[test]
    fn escape_round_trips_ascii_and_utf8() {
        let mut all: Vec<u8> = (0..0x80).collect();
        all.extend_from_slice("pässwörd 漢字 🔑".as_bytes());
        let escaped = escape(&all);
        assert!(!escaped.bytes().any(|b| b < 0x20 && b != b'%'));
        assert_eq!(unescape(&escaped), all);
    }

    #[test]
    fn escape_into_round_trips_every_byte() {
        let all: Vec<u8> = (0..=255).collect();
        let mut escaped = Vec::new();
        escape_into(&mut escaped, &all);
        assert!(!escaped.iter().any(|&b| b < 0x20));
        assert_eq!(unescape(&escaped), all);
    }

    #[test]
    fn escape_only_touches_percent_and_controls() {
        assert_eq!(escape(b"a%b\nc\rd\x1be f~"), "a%25b%0Ac%0Dd%1Be f~");
        assert_eq!(escape("pässwörd".as_bytes()), "pässwörd");
    }

    #[test]
    fn unescape_keeps_malformed_escapes() {
        assert_eq!(unescape("100%"), b"100%");
        assert_eq!(unescape("a%4"), b"a%4");
        assert_eq!(unescape("%zz%"), b"%zz%");
        assert_eq!(unescape("%0a%0A%2c"), b"\n\n,");
        assert_eq!(unescape("%%41"), b"%A");
    }

    #[test]
    fn data_writes_nothing_for_empty_value() {
        let mut out = Vec::new();
        data(&mut out, b"").unwrap();
        assert!(out.is_empty());
    }

    #[test]
    fn data_splits_long_values_without_breaking_escapes() {
        let value = vec![b'%'; 2000];
        let mut out = Vec::new();
        data(&mut out, &value).unwrap();
        let text = String::from_utf8(out).unwrap();
        let lines: Vec<&str> = text.lines().collect();
        assert!(lines.len() > 1);
        let mut joined = String::new();
        for line in &lines {
            assert!(line.len() < 1000, "line of {} bytes", line.len());
            let body = line.strip_prefix("D ").unwrap();
            assert_eq!(body.len() % 3, 0, "escape split across lines");
            joined.push_str(body);
        }
        assert_eq!(unescape(&joined), value);
    }

    #[test]
    fn option_forms() {
        let mut st = State::default();
        st.option("ttyname=/dev/pts/3");
        st.option("TTYTYPE xterm");
        st.option(" default-ok =_Okay ");
        st.option("default-cancel=Can%25cel");
        st.option("default-prompt");
        st.option("allow-external-password-cache");
        assert_eq!(st.ttyname.as_deref(), Some("/dev/pts/3"));
        assert_eq!(st.ttytype.as_deref(), Some("xterm"));
        assert_eq!(st.default_ok.as_deref(), Some("_Okay"));
        assert_eq!(st.default_cancel.as_deref(), Some("Can%cel"));
        assert_eq!(st.default_prompt.as_deref(), Some(""));
    }

    #[test]
    fn set_commands_fill_state() {
        let mut st = State::default();
        for line in [
            "SETDESC Enter%0Athe passphrase",
            "SETPROMPT Passphrase:",
            "SETERROR Bad passphrase",
            "SETTITLE Unlock",
            "SETOK _Yes",
            "SETCANCEL _No",
            "SETNOTOK _Never",
            "SETREPEATERROR mismatch",
            "SETTIMEOUT 30",
        ] {
            assert_eq!(run(&mut st, line), (String::new(), Ok(())));
        }
        assert_eq!(st.desc.as_deref(), Some("Enter\nthe passphrase"));
        assert_eq!(st.prompt.as_deref(), Some("Passphrase:"));
        assert_eq!(st.error.as_deref(), Some("Bad passphrase"));
        assert_eq!(st.title.as_deref(), Some("Unlock"));
        assert_eq!(st.ok.as_deref(), Some("_Yes"));
        assert_eq!(st.cancel.as_deref(), Some("_No"));
        assert_eq!(st.notok.as_deref(), Some("_Never"));
        assert_eq!(st.repeat_error.as_deref(), Some("mismatch"));
        assert_eq!(st.timeout, 30);
    }

    #[test]
    fn setrepeat_and_settimeout_defaults() {
        let mut st = State::default();
        ok(&mut st, "SETREPEAT");
        assert_eq!(st.repeat.as_deref(), Some("Repeat:"));
        ok(&mut st, "SETREPEAT Again:");
        assert_eq!(st.repeat.as_deref(), Some("Again:"));
        ok(&mut st, "SETTIMEOUT 5");
        ok(&mut st, "SETTIMEOUT soon");
        assert_eq!(st.timeout, 0);
    }

    #[test]
    fn reset_keeps_options_only() {
        let mut st = State::default();
        ok(&mut st, "OPTION ttyname=/dev/pts/9");
        ok(&mut st, "OPTION ttytype=screen");
        ok(&mut st, "OPTION default-ok=OK!");
        ok(&mut st, "OPTION default-cancel=Nope");
        ok(&mut st, "OPTION default-prompt=PIN?");
        ok(&mut st, "SETDESC desc");
        ok(&mut st, "SETPROMPT prompt");
        ok(&mut st, "SETREPEAT");
        ok(&mut st, "SETTIMEOUT 9");
        assert_eq!(run(&mut st, "RESET"), (String::new(), Ok(())));
        assert_eq!(st.ttyname.as_deref(), Some("/dev/pts/9"));
        assert_eq!(st.ttytype.as_deref(), Some("screen"));
        assert_eq!(st.default_ok.as_deref(), Some("OK!"));
        assert_eq!(st.default_cancel.as_deref(), Some("Nope"));
        assert_eq!(st.default_prompt.as_deref(), Some("PIN?"));
        assert_eq!(st.desc, None);
        assert_eq!(st.prompt, None);
        assert_eq!(st.repeat, None);
        assert_eq!(st.timeout, 0);
    }

    #[test]
    fn getinfo() {
        let mut st = State::default();
        assert_eq!(run(&mut st, "GETINFO flavor"), ("D tmux\n".into(), Ok(())));
        let version = format!("D {}\n", env!("CARGO_PKG_VERSION"));
        assert_eq!(run(&mut st, "GETINFO version"), (version, Ok(())));
        assert_eq!(run(&mut st, "GETINFO pid"), (format!("D {}\n", process::id()), Ok(())));
        assert_eq!(run(&mut st, "GETINFO ttyinfo"), ("D - - -\n".into(), Ok(())));
        ok(&mut st, "OPTION ttyname=/dev/pts/1");
        ok(&mut st, "OPTION ttytype=xterm");
        assert_eq!(run(&mut st, "GETINFO ttyinfo"), ("D /dev/pts/1 xterm -\n".into(), Ok(())));
        let (out, res) = run(&mut st, "GETINFO bogus");
        assert_eq!(out, "");
        assert_eq!(res.unwrap_err().0, ERR_ASS_PARAMETER);
    }

    #[test]
    fn unknown_and_ignored_commands() {
        let mut st = State::default();
        assert_eq!(run(&mut st, "FROBNICATE").1.unwrap_err().0, ERR_ASS_UNKNOWN_CMD);
        for line in [
            "SETREPEATOK ok",
            "SETQUALITYBAR",
            "SETQUALITYBAR_TT tip",
            "SETGENPIN gen",
            "SETGENPIN_TT tip",
            "CLEARPASSPHRASE",
            "NOP",
        ] {
            assert_eq!(run(&mut st, line), (String::new(), Ok(())), "{line}");
        }
    }

    #[test]
    fn keyinfo_is_kept_until_cleared() {
        let mut st = State::default();
        ok(&mut st, "SETKEYINFO n/ABCDEF");
        assert_eq!(st.keyinfo.as_deref(), Some("n/ABCDEF"));
        ok(&mut st, "SETKEYINFO --clear");
        assert_eq!(st.keyinfo, None);
        ok(&mut st, "SETKEYINFO s/ABCDEF");
        ok(&mut st, "RESET");
        assert_eq!(st.keyinfo, None);
    }

    #[test]
    fn request_fallbacks() {
        let mut st = State::default();
        let req = st.request(Kind::Pin);
        assert_eq!((req.title.as_str(), req.prompt.as_str()), ("gpg", "PIN:"));
        assert_eq!((req.ok.as_str(), req.cancel.as_str()), ("_OK", "_Cancel"));
        assert_eq!(req.repeat_error, "does not match - try again");
        assert!(req.repeat.is_none() && req.notok.is_none());

        st.option("default-prompt=Phrase:");
        st.option("default-ok=Fine");
        st.option("default-cancel=Stop");
        let req = st.request(Kind::Confirm);
        assert_eq!(req.kind, Kind::Confirm);
        assert_eq!((req.prompt.as_str(), req.ok.as_str(), req.cancel.as_str()), ("Phrase:", "Fine", "Stop"));

        ok(&mut st, "SETPROMPT Mine:");
        ok(&mut st, "SETOK Yes");
        ok(&mut st, "SETCANCEL No");
        let req = st.request(Kind::Pin);
        assert_eq!((req.prompt.as_str(), req.ok.as_str(), req.cancel.as_str()), ("Mine:", "Yes", "No"));
    }
}
