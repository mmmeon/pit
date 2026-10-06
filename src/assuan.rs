//! The pinentry side of the Assuan protocol that gpg-agent speaks.

use std::fs::OpenOptions;
use std::io::{self, BufRead, Write};
use std::os::fd::AsRawFd;
use std::process;

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

pub fn unescape(s: &str) -> Vec<u8> {
    let b = s.as_bytes();
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
    timeout: u64,
    // OPTIONs survive RESET.
    ttyname: Option<String>,
    ttytype: Option<String>,
    default_ok: Option<String>,
    default_cancel: Option<String>,
    default_prompt: Option<String>,
}

impl State {
    fn option(&mut self, arg: &str) {
        let arg = arg.trim();
        let (name, value) = arg.split_once(['=', ' ']).unwrap_or((arg, ""));
        let value = Some(text(value.trim_start_matches([' ', '='])));
        match name.to_ascii_lowercase().as_str() {
            "ttyname" => self.ttyname = value,
            "ttytype" => self.ttytype = value,
            "default-ok" => self.default_ok = value,
            "default-cancel" => self.default_cancel = value,
            "default-prompt" => self.default_prompt = value,
            _ => {}
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

    /// Asks the user. None means there's nowhere to ask.
    fn ask(&mut self, kind: Kind) -> io::Result<Option<Outcome>> {
        let mut req = self.request(kind);
        // Like pinentry: the error and repeat prompt apply to one dialog only.
        self.error = None;
        self.repeat = None;

        // gpg sends GPG_TTY on every call, and ssh's tty is kept current with
        // UPDATESTARTUPTTY. If that's an ordinary terminal, the user is
        // there, not in tmux, even if a tmux client is attached elsewhere.
        let open = |t: &str| OpenOptions::new().read(true).write(true).open(t);
        let outside = self.ttyname.as_deref().filter(|t| !tmux::owns_tty(t));
        let mut tty = outside.and_then(|t| open(t).ok());

        if tty.is_none()
            && let Some(client) = tmux::find_client()
        {
            let opt = |name| tmux::option(name);
            req.style = opt("@pinentry-style").and_then(|s| Style::parse(&s)).unwrap_or_default();
            req.echo = opt("@pinentry-echo").and_then(|s| Echo::parse(&s)).unwrap_or_default();
            let lay = ui::layout(&req, client.width.saturating_sub(4));
            req.width = lay.width;
            if let Some(outcome) = tmux::prompt(&client, &req, &lay)? {
                return Ok(Some(outcome));
            }
        }

        // Outside tmux, no tmux client, or the popup failed: ask on the
        // terminal itself, if we know it.
        if tty.is_none() {
            let Some(ttyname) = &self.ttyname else { return Ok(None) };
            tty = Some(open(ttyname)?);
        }
        let tty = tty.unwrap();
        req.style = Style::Bar;
        req.width = sys::winsize(tty.as_raw_fd()).map_or(78, |(cols, _)| cols).saturating_sub(2);
        ui::run(&tty, &req, None, true).map(Some)
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

fn no_pinentry(e: Option<io::Error>) -> Result<(), Failure> {
    match e {
        Some(e) => fail(ERR_NO_PIN_ENTRY, &format!("No pinentry ({e})")),
        None => fail(ERR_NO_PIN_ENTRY, "No pinentry (not in tmux and no tty)"),
    }
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
        "SETTIMEOUT" => st.timeout = arg.trim().parse().unwrap_or(0),
        "RESET" => {
            *st = State {
                ttyname: st.ttyname.take(),
                ttytype: st.ttytype.take(),
                default_ok: st.default_ok.take(),
                default_cancel: st.default_cancel.take(),
                default_prompt: st.default_prompt.take(),
                ..State::default()
            }
        }
        // Accepted but not shown.
        "SETKEYINFO" | "SETREPEATOK" | "SETQUALITYBAR" | "SETQUALITYBAR_TT" | "SETGENPIN"
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
                Ok(Some(Outcome::Pin { pin, repeated })) => {
                    if repeated {
                        writeln!(out, "S PIN_REPEATED")?;
                    }
                    data(out, &pin.0)?;
                    Ok(())
                }
                Ok(Some(Outcome::Timeout)) => fail(ERR_TIMEOUT, "Timeout"),
                Ok(Some(_)) => fail(ERR_CANCELED, "Operation cancelled"),
                Ok(None) => no_pinentry(None),
                Err(e) => no_pinentry(Some(e)),
            });
        }
        "CONFIRM" | "MESSAGE" => {
            let kind = match cmd {
                "CONFIRM" if !arg.contains("--one-button") => Kind::Confirm,
                _ => Kind::Message,
            };
            return Ok(match st.ask(kind) {
                Ok(Some(Outcome::Timeout)) => fail(ERR_TIMEOUT, "Timeout"),
                Ok(Some(_)) if kind == Kind::Message => Ok(()),
                Ok(Some(Outcome::Ok)) => Ok(()),
                Ok(Some(Outcome::NotOk)) => fail(ERR_NOT_CONFIRMED, "Not confirmed"),
                Ok(Some(_)) => fail(ERR_CANCELED, "Operation cancelled"),
                Ok(None) => no_pinentry(None),
                Err(e) => no_pinentry(Some(e)),
            });
        }
        _ => return Ok(fail(ERR_ASS_UNKNOWN_CMD, "Unknown IPC command")),
    }
    Ok(Ok(()))
}
