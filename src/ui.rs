//! The prompt itself: what gets asked, how it's laid out, and the key loop.

use std::collections::VecDeque;
use std::fmt::Write as _;
use std::fs::File;
use std::io::{self, Read, Write};
use std::mem;
use std::os::fd::AsRawFd;
use std::time::{Duration, Instant};

use unicode_width::{UnicodeWidthChar, UnicodeWidthStr};

use crate::assuan::{escape, escape_into, unescape};
use crate::sys;

const BOLD: &str = "\x1b[1m";
const DIM: &str = "\x1b[2m";
const RED: &str = "\x1b[1;31m";
const RESET: &str = "\x1b[0m";
/// How long to wait for the rest of an escape sequence before taking a lone
/// Esc as "cancel".
const ESC_WAIT: Duration = Duration::from_millis(30);

#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub enum Kind {
    #[default]
    Pin,
    Confirm,
    Message,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub enum Style {
    /// Full-width strip above the status line.
    #[default]
    Bar,
    /// Small centred box.
    Box,
    /// One line, with the description in the border title.
    Line,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub enum Echo {
    /// A fixed-width marker that changes on every key but hides the length.
    #[default]
    Marker,
    Dots,
    None,
}

macro_rules! names {
    ($ty:ident { $($variant:ident = $name:literal),* }) => {
        impl $ty {
            pub fn parse(s: &str) -> Option<$ty> {
                match s.trim() { $($name => Some($ty::$variant),)* _ => None }
            }
            fn name(self) -> &'static str {
                match self { $($ty::$variant => $name,)* }
            }
        }
    };
}
names!(Kind { Pin = "pin", Confirm = "confirm", Message = "message" });
names!(Style { Bar = "bar", Box = "box", Line = "line" });
names!(Echo { Marker = "marker", Dots = "dots", None = "none" });

/// Bytes that are zeroed when dropped, for anything holding a passphrase.
pub struct Secret(pub Vec<u8>);

impl Secret {
    pub fn new() -> Secret {
        Secret(Vec::with_capacity(512))
    }
}

impl Drop for Secret {
    fn drop(&mut self) {
        // Zero the whole allocation: pops and clears leave bytes behind.
        let ptr = self.0.as_mut_ptr();
        for i in 0..self.0.capacity() {
            unsafe { ptr.add(i).write_volatile(0) };
        }
    }
}

/// Everything the prompt needs to know; sent from the wrapper to the popup.
#[derive(Clone, Debug, Default)]
pub struct Request {
    pub kind: Kind,
    pub style: Style,
    pub echo: Echo,
    pub title: String,
    pub desc: String,
    pub prompt: String,
    pub error: String,
    pub repeat: Option<String>,
    pub repeat_error: String,
    pub ok: String,
    pub cancel: String,
    pub notok: Option<String>,
    pub timeout: u64,
    /// Content width, excluding border and padding.
    pub width: usize,
}

impl Request {
    pub fn encode(&self) -> String {
        let mut s = String::new();
        let mut put = |key: &str, value: &str| {
            let _ = writeln!(s, "{key} {}", escape(value.as_bytes()));
        };
        put("kind", self.kind.name());
        put("style", self.style.name());
        put("echo", self.echo.name());
        put("title", &self.title);
        put("desc", &self.desc);
        put("prompt", &self.prompt);
        put("error", &self.error);
        if let Some(repeat) = &self.repeat {
            put("repeat", repeat);
        }
        put("repeat-error", &self.repeat_error);
        put("ok", &self.ok);
        put("cancel", &self.cancel);
        if let Some(notok) = &self.notok {
            put("notok", notok);
        }
        put("timeout", &self.timeout.to_string());
        put("width", &self.width.to_string());
        s
    }

    pub fn decode(s: &str) -> Option<Request> {
        let mut req = Request::default();
        for line in s.lines() {
            let (key, value) = line.split_once(' ').unwrap_or((line, ""));
            let value = String::from_utf8_lossy(&unescape(value)).into_owned();
            match key {
                "kind" => req.kind = Kind::parse(&value)?,
                "style" => req.style = Style::parse(&value)?,
                "echo" => req.echo = Echo::parse(&value)?,
                "title" => req.title = value,
                "desc" => req.desc = value,
                "prompt" => req.prompt = value,
                "error" => req.error = value,
                "repeat" => req.repeat = Some(value),
                "repeat-error" => req.repeat_error = value,
                "ok" => req.ok = value,
                "cancel" => req.cancel = value,
                "notok" => req.notok = Some(value),
                "timeout" => req.timeout = value.parse().ok()?,
                "width" => req.width = value.parse().ok()?,
                _ => {}
            }
        }
        Some(req)
    }
}

pub enum Outcome {
    Pin { pin: Secret, repeated: bool },
    Ok,
    NotOk,
    Cancel,
    Timeout,
}

impl Outcome {
    pub fn encode(&self) -> Secret {
        let mut s = Secret::new();
        match self {
            Outcome::Pin { pin, repeated } => {
                s.0.extend_from_slice(if *repeated { b"PIN 1 " } else { b"PIN 0 " });
                escape_into(&mut s.0, &pin.0);
            }
            Outcome::Ok => s.0.extend_from_slice(b"OK"),
            Outcome::NotOk => s.0.extend_from_slice(b"NOTOK"),
            Outcome::Cancel => s.0.extend_from_slice(b"CANCEL"),
            Outcome::Timeout => s.0.extend_from_slice(b"TIMEOUT"),
        }
        s.0.push(b'\n');
        s
    }

    pub fn decode(line: &[u8]) -> Outcome {
        let line = line.strip_suffix(b"\n").unwrap_or(line);
        match line {
            b"OK" => Outcome::Ok,
            b"NOTOK" => Outcome::NotOk,
            b"TIMEOUT" => Outcome::Timeout,
            _ => match line.strip_prefix(b"PIN ") {
                Some(rest) if rest.len() >= 2 => Outcome::Pin {
                    pin: Secret(unescape(&String::from_utf8_lossy(&rest[2..]))),
                    repeated: rest[0] == b'1',
                },
                _ => Outcome::Cancel,
            },
        }
    }
}

fn width(s: &str) -> usize {
    UnicodeWidthStr::width(s)
}

/// Splits `s` after at most `w` columns (always taking at least one char).
fn split_at_width(s: &str, w: usize) -> (&str, &str) {
    let mut used = 0;
    for (i, c) in s.char_indices() {
        used += c.width().unwrap_or(0);
        if used > w && i > 0 {
            return s.split_at(i);
        }
    }
    (s, "")
}

/// Word-wraps each line of `text` to `w` columns.
fn wrap(text: &str, w: usize) -> Vec<String> {
    let mut lines = Vec::new();
    for para in text.lines() {
        let mut cur = String::new();
        for mut word in para.split_whitespace() {
            while !word.is_empty() {
                let sep = usize::from(!cur.is_empty());
                if width(&cur) + sep + width(word) <= w {
                    if sep == 1 {
                        cur.push(' ');
                    }
                    cur.push_str(word);
                    break;
                }
                if !cur.is_empty() {
                    lines.push(mem::take(&mut cur));
                    continue;
                }
                let (head, tail) = split_at_width(word, w);
                lines.push(head.to_string());
                word = tail;
            }
        }
        if !cur.is_empty() {
            lines.push(cur);
        }
    }
    lines
}

/// Joins `parts` with `sep`, breaking lines between parts where possible so
/// that e.g. a user ID isn't split across lines.
fn wrap_parts<'a>(parts: impl Iterator<Item = &'a str>, sep: &str, w: usize) -> Vec<String> {
    let mut lines: Vec<String> = Vec::new();
    for part in parts {
        let last = lines.last_mut().filter(|l| width(l) + width(sep) + width(part) <= w);
        match last {
            Some(line) => {
                line.push_str(sep);
                line.push_str(part);
            }
            None if width(part) <= w => lines.push(part.to_string()),
            None => lines.extend(wrap(part, w)),
        }
    }
    lines
}

/// "_Cancel" → ("Cancel", Some('c')); "__" is a literal underscore.
fn label(s: &str) -> (String, Option<char>) {
    let (mut text, mut key) = (String::new(), None);
    let mut chars = s.chars().peekable();
    while let Some(c) = chars.next() {
        if c != '_' {
            text.push(c);
        } else if chars.peek() == Some(&'_') {
            text.push(chars.next().unwrap());
        } else if key.is_none() {
            key = chars.peek().map(char::to_ascii_lowercase);
        }
    }
    (text, key)
}

#[derive(Clone, Copy)]
enum Choice {
    Ok,
    NotOk,
    Cancel,
}

struct Button {
    key: String,
    label: String,
    mnemonic: Option<char>,
    choice: Choice,
}

fn buttons(req: &Request) -> Vec<Button> {
    let (ok, ok_key) = label(&req.ok);
    let mut v = vec![Button { key: "⏎".into(), label: ok, mnemonic: ok_key, choice: Choice::Ok }];
    if req.kind == Kind::Confirm {
        if let Some(notok) = &req.notok {
            let (text, key) = label(notok);
            let key = key.or_else(|| text.chars().next().map(|c| c.to_ascii_lowercase()));
            let shown = key.map(String::from).unwrap_or_default();
            v.push(Button { key: shown, label: text, mnemonic: key, choice: Choice::NotOk });
        }
        let (cancel, key) = label(&req.cancel);
        v.push(Button { key: "esc".into(), label: cancel, mnemonic: key, choice: Choice::Cancel });
    }
    v
}

const MARKER_WIDTH: usize = 6;
const DOTS_WIDTH: usize = 16;

/// Widest the input line can get (prompt plus echo, or the buttons).
fn input_width(req: &Request) -> usize {
    match req.kind {
        Kind::Pin => {
            let prompt = width(&req.prompt).max(req.repeat.as_deref().map_or(0, width));
            prompt + match req.echo {
                Echo::Marker => 1 + MARKER_WIDTH,
                Echo::Dots => 1 + DOTS_WIDTH,
                Echo::None => 0,
            }
        }
        _ => {
            let b = buttons(req);
            b.iter().map(|b| width(&b.key) + 1 + width(&b.label)).sum::<usize>()
                + 3 * b.len().saturating_sub(1)
        }
    }
}

/// Rejoins the sentences gpg hard-wraps: a line that doesn't end a phrase
/// continues on the next.
fn phrases(paras: &[&str]) -> Vec<String> {
    let mut parts: Vec<String> = Vec::new();
    for p in paras {
        match parts.last_mut() {
            Some(last) if !last.ends_with([':', ',', '.', ';', '!', '?', '"']) => {
                last.push(' ');
                last.push_str(p);
            }
            _ => parts.push(p.to_string()),
        }
    }
    parts
}

/// The user ID gpg quotes in its descriptions, else the first phrase.
fn summary(paras: &[&str]) -> Option<String> {
    let all = paras.join("\n");
    if let Some((_, rest)) = all.split_once('"')
        && let Some((quoted, _)) = rest.split_once('"')
    {
        return Some(quoted.to_string());
    }
    phrases(paras).first().map(|p| p.trim_end_matches(':').to_string())
}

/// Where everything goes. The popup is sized from this, so the wrapper and
/// the popup must compute the same thing from the same Request.
pub struct Layout {
    pub title: String,
    pub desc: Vec<String>,
    /// None when errors are shown inline on the input row.
    pub error_row: Option<usize>,
    pub input_row: usize,
    pub rows: usize,
    pub width: usize,
}

pub fn layout(req: &Request, max: usize) -> Layout {
    let max = max.max(10);
    let paras: Vec<&str> = req.desc.lines().map(str::trim).filter(|l| !l.is_empty()).collect();
    let input_w = input_width(req);
    let repeat_error = req.repeat.as_ref().map(|_| req.repeat_error.as_str());
    let err_w = [Some(req.error.as_str()), repeat_error].into_iter().flatten().map(width).max();
    // Reserve the error row whenever one can appear, so the size never changes.
    let err_w = err_w.filter(|&w| w > 0 || req.repeat.is_some());
    let title = format!(" {} ", req.title);

    match req.style {
        Style::Bar => {
            let parts = phrases(&paras);
            let parts = parts.iter().map(|p| p.trim_end_matches([':', ',']));
            let desc = wrap_parts(parts, " · ", max);
            let error_row = err_w.map(|_| desc.len());
            let input_row = desc.len() + usize::from(err_w.is_some());
            Layout { title, desc, error_row, input_row, rows: input_row + 1, width: max }
        }
        Style::Box => {
            let longest = paras.iter().map(|p| width(p)).max().unwrap_or(0);
            let w = longest.max(input_w).max(err_w.unwrap_or(0)).clamp(20.min(max), max.min(76));
            let desc = wrap(&paras.join("\n"), w);
            let top = desc.len() + usize::from(!desc.is_empty());
            let error_row = err_w.map(|_| top);
            let input_row = top + usize::from(err_w.is_some());
            Layout { title, desc, error_row, input_row, rows: input_row + 1, width: w }
        }
        Style::Line => {
            let title = match summary(&paras) {
                Some(s) => format!(" {} · {s} ", req.title),
                None => title,
            };
            let line_w = err_w.map_or(0, |w| w + 2) + input_w;
            let w = line_w.max(width(&title) + 2).clamp(30.min(max), max);
            Layout { title, desc: Vec::new(), error_row: None, input_row: 0, rows: 1, width: w }
        }
    }
}

/// Renders styled segments, cut to `w` columns with an ellipsis.
fn render(segs: &[(&str, String)], w: usize) -> String {
    let (mut out, mut used) = (String::new(), 0);
    for (style, text) in segs {
        let fits = used + width(text) <= w;
        let text = if fits { text.as_str() } else { split_at_width(text, w.saturating_sub(used + 1)).0 };
        out.push_str(style);
        out.push_str(text);
        if !style.is_empty() {
            out.push_str(RESET);
        }
        used += width(text);
        if !fits {
            out.push('…');
            break;
        }
    }
    out
}

enum Key {
    Text(Vec<u8>),
    Enter,
    Backspace,
    Clear,
    Cancel,
    Eof,
    Ignore,
    Timeout,
    Hangup,
}

struct Ui<'a> {
    tty: &'a File,
    ctl: Option<&'a File>,
    req: &'a Request,
    lay: Layout,
    inline: bool,
    /// Cursor row, for relative movement when drawing inline.
    row: usize,
    pending: VecDeque<u8>,
    pin: Secret,
    /// The first entry while asking to repeat it.
    first: Option<Secret>,
    error: String,
    marker: u32,
}

/// Shows the prompt on `tty` and waits for an answer. `inline` draws in place
/// on an ordinary terminal instead of filling a popup. The prompt gives up if
/// `ctl` hangs up, which means the wrapper has gone away.
pub fn run(tty: &File, req: &Request, ctl: Option<&File>, inline: bool) -> io::Result<Outcome> {
    let _raw = sys::RawMode::enable(tty.as_raw_fd())?;
    let mut ui = Ui {
        tty,
        ctl,
        req,
        lay: layout(req, req.width),
        inline,
        row: 0,
        pending: VecDeque::new(),
        pin: Secret::new(),
        first: None,
        error: req.error.clone(),
        marker: 0,
    };
    ui.start()?;
    let deadline = (req.timeout > 0).then(|| Instant::now() + Duration::from_secs(req.timeout));
    let outcome = match req.kind {
        Kind::Pin => ui.pin_loop(deadline),
        _ => ui.button_loop(deadline),
    };
    let _ = ui.finish();
    outcome
}

impl Ui<'_> {
    fn write(&self, s: &str) -> io::Result<()> {
        let mut tty = self.tty;
        tty.write_all(s.as_bytes())?;
        tty.flush()
    }

    fn goto(&mut self, row: usize) -> String {
        if !self.inline {
            return format!("\x1b[{};1H", row + 1);
        }
        let mut s = match row.cmp(&self.row) {
            std::cmp::Ordering::Less => format!("\x1b[{}A", self.row - row),
            std::cmp::Ordering::Greater => format!("\x1b[{}B", row - self.row),
            std::cmp::Ordering::Equal => String::new(),
        };
        s.push('\r');
        self.row = row;
        s
    }

    fn row_text(&self, row: usize) -> String {
        let lay = &self.lay;
        let segs = if row < lay.desc.len() {
            vec![("", lay.desc[row].clone())]
        } else if Some(row) == lay.error_row {
            vec![(RED, self.error.clone())]
        } else if row == lay.input_row {
            self.input_segments()
        } else {
            Vec::new()
        };
        format!("\x1b[2K {}", render(&segs, lay.width))
    }

    fn input_segments(&self) -> Vec<(&'static str, String)> {
        let mut segs = Vec::new();
        if self.lay.error_row.is_none() && !self.error.is_empty() {
            segs.push((RED, self.error.clone()));
            segs.push(("", "  ".into()));
        }
        if self.req.kind != Kind::Pin {
            for (i, b) in buttons(self.req).into_iter().enumerate() {
                if i > 0 {
                    segs.push(("", "   ".into()));
                }
                segs.push((DIM, b.key));
                segs.push(("", " ".into()));
                segs.push((BOLD, b.label));
            }
            return segs;
        }
        let prompt = match (&self.first, &self.req.repeat) {
            (Some(_), Some(repeat)) => repeat.clone(),
            _ => self.req.prompt.clone(),
        };
        segs.push((BOLD, prompt));
        // Count chars, not bytes, without decoding the passphrase.
        let typed = self.pin.0.iter().filter(|&&b| b & 0xc0 != 0x80).count();
        match self.req.echo {
            Echo::Marker if typed == 0 => segs.push((DIM, " [····]".into())),
            Echo::Marker => {
                let dots: String = (0..4).map(|i| if self.marker >> i & 1 == 1 { '•' } else { '·' }).collect();
                segs.push(("", format!(" [{dots}]")));
            }
            Echo::Dots => segs.push(("", format!(" {}", "•".repeat(typed)))),
            Echo::None => {}
        }
        segs
    }

    fn start(&mut self) -> io::Result<()> {
        let mut s = String::from("\x1b[?25l");
        if self.inline {
            s.push('\r');
            for row in 0..self.lay.rows {
                if row > 0 {
                    s.push_str("\r\n");
                }
                s.push_str(&self.row_text(row));
            }
            self.row = self.lay.rows - 1;
        } else {
            s.push_str("\x1b[2J");
            for row in 0..self.lay.rows {
                s += &self.goto(row);
                s += &self.row_text(row);
            }
        }
        self.write(&s)
    }

    /// Redraws the rows that change while typing.
    fn refresh(&mut self) -> io::Result<()> {
        let mut s = String::new();
        for row in self.lay.error_row.into_iter().chain([self.lay.input_row]) {
            s += &self.goto(row);
            s += &self.row_text(row);
        }
        self.write(&s)
    }

    fn finish(&mut self) -> io::Result<()> {
        let mut s = String::new();
        if self.inline {
            s += &self.goto(0);
            s += "\x1b[J";
        }
        s += "\x1b[0m\x1b[?25h";
        self.write(&s)
    }

    /// Reads whatever input is ready. Returns a key only for timeouts and
    /// hangups; otherwise the bytes land in `pending`.
    fn fill(&mut self, timeout: Option<Duration>) -> io::Result<Option<Key>> {
        let mut fds = vec![self.tty.as_raw_fd()];
        fds.extend(self.ctl.map(|c| c.as_raw_fd()));
        let revents = sys::poll(&fds, timeout)?;
        if revents.get(1).is_some_and(|&r| r != 0) || revents[0] & (libc::POLLHUP | libc::POLLERR) != 0 {
            return Ok(Some(Key::Hangup));
        }
        if revents[0] == 0 {
            return Ok(Some(Key::Timeout));
        }
        let mut buf = [0; 64];
        let n = (&mut &*self.tty).read(&mut buf)?;
        if n == 0 {
            return Ok(Some(Key::Hangup));
        }
        self.pending.extend(&buf[..n]);
        buf.fill(0);
        Ok(None)
    }

    /// Whether more input is waiting, giving it a moment to arrive.
    fn more(&mut self) -> io::Result<bool> {
        if self.pending.is_empty() {
            self.fill(Some(ESC_WAIT))?;
        }
        Ok(!self.pending.is_empty())
    }

    fn key(&mut self, deadline: Option<Instant>) -> io::Result<Key> {
        while self.pending.is_empty() {
            let left = deadline.map(|d| d.saturating_duration_since(Instant::now()));
            if left == Some(Duration::ZERO) {
                return Ok(Key::Timeout);
            }
            if let Some(key) = self.fill(left)? {
                return Ok(key);
            }
        }
        let b = self.pending.pop_front().unwrap();
        Ok(match b {
            b'\r' | b'\n' => Key::Enter,
            0x7f | 0x08 => Key::Backspace,
            0x15 | 0x17 => Key::Clear,
            0x03 => Key::Cancel,
            0x04 => Key::Eof,
            0x1b if !self.more()? => Key::Cancel,
            0x1b => {
                // An escape sequence (arrow keys and such): skip it.
                match self.pending.pop_front() {
                    Some(b'[') => {
                        while self.more()? {
                            if (0x40..=0x7e).contains(&self.pending.pop_front().unwrap()) {
                                break;
                            }
                        }
                    }
                    Some(b'O') if self.more()? => drop(self.pending.pop_front()),
                    _ => {}
                }
                Key::Ignore
            }
            ..0x20 => Key::Ignore,
            _ => {
                let len = match b {
                    0xc0..=0xdf => 2,
                    0xe0..=0xef => 3,
                    0xf0..=0xf7 => 4,
                    _ => 1,
                };
                let mut text = vec![b];
                while text.len() < len && self.more()? {
                    text.push(self.pending.pop_front().unwrap());
                }
                Key::Text(text)
            }
        })
    }

    fn reroll_marker(&mut self) {
        loop {
            let m = sys::random() & 0xf;
            if m.count_ones() >= 2 && m != self.marker {
                self.marker = m;
                return;
            }
        }
    }

    fn pin_loop(&mut self, deadline: Option<Instant>) -> io::Result<Outcome> {
        loop {
            match self.key(deadline)? {
                Key::Text(mut text) => {
                    self.pin.0.extend_from_slice(&text);
                    text.fill(0);
                    self.reroll_marker();
                }
                Key::Backspace => {
                    while let Some(b) = self.pin.0.pop() {
                        if b & 0xc0 != 0x80 {
                            break;
                        }
                    }
                    self.reroll_marker();
                }
                Key::Clear => self.pin.0.clear(),
                Key::Enter => {
                    let pin = mem::replace(&mut self.pin, Secret::new());
                    if self.req.repeat.is_none() {
                        return Ok(Outcome::Pin { pin, repeated: false });
                    }
                    match self.first.take() {
                        None => self.first = Some(pin),
                        Some(first) if first.0 == pin.0 => {
                            return Ok(Outcome::Pin { pin, repeated: true });
                        }
                        Some(_) => self.error = self.req.repeat_error.clone(),
                    }
                }
                Key::Eof if !self.pin.0.is_empty() => continue,
                Key::Cancel | Key::Eof | Key::Hangup => return Ok(Outcome::Cancel),
                Key::Timeout => return Ok(Outcome::Timeout),
                Key::Ignore => continue,
            }
            self.refresh()?;
        }
    }

    fn button_loop(&mut self, deadline: Option<Instant>) -> io::Result<Outcome> {
        let message = self.req.kind == Kind::Message;
        let buttons = buttons(self.req);
        let choice = loop {
            match self.key(deadline)? {
                Key::Enter => break Choice::Ok,
                Key::Cancel | Key::Hangup if !message => break Choice::Cancel,
                Key::Cancel | Key::Hangup => break Choice::Ok,
                Key::Timeout => return Ok(Outcome::Timeout),
                Key::Text(text) => {
                    let c = String::from_utf8_lossy(&text).chars().next().map(|c| c.to_ascii_lowercase());
                    if let Some(b) = buttons.iter().find(|b| b.mnemonic.is_some() && b.mnemonic == c) {
                        break b.choice;
                    }
                }
                _ => {}
            }
        };
        Ok(match choice {
            Choice::Ok => Outcome::Ok,
            Choice::NotOk => Outcome::NotOk,
            Choice::Cancel => Outcome::Cancel,
        })
    }
}
