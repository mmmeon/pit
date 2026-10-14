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
    /// The command and pane that asked, if known.
    pub origin: String,
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
        put("origin", &self.origin);
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
                "origin" => req.origin = value,
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
                    pin: Secret(unescape(&rest[2..])),
                    repeated: rest[0] == b'1',
                },
                _ => Outcome::Cancel,
            },
        }
    }
}

pub fn width(s: &str) -> usize {
    UnicodeWidthStr::width(s)
}

/// Splits `s` after at most `w` columns (always taking at least one char).
pub fn split_at_width(s: &str, w: usize) -> (&str, &str) {
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
    let head = format!(" {}", req.title);

    match req.style {
        Style::Bar => {
            let parts = phrases(&paras);
            let parts = parts.iter().map(|p| p.trim_end_matches([':', ',']));
            let desc = wrap_parts(parts, " · ", max);
            let error_row = err_w.map(|_| desc.len());
            let input_row = desc.len() + usize::from(err_w.is_some());
            let title = title(&head, &req.origin, max);
            Layout { title, desc, error_row, input_row, rows: input_row + 1, width: max }
        }
        Style::Box => {
            let longest = paras.iter().map(|p| width(p)).max().unwrap_or(0);
            let w = longest.max(input_w).max(err_w.unwrap_or(0)).clamp(20.min(max), max.min(76));
            let desc = wrap(&paras.join("\n"), w);
            let top = desc.len() + usize::from(!desc.is_empty());
            let error_row = err_w.map(|_| top);
            let input_row = top + usize::from(err_w.is_some());
            let title = title(&head, &req.origin, w);
            Layout { title, desc, error_row, input_row, rows: input_row + 1, width: w }
        }
        Style::Line => {
            let bare = match summary(&paras) {
                Some(s) => format!(" {} · {s} ", req.title),
                None => format!(" {} ", req.title),
            };
            // Sized without the origin, which may then be cut.
            let line_w = err_w.map_or(0, |w| w + 2) + input_w;
            let w = line_w.max(width(&bare) + 2).clamp(30.min(max), max);
            let title = title(bare.trim_end(), &req.origin, w);
            Layout { title, desc: Vec::new(), error_row: None, input_row: 0, rows: 1, width: w }
        }
    }
}

/// Fewest columns of the origin worth showing in a title.
const MIN_ORIGIN: usize = 8;

/// The border title in `w` columns: `head`, then the origin. tmux would cut
/// it mid-separator, so the origin is cut here, or left out if too little of
/// it would show.
fn title(head: &str, origin: &str, w: usize) -> String {
    let cut = |s: &str, w| render(&[("", s.to_string())], w);
    let full = if origin.is_empty() { format!("{head} ") } else { format!("{head} · {origin} ") };
    if width(&full) <= w {
        return full;
    }
    let room = w.saturating_sub(width(head) + width(" ·  "));
    if !origin.is_empty() && room >= MIN_ORIGIN {
        return format!("{head} · {} ", cut(origin, room));
    }
    format!("{} ", cut(head, w.saturating_sub(1)))
}

/// Renders styled segments, cut to `w` columns with an ellipsis.
fn render(segs: &[(&str, String)], w: usize) -> String {
    let cut = segs.iter().map(|(_, t)| width(t)).sum::<usize>() > w;
    // Leave a column for the ellipsis when cutting.
    let room = if cut { w.saturating_sub(1) } else { w };
    let (mut out, mut used) = (String::new(), 0);
    for (style, text) in segs {
        let fits = used + width(text) <= room;
        let text = match fits {
            true => text.as_str(),
            // split_at_width always takes a char: drop it if it doesn't fit.
            false => Some(split_at_width(text, room - used).0).filter(|t| used + width(t) <= room).unwrap_or(""),
        };
        out.push_str(style);
        out.push_str(text);
        if !style.is_empty() {
            out.push_str(RESET);
        }
        used += width(text);
        if !fits {
            break;
        }
    }
    if cut {
        out.push('…');
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

#[cfg(test)]
mod tests {
    use super::*;

    fn full_request() -> Request {
        Request {
            kind: Kind::Confirm,
            style: Style::Line,
            echo: Echo::Dots,
            title: "Unlock key".into(),
            origin: String::new(),
            desc: "Please enter the passphrase for\n\"Alice <a@x>\"\n100% sure? 漢字".into(),
            prompt: "Pass phrase:".into(),
            error: "Bad\rpassphrase".into(),
            repeat: Some("Repeat:".into()),
            repeat_error: "mismatch %25".into(),
            ok: "_OK".into(),
            cancel: "_Cancel".into(),
            notok: Some("_No".into()),
            timeout: 42,
            width: 77,
        }
    }

    fn pin(outcome: Outcome) -> (Vec<u8>, bool) {
        match outcome {
            Outcome::Pin { pin, repeated } => (pin.0.clone(), repeated),
            _ => panic!("not a pin"),
        }
    }

    #[test]
    fn request_round_trips() {
        let req = full_request();
        let back = Request::decode(&req.encode()).unwrap();
        assert_eq!(back.encode(), req.encode());
        assert_eq!(back.desc, req.desc);
        assert_eq!(back.error, req.error);
        assert_eq!(back.repeat_error, req.repeat_error);
        assert_eq!((back.kind, back.style, back.echo), (req.kind, req.style, req.echo));
        assert_eq!((back.timeout, back.width), (42, 77));
        assert_eq!(back.notok.as_deref(), Some("_No"));
    }

    #[test]
    fn request_round_trips_optional_fields() {
        for (repeat, notok) in [(None, None), (Some(String::new()), Some(String::new()))] {
            let req = Request { repeat: repeat.clone(), notok: notok.clone(), ..full_request() };
            let back = Request::decode(&req.encode()).unwrap();
            assert_eq!((back.repeat, back.notok), (repeat, notok));
        }
        for kind in [Kind::Pin, Kind::Confirm, Kind::Message] {
            for style in [Style::Bar, Style::Box, Style::Line] {
                for echo in [Echo::Marker, Echo::Dots, Echo::None] {
                    let req = Request { kind, style, echo, ..full_request() };
                    let back = Request::decode(&req.encode()).unwrap();
                    assert_eq!((back.kind, back.style, back.echo), (kind, style, echo));
                }
            }
        }
    }

    #[test]
    fn request_decode_rejects_bad_values() {
        assert!(Request::decode("kind bogus\n").is_none());
        assert!(Request::decode("style\n").is_none());
        assert!(Request::decode("timeout soon\n").is_none());
        assert!(Request::decode("width -1\n").is_none());
        let req = Request::decode("future-key whatever\ntitle t\n").unwrap();
        assert_eq!(req.title, "t");
    }

    #[test]
    fn names_parse() {
        assert_eq!(Style::parse(" box\n"), Some(Style::Box));
        assert_eq!(Style::parse("BOX"), None);
        assert_eq!(Echo::parse("none"), Some(Echo::None));
        assert_eq!(Echo::parse("stars"), None);
        assert_eq!(Kind::parse("message"), Some(Kind::Message));
    }

    #[test]
    fn outcome_round_trips() {
        let secret = "p%ss\nwörd\x01 ".as_bytes().to_vec();
        for repeated in [false, true] {
            let line = Outcome::Pin { pin: Secret(secret.clone()), repeated }.encode();
            assert_eq!(line.0.iter().filter(|&&b| b == b'\n').count(), 1);
            assert_eq!(pin(Outcome::decode(&line.0)), (secret.clone(), repeated));
        }
        assert_eq!(pin(Outcome::decode(b"PIN 0 \n")), (Vec::new(), false));
        assert!(matches!(Outcome::decode(&Outcome::Ok.encode().0), Outcome::Ok));
        assert!(matches!(Outcome::decode(&Outcome::NotOk.encode().0), Outcome::NotOk));
        assert!(matches!(Outcome::decode(&Outcome::Cancel.encode().0), Outcome::Cancel));
        assert!(matches!(Outcome::decode(&Outcome::Timeout.encode().0), Outcome::Timeout));
    }

    #[test]
    fn outcome_garbage_is_cancel() {
        for line in [&b""[..], b"\n", b"PIN", b"PIN 1", b"ok\n", b"READY\n"] {
            assert!(matches!(Outcome::decode(line), Outcome::Cancel), "{line:?}");
        }
    }

    #[test]
    fn outcome_keeps_non_utf8_pin_bytes() {
        // A Latin-1 terminal sends é as the single byte 0xe9.
        let secret = vec![b'p', 0xe9, b'x'];
        let line = Outcome::Pin { pin: Secret(secret.clone()), repeated: false }.encode();
        assert_eq!(pin(Outcome::decode(&line.0)).0, secret);
    }

    #[test]
    fn split_at_width_cases() {
        assert_eq!(split_at_width("abcdef", 3), ("abc", "def"));
        assert_eq!(split_at_width("abc", 3), ("abc", ""));
        assert_eq!(split_at_width("漢字", 3), ("漢", "字"));
        assert_eq!(split_at_width("漢字", 1), ("漢", "字"));
        assert_eq!(split_at_width("abc", 0), ("a", "bc"));
        assert_eq!(split_at_width("e\u{301}x", 1), ("e\u{301}", "x"));
    }

    #[test]
    fn wrap_cases() {
        assert_eq!(wrap("the quick brown fox", 9), ["the quick", "brown fox"]);
        assert_eq!(wrap("a\n\nb", 9), ["a", "b"]);
        assert_eq!(wrap("  spaced   out  ", 20), ["spaced out"]);
        assert_eq!(wrap("abcdefghij x", 4), ["abcd", "efgh", "ij x"]);
        assert_eq!(wrap("漢字漢字", 5), ["漢字", "漢字"]);
        assert!(wrap("", 10).is_empty());
    }

    #[test]
    fn wrap_never_exceeds_width() {
        let text = "Please enter the passphrase to unlock the OpenPGP secret key: \
                    \"Ålice Ünicode 漢字テスト <alice@example.org>\" 3072-bit RSA key, \
                    ID 0123456789ABCDEF, created 2024-01-01. averyveryverylongwordindeed";
        for w in 1..60 {
            for line in wrap(text, w) {
                assert!(width(&line) <= w.max(2), "w={w} {line:?}");
            }
            let parts = ["one", "two three", "averyveryverylongwordindeed", "漢字"];
            for line in wrap_parts(parts.into_iter(), " · ", w) {
                assert!(width(&line) <= w.max(2), "w={w} {line:?}");
            }
        }
    }

    #[test]
    fn wrap_parts_keeps_parts_together() {
        let parts = ["Unlock key", "Alice <a@x>", "RSA"];
        assert_eq!(wrap_parts(parts.into_iter(), " · ", 100), ["Unlock key · Alice <a@x> · RSA"]);
        assert_eq!(wrap_parts(parts.into_iter(), " · ", 20), ["Unlock key", "Alice <a@x> · RSA"]);
        assert_eq!(wrap_parts(["a b c d e f"].into_iter(), " · ", 5), ["a b c", "d e f"]);
    }

    #[test]
    fn label_cases() {
        assert_eq!(label("_Cancel"), ("Cancel".into(), Some('c')));
        assert_eq!(label("Do_n't"), ("Don't".into(), Some('n')));
        assert_eq!(label("a__b"), ("a_b".into(), None));
        assert_eq!(label("_A_B"), ("AB".into(), Some('a')));
        assert_eq!(label("trailing_"), ("trailing".into(), None));
        assert_eq!(label("OK"), ("OK".into(), None));
    }

    #[test]
    fn buttons_per_kind() {
        let req = Request { kind: Kind::Message, ..full_request() };
        let b = buttons(&req);
        assert_eq!(b.len(), 1);
        assert_eq!((b[0].key.as_str(), b[0].label.as_str(), b[0].mnemonic), ("⏎", "OK", Some('o')));

        let req = Request { kind: Kind::Confirm, notok: Some("Maybe".into()), ..full_request() };
        let b = buttons(&req);
        let summary: Vec<_> = b.iter().map(|b| (b.key.as_str(), b.label.as_str(), b.mnemonic)).collect();
        assert_eq!(
            summary,
            [("⏎", "OK", Some('o')), ("m", "Maybe", Some('m')), ("esc", "Cancel", Some('c'))]
        );
        assert!(matches!(b[1].choice, Choice::NotOk));

        let req = Request { kind: Kind::Confirm, notok: None, ..full_request() };
        assert_eq!(buttons(&req).len(), 2);
    }

    #[test]
    fn input_width_cases() {
        let pin = |echo, repeat: Option<&str>| Request {
            kind: Kind::Pin,
            echo,
            prompt: "PIN:".into(),
            repeat: repeat.map(Into::into),
            ..full_request()
        };
        assert_eq!(input_width(&pin(Echo::None, None)), 4);
        assert_eq!(input_width(&pin(Echo::Marker, None)), 4 + 1 + MARKER_WIDTH);
        assert_eq!(input_width(&pin(Echo::Dots, Some("Repeat PIN:"))), 11 + 1 + DOTS_WIDTH);
        // "⏎ OK" + "   " + "n No" + "   " + "esc Cancel"
        let req = Request { kind: Kind::Confirm, ..full_request() };
        assert_eq!(input_width(&req), 4 + 3 + 4 + 3 + 10);
    }

    #[test]
    fn phrases_and_summary() {
        let paras = ["Please enter the passphrase to unlock", "the OpenPGP secret key:", "\"Alice <a@x>\"", "255-bit key,"];
        assert_eq!(
            phrases(&paras),
            ["Please enter the passphrase to unlock the OpenPGP secret key:", "\"Alice <a@x>\"", "255-bit key,"]
        );
        assert_eq!(summary(&paras).as_deref(), Some("Alice <a@x>"));
        assert_eq!(summary(&["Enter new", "passphrase:"]).as_deref(), Some("Enter new passphrase"));
        assert_eq!(summary(&[]), None);
    }

    #[test]
    fn layout_bar() {
        let req = Request { kind: Kind::Pin, style: Style::Bar, error: String::new(), repeat: None, ..full_request() };
        let lay = layout(&req, 200);
        assert_eq!(lay.width, 200);
        assert_eq!(lay.desc, ["Please enter the passphrase for \"Alice <a@x>\" · 100% sure? 漢字"]);
        assert_eq!((lay.error_row, lay.input_row, lay.rows), (None, 1, 2));
        assert_eq!(lay.title, " Unlock key ");

        // An error row is reserved for SETERROR, and for repeat even before a mismatch.
        let lay = layout(&Request { error: "bad".into(), ..req.clone() }, 200);
        assert_eq!((lay.error_row, lay.input_row, lay.rows), (Some(1), 2, 3));
        let lay = layout(&Request { repeat: Some("Again:".into()), ..req.clone() }, 200);
        assert_eq!((lay.error_row, lay.input_row, lay.rows), (Some(1), 2, 3));

        assert_eq!(layout(&req, 3).width, 10);
    }

    #[test]
    fn layout_box() {
        let req = Request { kind: Kind::Pin, style: Style::Box, error: String::new(), repeat: None, ..full_request() };
        let short = Request { desc: "Hi".into(), prompt: "P:".into(), echo: Echo::None, ..req.clone() };
        let lay = layout(&short, 200);
        assert_eq!(lay.width, 20);
        assert_eq!((lay.desc.len(), lay.error_row, lay.input_row, lay.rows), (1, None, 2, 3));

        let long = Request { desc: "word ".repeat(40), ..req.clone() };
        let lay = layout(&long, 200);
        assert_eq!(lay.width, 76);
        assert!(lay.desc.len() > 1);
        assert_eq!(layout(&long, 40).width, 40);

        let empty = Request { desc: String::new(), ..req };
        let lay = layout(&empty, 200);
        assert_eq!((lay.desc.len(), lay.input_row, lay.rows), (0, 0, 1));
    }

    #[test]
    fn layout_line() {
        let req = Request { kind: Kind::Pin, style: Style::Line, ..full_request() };
        let lay = layout(&req, 200);
        assert_eq!((lay.rows, lay.input_row, lay.error_row), (1, 0, None));
        assert!(lay.desc.is_empty());
        assert_eq!(lay.title, " Unlock key · Alice <a@x> ");
        assert!(lay.width >= 30);
        assert_eq!(layout(&req, 12).width, 12);

        let req = Request { origin: "git commit @ work:2.1".into(), ..req };
        // The popup isn't widened for the origin, so it's cut to fit.
        assert_eq!(layout(&req, 200).title, " Unlock key · Alice <a@x> · git commit @ wo… ");
        assert_eq!(layout(&req, 200).width, layout(&Request { origin: String::new(), ..req.clone() }, 200).width);
        let req = Request { style: Style::Box, ..req };
        assert_eq!(layout(&req, 200).title, " Unlock key · git commit @ wo… ");
    }

    #[test]
    fn title_fits_its_border() {
        assert_eq!(title(" Unlock", "git commit @ work:2.1", 40), " Unlock · git commit @ work:2.1 ");
        assert_eq!(title(" Unlock", "git commit @ work:2.1", 22), " Unlock · git commit… ");
        // Too little of the origin would show: no dangling separator.
        assert_eq!(title(" Unlock", "git commit @ work:2.1", 18), " Unlock ");
        assert_eq!(title(" Unlock key", "", 8), " Unloc… ");
        for w in 1..40 {
            let t = title(" Unlock · Alice <a@x>", "git commit @ work:2.1", w);
            assert!(width(&t) <= w.max(2), "w={w} {t:?}");
            assert!(!t.trim_end().ends_with('·'), "w={w} {t:?}");
        }
    }

    #[test]
    fn layout_is_stable_at_its_own_width() {
        let descs = ["", "Short", &"word ".repeat(30), "Please enter the passphrase for\n\"Alice <a@x>\"\n3072-bit RSA key"];
        for desc in descs {
            for kind in [Kind::Pin, Kind::Confirm, Kind::Message] {
                for style in [Style::Bar, Style::Box, Style::Line] {
                    for echo in [Echo::Marker, Echo::Dots, Echo::None] {
                        for repeat in [None, Some("Repeat:".to_string())] {
                            for max in [0, 5, 10, 25, 40, 80, 300] {
                                let req = Request { desc: desc.into(), kind, style, echo, repeat: repeat.clone(), ..full_request() };
                                let a = layout(&req, max);
                                let b = layout(&req, a.width);
                                let ctx = format!("{kind:?} {style:?} {echo:?} max={max} desc={desc:?}");
                                assert_eq!((a.width, a.rows, a.input_row, a.error_row), (b.width, b.rows, b.input_row, b.error_row), "{ctx}");
                                assert_eq!((&a.title, &a.desc), (&b.title, &b.desc), "{ctx}");
                                for line in &a.desc {
                                    assert!(width(line) <= a.width.max(2), "{ctx} {line:?}");
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    #[test]
    fn render_cuts_with_ellipsis() {
        let segs = [("", "hello".to_string()), (BOLD, "world".to_string()), ("", "!".to_string())];
        assert_eq!(render(&segs, 20), format!("hello{BOLD}world{RESET}!"));
        assert_eq!(render(&segs, 7), format!("hello{BOLD}w{RESET}…"));
        assert_eq!(render(&[("", "漢字漢字".into())], 5), "漢字…");
        assert_eq!(render(&[], 5), "");
    }

    #[test]
    fn render_never_exceeds_width() {
        let segs = [("", "hello".to_string()), (BOLD, "world".to_string())];
        assert_eq!(render(&segs, 5), "hell…");
        assert_eq!(render(&[("", "漢字".into())], 2), "…");
        assert_eq!(render(&[("", "a漢字".into())], 3), "a…");
        let texts = ["hello", "漢字漢字", "e\u{301}e\u{301}", "", "x"];
        for w in 1..14 {
            for a in texts {
                for b in texts {
                    let segs = [(BOLD, a.to_string()), ("", b.to_string()), (RED, "漢".to_string())];
                    let out = render(&segs, w).replace(BOLD, "").replace(RED, "").replace(RESET, "");
                    assert!(width(&out) <= w, "w={w} {out:?}");
                }
            }
        }
    }
}
