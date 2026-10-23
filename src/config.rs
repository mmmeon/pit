//! The user's settings, from $XDG_CONFIG_HOME/pit/config.toml (by default
//! ~/.config/pit/config.toml), read for each prompt so edits apply at once:
//!
//!   echo = "marker"       # marker|dots|none
//!   origin = "short"      # short|full, the command named in the title
//!   hook = '<command>'    # run on a prompt opening and closing
//!   pending = "never"     # never|wait, for `pit answer` when there's nowhere to ask
//!   show = "origin intro identity key created"  # the parts of a prompt shown
//!   intro = "<text>"      # in place of gpg's intro, with {identity} {key} {created} {date}
//!   [tmux]
//!   style = "bar"         # bar|box|line, for the popup
//!   inline = "auto"       # auto|never, asking in a pane in place
//!   [gui]
//!   pinentry = "<program>" # another pinentry, for a display
//!   order = "last"        # last|first, before or after the terminal
//!
//! Only TOML's strings are understood, which is all these need. A key that
//! doesn't parse or isn't known is skipped: a typo shouldn't stand between
//! the user and their passphrase.

use std::env;
use std::fs::File;
use std::io::Read;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};

use crate::sys;
use crate::ui::{Echo, Request, Style};

pub struct Config {
    pub echo: Echo,
    pub hook: Option<String>,
    /// Whether to name the command that asked with its whole command line,
    /// not only the program and subcommand.
    pub full_origin: bool,
    pub style: Style,
    /// Whether a pane may be asked in place, instead of in a popup.
    pub inline: bool,
    /// A graphical pinentry to hand the prompt to.
    pub gui: Option<String>,
    /// Whether to try `gui` before the terminal, not after.
    pub gui_first: bool,
    /// Whether a prompt with nowhere to go waits for `pit answer`.
    pub pending: bool,
    pub show: Show,
    /// Text in place of gpg's intro, with placeholders for the other parts.
    pub intro: Option<String>,
}

/// The parts of a prompt shown. The rest of a description, which pit can't
/// tell apart, is always shown, and so is gpg-agent's note on a request
/// from a remote site.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Show {
    /// Who asked, in the title.
    pub origin: bool,
    /// gpg's line before the user ID ("Please enter the passphrase...").
    pub intro: bool,
    /// The quoted user ID.
    pub identity: bool,
    /// The key's length, algorithm and ID ("255-bit EDDSA key, ID ...").
    pub key: bool,
    /// When the key was created.
    pub created: bool,
}

impl Default for Show {
    fn default() -> Show {
        Show { origin: true, intro: true, identity: true, key: true, created: true }
    }
}

impl Show {
    /// Only the parts named in `s`, separated by spaces or commas. Unknown
    /// names are skipped.
    fn parse(s: &str) -> Show {
        let names: Vec<&str> = s.split([' ', '\t', ',']).filter(|n| !n.is_empty()).collect();
        let has = |n: &str| names.contains(&n);
        Show { origin: has("origin"), intro: has("intro"), identity: has("identity"), key: has("key"), created: has("created") }
    }
}

impl Default for Config {
    fn default() -> Config {
        Config {
            echo: Echo::default(),
            hook: None,
            full_origin: false,
            style: Style::default(),
            inline: true,
            gui: None,
            gui_first: false,
            pending: false,
            show: Show::default(),
            intro: None,
        }
    }
}

impl Config {
    pub fn load() -> Config {
        let dir = env::var_os("XDG_CONFIG_HOME")
            .map(PathBuf::from)
            .filter(|d| d.is_absolute())
            .or_else(|| env::var_os("HOME").map(|h| PathBuf::from(h).join(".config")));
        dir.map_or_else(Config::default, |d| Config::read(&d.join("pit/config.toml")))
    }

    /// The settings in the file at `path`, if there is one. `hook` and
    /// `gui.pinentry` name programs to run as us, so they're taken only
    /// from a file that's ours and that no one else can write.
    fn read(path: &Path) -> Config {
        let Ok(mut file) = File::open(path) else { return Config::default() };
        let mut text = String::new();
        if file.read_to_string(&mut text).is_err() {
            return Config::default();
        }
        let mut c = Config::parse(&text);
        // Of the file read, not whatever is at the path by now.
        let ours = file.metadata().is_ok_and(|m| m.uid() == sys::uid() && m.mode() & 0o022 == 0);
        if !ours {
            c.hook = None;
            c.gui = None;
        }
        c
    }

    fn parse(text: &str) -> Config {
        let mut c = Config::default();
        for (key, v) in values(text) {
            match key.as_str() {
                "echo" => c.echo = Echo::parse(&v).unwrap_or(c.echo),
                "hook" => c.hook = Some(v).filter(|v| !v.trim().is_empty()),
                "origin" => match v.as_str() {
                    "short" => c.full_origin = false,
                    "full" => c.full_origin = true,
                    _ => {}
                },
                "tmux.style" => c.style = Style::parse(&v).unwrap_or(c.style),
                "tmux.inline" => match v.as_str() {
                    "auto" => c.inline = true,
                    "never" => c.inline = false,
                    _ => {}
                },
                "pending" => match v.as_str() {
                    "wait" => c.pending = true,
                    "never" => c.pending = false,
                    _ => {}
                },
                "show" => c.show = Show::parse(&v),
                "intro" => c.intro = Some(v).filter(|v| !v.trim().is_empty()),
                "gui.pinentry" => c.gui = Some(v).filter(|v| !v.trim().is_empty()),
                "gui.order" => match v.as_str() {
                    "first" => c.gui_first = true,
                    "last" => c.gui_first = false,
                    _ => {}
                },
                _ => {}
            }
        }
        c
    }
}

/// The string values in `text`, keyed `section.key`, or `key` before any
/// section.
fn values(mut s: &str) -> Vec<(String, String)> {
    let mut out = Vec::new();
    let mut section = Some(String::new());
    while !s.is_empty() {
        let t = s.trim_start_matches([' ', '\t']);
        let (line, next) = t.split_once('\n').unwrap_or((t, ""));
        s = next;
        if let Some(h) = line.strip_prefix('[') {
            // Keys under a header that doesn't parse are skipped too.
            section = h
                .split_once(']')
                .filter(|(name, after)| bare(name.trim()) && blank(after))
                .map(|(name, _)| name.trim().to_string());
        } else if let Some((key, _)) = line.split_once('=').filter(|(k, _)| bare(k.trim()))
            && let Some((value, after)) = string(t[key.len() + 1..].trim_start_matches([' ', '\t']))
        {
            // A multi-line value carries on past this line.
            let (tail, next) = after.split_once('\n').unwrap_or((after, ""));
            s = next;
            if let (Some(sec), Some(value), true) = (&section, value, blank(tail)) {
                let key = key.trim();
                out.push((if sec.is_empty() { key.to_string() } else { format!("{sec}.{key}") }, value));
            }
        }
    }
    out
}

fn bare(key: &str) -> bool {
    !key.is_empty() && key.chars().all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
}

/// Nothing but a comment, if that.
fn blank(s: &str) -> bool {
    let s = s.trim();
    s.is_empty() || s.starts_with('#')
}

/// A TOML string at the start of `v`, and what follows it. None if it isn't
/// one or doesn't end; Some((None, _)) if it ends but is invalid inside.
fn string(v: &str) -> Option<(Option<String>, &str)> {
    // A newline right after the opening quotes isn't part of the value.
    let first_line = |s: &str| s.strip_prefix("\r\n").or(s.strip_prefix('\n')).unwrap_or(s).to_string();
    if let Some(r) = v.strip_prefix("'''") {
        let (body, after) = r.split_once("'''")?;
        Some((Some(first_line(body)), after))
    } else if let Some(r) = v.strip_prefix("\"\"\"") {
        let (body, after) = basic(r, "\"\"\"")?;
        Some((body.map(|b| first_line(&b)), after))
    } else if let Some(r) = v.strip_prefix('\'') {
        let (body, after) = r.split_once('\'')?;
        (!body.contains('\n')).then(|| (Some(body.to_string()), after))
    } else {
        basic(v.strip_prefix('"')?, "\"")
    }
}

/// A basic string's body, up to `close`, with its escapes undone.
fn basic<'a>(r: &'a str, close: &str) -> Option<(Option<String>, &'a str)> {
    let multi = close.len() > 1;
    let mut out = Some(String::new());
    let mut chars = r.char_indices();
    // After a backslash ending a line, whitespace up to the next text goes.
    let mut joining = false;
    while let Some((i, c)) = chars.next() {
        if r[i..].starts_with(close) {
            return Some((out, &r[i + close.len()..]));
        }
        if c == '\n' && !multi {
            return None;
        }
        if joining && c.is_whitespace() {
            continue;
        }
        joining = false;
        let c = match c {
            '\\' => match chars.next()?.1 {
                'n' => Some('\n'),
                't' => Some('\t'),
                'r' => Some('\r'),
                'b' => Some('\u{8}'),
                'f' => Some('\u{c}'),
                'e' => Some('\u{1b}'),
                '"' => Some('"'),
                '\\' => Some('\\'),
                e @ ('u' | 'U') => {
                    let n = if e == 'u' { 4 } else { 8 };
                    let hex: Option<String> = (0..n).map(|_| chars.next().map(|(_, h)| h)).collect();
                    hex.filter(|h| h.chars().all(|c| c.is_ascii_hexdigit()))
                        .and_then(|h| char::from_u32(u32::from_str_radix(&h, 16).ok()?))
                }
                w if multi && w.is_whitespace() => {
                    joining = true;
                    continue;
                }
                _ => None,
            },
            c => Some(c),
        };
        match (&mut out, c) {
            (Some(s), Some(c)) => s.push(c),
            _ => out = None,
        }
    }
    None
}

/// The user's hook command, run for a prompt opening and then, once this is
/// dropped or the process dies, closing.
pub struct Hook(Option<Child>);

impl Hook {
    /// Runs `cmd`, if any, for a prompt opening at `place`. In the
    /// background: it never holds up the prompt. One shell runs both events,
    /// so close never comes before open is done.
    pub fn open(cmd: Option<&str>, req: &Request, place: &str) -> Hook {
        let Some(cmd) = cmd else { return Hook(None) };
        const BOTH: &str = r#"PIT_EVENT=open sh -c "$1" </dev/null; read -r x; PIT_EVENT=close exec sh -c "$1" </dev/null"#;
        let child = Command::new("sh")
            .args(["-c", BOTH, "sh", cmd])
            .env("PIT_TITLE", &req.title)
            .env("PIT_ORIGIN", &req.origin)
            .env("PIT_ORIGIN_GUESS", if req.guess { "1" } else { "" })
            .env("PIT_WHERE", place)
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn();
        Hook(child.ok())
    }
}

impl Drop for Hook {
    fn drop(&mut self) {
        // The end of its stdin says the prompt closed.
        if let Some(mut child) = self.0.take() {
            drop(child.stdin.take());
            std::thread::spawn(move || child.wait());
        }
    }
}

#[cfg(test)]
mod tests {
    use std::fs;

    use super::*;

    fn kv(k: &str, v: &str) -> (String, String) {
        (k.into(), v.into())
    }

    #[test]
    fn all_settings() {
        let c = Config::parse(
            "# pit\necho = \"dots\"\norigin = \"full\"\nhook = 'notify-send hi'\n\n[tmux]\nstyle = \"box\" # centred\ninline = 'never'\n",
        );
        assert_eq!((c.echo, c.hook.as_deref(), c.style, c.inline), (Echo::Dots, Some("notify-send hi"), Style::Box, false));
        assert!(c.full_origin);
    }

    #[test]
    fn defaults_when_empty() {
        let c = Config::parse("");
        assert_eq!((c.echo, c.hook, c.style, c.inline), (Echo::Marker, None, Style::Bar, true));
        assert!(!c.full_origin);
        assert_eq!((c.gui, c.gui_first, c.pending), (None, false, false));
    }

    #[test]
    fn gui_and_pending() {
        let c = Config::parse("pending = \"wait\"\n[gui]\npinentry = \"pinentry-qt\"\norder = \"first\"\n");
        assert_eq!((c.gui.as_deref(), c.gui_first, c.pending), (Some("pinentry-qt"), true, true));
        let c = Config::parse("pending = \"later\"\n[gui]\npinentry = ' '\norder = \"sometimes\"\n");
        assert_eq!((c.gui, c.gui_first, c.pending), (None, false, false));
    }

    #[test]
    fn bad_and_unknown_keys_are_skipped() {
        let c = Config::parse(
            "echo = dots\norigin = \"everything\"\nstyle = \"box\"\n[tmux]\nstyle = \"round\"\ninline = \"never\" trailing\n[tmux\ninline = \"never\"\n",
        );
        assert_eq!((c.echo, c.style, c.inline, c.full_origin), (Echo::Marker, Style::Bar, true, false));
    }

    #[test]
    fn later_keys_survive_a_bad_one() {
        let c = Config::parse("echo = \"a\\qb\"\nhook = \"x\"\n[tmux]\nstyle = \"line\"\n");
        assert_eq!((c.echo, c.hook.as_deref(), c.style), (Echo::Marker, Some("x"), Style::Line));
    }

    #[test]
    fn multi_line_strings() {
        let text = "hook = '''\n[ \"$PIT_EVENT\" = open ] &&\n  notify-send x\n'''\nb = \"\"\"\nline \\\n    joined\\t\\u00e9\"\"\"\n[tmux]\nk = \"v\"\n";
        assert_eq!(
            values(text),
            [kv("hook", "[ \"$PIT_EVENT\" = open ] &&\n  notify-send x\n"), kv("b", "line joined\té"), kv("tmux.k", "v")]
        );
    }

    #[test]
    fn single_line_strings_end_on_their_line() {
        assert_eq!(values("a = \"x\ny\"\nb = 'p\nq'\nc = \"ok\"\n"), [kv("c", "ok")]);
    }

    #[test]
    fn escapes() {
        assert_eq!(values(r#"a = "q\"b\\s\n\U0001F600""#), [kv("a", "q\"b\\s\n😀")]);
        assert_eq!(values(r"a = 'C:\no\escape'"), [kv("a", r"C:\no\escape")]);
        assert_eq!(values(r#"a = "\u12""#), [] as [(String, String); 0]);
    }

    #[test]
    fn show() {
        assert_eq!(Config::parse("").show, Show::default());
        let c = Config::parse("show = \"identity, key  bogus\"\n");
        assert_eq!(c.show, Show { origin: false, intro: false, identity: true, key: true, created: false });
        let none = Show { origin: false, intro: false, identity: false, key: false, created: false };
        assert_eq!(Config::parse("show = \"\"").show, none);
        assert_eq!(Config::parse("intro = 'Unlock {identity}'").intro.as_deref(), Some("Unlock {identity}"));
        assert_eq!(Config::parse("intro = ' '").intro, None);
    }

    #[test]
    fn blank_hook_is_no_hook() {
        assert_eq!(Config::parse("hook = '  '").hook, None);
    }

    #[test]
    fn programs_come_only_from_a_file_no_one_else_can_write() {
        use std::os::unix::fs::PermissionsExt;
        let dir = env::temp_dir().join(format!("pit-config-test-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("config.toml");
        fs::write(&path, "echo = \"dots\"\nhook = 'notify-send hi'\n[gui]\npinentry = \"pinentry-qt\"\n").unwrap();
        for (mode, kept) in [(0o644, true), (0o600, true), (0o664, false), (0o646, false), (0o666, false)] {
            fs::set_permissions(&path, fs::Permissions::from_mode(mode)).unwrap();
            let c = Config::read(&path);
            assert_eq!(c.echo, Echo::Dots, "{mode:o}");
            assert_eq!(c.hook.is_some(), kept, "{mode:o}");
            assert_eq!(c.gui.is_some(), kept, "{mode:o}");
        }
        assert_eq!(Config::read(&dir.join("missing.toml")).echo, Echo::Marker);
        let _ = fs::remove_dir_all(&dir);
    }
}
