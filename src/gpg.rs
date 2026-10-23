//! Naming the key a prompt is about, for descriptions that only give its
//! fingerprint (gpg-agent's ssh prompts, when the key has no comment) or
//! the card it's on (smartcard PIN prompts).

use std::fs::{self, File};
use std::io::Read;
use std::os::fd::AsRawFd;
use std::path::Path;
use std::process::{Command, Stdio};
use std::sync::OnceLock;
use std::time::{Duration, Instant};

use crate::config::Show;
use crate::ui::{self, Secret};
use crate::{origin, sys};

/// Never hold up the prompt for long just to name the key.
const TIMEOUT: Duration = Duration::from_secs(1);

/// Most of a key file looked at: stubs are well under this.
const MAX_KEY_FILE: usize = 64 * 1024;

/// The user ID of the OpenPGP key holding the keygrip in a SETKEYINFO
/// argument ("n/GRIP"), if gpg knows it.
pub fn key_name(keyinfo: &str) -> Option<String> {
    let (_, grip) = keyinfo.split_once('/')?;
    grip_name(grip, Instant::now() + TIMEOUT)
}

/// The user ID of the OpenPGP key holding `grip`, if gpg says by `deadline`.
fn grip_name(grip: &str, deadline: Instant) -> Option<String> {
    if grip.len() != 40 || !grip.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    let listing = colons(&["--list-keys", "--", &format!("&{grip}")], deadline)?;
    user_id(&String::from_utf8_lossy(&listing))
}

/// The user ID of the OpenPGP key with subkeys on the card a PIN prompt
/// names ("Number: 30 774 964"). gpg-agent sends no keyinfo for those, and
/// is busy with the card meanwhile, so asking gpg for secret keys would
/// stall: read the agent's key stubs instead, which name their card.
pub fn card_name(desc: &str) -> Option<String> {
    let number = card_number(desc)?;
    let dir = Path::new(&homedir()?).join("private-keys-v1.d");
    let mut grips: Vec<String> = fs::read_dir(dir)
        .ok()?
        .flatten()
        .filter_map(|e| {
            let grip = e.file_name().to_str()?.strip_suffix(".key")?.to_string();
            let serial = read_token(&e.path())?;
            on_card(&serial, &number).then_some(grip)
        })
        .collect();
    grips.sort();
    // A card holds a few keys: TIMEOUT is for them all.
    let deadline = Instant::now() + TIMEOUT;
    grips.iter().find_map(|g| grip_name(g, deadline))
}

/// The card serial in the key file at `path`, if it's a stub for a key on
/// a card. Read a little at a time, no further than it takes to tell, and
/// wiped when done: it may be a real key, and not even protected.
fn read_token(path: &Path) -> Option<String> {
    let mut file = File::open(path).ok()?;
    let mut buf = Secret::with_capacity(MAX_KEY_FILE);
    let mut chunk = [0u8; 256];
    while buf.0.len() < MAX_KEY_FILE {
        let n = file.read(&mut chunk).ok()?;
        buf.extend(&chunk[..n]);
        chunk.fill(0);
        if let Some(settled) = token(&buf.0, n == 0) {
            return settled;
        }
        if n == 0 {
            break;
        }
    }
    None
}

/// The card serial number in a key file's `Token:` line, if it's a stub
/// for a key on a card: Some(Some(serial)). Some(None) once it's settled
/// that there's none, which a real key's `Key:` line says at once: no need
/// to look further. None while the `key` read so far hasn't said, unless
/// it's `all` of the file.
fn token(key: &[u8], all: bool) -> Option<Option<String>> {
    const SHADOWED: &[u8] = b"Key: (shadowed-private-key";
    let mut lines: Vec<&[u8]> = key.split(|&b| b == b'\n').collect();
    // The last piece is a line only at the end of the file.
    let tail = if all { None } else { lines.pop() };
    for line in lines {
        if let Some(t) = line.strip_prefix(b"Token: ") {
            let serial = t.split(|&b| b == b' ').next().unwrap_or_default();
            return Some(std::str::from_utf8(serial).ok().filter(|s| !s.is_empty()).map(String::from));
        }
        if line.starts_with(b"Key: ") && !line.starts_with(SHADOWED) {
            return Some(None);
        }
    }
    // A real key's `Key:` line is long: the start of it is enough.
    match tail {
        Some(t) if t.starts_with(b"Key: ") && t.len() >= SHADOWED.len() && !t.starts_with(SHADOWED) => Some(None),
        _ if all => Some(None),
        _ => None,
    }
}

/// Whether the OpenPGP card with application ID `serial` (D27600012401,
/// version, 4 digits of maker, 8 of serial, 0000) is the one a prompt
/// numbers: by its serial alone, or with the maker in front. A YubiKey's
/// is shown as a decimal number, which may be only 7 digits long.
fn on_card(serial: &str, number: &str) -> bool {
    let serial = serial.to_ascii_uppercase();
    let number = number.to_ascii_uppercase();
    // ASCII, so the slices below fall on characters.
    serial.is_ascii()
        && serial.len() == 32
        && serial.starts_with("D27600012401")
        && match number.len() {
            7 | 8 => serial[20..28] == format!("{number:0>8}"),
            12 => serial[16..28] == number,
            _ => false,
        }
}

/// The card number in a PIN prompt, without spaces.
fn card_number(desc: &str) -> Option<String> {
    let number: String = desc
        .lines()
        // scdaemon puts a unit separator after the label, for alignment.
        .find_map(|l| l.trim().replace('\u{1f}', "").strip_prefix("Number:").map(String::from))?
        .split_whitespace()
        .collect();
    (!number.is_empty() && number.bytes().all(|b| b.is_ascii_hexdigit())).then_some(number)
}

/// The `--homedir` gpg-agent, our parent, was started with. It needn't be in
/// the environment it gave us, and without it gpg would look in ~/.gnupg.
fn agent_homedir() -> Option<String> {
    static DIR: OnceLock<Option<String>> = OnceLock::new();
    DIR.get_or_init(|| homedir_arg(&origin::args(std::os::unix::process::parent_id()))).clone()
}

fn homedir_arg(args: &[String]) -> Option<String> {
    args.iter().enumerate().find_map(|(i, a)| match a.strip_prefix("--homedir") {
        Some("") => args.get(i + 1).cloned(),
        Some(v) => v.strip_prefix('=').map(String::from),
        None => None,
    })
}

/// gpg's home: gpg-agent's, else GNUPGHOME, else ~/.gnupg.
fn homedir() -> Option<String> {
    agent_homedir()
        .or_else(|| std::env::var("GNUPGHOME").ok())
        .or_else(|| std::env::var("HOME").ok().map(|h| format!("{h}/.gnupg")))
}

/// Runs gpg with `--with-colons` and `args`, if it's done by `deadline`.
fn colons(args: &[&str], deadline: Instant) -> Option<Vec<u8>> {
    if Instant::now() >= deadline {
        return None;
    }
    let mut gpg = Command::new("gpg");
    // It finds GNUPGHOME and ~/.gnupg itself. Spelt out, ~/.gnupg can look
    // like another home to it, with its own sockets and daemons.
    if let Some(dir) = agent_homedir() {
        gpg.arg("--homedir").arg(dir);
    }
    let mut child = gpg
        .args(["--batch", "--no-auto-check-trustdb", "--with-colons"])
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .ok()?;
    let mut out = child.stdout.take()?;
    let (mut buf, mut chunk) = (Vec::new(), [0; 4096]);
    let done = loop {
        let Some(left) = deadline.checked_duration_since(Instant::now()) else { break false };
        match sys::poll(&[out.as_raw_fd()], Some(left)) {
            Ok(r) if r[0] != 0 => {}
            _ => break false,
        }
        match out.read(&mut chunk) {
            Ok(0) => break true,
            Ok(n) => buf.extend_from_slice(&chunk[..n]),
            Err(_) => break false,
        }
    };
    if !done {
        let _ = child.kill();
    }
    let ok = child.wait().is_ok_and(|s| s.success());
    (done && ok).then_some(buf)
}

/// The primary user ID from a `--with-colons` listing. There's no field for
/// it: gpg lists the primary first, and only moves a revoked one down. As
/// it may be shown, with nothing in it that would do more than show.
fn user_id(listing: &str) -> Option<String> {
    listing
        .lines()
        .map(|l| l.split(':').collect::<Vec<_>>())
        .find(|f| f[0] == "uid" && f.get(1) != Some(&"r"))
        .and_then(|f| f.get(9).map(|uid| ui::clean(&unescape(uid), false)))
        .filter(|uid| !uid.is_empty())
}

/// Undoes gpg's `\xNN` escapes in colon listings.
fn unescape(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        let hex = b.get(i + 2..i + 4).and_then(|h| std::str::from_utf8(h).ok());
        match (b[i], b.get(i + 1), hex.and_then(|h| u8::from_str_radix(h, 16).ok())) {
            (b'\\', Some(b'x'), Some(v)) => {
                out.push(v);
                i += 4;
            }
            (c, ..) => {
                out.push(c);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// Puts `name` next to the fingerprint in `desc`, or on a line of its own.
/// It's quoted the way gpg quotes user IDs, so the line style picks it up.
pub fn add_name(desc: &str, name: &str) -> String {
    let mut lines: Vec<String> = desc.lines().map(String::from).collect();
    match lines.iter_mut().find(|l| is_fingerprint(l.trim())) {
        Some(line) => line.push_str(&format!(" \"{name}\"")),
        None => lines.push(format!("\"{name}\"")),
    }
    lines.join("\n")
}

#[derive(Clone, Copy, PartialEq)]
enum Part {
    Note,
    Intro,
    Identity,
    Key,
    Created,
    Other,
}

fn words(l: &str) -> impl Iterator<Item = &str> {
    l.split(|c: char| c.is_whitespace() || "(),.;".contains(c)).filter(|w| !w.is_empty())
}

/// A YYYY-MM-DD date, as gpg writes them in any language.
fn date(w: &str) -> bool {
    let b = w.as_bytes();
    b.len() == 10 && b[4] == b'-' && b[7] == b'-' && b.iter().enumerate().all(|(i, c)| i == 4 || i == 7 || c.is_ascii_digit())
}

/// What each line of `desc` is. Told apart by their shape, which holds in
/// any language: the user ID is quoted, the key line names a 16-digit ID,
/// the created line has a date, and the intro is what comes before the user
/// ID. gpg-agent's note is ahead of a blank line.
fn parts(desc: &str) -> Vec<(Part, &str)> {
    let lines: Vec<&str> = desc.lines().collect();
    // The note, if any: up to the first blank line, with more after it.
    let body = match lines.iter().position(|l| l.trim().is_empty()) {
        Some(i) if lines[..i].iter().any(|l| !l.trim().is_empty()) && lines[i..].iter().any(|l| !l.trim().is_empty()) => i,
        _ => 0,
    };
    let identity = lines[body..].iter().position(|l| l.trim().starts_with('"')).map(|i| i + body);
    let part = |i: usize, t: &str| {
        if i < body {
            Part::Note
        } else if t.is_empty() {
            Part::Other
        } else if Some(i) == identity {
            Part::Identity
        } else if identity.is_some_and(|id| i < id) {
            Part::Intro
        } else if words(t).any(date) {
            Part::Created
        } else if words(t).any(|w| w.len() == 16 && w.bytes().all(|b| b.is_ascii_hexdigit())) {
            Part::Key
        } else {
            Part::Other
        }
    };
    lines.iter().enumerate().map(|(i, l)| (part(i, l.trim()), *l)).collect()
}

/// `desc` without the parts of gpg's description `show` leaves out, and
/// with its intro replaced by `intro`, if given, where {identity}, {key}
/// and {created} stand for those parts, and {date} for the created date. gpg-agent's note, and anything not
/// one of these parts, stays.
pub fn trim_desc(desc: &str, show: &Show, intro: Option<&str>) -> String {
    let parts = parts(desc);
    let of = |p: Part| parts.iter().find(|(q, _)| *q == p).map_or("", |(_, l)| l.trim());
    let mut out: Vec<String> = Vec::new();
    let mut intro_done = false;
    for &(part, line) in &parts {
        let shown = match part {
            Part::Note | Part::Other => true,
            Part::Intro => show.intro,
            Part::Identity => show.identity,
            Part::Key => show.key,
            Part::Created => show.created,
        };
        match (part, intro) {
            _ if !shown => {}
            (Part::Intro, Some(t)) => {
                if !intro_done {
                    out.push(
                        t.replace("{identity}", of(Part::Identity).trim_matches('"'))
                            .replace("{key}", of(Part::Key).trim_end_matches(','))
                            .replace("{created}", of(Part::Created).trim_end_matches('.'))
                            .replace("{date}", words(of(Part::Created)).find(|w| date(w)).unwrap_or("")),
                    );
                    intro_done = true;
                }
            }
            _ => out.push(line.to_string()),
        }
    }
    out.join("\n")
}

fn is_fingerprint(s: &str) -> bool {
    let hex = |s: &str| s.len() >= 16 && s.bytes().all(|b| b.is_ascii_hexdigit() || b == b':');
    !s.contains(char::is_whitespace)
        && (s.starts_with("SHA256:") || s.strip_prefix("MD5:").is_some_and(hex) || hex(s))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn trims_desc() {
        let desc = "Please enter the passphrase to unlock the OpenPGP secret key:\n\"User <a@x>\"\n255-bit EDDSA key, ID 3AA5C34371567BD2,\ncreated 2024-03-01.\n";
        let all = Show::default();
        let only = |f: fn(&mut Show)| {
            let mut s = Show { origin: false, intro: false, identity: false, key: false, created: false };
            f(&mut s);
            trim_desc(desc, &s, None)
        };
        assert_eq!(trim_desc(desc, &all, None), desc.trim_end());
        assert_eq!(only(|s| s.intro = true), "Please enter the passphrase to unlock the OpenPGP secret key:");
        assert_eq!(only(|s| s.identity = true), "\"User <a@x>\"");
        assert_eq!(only(|s| s.key = true), "255-bit EDDSA key, ID 3AA5C34371567BD2,");
        assert_eq!(only(|s| s.created = true), "created 2024-03-01.");
        // gpg-agent's note on a remote request, and what isn't known, stay.
        let remote = format!("Note: Request from a remote site.\n\n{desc}");
        assert_eq!(trim_desc(&remote, &Show { identity: false, ..all }, None).lines().next(), Some("Note: Request from a remote site."));
        assert_eq!(trim_desc("No card found.", &Show { intro: false, ..all }, None), "No card found.");
    }

    #[test]
    fn replaces_intro() {
        let desc = "Please enter the passphrase to unlock\nthe OpenPGP secret key:\n\"User <a@x>\"\n255-bit EDDSA key, ID 3AA5C34371567BD2,\ncreated 2024-03-01.";
        let show = Show { identity: false, key: false, created: false, ..Show::default() };
        let t = "Unlock {identity} ({key}, {created}) {other}";
        assert_eq!(
            trim_desc(desc, &show, Some(t)),
            "Unlock User <a@x> (255-bit EDDSA key, ID 3AA5C34371567BD2, created 2024-03-01) {other}"
        );
        assert_eq!(trim_desc(desc, &Show { intro: false, ..show }, Some(t)), "");
        assert_eq!(trim_desc(desc, &show, Some("Unlock (Created {date})")), "Unlock (Created 2024-03-01)");
        // No user ID, no intro to replace.
        assert_eq!(trim_desc("Enter the PIN", &show, Some("x")), "Enter the PIN");
    }

    #[test]
    fn picks_primary_user_id() {
        let listing = "pub:u:4096:1:401FEB2D1CDE5779:1753544617:::u:::cESCA::::::23::0:\n\
                       uid:r::::1::AAAA::Old <old@x>::::::::::0:\n\
                       uid:u::::1753544617::C0CE::User\\x3a Work <a@x>::::::::::0:\n\
                       sub:u:4096:1:D34730BA1575C063:1753544664:1830358800:::::a::::::23:\n";
        assert_eq!(user_id(listing).as_deref(), Some("User: Work <a@x>"));
        assert_eq!(user_id("pub:u:4096:1:401FEB2D1CDE5779:1:::u:::cESCA:\n"), None);
        assert_eq!(user_id(""), None);
        // A user ID goes into the prompt's text: nothing in it may draw.
        assert_eq!(user_id("uid:u::::1::C0CE::Eve\\x1b[2K\\x07 <e@x>::::::::::0:\n").as_deref(), Some("Eve[2K <e@x>"));
    }

    #[test]
    fn unescapes_colon_listing() {
        assert_eq!(unescape("a\\x3ab\\x5c\\xc3\\xa9"), "a:b\\é");
        assert_eq!(unescape("trailing\\x3"), "trailing\\x3");
    }

    #[test]
    fn rejects_bad_keyinfo() {
        assert_eq!(key_name("n/ABCDEF"), None);
        assert_eq!(key_name("--clear"), None);
        assert_eq!(key_name(&format!("n/{}", "Z".repeat(40))), None);
    }

    #[test]
    fn reads_only_stubs() {
        let stub = "Created: 20241205T193049\nKey: (shadowed-private-key (rsa (n #00D5#)))\n\
                    Token: D2760001240100000006307749640000 OPENPGP.1\n";
        let serial = Some(Some("D2760001240100000006307749640000".to_string()));
        assert_eq!(token(stub.as_bytes(), false), serial);
        assert_eq!(token(stub.as_bytes(), true), serial);
        assert_eq!(token("Key: (protected-private-key (rsa))\nToken: D276 X\n".as_bytes(), false), Some(None));
        assert_eq!(token("Key: (private-key (rsa))\n".as_bytes(), true), Some(None));
        // Cut short: a stub isn't settled until its Token line is whole, a
        // real key as soon as its Key line has begun.
        assert_eq!(token(&stub.as_bytes()[..60], false), None);
        assert_eq!(token("Created: 1\nToken: D276".as_bytes(), false), None);
        assert_eq!(token("Created: 1\nToken: D276".as_bytes(), true), Some(Some("D276".into())));
        assert_eq!(token("Created: 1\nKey: (protected-private-key (rsa (n #00".as_bytes(), false), Some(None));
        assert_eq!(token("Created: 1\nKey: (sh".as_bytes(), false), None);
        assert_eq!(token("Created: 1\n".as_bytes(), true), Some(None));
        assert_eq!(token("Token: \n".as_bytes(), false), Some(None));
    }

    #[test]
    fn reads_no_more_of_a_key_file_than_it_takes() {
        let dir = std::env::temp_dir().join(format!("pit-gpg-test-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        let stub = dir.join("stub.key");
        fs::write(&stub, "Created: 1\nKey: (shadowed-private-key (rsa (n #00D5#)))\nToken: D2760001240100000006307749640000 OPENPGP.1\n").unwrap();
        assert_eq!(read_token(&stub).as_deref(), Some("D2760001240100000006307749640000"));
        let real = dir.join("real.key");
        fs::write(&real, format!("Created: 1\nKey: (protected-private-key (rsa (n #{}#)))\n", "AB".repeat(100_000))).unwrap();
        assert_eq!(read_token(&real), None);
        let big = dir.join("big.key");
        fs::write(&big, format!("Created: 1\n{}Token: X\n", "Comment: x\n".repeat(10_000))).unwrap();
        assert_eq!(read_token(&big), None, "stops at MAX_KEY_FILE");
        assert_eq!(read_token(&dir.join("missing.key")), None);
        // Through a fifo whose writer stays open after the head: reading any
        // further than the head would wait on it.
        let heads = [
            ("stub", "Created: 1\nKey: (shadowed-private-key (rsa (n #00D5#)))\nToken: D276000124010000000630774964 X\n", Some("D276000124010000000630774964")),
            ("real", "Created: 1\nKey: (protected-private-key (rsa (n #00", None),
        ];
        for (name, head, want) in heads {
            let fifo = dir.join(format!("{name}-fifo.key"));
            sys::mkfifo(&fifo).unwrap();
            let writer = fifo.clone();
            std::thread::spawn(move || {
                let mut w = File::options().write(true).open(writer).unwrap();
                std::io::Write::write_all(&mut w, head.as_bytes()).unwrap();
                std::thread::sleep(Duration::from_secs(5));
            });
            let start = Instant::now();
            assert_eq!(read_token(&fifo).as_deref(), want, "{name}");
            assert!(start.elapsed() < Duration::from_secs(2), "{name}: read past the head");
        }
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn matches_only_the_cards_serial() {
        let sn = "D2760001240100000006307749640000";
        assert!(on_card(sn, "30774964"));
        assert!(on_card(sn, "000630774964"));
        assert!(on_card(&sn.to_lowercase(), "30774964"));
        assert!(on_card("D2760001240103040006041234560000", "4123456"));
        // Across maker and serial, or the wrong card.
        assert!(!on_card(sn, "06307749"));
        assert!(!on_card(sn, "27425671"));
        assert!(!on_card(sn, "3077496"));
        assert!(!on_card(sn, "077496"));
        assert!(!on_card("D2760001240100000006307749", "30774964"));
        // 32 bytes, but not all characters: no panic slicing it.
        assert!(!on_card("D27600012401000é0006307749640000", "30774964"));
    }

    #[test]
    fn finds_the_agents_homedir() {
        let args = |a: &[&str]| a.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        assert_eq!(homedir_arg(&args(&["gpg-agent", "--homedir", "/h/gpg", "--daemon"])).as_deref(), Some("/h/gpg"));
        assert_eq!(homedir_arg(&args(&["gpg-agent", "--homedir=/h/gpg"])).as_deref(), Some("/h/gpg"));
        assert_eq!(homedir_arg(&args(&["gpg-agent", "--homedirx"])), None);
        assert_eq!(homedir_arg(&args(&["gpg-agent", "--daemon"])), None);
    }

    #[test]
    fn reads_the_card_number() {
        let desc = "Please unlock the card\n\nNumber\u{1f}: 0006 30774964\nHolder\u{1f}: \nCounter\u{1f}: 12";
        assert_eq!(card_number(desc).as_deref(), Some("000630774964"));
        // As gpg-agent passes on a YubiKey's: its serial in decimal.
        assert_eq!(card_number("Please unlock the card\n\nNumber: 30 774 964\nHolder: \nCounter: 3").as_deref(), Some("30774964"));
        assert_eq!(card_number("Please unlock the card\n\nNumber: 4 123 456\nHolder: ").as_deref(), Some("4123456"));
        assert_eq!(card_number("Please unlock the card\n\nHolder: x"), None);
        assert_eq!(card_number("Please unlock the card\n\nNumber: 0006 zz"), None);
    }

    #[test]
    fn name_goes_next_to_the_fingerprint() {
        let ssh = "Please enter the passphrase for the ssh key\n  SHA256:xkwLotlAn0n11CS5wQxDJgwquzzGFAcI7qTH0LAY9zM";
        assert_eq!(
            add_name(ssh, "User <a@x>"),
            "Please enter the passphrase for the ssh key\n  SHA256:xkwLotlAn0n11CS5wQxDJgwquzzGFAcI7qTH0LAY9zM \"User <a@x>\""
        );
        let md5 = "Key\n  MD5:0a:1b:2c:3d:4e:5f:60:71:82:93:a4:b5:c6:d7:e8:f9";
        assert!(add_name(md5, "A").ends_with("f9 \"A\""));
        let grip = "Unlock\nF7B3C2C05034670E19160ED6C2BE2E92C40D05DF";
        assert!(add_name(grip, "A").ends_with("05DF \"A\""));
        assert_eq!(add_name("Unlock the key", "A"), "Unlock the key\n\"A\"");
    }
}
