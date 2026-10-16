//! Naming the key a prompt is about, for descriptions that only give its
//! fingerprint (gpg-agent's ssh prompts, when the key has no comment) or
//! the card it's on (smartcard PIN prompts).

use std::fs;
use std::io::Read;
use std::os::fd::AsRawFd;
use std::path::Path;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use crate::sys;

/// Never hold up the prompt for long just to name the key.
const TIMEOUT: Duration = Duration::from_secs(1);

/// The user ID of the OpenPGP key holding the keygrip in a SETKEYINFO
/// argument ("n/GRIP"), if gpg knows it.
pub fn key_name(keyinfo: &str) -> Option<String> {
    let (_, grip) = keyinfo.split_once('/')?;
    if grip.len() != 40 || !grip.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    let listing = colons(&["--list-keys", "--", &format!("&{grip}")])?;
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
            on_card(&fs::read(e.path()).ok()?, &number).then_some(grip)
        })
        .collect();
    grips.sort();
    grips.iter().find_map(|g| key_name(&format!("n/{g}")))
}

/// Whether a key file is a stub for a key on the card whose serial number
/// holds `number`: its `Token:` line names the card.
fn on_card(key: &[u8], number: &str) -> bool {
    let number = number.to_ascii_uppercase();
    key.split(|&b| b == b'\n').any(|l| {
        l.strip_prefix(b"Token: ")
            .and_then(|t| t.split(|&b| b == b' ').next())
            .is_some_and(|sn| String::from_utf8_lossy(sn).to_ascii_uppercase().contains(&number))
    })
}

/// The card number in a PIN prompt, without spaces.
fn card_number(desc: &str) -> Option<String> {
    let number: String = desc
        .lines()
        // scdaemon puts a unit separator after the label, for alignment.
        .find_map(|l| l.trim().replace('\u{1f}', "").strip_prefix("Number:").map(String::from))?
        .split_whitespace()
        .collect();
    (number.len() >= 8 && number.bytes().all(|b| b.is_ascii_hexdigit())).then_some(number)
}

/// The `--homedir` gpg-agent, our parent, was started with. It needn't be in
/// the environment it gave us, and without it gpg would look in ~/.gnupg.
fn agent_homedir() -> Option<String> {
    homedir_arg(&std::fs::read(format!("/proc/{}/cmdline", std::os::unix::process::parent_id())).ok()?)
}

fn homedir_arg(cmdline: &[u8]) -> Option<String> {
    let args: Vec<String> = cmdline.split(|&b| b == 0).map(|a| String::from_utf8_lossy(a).into_owned()).collect();
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

/// Runs gpg with `--with-colons` and `args`, within TIMEOUT.
fn colons(args: &[&str]) -> Option<Vec<u8>> {
    let mut gpg = Command::new("gpg");
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
    let deadline = Instant::now() + TIMEOUT;
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
/// it: gpg lists the primary first, and only moves a revoked one down.
fn user_id(listing: &str) -> Option<String> {
    listing
        .lines()
        .map(|l| l.split(':').collect::<Vec<_>>())
        .find(|f| f[0] == "uid" && f.get(1) != Some(&"r"))
        .and_then(|f| f.get(9).map(|uid| unescape(uid)))
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

fn is_fingerprint(s: &str) -> bool {
    let hex = |s: &str| s.len() >= 16 && s.bytes().all(|b| b.is_ascii_hexdigit() || b == b':');
    !s.contains(char::is_whitespace)
        && (s.starts_with("SHA256:") || s.strip_prefix("MD5:").is_some_and(hex) || hex(s))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn picks_primary_user_id() {
        let listing = "pub:u:4096:1:401FEB2D1CDE5779:1753544617:::u:::cESCA::::::23::0:\n\
                       uid:r::::1::AAAA::Old <old@x>::::::::::0:\n\
                       uid:u::::1753544617::C0CE::Alice\\x3a Work <a@x>::::::::::0:\n\
                       sub:u:4096:1:D34730BA1575C063:1753544664:1830358800:::::a::::::23:\n";
        assert_eq!(user_id(listing).as_deref(), Some("Alice: Work <a@x>"));
        assert_eq!(user_id("pub:u:4096:1:401FEB2D1CDE5779:1:::u:::cESCA:\n"), None);
        assert_eq!(user_id(""), None);
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
    fn stub_names_its_card() {
        let stub = b"Created: 20241205T193049\nKey: (shadowed-private-key (rsa (n #00D5#)))\n\
                     Token: D2760001240100000006307749640000 OPENPGP.1\n";
        assert!(on_card(stub, "30774964"));
        assert!(on_card(stub, "000630774964"));
        assert!(!on_card(stub, "27425671"));
        assert!(!on_card(b"Key: (private-key (rsa (n #00D5#)))\n", "30774964"));
    }

    #[test]
    fn finds_the_agents_homedir() {
        assert_eq!(homedir_arg(b"gpg-agent\0--homedir\0/h/gpg\0--daemon\0").as_deref(), Some("/h/gpg"));
        assert_eq!(homedir_arg(b"gpg-agent\0--homedir=/h/gpg\0").as_deref(), Some("/h/gpg"));
        assert_eq!(homedir_arg(b"gpg-agent\0--daemon\0"), None);
    }

    #[test]
    fn reads_the_card_number() {
        let desc = "Please unlock the card\n\nNumber\u{1f}: 0006 30774964\nHolder\u{1f}: \nCounter\u{1f}: 12";
        assert_eq!(card_number(desc).as_deref(), Some("000630774964"));
        // As gpg-agent passes on a YubiKey's: its serial in decimal.
        assert_eq!(card_number("Please unlock the card\n\nNumber: 30 774 964\nHolder: \nCounter: 3").as_deref(), Some("30774964"));
        assert_eq!(card_number("Please unlock the card\n\nHolder: x"), None);
        assert_eq!(card_number("Please unlock the card\n\nNumber: 0006 zz"), None);
    }

    #[test]
    fn name_goes_next_to_the_fingerprint() {
        let ssh = "Please enter the passphrase for the ssh key\n  SHA256:xkwLotlAn0n11CS5wQxDJgwquzzGFAcI7qTH0LAY9zM";
        assert_eq!(
            add_name(ssh, "Alice <a@x>"),
            "Please enter the passphrase for the ssh key\n  SHA256:xkwLotlAn0n11CS5wQxDJgwquzzGFAcI7qTH0LAY9zM \"Alice <a@x>\""
        );
        let md5 = "Key\n  MD5:0a:1b:2c:3d:4e:5f:60:71:82:93:a4:b5:c6:d7:e8:f9";
        assert!(add_name(md5, "A").ends_with("f9 \"A\""));
        let grip = "Unlock\nF7B3C2C05034670E19160ED6C2BE2E92C40D05DF";
        assert!(add_name(grip, "A").ends_with("05DF \"A\""));
        assert_eq!(add_name("Unlock the key", "A"), "Unlock the key\n\"A\"");
    }
}
