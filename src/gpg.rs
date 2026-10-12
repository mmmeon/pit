//! Naming the key a prompt is about, for descriptions that only give its
//! fingerprint (gpg-agent's ssh prompts, when the key has no comment).

use std::io::Read;
use std::os::fd::AsRawFd;
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
    let listing = list_key(grip)?;
    user_id(&String::from_utf8_lossy(&listing))
}

fn list_key(grip: &str) -> Option<Vec<u8>> {
    let mut child = Command::new("gpg")
        .args(["--batch", "--no-auto-check-trustdb", "--with-colons", "--list-keys", "--"])
        .arg(format!("&{grip}"))
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
