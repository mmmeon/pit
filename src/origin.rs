//! Who asked: the process gpg-agent names in `OPTION owner`, and the tmux
//! pane it runs in. Read from /proc, so Linux only.

use std::fs;
use std::os::unix::fs::MetadataExt;

use crate::{sys, tmux};

/// Shells, and what sits above them, end the walk up from the requester:
/// the command typed at the prompt is the last process below one.
const STOP: &[&str] = &[
    "sh", "bash", "zsh", "fish", "dash", "ksh", "mksh", "tcsh", "csh", "nu", "elvish", "xonsh",
    "login", "sshd", "systemd", "init",
];

/// Longest command and pane shown; the rest is cut with an ellipsis.
const MAX_CMD: usize = 40;
const MAX_PANE: usize = 24;

pub struct Origin {
    pub cmd: Option<String>,
    /// `session:window.pane`.
    pub pane: Option<String>,
}

impl Origin {
    pub fn label(&self) -> Option<String> {
        match (&self.cmd, &self.pane) {
            (Some(c), Some(p)) => Some(format!("{c} @ {p}")),
            (c, p) => c.clone().or_else(|| p.clone()),
        }
    }
}

/// The pid in `owner=<pid>/<uid> <host>`, if it's our own user's process
/// on this host.
pub fn owner_pid(value: &str) -> Option<u32> {
    let (pid, rest) = value.split_once('/')?;
    let uid = rest.split(' ').next()?;
    if uid.parse() != Ok(sys::uid()) {
        return None;
    }
    if let Some((_, host)) = rest.split_once(' ')
        && Some(host.trim()) != hostname().as_deref()
    {
        return None;
    }
    pid.parse().ok().filter(|&p| p > 1)
}

pub fn find(pid: u32) -> Origin {
    // The agent's pid may mean another process here (another pid namespace,
    // or reused since): never describe anyone else's.
    if !ours(pid) {
        return Origin { cmd: None, pane: None };
    }
    let panes = tmux::pane_pids();
    let chain = ancestors(pid);
    let pane = chain
        .iter()
        .find_map(|p| panes.iter().find(|(pp, _)| pp == p))
        .map(|(_, l)| l.clone());
    let top = chain
        .iter()
        .take_while(|&&p| !panes.iter().any(|(pp, _)| *pp == p))
        .take_while(|&&p| ours(p) && comm(p).is_some_and(|c| !STOP.contains(&c.as_str())))
        .last()
        .or(chain.first());
    Origin {
        cmd: top.and_then(|&p| cmdline(p)),
        pane: pane.map(|p| cut(&p, MAX_PANE)),
    }
}

fn ours(pid: u32) -> bool {
    fs::metadata(format!("/proc/{pid}")).is_ok_and(|m| m.uid() == sys::uid())
}

fn hostname() -> Option<String> {
    Some(
        fs::read_to_string("/proc/sys/kernel/hostname")
            .ok()?
            .trim()
            .to_string(),
    )
}

/// `pid` and its parents, up to but not including init.
fn ancestors(pid: u32) -> Vec<u32> {
    let mut chain = Vec::new();
    let mut p = pid;
    while p > 1 && chain.len() < 64 {
        chain.push(p);
        match ppid(p) {
            Some(pp) => p = pp,
            None => break,
        }
    }
    chain
}

fn ppid(pid: u32) -> Option<u32> {
    let stat = fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    // comm is in parens and may hold spaces; the fields after it don't.
    let rest = &stat[stat.rfind(')')? + 1..];
    rest.split_whitespace().nth(1)?.parse().ok()
}

fn comm(pid: u32) -> Option<String> {
    let c = fs::read_to_string(format!("/proc/{pid}/comm")).ok()?;
    Some(c.trim().trim_start_matches('-').to_string())
}

fn cmdline(pid: u32) -> Option<String> {
    let raw = fs::read(format!("/proc/{pid}/cmdline")).ok()?;
    let mut args = raw
        .split(|&b| b == 0)
        .filter(|a| !a.is_empty())
        .map(String::from_utf8_lossy);
    let argv0 = args.next()?;
    let name = argv0.rsplit('/').next().unwrap_or(&argv0).to_string();
    let line: String = std::iter::once(name)
        .chain(args.map(|a| a.into_owned()))
        .collect::<Vec<_>>()
        .join(" ")
        .chars()
        .filter(|c| !c.is_control())
        .collect();
    Some(cut(&line, MAX_CMD))
}

fn cut(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        return s.to_string();
    }
    s.chars().take(max - 1).chain(['…']).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn owner_must_be_us_on_this_host() {
        let (uid, host) = (sys::uid(), hostname().unwrap());
        assert_eq!(owner_pid(&format!("1234/{uid} some-other-host.invalid")), None);
        assert_eq!(owner_pid(&format!("1234/{uid} {host}")), Some(1234));
        assert_eq!(owner_pid(&format!("1234/{uid}")), Some(1234));
        assert_eq!(owner_pid(&format!("1234/{} {host}", uid + 1)), None);
        assert_eq!(owner_pid(&format!("1/{uid} {host}")), None);
        assert_eq!(owner_pid("junk"), None);
    }

    #[test]
    fn finds_this_process() {
        let me = std::process::id();
        assert!(ancestors(me).starts_with(&[me, std::os::unix::process::parent_id()]));
        assert!(cmdline(me).is_some_and(|c| !c.contains('/')));
        assert!(ours(me));
        // init is root's: never described to anyone else.
        if sys::uid() != 0 {
            assert!(find(1).label().is_none());
        }
    }

    #[test]
    fn long_commands_are_cut() {
        assert_eq!(cut("abcdef", 4), "abc…");
        assert_eq!(cut("abc", 4), "abc");
    }

    #[test]
    fn label_joins_what_and_where() {
        let o = |c: Option<&str>, p: Option<&str>| {
            Origin {
                cmd: c.map(Into::into),
                pane: p.map(Into::into),
            }
            .label()
        };
        assert_eq!(
            o(Some("git commit"), Some("work:2.1")).as_deref(),
            Some("git commit @ work:2.1")
        );
        assert_eq!(o(None, Some("work:2.1")).as_deref(), Some("work:2.1"));
        assert_eq!(o(None, None), None);
    }
}
