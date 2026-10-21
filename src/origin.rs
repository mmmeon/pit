//! Who asked: the process gpg-agent names in `OPTION owner`, and the tmux
//! pane it runs in. Read from /proc, so Linux only.

use std::fs;
use std::io;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};

use crate::{sys, tmux, ui};

/// Shells, and what sits above them, end the walk up from the requester:
/// the command typed at the prompt is the last process below one. A shell
/// running `-c` for another program (git's gpg.program, make, editors) is
/// passed through instead.
const SHELLS: &[&str] = &["sh", "bash", "zsh", "fish", "dash", "ksh", "mksh", "tcsh", "csh", "nu", "elvish", "xonsh"];
const ABOVE: &[&str] = &["login", "sshd", "systemd", "init"];

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

/// Whether `pid` listens on a gpg-agent socket itself: a proxy in front of
/// the agent (yubikey-touch-detector), which the agent then sees as the
/// requester of everything that passes through it, not whoever really asked.
pub fn is_agent_proxy(pid: u32) -> bool {
    let Ok(table) = fs::read_to_string("/proc/net/unix") else { return false };
    listens_on_agent(&agent_sockets(&table), &sockets(pid))
}

/// The inodes of the sockets `pid` has open.
fn sockets(pid: u32) -> Vec<u64> {
    let Ok(fds) = fs::read_dir(format!("/proc/{pid}/fd")) else { return Vec::new() };
    fds.flatten()
        .filter_map(|e| fs::read_link(e.path()).ok()?.to_str()?.strip_prefix("socket:[")?.strip_suffix(']')?.parse().ok())
        .collect()
}

/// The sockets on a gpg-agent socket's path in `table`, from /proc/net/unix:
/// each one's inode, and whether it's listening. The others there are
/// connections accepted on it.
fn agent_sockets(table: &str) -> Vec<(u64, bool)> {
    // Num RefCount Protocol Flags Type St Inode Path; 0x10000 is listening.
    // The path may hold spaces, so its name is taken from the end of the
    // line. Any of the agent's sockets will do: .ssh, .extra and .browser
    // are proxied just the same.
    table
        .lines()
        .skip(1)
        .filter(|l| l.rsplit('/').next().is_some_and(|n| n.starts_with("S.gpg-agent")))
        .filter_map(|l| {
            let f: Vec<&str> = l.split_whitespace().take(7).collect();
            let flags = u32::from_str_radix(f.get(3)?.trim_start_matches("0x"), 16).ok()?;
            Some((f.get(6)?.parse().ok()?, flags & 0x10000 != 0))
        })
        .collect()
}

fn listens_on_agent(agent: &[(u64, bool)], inodes: &[u64]) -> bool {
    agent.iter().any(|(i, listening)| *listening && inodes.contains(i))
}

/// Who asked through the proxy `proxy`: the one process at the other end
/// of the connections it accepted on a gpg-agent socket, followed through
/// any proxy in front of it. With several (clients at once), the one on the
/// terminal `tty`, if only one is.
pub fn proxy_client(proxy: u32, tty: Option<&str>) -> Option<u32> {
    let clients = proxy_clients(proxy);
    if let [c] = clients[..] {
        return Some(c);
    }
    let dev = fs::metadata(tty?).ok()?.rdev();
    let on: Vec<u32> = clients
        .into_iter()
        .filter(|&c| ancestors(c).into_iter().any(|p| stat(p, 4).is_some_and(|t| t as u64 == dev)))
        .collect();
    if let [c] = on[..] { Some(c) } else { None }
}

fn proxy_clients(proxy: u32) -> Vec<u32> {
    let Ok(table) = fs::read_to_string("/proc/net/unix") else { return Vec::new() };
    let Ok(peers) = sys::unix_peers() else { return Vec::new() };
    let agent = agent_sockets(&table);
    let Ok(procs) = fs::read_dir("/proc") else { return Vec::new() };
    let held: Vec<(u32, Vec<u64>)> = procs
        .flatten()
        .filter_map(|e| e.file_name().to_str()?.parse().ok())
        .filter(|&p| ours(p))
        .map(|p| (p, sockets(p)))
        .collect();
    let socks = |p: u32| held.iter().find(|(q, _)| *q == p).map_or(&[][..], |(_, s)| &s[..]);
    // A proxy may connect to itself (yubikey-touch-detector does): never
    // its own client.
    let mut seen = vec![proxy];
    let mut todo = vec![proxy];
    let mut clients = Vec::new();
    while let Some(p) = todo.pop() {
        let accepted: Vec<u64> = agent.iter().filter(|(i, l)| !l && socks(p).contains(i)).map(|(i, _)| *i).collect();
        let ends: Vec<u64> = peers.iter().filter(|(i, _)| accepted.contains(i)).map(|(_, peer)| *peer).collect();
        for &(q, ref s) in &held {
            if seen.contains(&q) || !s.iter().any(|i| ends.contains(i)) {
                continue;
            }
            seen.push(q);
            if listens_on_agent(&agent, s) {
                todo.push(q);
            } else {
                clients.push(q);
            }
        }
    }
    clients
}

pub fn find(pid: u32, full: bool) -> Origin {
    // The kernel gives the agent the requester's pid as seen from its own pid
    // namespace, which is ours too, so it's the right process unless it has
    // exited and the pid was reused: never describe anyone else's.
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
        .take_while(|&&p| ours(p) && comm(p).is_some_and(|c| !stops(&c) || wrapper(p)))
        .filter(|&&p| !wrapper(p))
        .last()
        .or(chain.first());
    Origin {
        cmd: top.and_then(|&p| cmdline(p, full)),
        pane: pane.map(|p| cut(&p, MAX_PANE)),
    }
}

/// Whether `path` is a terminal device: gpg says "not a tty" when it has none.
pub fn is_tty(path: &str) -> bool {
    use std::os::fd::AsRawFd;
    fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOCTTY | libc::O_NONBLOCK)
        .open(path)
        .is_ok_and(|f| unsafe { libc::isatty(f.as_raw_fd()) == 1 })
}

/// Where the requester likely is when it isn't known (it asked through a
/// proxy): the pane on the terminal `tty`. Only that: what runs there may
/// well not be who asked, and its command line may hold secrets.
pub fn find_tty(tty: &str) -> Origin {
    Origin { cmd: None, pane: tmux::pane_on(tty).map(|p| cut(&p, MAX_PANE)) }
}

fn stops(comm: &str) -> bool {
    SHELLS.contains(&comm) || ABOVE.contains(&comm)
}

/// A shell started with `-c` (or `-ec` and the like) to run a command.
fn wrapper(pid: u32) -> bool {
    comm(pid).is_some_and(|c| SHELLS.contains(&c.as_str()))
        && args(pid).iter().skip(1).take_while(|a| a.starts_with('-')).any(|a| !a.starts_with("--") && a.contains('c'))
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
    stat(pid, 1)?.try_into().ok()
}

/// Field `n` of /proc/<pid>/stat, counting from the one after comm: 0 is
/// state, 1 ppid, 2 pgrp, 4 tty_nr, 5 tpgid.
fn stat(pid: u32, n: usize) -> Option<i64> {
    let stat = fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    // comm is in parens and may hold spaces; the fields after it don't.
    let rest = &stat[stat.rfind(')')? + 1..];
    rest.split_whitespace().nth(n)?.parse().ok()
}

/// Whether `pid` runs on the terminal `tty` and is in its foreground: the
/// command typed there is still waiting on it, not the shell prompt or
/// another job.
pub fn in_foreground(pid: u32, tty: &str) -> bool {
    let Ok(dev) = fs::metadata(tty).map(|m| m.rdev()) else { return false };
    // tty_nr and st_rdev share the kernel's encoding of the device number.
    ours(pid)
        && stat(pid, 4).is_some_and(|t| t as u64 == dev)
        && stat(pid, 2).is_some_and(|g| g > 0 && Some(g) == stat(pid, 5))
}

/// Whether something other than the requester `owner` may be reading the
/// terminal `dev`, and would take some of the passphrase (`cat | gpg -d`, or
/// `cat` in the foreground with gpg elsewhere): a process in its foreground
/// job with it as input. If `owner` is in that job, those above it are
/// waiting on it. One we may not look at (sudo) could be reading. One that
/// opens /dev/tty itself isn't seen, but those (pagers, editors) mostly put
/// it in raw mode, which the caller checks. Without an owner, the requester
/// can't be told apart from anyone else, so anything reading counts: better
/// not to ask than to give away some of the passphrase.
pub fn other_reader(dev: u64, owner: Option<u32>) -> bool {
    let Ok(procs) = fs::read_dir("/proc") else { return true };
    let procs: Vec<u32> = procs.flatten().filter_map(|e| e.file_name().to_str()?.parse().ok()).collect();
    // Anything the terminal controls knows its foreground job.
    let Some(fg) = procs
        .iter()
        .filter(|&&p| stat(p, 4).is_some_and(|t| t as u64 == dev))
        .find_map(|&p| stat(p, 5).filter(|&g| g > 0))
    else {
        return false;
    };
    let waiting = match owner {
        Some(owner) if stat(owner, 2) == Some(fg) => ancestors(owner),
        _ => Vec::new(),
    };
    procs
        .into_iter()
        .filter(|p| !waiting.contains(p) && stat(*p, 2) == Some(fg))
        .any(|p| match fs::metadata(format!("/proc/{p}/fd/0")) {
            Ok(m) => m.rdev() == dev,
            Err(e) => e.kind() == io::ErrorKind::PermissionDenied,
        })
}

fn comm(pid: u32) -> Option<String> {
    let c = fs::read_to_string(format!("/proc/{pid}/comm")).ok()?;
    Some(c.trim().trim_start_matches('-').to_string())
}

pub fn args(pid: u32) -> Vec<String> {
    let raw = fs::read(format!("/proc/{pid}/cmdline")).unwrap_or_default();
    raw.split(|&b| b == 0).filter(|a| !a.is_empty()).map(|a| String::from_utf8_lossy(a).into_owned()).collect()
}

fn cmdline(pid: u32, full: bool) -> Option<String> {
    command(&args(pid), full)
}

/// Programs whose first word is a subcommand worth naming (`git commit`).
/// For any other, a first argument could be anything, a password included.
const SUBCOMMANDS: &[&str] = &[
    "git", "gpg", "gpgsm", "gpg-connect-agent", "pass", "gopass", "sops", "chezmoi", "yadm", "git-crypt", "tomb", "cargo",
    "docker", "podman", "kubectl", "helm", "aws", "aws-vault", "gcloud", "az", "gh", "glab", "hg", "svn", "npm", "yarn",
    "pnpm", "pip", "go", "rustup", "nix", "apt", "apt-get", "dnf", "systemctl", "op", "bw", "vault", "keybase", "rclone",
    "borg", "restic", "duplicity",
];

/// The command `args` as shown: with `full`, all of it; otherwise only the
/// program, and the next word if it's a subcommand (`git commit`) of a
/// program known for them. The rest may hold secrets (`mysql -p…`, a URL
/// with a password), and the program is enough to say what asked.
fn command(args: &[String], full: bool) -> Option<String> {
    let (argv0, rest) = args.split_first()?;
    let name = argv0.rsplit('/').next().unwrap_or(argv0);
    let sub = |a: &&String| {
        SUBCOMMANDS.contains(&name)
            && a.len() <= 20
            && a.starts_with(|c: char| c.is_ascii_lowercase())
            && a.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-' || c == '_')
    };
    let rest: Vec<&String> = if full { rest.iter().collect() } else { rest.first().filter(sub).into_iter().collect() };
    let line = std::iter::once(name).chain(rest.into_iter().map(String::as_str)).collect::<Vec<_>>().join(" ");
    Some(cut(&ui::clean(&line, false), MAX_CMD))
}

/// `s` in at most `max` columns, cut with an ellipsis.
fn cut(s: &str, max: usize) -> String {
    if ui::width(s) <= max {
        return s.to_string();
    }
    format!("{}…", ui::split_at_width(s, max - 1).0)
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
        assert!(cmdline(me, true).is_some_and(|c| !c.contains('/')));
        assert!(ours(me));
        // init is root's: never described to anyone else.
        if sys::uid() != 0 {
            assert!(find(1, true).label().is_none());
        }
    }

    #[test]
    fn ordinary_processes_are_not_agent_proxies() {
        assert!(!is_agent_proxy(std::process::id()));
        assert!(!is_agent_proxy(u32::MAX));
    }

    #[test]
    fn agent_sockets_are_found_by_name_while_listening() {
        let table = "\
Num       RefCount Protocol Flags    Type St Inode Path
0000000000000000: 00000002 00000000 00010000 0001 01 101 /run/user/1000/gnupg/S.gpg-agent
0000000000000000: 00000003 00000000 00000000 0001 03 102 /run/user/1000/gnupg/S.gpg-agent
0000000000000000: 00000002 00000000 00010000 0001 01 103 /home/a b/.gnupg/S.gpg-agent.ssh
0000000000000000: 00000002 00000000 00010000 0001 01 104 /tmp/S.gpg-agent/other
0000000000000000: 00000002 00000000 00010000 0001 01 105 @S.gpg-agent
0000000000000000: 00000002 00000000 00010000 0001 01 106
";
        // Only the socket's own name counts, the path may hold a space, and
        // abstract or unnamed sockets aren't the agent's. 102 was accepted
        // on it: a connection, not a listener.
        let agent = agent_sockets(table);
        assert_eq!(agent, [(101, true), (102, false), (103, true)]);
        let has = |i: u64| listens_on_agent(&agent, &[i]);
        assert!(has(101) && has(103));
        assert!(!has(102) && !has(104) && !has(10));
        assert!(!listens_on_agent(&agent, &[]));
    }

    #[test]
    fn proxy_without_clients_names_no_one() {
        assert_eq!(proxy_client(std::process::id(), None), None);
        assert_eq!(proxy_client(u32::MAX, Some("/dev/null")), None);
    }

    #[test]
    fn command_is_the_program_and_subcommand() {
        let c = |args: &[&str], full| command(&args.iter().map(|a| a.to_string()).collect::<Vec<_>>(), full);
        assert_eq!(c(&["/usr/bin/git", "commit", "-S", "-m", "fix"], false).as_deref(), Some("git commit"));
        assert_eq!(c(&["/usr/bin/git", "commit", "-S", "-m", "fix"], true).as_deref(), Some("git commit -S -m fix"));
        // What could be a secret, or lead to one, is left out.
        assert_eq!(c(&["mysql", "-phunter2"], false).as_deref(), Some("mysql"));
        assert_eq!(c(&["psql", "postgres://u:pw@h/db"], false).as_deref(), Some("psql"));
        assert_eq!(c(&["vault", "login", "s.AbC123"], false).as_deref(), Some("vault login"));
        assert_eq!(c(&["tool", "Hunter2"], false).as_deref(), Some("tool"));
        assert_eq!(c(&["sleep", "999"], false).as_deref(), Some("sleep"));
        assert_eq!(c(&["git", "a-very-long-word-that-is-no-subcommand"], false).as_deref(), Some("git"));
        // A word that could be a subcommand, of a program not known for them.
        assert_eq!(c(&["tool", "hunter2"], false).as_deref(), Some("tool"));
        assert_eq!(c(&["/usr/bin/pass", "show", "mail"], false).as_deref(), Some("pass show"));
        assert_eq!(c(&[], false), None);
    }

    #[test]
    fn only_terminals_are_ttys() {
        assert!(!is_tty("not a tty"));
        assert!(!is_tty("/nonexistent"));
        assert!(!is_tty("/dev/null"));
    }

    #[test]
    fn foreground_needs_the_same_terminal() {
        let me = std::process::id();
        assert!(!in_foreground(me, "/dev/null"));
        assert!(!in_foreground(me, "/nonexistent"));
    }

    #[test]
    fn long_commands_are_cut() {
        assert_eq!(cut("abcdef", 4), "abc…");
        assert_eq!(cut("abc", 4), "abc");
        assert_eq!(cut("漢字漢字", 5), "漢字…");
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
