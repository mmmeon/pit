//! Thin wrappers over the libc calls std doesn't cover.

use std::env;
use std::ffi::{CString, OsStr};
use std::fs;
use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{DirBuilderExt, MetadataExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicI32, Ordering};
use std::time::Duration;

fn cstr(path: &Path) -> io::Result<CString> {
    CString::new(path.as_os_str().as_bytes()).map_err(io::Error::other)
}

fn check(ret: libc::c_int) -> io::Result<libc::c_int> {
    if ret < 0 { Err(io::Error::last_os_error()) } else { Ok(ret) }
}

/// A directory of our own for what passes between our processes, made
/// private to us if it isn't there: under XDG_RUNTIME_DIR, which is in
/// memory and ours alone. Each side must find the same one from its own
/// environment: gpg-agent's may lack the variable, so systemd's default
/// stands in. Only without either does it go under the temp directory.
pub fn runtime_dir() -> io::Result<PathBuf> {
    let uid = uid();
    let base = env::var_os("XDG_RUNTIME_DIR")
        .map(PathBuf::from)
        .filter(|d| d.is_absolute())
        .or_else(|| Some(PathBuf::from(format!("/run/user/{uid}"))).filter(|d| d.is_dir()));
    let dir = match base {
        Some(base) => base.join("pit"),
        None => env::temp_dir().join(format!("pit-{uid}")),
    };
    match fs::DirBuilder::new().mode(0o700).create(&dir) {
        Err(e) if e.kind() != io::ErrorKind::AlreadyExists => return Err(e),
        _ => {}
    }
    // Under /tmp someone else could have made it first.
    let m = fs::symlink_metadata(&dir)?;
    if !m.is_dir() || m.uid() != uid || m.mode() & 0o077 != 0 {
        return Err(io::Error::other(format!("{} isn't a private directory of ours", dir.display())));
    }
    Ok(dir)
}

/// A fresh private directory under `base`.
pub fn mkdtemp(base: &Path) -> io::Result<PathBuf> {
    let template = base.join("pit.XXXXXX");
    let mut buf = cstr(&template)?.into_bytes_with_nul();
    if unsafe { libc::mkdtemp(buf.as_mut_ptr().cast()) }.is_null() {
        return Err(io::Error::last_os_error());
    }
    buf.pop();
    Ok(PathBuf::from(OsStr::from_bytes(&buf)))
}

pub fn mkfifo(path: &Path) -> io::Result<()> {
    check(unsafe { libc::mkfifo(cstr(path)?.as_ptr(), 0o600) }).map(drop)
}

pub fn set_nonblocking(fd: RawFd, on: bool) -> io::Result<()> {
    let flags = check(unsafe { libc::fcntl(fd, libc::F_GETFL) })?;
    let flags = if on { flags | libc::O_NONBLOCK } else { flags & !libc::O_NONBLOCK };
    check(unsafe { libc::fcntl(fd, libc::F_SETFL, flags) }).map(drop)
}

/// Waits until one of `fds` is readable or hung up; returns each one's revents.
pub fn poll(fds: &[RawFd], timeout: Option<Duration>) -> io::Result<Vec<i16>> {
    let mut pfds: Vec<_> = fds
        .iter()
        .map(|&fd| libc::pollfd { fd, events: libc::POLLIN, revents: 0 })
        .collect();
    let ms = timeout.map_or(-1, |t| t.as_millis().min(i32::MAX as u128) as libc::c_int);
    loop {
        match check(unsafe { libc::poll(pfds.as_mut_ptr(), pfds.len() as _, ms) }) {
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            r => r?,
        };
        return Ok(pfds.iter().map(|p| p.revents).collect());
    }
}

/// Terminal size as (columns, rows).
pub fn winsize(fd: RawFd) -> Option<(usize, usize)> {
    let mut ws: libc::winsize = unsafe { std::mem::zeroed() };
    let ok = unsafe { libc::ioctl(fd, libc::TIOCGWINSZ, &mut ws) } == 0 && ws.ws_col > 0;
    ok.then_some((ws.ws_col as usize, ws.ws_row as usize))
}

/// Whether the terminal on `fd` reads whole lines, as a shell leaves it for
/// the command it runs. A full-screen program turns that off to take keys
/// one at a time, and then owns the screen.
pub fn line_mode(fd: RawFd) -> bool {
    let mut t: libc::termios = unsafe { std::mem::zeroed() };
    unsafe { libc::tcgetattr(fd, &mut t) == 0 && t.c_lflag & libc::ICANON != 0 }
}

/// Each connected Unix socket's inode, with its peer's: what `ss -x` shows,
/// from the kernel's socket diagnostics, which needs no privileges.
pub fn unix_peers() -> io::Result<Vec<(u64, u64)>> {
    // From linux/sock_diag.h and linux/unix_diag.h.
    const SOCK_DIAG_BY_FAMILY: u16 = 20;
    const UDIAG_SHOW_PEER: u32 = 4;
    const UNIX_DIAG_PEER: u16 = 2;
    #[repr(C)]
    struct Request {
        nlh: libc::nlmsghdr,
        family: u8,
        protocol: u8,
        pad: u16,
        states: u32,
        ino: u32,
        show: u32,
        cookie: [u32; 2],
    }
    let fd = check(unsafe { libc::socket(libc::AF_NETLINK, libc::SOCK_DGRAM | libc::SOCK_CLOEXEC, libc::NETLINK_SOCK_DIAG) })?;
    let fd = unsafe { OwnedFd::from_raw_fd(fd) };
    let req = Request {
        nlh: libc::nlmsghdr {
            nlmsg_len: size_of::<Request>() as u32,
            nlmsg_type: SOCK_DIAG_BY_FAMILY,
            nlmsg_flags: (libc::NLM_F_REQUEST | libc::NLM_F_DUMP) as u16,
            nlmsg_seq: 1,
            nlmsg_pid: 0,
        },
        family: libc::AF_UNIX as u8,
        protocol: 0,
        pad: 0,
        states: !0,
        ino: 0,
        show: UDIAG_SHOW_PEER,
        cookie: [!0; 2],
    };
    let mut kernel: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
    kernel.nl_family = libc::AF_NETLINK as _;
    let sent = unsafe {
        libc::sendto(
            fd.as_raw_fd(),
            (&raw const req).cast(),
            size_of::<Request>(),
            0,
            (&raw const kernel).cast(),
            size_of::<libc::sockaddr_nl>() as _,
        )
    };
    if sent < 0 {
        return Err(io::Error::last_os_error());
    }
    let u16_at = |b: &[u8], i: usize| u16::from_ne_bytes([b[i], b[i + 1]]);
    let u32_at = |b: &[u8], i: usize| u32::from_ne_bytes([b[i], b[i + 1], b[i + 2], b[i + 3]]);
    let align = |n: usize| (n + 3) & !3;
    let mut peers = Vec::new();
    let mut buf = vec![0u8; 32 << 10];
    loop {
        let n = unsafe { libc::recv(fd.as_raw_fd(), buf.as_mut_ptr().cast(), buf.len(), 0) };
        if n < 0 {
            let e = io::Error::last_os_error();
            if e.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(e);
        }
        let mut msgs = &buf[..n as usize];
        // Each message: nlmsghdr (16 bytes), then unix_diag_msg (16 bytes:
        // family, type, state, pad, inode, cookie), then attributes.
        while msgs.len() >= 16 {
            let len = u32_at(msgs, 0) as usize;
            if len < 16 || len > msgs.len() {
                return Err(io::Error::new(io::ErrorKind::InvalidData, "short netlink message"));
            }
            match i32::from(u16_at(msgs, 4)) {
                libc::NLMSG_DONE => return Ok(peers),
                libc::NLMSG_ERROR => return Err(io::Error::other("socket diagnostics failed")),
                _ => {}
            }
            let body = &msgs[16..len];
            if body.len() >= 16 {
                let ino = u32_at(body, 4);
                let mut attrs = &body[16..];
                while attrs.len() >= 4 {
                    let alen = u16_at(attrs, 0) as usize;
                    if alen < 4 || alen > attrs.len() {
                        break;
                    }
                    if u16_at(attrs, 2) == UNIX_DIAG_PEER && alen >= 8 {
                        peers.push((ino.into(), u32_at(attrs, 4).into()));
                    }
                    attrs = &attrs[align(alen).min(attrs.len())..];
                }
            }
            msgs = &msgs[align(len).min(msgs.len())..];
        }
    }
}

pub fn uid() -> u32 {
    unsafe { libc::getuid() }
}

pub fn random() -> u32 {
    let mut n = 0u32;
    unsafe { libc::getrandom((&raw mut n).cast(), 4, 0) };
    n
}

pub fn ignore_interrupts() {
    unsafe {
        libc::signal(libc::SIGINT, libc::SIG_IGN);
        libc::signal(libc::SIGQUIT, libc::SIG_IGN);
    }
}

/// Keeps the passphrase out of core dumps, and other processes of ours
/// (a debugger) from reading our memory; and what's mapped so far, the
/// stack included, out of swap. Neither survives exec, so the programs we
/// run are unaffected. Locking may be refused (RLIMIT_MEMLOCK), and then
/// things carry on as before: it's for the passphrase, not required by it.
pub fn protect_memory() {
    unsafe {
        libc::prctl(libc::PR_SET_DUMPABLE, 0);
        libc::mlockall(libc::MCL_CURRENT);
    }
}

/// Keeps the pages holding `bytes` out of swap, if allowed. They're never
/// unlocked: a page may hold more than one secret, and we don't live long.
pub fn lock(bytes: &[u8]) {
    if !bytes.is_empty() {
        unsafe { libc::mlock(bytes.as_ptr().cast(), bytes.len()) };
    }
}

const CAUGHT: [libc::c_int; 3] = [libc::SIGINT, libc::SIGTERM, libc::SIGHUP];
static INTERRUPT_FD: AtomicI32 = AtomicI32::new(-1);

extern "C" fn on_interrupt(_: libc::c_int) {
    let fd = INTERRUPT_FD.load(Ordering::Relaxed);
    if fd >= 0 {
        unsafe { libc::write(fd, [0u8].as_ptr().cast(), 1) };
    }
}

/// Turns SIGINT, SIGTERM and SIGHUP into a readable pipe until dropped.
/// gpg-agent cancels a pinentry with SIGINT, e.g. when the command that
/// asked goes away; caught, the prompt can still put the terminal back.
pub struct Interrupts {
    read: OwnedFd,
    _write: OwnedFd,
    old: [libc::sigaction; CAUGHT.len()],
}

impl Interrupts {
    pub fn catch() -> io::Result<Interrupts> {
        let mut fds = [0; 2];
        check(unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC | libc::O_NONBLOCK) })?;
        let (read, write) = unsafe { (OwnedFd::from_raw_fd(fds[0]), OwnedFd::from_raw_fd(fds[1])) };
        INTERRUPT_FD.store(write.as_raw_fd(), Ordering::Relaxed);
        let mut sa: libc::sigaction = unsafe { std::mem::zeroed() };
        sa.sa_sigaction = on_interrupt as extern "C" fn(libc::c_int) as libc::sighandler_t;
        // Reads and writes carry on; poll returns, and sees the pipe.
        sa.sa_flags = libc::SA_RESTART;
        let mut old: [libc::sigaction; CAUGHT.len()] = unsafe { std::mem::zeroed() };
        for (&sig, old) in CAUGHT.iter().zip(&mut old) {
            unsafe {
                libc::sigemptyset(&mut sa.sa_mask);
                libc::sigaction(sig, &sa, old);
            }
        }
        Ok(Interrupts { read, _write: write, old })
    }

    /// Readable once one of the signals has arrived.
    pub fn fd(&self) -> RawFd {
        self.read.as_raw_fd()
    }
}

impl Drop for Interrupts {
    fn drop(&mut self) {
        for (&sig, old) in CAUGHT.iter().zip(&self.old) {
            unsafe { libc::sigaction(sig, old, std::ptr::null_mut()) };
        }
        INTERRUPT_FD.store(-1, Ordering::Relaxed);
    }
}

/// Puts a terminal in raw mode until dropped.
pub struct RawMode {
    fd: RawFd,
    orig: libc::termios,
}

impl RawMode {
    pub fn enable(fd: RawFd) -> io::Result<RawMode> {
        let mut orig: libc::termios = unsafe { std::mem::zeroed() };
        check(unsafe { libc::tcgetattr(fd, &mut orig) })?;
        let mut raw = orig;
        unsafe { libc::cfmakeraw(&mut raw) };
        check(unsafe { libc::tcsetattr(fd, libc::TCSAFLUSH, &raw) })?;
        Ok(RawMode { fd, orig })
    }
}

impl Drop for RawMode {
    fn drop(&mut self) {
        unsafe { libc::tcsetattr(self.fd, libc::TCSAFLUSH, &self.orig) };
    }
}
