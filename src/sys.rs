//! Thin wrappers over the libc calls std doesn't cover.

use std::env;
use std::ffi::{CString, OsStr};
use std::io;
use std::os::fd::RawFd;
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::time::Duration;

fn cstr(path: &Path) -> io::Result<CString> {
    CString::new(path.as_os_str().as_bytes()).map_err(io::Error::other)
}

fn check(ret: libc::c_int) -> io::Result<libc::c_int> {
    if ret < 0 { Err(io::Error::last_os_error()) } else { Ok(ret) }
}

pub fn mkdtemp() -> io::Result<PathBuf> {
    let template = env::temp_dir().join("pinentry-tmux.XXXXXX");
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
