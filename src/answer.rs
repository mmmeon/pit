//! A prompt with nowhere to go, left waiting for `pit answer` in whichever
//! terminal the user picks.
//!
//! The waiting pinentry listens on `<pid>.sock` in a private directory
//! under $XDG_RUNTIME_DIR. `pit answer` connects, gets the Request, asks on
//! its own terminal and sends back the Outcome line, the same lines a popup
//! uses. If it goes away without answering, the prompt waits again.

use std::env;
use std::fs::{self, DirBuilder, File};
use std::io::{self, Read, Write};
use std::os::fd::{AsRawFd, OwnedFd};
use std::os::unix::fs::{DirBuilderExt, MetadataExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::PathBuf;
use std::process;
use std::time::{Duration, Instant};

use crate::config::Hook;
use crate::sys;
use crate::ui::{self, Outcome, Request, Secret, Style};

/// How long `pit answer` waits on a prompt before taking it for one that's
/// being answered elsewhere.
const BUSY: Duration = Duration::from_secs(1);

/// The directory the sockets go in, made private to us if it isn't there.
/// Both sides must find the same one from their own environments:
/// gpg-agent's may lack XDG_RUNTIME_DIR, so systemd's default stands in.
fn dir() -> io::Result<PathBuf> {
    let uid = sys::uid();
    let base = env::var_os("XDG_RUNTIME_DIR")
        .map(PathBuf::from)
        .filter(|d| d.is_absolute())
        .or_else(|| Some(PathBuf::from(format!("/run/user/{uid}"))).filter(|d| d.is_dir()));
    let dir = match base {
        Some(base) => base.join("pit"),
        None => env::temp_dir().join(format!("pit-{uid}")),
    };
    match DirBuilder::new().mode(0o700).create(&dir) {
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

/// The socket, removed when the prompt is done.
struct Listening(PathBuf);

impl Drop for Listening {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.0);
    }
}

/// Waits for `pit answer` to ask `req`, up to its timeout.
pub fn wait(req: &Request, hook: Option<&str>) -> io::Result<Outcome> {
    let path = dir()?.join(format!("{}.sock", process::id()));
    let _ = fs::remove_file(&path);
    let listener = UnixListener::bind(&path)?;
    let _listening = Listening(path);
    // Tells the user where to go: e.g. a notification to run `pit answer`.
    let _hook = Hook::open(hook, req, "pending");
    let deadline = (req.timeout > 0).then(|| Instant::now() + Duration::from_secs(req.timeout));
    loop {
        let left = deadline.map(|d| d.saturating_duration_since(Instant::now()));
        if left == Some(Duration::ZERO) || sys::poll(&[listener.as_raw_fd()], left)?[0] == 0 {
            return Ok(Outcome::Timeout);
        }
        let Ok((stream, _)) = listener.accept() else { continue };
        if let Some(outcome) = serve(stream, req, deadline)? {
            return Ok(outcome);
        }
    }
}

/// Sends `req` to one `pit answer` and reads its answer. None if it went
/// away first.
fn serve(mut stream: UnixStream, req: &Request, deadline: Option<Instant>) -> io::Result<Option<Outcome>> {
    // Whatever time is left, so the prompt gives up when we would.
    let left = deadline.map(|d| d.saturating_duration_since(Instant::now()));
    let req = Request { timeout: left.map_or(0, |l| l.as_secs().max(1)), ..req.clone() };
    if stream.write_all(format!("{}\n", req.encode()).as_bytes()).is_err() {
        return Ok(None);
    }
    stream.set_read_timeout(left.map(|l| l + Duration::from_secs(2)))?;
    let mut buf = Secret::new();
    let mut chunk = [0; 256];
    loop {
        match stream.read(&mut chunk) {
            Ok(0) | Err(_) => return Ok(None),
            Ok(n) => buf.0.extend_from_slice(&chunk[..n]),
        }
        chunk.fill(0);
        if buf.0.ends_with(b"\n") {
            return Ok(Some(Outcome::decode(&buf.0)));
        }
    }
}

/// `pit answer`: asks the oldest waiting prompt here, on this terminal.
pub fn main() -> io::Result<()> {
    let dir = dir()?;
    let mut socks: Vec<_> = fs::read_dir(&dir)?
        .flatten()
        .filter(|e| e.file_name().to_string_lossy().ends_with(".sock"))
        .map(|e| (e.metadata().and_then(|m| m.modified()).ok(), e.path()))
        .collect();
    socks.sort();
    let mut busy = false;
    for (_, path) in socks {
        let mut stream = match UnixStream::connect(&path) {
            Ok(s) => s,
            // Left by a pinentry that was killed.
            Err(e) if e.kind() == io::ErrorKind::ConnectionRefused => {
                let _ = fs::remove_file(&path);
                continue;
            }
            Err(_) => continue,
        };
        stream.set_read_timeout(Some(BUSY))?;
        let Some(req) = read_request(&mut stream) else {
            busy = true;
            continue;
        };
        stream.set_read_timeout(None)?;
        return ask(stream, req);
    }
    Err(io::Error::other(if busy { "the waiting prompt is being answered elsewhere" } else { "nothing is waiting for an answer" }))
}

/// The Request, up to the blank line that ends it.
fn read_request(stream: &mut UnixStream) -> Option<Request> {
    let mut buf = Vec::new();
    let mut chunk = [0; 1024];
    while !buf.ends_with(b"\n\n") {
        let n = stream.read(&mut chunk).ok().filter(|&n| n > 0)?;
        buf.extend_from_slice(&chunk[..n]);
    }
    Request::decode(std::str::from_utf8(&buf).ok()?)
}

fn ask(mut stream: UnixStream, mut req: Request) -> io::Result<()> {
    let tty = File::options().read(true).write(true).open("/dev/tty")?;
    // The prompt gives up if the pinentry goes away.
    let ctl = File::from(OwnedFd::from(stream.try_clone()?));
    req.style = Style::Bar;
    req.width = sys::winsize(tty.as_raw_fd()).map_or(78, |(cols, _)| cols).saturating_sub(2);
    // Inline prompts have no border to carry the title, and here who asked
    // matters most: it could be anything on this machine.
    let head = req.heading();
    let (head, _) = ui::split_at_width(&head, req.width);
    (&tty).write_all(format!("\r\x1b[2m {head}\x1b[0m\r\n").as_bytes())?;
    let outcome = ui::run(&tty, &req, Some(&ctl), true);
    (&tty).write_all(b"\x1b[A\r\x1b[J")?;
    stream.write_all(&outcome?.encode().0)
}
