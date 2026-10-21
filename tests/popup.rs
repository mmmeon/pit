//! Prompting in a tmux popup, on an isolated tmux server with a client
//! attached from a pty.

mod common;

use std::os::unix::process::CommandExt;
use std::thread;
use std::time::{Duration, Instant};

use common::*;

const DESC: &str = "SETDESC Please enter the passphrase for%0A\"User <a@x>\"";

/// Rows of `screen`, trimmed of trailing blanks.
fn rows(screen: &vt100::Screen) -> Vec<String> {
    let (_, cols) = screen.size();
    screen.rows(0, cols).map(|r| r.trim_end().to_string()).collect()
}

/// The popup's border box: (top, bottom, left, right), inclusive.
fn popup_box(screen: &vt100::Screen) -> (usize, usize, usize, usize) {
    let rows = rows(screen);
    let top = rows.iter().position(|r| r.contains('┌')).expect("no popup");
    let bottom = top + rows[top..].iter().position(|r| r.contains('└')).unwrap();
    let left = rows[top].chars().position(|c| c == '┌').unwrap();
    let right = rows[top].chars().position(|c| c == '┐').unwrap();
    (top, bottom, left, right)
}

struct Setup<'a> {
    sb: &'a Sandbox,
    tmux: Tmux<'a>,
    client: Client,
    p: Pinentry,
}

impl<'a> Setup<'a> {
    fn new(sb: &'a Sandbox) -> Setup<'a> {
        let tmux = Tmux::start(sb);
        let client = tmux.attach(30, 100);
        let p = Pinentry::spawn(sb, &[]);
        Setup { sb, tmux, client, p }
    }

    fn pty(&self) -> &Pty {
        &self.client.pty
    }
}

impl Drop for Setup<'_> {
    fn drop(&mut self) {
        if !thread::panicking() {
            assert_eq!(self.sb.leftovers(), Vec::<String>::new(), "files left behind");
        }
    }
}

#[test]
fn bar_popup_along_the_bottom() {
    require_tmux!();
    let sb = Sandbox::new();
    let mut s = Setup::new(&sb);
    s.p.setup(&[DESC, "SETPROMPT Passphrase:", "SETTITLE Unlock"]);
    s.p.start("GETPIN");
    let screen = s.pty().wait_text("Passphrase:");
    let (height, width) = s.pty().size();
    let (top, bottom, left, right) = popup_box(&screen);
    let rows = rows(&screen);
    assert!(rows[top].starts_with("┌─ Unlock ─"), "{}", rows[top]);
    assert_eq!((left, right), (0, width - 1), "bar spans the client");
    assert_eq!(bottom, height - 2, "bar sits right above the status line");
    assert_eq!(bottom - top - 1, 2, "description + input");
    assert!(rows[top + 1].contains("Please enter the passphrase for \"User <a@x>\""));
    assert!(rows[top + 2].contains("Passphrase: [····]"));

    s.pty().send("hunter2\r");
    assert_eq!(s.p.finish(), ["D hunter2", "OK"]);
    s.pty().wait_gone("Passphrase:");
}

#[test]
fn box_popup_is_centred() {
    require_tmux!();
    let sb = Sandbox::new();
    let mut s = Setup::new(&sb);
    sb.config("[tmux]\nstyle = \"box\"");
    s.p.setup(&[DESC, "SETTITLE Unlock"]);
    s.p.start("GETPIN");
    let screen = s.pty().wait_text("PIN:");
    let (top, bottom, left, right) = popup_box(&screen);
    let rows = rows(&screen);
    // Description, blank, input.
    assert_eq!(bottom - top - 1, 4, "{rows:#?}");
    assert!(rows[top + 1].contains("Please enter the passphrase for"));
    assert!(rows[top + 2].contains("\"User <a@x>\""));
    assert!(rows[top + 4].contains("PIN: [····]"));
    let (height, width) = s.pty().size();
    assert!(right - left + 1 < width);
    assert!(left.abs_diff(width - 1 - right) <= 1, "not centred: {left}..{right}");
    // Centred in the rows above the status line.
    assert!(top.abs_diff(height - 2 - bottom) <= 1, "not centred: {top}..{bottom}");
    s.pty().send("\x1b");
    assert_eq!(err_code(&s.p.finish()), Some(ERR_CANCELED));
    s.pty().wait_gone("PIN:");
}

#[test]
fn line_popup_puts_summary_in_title() {
    require_tmux!();
    let sb = Sandbox::new();
    let mut s = Setup::new(&sb);
    sb.config("[tmux]\nstyle = \"line\"");
    s.p.setup(&[DESC, "SETTITLE Unlock"]);
    s.p.start("GETPIN");
    let screen = s.pty().wait_text("PIN:");
    let (top, bottom, _, _) = popup_box(&screen);
    let rows = rows(&screen);
    assert_eq!(bottom - top, 2, "{rows:#?}");
    assert!(rows[top].contains(" Unlock · User <a@x> "), "{}", rows[top]);
    assert!(rows[top + 1].contains("PIN: [····]"));
    assert!(!screen.contents().contains("Please enter"));
    s.pty().send("x\r");
    assert_eq!(s.p.finish(), ["D x", "OK"]);
}

#[test]
fn echo_options() {
    require_tmux!();
    for (echo, shown) in [("dots", "PIN: •••"), ("none", "PIN:")] {
        let sb = Sandbox::new();
        let mut s = Setup::new(&sb);
        sb.config(&format!("echo = \"{echo}\""));
        s.p.start("GETPIN");
        s.pty().wait_text("PIN:");
        s.pty().send("abc");
        if echo == "dots" {
            s.pty().wait_text(shown);
        } else {
            thread::sleep(Duration::from_millis(200));
            let row = rows(&s.pty().screen()).into_iter().find(|r| r.contains("PIN:")).unwrap();
            assert_eq!(row.trim_matches(['│', ' ']), shown);
        }
        s.pty().send("\r");
        assert_eq!(s.p.finish(), ["D abc", "OK"], "{echo}");
    }
}

#[test]
fn confirm_and_message_in_popup() {
    require_tmux!();
    let sb = Sandbox::new();
    let mut s = Setup::new(&sb);
    s.p.setup(&["SETDESC Allow access?", "SETOK _Allow", "SETNOTOK _Deny"]);
    s.p.start("CONFIRM");
    s.pty().wait_text("⏎ Allow   d Deny   esc Cancel");
    s.pty().send("d");
    assert_eq!(err_code(&s.p.finish()), Some(ERR_NOT_CONFIRMED));
    s.pty().wait_gone("Allow access?");

    s.p.start("CONFIRM");
    s.pty().wait_text("Allow access?");
    s.pty().send("a");
    assert_eq!(s.p.finish(), ["OK"]);
    s.pty().wait_gone("Allow access?");

    s.p.setup(&["SETDESC Card removed"]);
    s.p.start("MESSAGE");
    s.pty().wait_text("Card removed");
    s.pty().send("\r");
    assert_eq!(s.p.finish(), ["OK"]);
}

#[test]
fn repeat_in_popup() {
    require_tmux!();
    let sb = Sandbox::new();
    let mut s = Setup::new(&sb);
    s.p.setup(&["SETPROMPT New:", "SETREPEAT Again:"]);
    s.p.start("GETPIN");
    s.pty().wait_text("New:");
    s.pty().send("aa\r");
    s.pty().wait_text("Again:");
    s.pty().send("bb\r");
    s.pty().wait_text("does not match - try again");
    s.pty().send("cc\r");
    s.pty().wait_text("Again:");
    s.pty().send("cc\r");
    assert_eq!(s.p.finish(), ["S PIN_REPEATED", "D cc", "OK"]);
}

#[test]
fn opens_on_most_recently_active_client() {
    require_tmux!();
    let sb = Sandbox::new();
    let tmux = Tmux::start(&sb);
    // Long enough that the note to `a` can't be gone before we look.
    tmux.set("display-time", "10000");
    let b = tmux.attach(30, 100);
    let a = tmux.attach(30, 100);
    // Activity is tracked in whole seconds.
    thread::sleep(Duration::from_millis(1100));
    b.pty.send("x");
    let mut p = Pinentry::spawn(&sb, &[]);
    p.start("GETPIN");
    b.pty.wait_text("PIN:");
    assert!(!a.pty.text().contains("PIN:"));
    a.pty.wait_text(&format!("pinentry: gpg - prompt open on {}", b.pty.path()));
    b.pty.send("ok\r");
    assert_eq!(p.finish(), ["D ok", "OK"]);
}

#[test]
fn outside_terminal_wins_over_attached_client() {
    require_tmux!();
    let sb = Sandbox::new();
    let tmux = Tmux::start(&sb);
    let client = tmux.attach(30, 100);
    let term = Pty::term(24, 80);
    let mut p = Pinentry::spawn(&sb, &["--ttyname", term.path()]);
    p.start("GETPIN");
    term.wait_text("PIN:");
    assert!(!client.pty.text().contains("PIN:"));
    term.send("here\r");
    assert_eq!(p.finish(), ["D here", "OK"]);
    term.wait_gone("PIN:");
}

#[test]
fn falls_back_to_pane_when_popup_cannot_open() {
    require_tmux!();
    let sb = Sandbox::new();
    let tmux = Tmux::start(&sb);
    let client = tmux.attach(30, 100);
    let mut busy = tmux.busy_popup(&client);
    client.pty.wait_text("busy");
    // With no owner to tell apart, the pane must have nothing reading it.
    let pane = tmux.run(&["new-window", "-P", "-F", "#{pane_tty}", "exec sleep 999 </dev/null"]).trim().to_string();
    let mut p = Pinentry::spawn(&sb, &["--ttyname", &pane]);
    p.start("GETPIN");
    wait_until("prompt in pane", || tmux.capture().contains("PIN:").then_some(()), || tmux.capture());
    tmux.send_keys(&["-l", "s3cret"]);
    tmux.send_keys(&["Enter"]);
    assert_eq!(p.finish(), ["D s3cret", "OK"]);
    wait_until("prompt erased", || (!tmux.capture().contains("PIN:")).then_some(()), || tmux.capture());
    assert_eq!(sb.leftovers(), Vec::<String>::new());
    let _ = busy.kill();
    let _ = busy.wait();
}

#[test]
fn closing_popup_cancels() {
    require_tmux!();
    let sb = Sandbox::new();
    let mut s = Setup::new(&sb);
    s.p.start("GETPIN");
    s.pty().wait_text("PIN:");
    s.tmux.close_popup(&s.client);
    assert_eq!(err_code(&s.p.finish()), Some(ERR_CANCELED));
    s.pty().wait_gone("PIN:");
}

#[test]
fn killed_pinentry_closes_popup() {
    require_tmux!();
    let sb = Sandbox::new();
    let mut s = Setup::new(&sb);
    s.p.start("GETPIN");
    s.pty().wait_text("PIN:");
    let start = Instant::now();
    s.p.kill();
    s.pty().wait_gone("PIN:");
    assert!(start.elapsed() < Duration::from_secs(2));
}

#[test]
fn timeout_closes_popup() {
    require_tmux!();
    let sb = Sandbox::new();
    let mut s = Setup::new(&sb);
    s.p.setup(&["SETTIMEOUT 1"]);
    s.p.start("GETPIN");
    s.pty().wait_text("PIN:");
    assert_eq!(err_code(&s.p.finish()), Some(ERR_TIMEOUT));
    s.pty().wait_gone("PIN:");
}

#[test]
fn second_prompt_after_first() {
    require_tmux!();
    let sb = Sandbox::new();
    let mut s = Setup::new(&sb);
    s.p.setup(&["SETERROR Bad passphrase"]);
    for (i, pin) in ["one", "two"].into_iter().enumerate() {
        s.p.start("GETPIN");
        s.pty().wait_text("PIN:");
        assert_eq!(s.pty().text().contains("Bad passphrase"), i == 0);
        s.pty().send(pin);
        s.pty().send("\r");
        assert_eq!(s.p.finish(), [format!("D {pin}"), "OK".into()]);
        s.pty().wait_gone("PIN:");
    }
}

fn uid() -> u32 {
    unsafe { libc::getuid() }
}

fn hostname() -> String {
    std::fs::read_to_string("/proc/sys/kernel/hostname").unwrap().trim().to_string()
}

/// Processes below `pid`, depth first.
fn descendants(pid: u32) -> Vec<u32> {
    let children = std::fs::read_to_string(format!("/proc/{pid}/task/{pid}/children")).unwrap_or_default();
    children.split_whitespace().filter_map(|c| c.parse().ok()).flat_map(|c| [vec![c], descendants(c)].concat()).collect()
}

/// Runs `cmd` in a new window. Returns its pane as `session:window.pane` and
/// the pid of the process called `name` under it.
fn in_window(tmux: &Tmux, cmd: &str, name: &str) -> (String, u32) {
    // The trailing `:` keeps the shell from exec'ing the command.
    let out = tmux.run(&["new-window", "-d", "-P", "-F", "#{pane_pid} #S:#I.#P", &format!("{cmd}; :")]);
    let (shell, pane) = out.trim().split_once(' ').unwrap();
    let shell: u32 = shell.parse().unwrap();
    let comm = |p: u32| std::fs::read_to_string(format!("/proc/{p}/comm")).unwrap_or_default();
    let pid = wait_until(
        name,
        || descendants(shell).into_iter().find(|&p| comm(p).trim() == name),
        || tmux.run(&["list-panes", "-a"]),
    );
    (pane.to_string(), pid)
}

#[test]
fn title_names_command_and_pane() {
    require_tmux!();
    let sb = Sandbox::new();
    let mut s = Setup::new(&sb);
    // timeout stands in for git: the command typed, which runs the requester.
    let (pane, pid) = in_window(&s.tmux, "timeout 1000 sleep 999", "sleep");
    s.p.setup(&["SETTITLE Unlock", &format!("OPTION owner={pid}/{} {}", uid(), hostname())]);
    s.p.start("GETPIN");
    let screen = s.pty().wait_text("PIN:");
    let top = &rows(&screen)[popup_box(&screen).0];
    // Only the program: the rest of a command line may hold secrets.
    assert!(top.contains(&format!(" Unlock · timeout @ {pane} ")), "{top}");
    s.pty().send("\x1b");
    assert_eq!(err_code(&s.p.finish()), Some(ERR_CANCELED));
}

#[test]
fn owner_on_another_host_is_ignored() {
    require_tmux!();
    let sb = Sandbox::new();
    let mut s = Setup::new(&sb);
    let (_, pid) = in_window(&s.tmux, "sleep 999", "sleep");
    s.p.setup(&["SETTITLE Unlock", &format!("OPTION owner={pid}/{} elsewhere.invalid", uid())]);
    s.p.start("GETPIN");
    let screen = s.pty().wait_text("PIN:");
    let top = &rows(&screen)[popup_box(&screen).0];
    assert!(top.starts_with("┌─ Unlock ─"), "{top}");
    s.pty().send("\x1b");
    assert_eq!(err_code(&s.p.finish()), Some(ERR_CANCELED));
}

#[test]
fn title_skips_sh_c_wrappers() {
    require_tmux!();
    let sb = Sandbox::new();
    let mut s = Setup::new(&sb);
    // Like git running gpg.program through `sh -c`: name git, not gpg. In
    // full, to see that it's that command line.
    sb.config("origin = \"full\"");
    let (pane, pid) = in_window(&s.tmux, "timeout 999 sh -c 'sleep 998; :'", "sleep");
    s.p.setup(&["SETTITLE Unlock", &format!("OPTION owner={pid}/{} {}", uid(), hostname())]);
    s.p.start("GETPIN");
    let screen = s.pty().wait_text("PIN:");
    let top = &rows(&screen)[popup_box(&screen).0];
    assert!(top.contains(&format!(" Unlock · timeout 999 sh -c sleep 998; : @ {pane} ")), "{top}");
    s.pty().send("\x1b");
    assert_eq!(err_code(&s.p.finish()), Some(ERR_CANCELED));
}

#[test]
fn title_names_the_client_behind_a_proxy() {
    require_tmux!();
    let sb = Sandbox::new();
    let mut s = Setup::new(&sb);
    let proxy = Proxy::start(&sb);
    // Typed at a shell, like gpg would be; only sleep keeps the connection.
    let mut cmd = std::process::Command::new("sh");
    cmd.arg("-s").stdin(std::process::Stdio::piped()).stdout(std::process::Stdio::null()).stderr(std::process::Stdio::null()).process_group(0);
    let mut client = proxy.spawn(&mut cmd);
    let shell = client.0.id();
    let mut script = client.0.stdin.take().unwrap();
    std::io::Write::write_all(&mut script, b"sleep 998 <&3 3<&- & exec 3<&-; wait\n").unwrap();
    wait_until("shell to let go of the connection", || (!std::path::Path::new(&format!("/proc/{shell}/fd/3")).exists()).then_some(()), String::new);
    let (top, log) = ask_through_proxy(&mut s, &proxy, "not a tty");
    // Known, not guessed: no mark.
    assert!(top.contains(" Unlock · sleep ─"), "{top}");
    let tty = s.pty().path();
    assert_eq!(log, [format!("open popup {tty} Unlock||sleep"), format!("close popup {tty} Unlock||sleep")]);
    drop(script);
}

/// Asks through `proxy` in front of the agent, with GPG_TTY `tty`, and logs
/// what the hook is told. Returns the popup's top border and the log.
fn ask_through_proxy(s: &mut Setup, proxy: &Proxy, tty: &str) -> (String, Vec<String>) {
    let log = log_hook(s.sb);
    s.p.setup(&["SETTITLE Unlock", &format!("OPTION ttyname={tty}"), &format!("OPTION owner={}/{} {}", proxy.pid, uid(), hostname())]);
    s.p.start("GETPIN");
    let screen = s.pty().wait_text("PIN:");
    let top = rows(&screen)[popup_box(&screen).0].clone();
    s.pty().send("\x1b");
    assert_eq!(err_code(&s.p.finish()), Some(ERR_CANCELED));
    (top, hook_lines(&log, 2))
}

#[test]
fn behind_a_proxy_the_terminal_names_a_guess() {
    require_tmux!();
    let sb = Sandbox::new();
    let mut s = Setup::new(&sb);
    let (pane, _) = in_window(&s.tmux, "sleep 999", "sleep");
    let tty = s.tmux.run(&["display", "-p", "-t", &pane, "#{pane_tty}"]).trim().to_string();
    // No client: only the pane, never what runs there, which may not be
    // who asked.
    let (top, log) = ask_through_proxy(&mut s, &Proxy::start(&sb), &tty);
    let origin = pane;
    assert!(top.contains(&format!(" Unlock · {origin} ? ")), "{top}");
    let client = s.pty().path();
    assert_eq!(log, [format!("open popup {client} Unlock|1|{origin}"), format!("close popup {client} Unlock|1|{origin}")]);
}

#[test]
fn behind_a_proxy_without_a_terminal_the_watched_pane_is_a_guess() {
    require_tmux!();
    let sb = Sandbox::new();
    let mut s = Setup::new(&sb);
    let (pane, _) = in_window(&s.tmux, "sleep 999", "sleep");
    s.tmux.run(&["select-window", "-t", &pane]);
    let (top, log) = ask_through_proxy(&mut s, &Proxy::start(&sb), "not a tty");
    let origin = pane;
    assert!(top.contains(&format!(" Unlock · {origin} ? ")), "{top}");
    let client = s.pty().path();
    assert_eq!(log, [format!("open popup {client} Unlock|1|{origin}"), format!("close popup {client} Unlock|1|{origin}")]);
}

#[test]
fn hash_in_title_is_not_a_tmux_format() {
    require_tmux!();
    let sb = Sandbox::new();
    let tmux = Tmux::start(&sb);
    tmux.set("display-time", "10000");
    let b = tmux.attach(30, 100);
    let a = tmux.attach(30, 100);
    thread::sleep(Duration::from_millis(1100));
    b.pty.send("x");
    let mut p = Pinentry::spawn(&sb, &[]);
    p.setup(&["SETTITLE Key #{pane_id}"]);
    p.start("GETPIN");
    let screen = b.pty.wait_text("PIN:");
    assert!(rows(&screen)[popup_box(&screen).0].contains(" Key #{pane_id} "));
    a.pty.wait_text("pinentry: Key #{pane_id} - prompt open on");
    b.pty.send("\x1b");
    assert_eq!(err_code(&p.finish()), Some(ERR_CANCELED));
}

/// A pinentry asked by the process `name` run by `cmd` in a new window,
/// with GPG_TTY set to that window's pane. Returns the pane and its tty.
fn asked_from_window(s: &mut Setup, cmd: &str, name: &str) -> (String, String) {
    let (pane, pid) = in_window(&s.tmux, cmd, name);
    let tty = s.tmux.run(&["display", "-p", "-t", &pane, "#{pane_tty}"]).trim().to_string();
    s.p.setup(&[&format!("OPTION ttyname={tty}"), &format!("OPTION owner={pid}/{} {}", uid(), hostname())]);
    s.p.start("GETPIN");
    (pane, tty)
}

/// Waits for the prompt in place on `pane`, then types `keys` into it.
fn answer_in_pane(s: &Setup, pane: &str, keys: &str) {
    let capture = || s.tmux.run(&["capture-pane", "-p", "-t", pane]);
    wait_until("inline prompt", || capture().contains("PIN:").then_some(()), capture);
    s.tmux.run(&["send-keys", "-t", pane, keys, "Enter"]);
}

#[test]
fn foreground_command_in_a_pane_is_asked_in_place() {
    require_tmux!();
    let sb = Sandbox::new();
    let mut s = Setup::new(&sb);
    let (pane, _) = asked_from_window(&mut s, "sleep 999", "sleep");
    answer_in_pane(&s, &pane, "hunter2");
    assert_eq!(s.p.finish(), ["D hunter2", "OK"]);
}

#[test]
fn inline_can_be_turned_off() {
    require_tmux!();
    let sb = Sandbox::new();
    let mut s = Setup::new(&sb);
    sb.config("[tmux]\ninline = \"never\"");
    asked_from_window(&mut s, "sleep 999", "sleep");
    s.pty().wait_text("PIN:");
    s.pty().send("\x1b");
    assert_eq!(err_code(&s.p.finish()), Some(ERR_CANCELED));
}

#[test]
fn full_screen_program_gets_a_popup() {
    require_tmux!();
    let sb = Sandbox::new();
    let mut s = Setup::new(&sb);
    asked_from_window(&mut s, "printf '\\033[?1049h'; sleep 999", "sleep");
    s.pty().wait_text("PIN:");
    s.pty().send("\x1b");
    assert_eq!(err_code(&s.p.finish()), Some(ERR_CANCELED));
}

#[test]
fn background_job_gets_a_popup() {
    require_tmux!();
    let sb = Sandbox::new();
    let mut s = Setup::new(&sb);
    // With job control the shell keeps the foreground, as at a prompt.
    asked_from_window(&mut s, "set -m; sleep 999 & wait", "sleep");
    s.pty().wait_text("PIN:");
    s.pty().send("\x1b");
    assert_eq!(err_code(&s.p.finish()), Some(ERR_CANCELED));
}

#[test]
fn terminal_in_raw_mode_outside_tmux_gets_a_popup() {
    require_tmux!();
    let sb = Sandbox::new();
    let tmux = Tmux::start(&sb);
    let client = tmux.attach(30, 100);
    let term = Pty::term(24, 80);
    term.raw();
    let mut p = Pinentry::spawn(&sb, &["--ttyname", term.path()]);
    p.start("GETPIN");
    client.pty.wait_text("PIN:");
    assert!(!term.text().contains("PIN:"));
    client.pty.send("\x1b");
    assert_eq!(err_code(&p.finish()), Some(ERR_CANCELED));
}

/// Points the hook at a log of its events. Returns the log's path.
fn log_hook(sb: &Sandbox) -> std::path::PathBuf {
    let log = sb.tmp().join("hook.log");
    hook(sb, &format!("echo \"$PIT_EVENT $PIT_WHERE $PIT_TITLE|$PIT_ORIGIN_GUESS|$PIT_ORIGIN\" >> {}", log.display()));
    log
}

fn hook(sb: &Sandbox, cmd: &str) {
    sb.config(&format!("hook = '''{cmd}'''"));
}

/// The log once it has `n` lines, removed so the sandbox ends empty.
fn hook_lines(log: &std::path::Path, n: usize) -> Vec<String> {
    let read = || std::fs::read_to_string(log).unwrap_or_default();
    let lines = wait_until("hook", || {
        let l: Vec<String> = read().lines().map(Into::into).collect();
        (l.len() >= n).then_some(l)
    }, read);
    std::fs::remove_file(log).unwrap();
    lines
}

#[test]
fn hook_runs_on_popup_open_and_close() {
    require_tmux!();
    let sb = Sandbox::new();
    let mut s = Setup::new(&sb);
    let log = log_hook(&sb);
    s.p.setup(&["SETTITLE Unlock"]);
    s.p.start("GETPIN");
    s.pty().wait_text("PIN:");
    s.pty().send("\x1b");
    assert_eq!(err_code(&s.p.finish()), Some(ERR_CANCELED));
    let tty = s.pty().path();
    assert_eq!(hook_lines(&log, 2), [format!("open popup {tty} Unlock||"), format!("close popup {tty} Unlock||")]);
}

#[test]
fn hook_runs_on_inline_open_and_close() {
    require_tmux!();
    let sb = Sandbox::new();
    let mut s = Setup::new(&sb);
    let log = log_hook(&sb);
    let (pane, tty) = asked_from_window(&mut s, "sleep 999", "sleep");
    answer_in_pane(&s, &pane, "x");
    assert_eq!(s.p.finish(), ["D x", "OK"]);
    assert_eq!(hook_lines(&log, 2), [format!("open inline {tty} gpg||sleep @ {pane}"), format!("close inline {tty} gpg||sleep @ {pane}")]);
}

#[test]
fn hook_closes_after_a_slow_open() {
    require_tmux!();
    let sb = Sandbox::new();
    let mut s = Setup::new(&sb);
    let log = sb.tmp().join("hook.log");
    let cmd = format!("[ \"$PIT_EVENT\" = open ] && sleep 1; echo $PIT_EVENT >> {}", log.display());
    hook(&sb, &cmd);
    s.p.start("GETPIN");
    s.pty().wait_text("PIN:");
    s.pty().send("\x1b");
    assert_eq!(err_code(&s.p.finish()), Some(ERR_CANCELED));
    assert_eq!(hook_lines(&log, 2), ["open", "close"]);
}

#[test]
fn slow_hook_does_not_hold_up_the_prompt() {
    require_tmux!();
    let sb = Sandbox::new();
    let mut s = Setup::new(&sb);
    let pid = sb.tmp().join("hook.pid");
    let cmd = format!("[ \"$PIT_EVENT\" = open ] || exit 0; echo $$ > {}; exec sleep 100", pid.display());
    hook(&sb, &cmd);
    let start = Instant::now();
    s.p.start("GETPIN");
    s.pty().wait_text("PIN:");
    s.pty().send("\x1b");
    assert_eq!(err_code(&s.p.finish()), Some(ERR_CANCELED));
    assert!(start.elapsed() < Duration::from_secs(10));
    // Not left sleeping after the test.
    let read = || std::fs::read_to_string(&pid).unwrap_or_default();
    let sleeper: i32 = wait_until("hook to start", || read().trim().parse().ok(), read);
    assert_eq!(unsafe { libc::kill(sleeper, libc::SIGTERM) }, 0);
    std::fs::remove_file(&pid).unwrap();
}

/// Runs the hook at PIT_TEST_HOOK through every kind of prompt, each
/// answered after a pause, to see what it does with real events:
///   PIT_TEST_HOOK=hooks/notify-send cargo test --test popup try_a_hook
/// Passes without doing anything when unset.
#[test]
fn try_a_hook() {
    let Some(path) = std::env::var_os("PIT_TEST_HOOK") else { return };
    require_tmux!();
    let path = std::fs::canonicalize(path).expect("PIT_TEST_HOOK");
    let pause = || thread::sleep(Duration::from_secs(2));
    let sb = Sandbox::new();
    let mut s = Setup::new(&sb);
    hook(&sb, &path.display().to_string());

    s.p.setup(&["SETTITLE Unlock", DESC]);
    s.p.start("GETPIN");
    s.pty().wait_text("PIN:");
    pause();
    s.pty().send("hunter2\r");
    assert_eq!(s.p.finish(), ["D hunter2", "OK"]);
    pause();

    s.p.setup(&["SETDESC Allow access?", "SETOK _Allow", "SETNOTOK _Deny"]);
    s.p.start("CONFIRM");
    s.pty().wait_text("Allow access?");
    pause();
    s.pty().send("a");
    assert_eq!(s.p.finish(), ["OK"]);
    pause();

    s.p.setup(&["SETDESC Card removed"]);
    s.p.start("MESSAGE");
    s.pty().wait_text("Card removed");
    pause();
    s.pty().send("\r");
    assert_eq!(s.p.finish(), ["OK"]);
    pause();

    // Behind a proxy in front of the agent: who asked is a guess.
    let proxy = Proxy::start(&sb);
    s.p.setup(&["SETDESC Behind a proxy", &format!("OPTION owner={}/{} {}", proxy.pid, uid(), hostname())]);
    s.p.start("GETPIN");
    s.pty().wait_text("PIN:");
    pause();
    s.pty().send("hunter2\r");
    assert_eq!(s.p.finish(), ["D hunter2", "OK"]);
    drop(proxy);
    pause();

    let (pane, _) = asked_from_window(&mut s, "sleep 999", "sleep");
    pause();
    answer_in_pane(&s, &pane, "hunter2");
    assert_eq!(s.p.finish(), ["D hunter2", "OK"]);
    pause();
}

#[test]
fn another_reader_in_the_job_gets_a_popup() {
    require_tmux!();
    let sb = Sandbox::new();
    let mut s = Setup::new(&sb);
    // cat reads the pane: it could take some of the keys.
    asked_from_window(&mut s, "cat | sleep 999", "sleep");
    s.pty().wait_text("PIN:");
    s.pty().send("\x1b");
    assert_eq!(err_code(&s.p.finish()), Some(ERR_CANCELED));
}

#[test]
fn another_reader_in_the_job_is_not_asked_when_the_popup_cant_show() {
    require_tmux!();
    let sb = Sandbox::new();
    let mut s = Setup::new(&sb);
    s.tmux.run(&["detach-client", "-t", s.pty().path()]);
    let (pane, _) = asked_from_window(&mut s, "cat | sleep 999", "sleep");
    assert_eq!(err_code(&s.p.finish()), Some(ERR_NO_PIN_ENTRY));
    assert!(!s.tmux.run(&["capture-pane", "-p", "-t", &pane]).contains("PIN:"));
}

#[test]
fn reader_of_a_pipe_in_the_job_is_fine() {
    require_tmux!();
    let sb = Sandbox::new();
    let mut s = Setup::new(&sb);
    // Like `gpg ... | tee out`: cat reads the pipe, not the pane.
    let (pane, _) = asked_from_window(&mut s, "sleep 999 | cat", "sleep");
    answer_in_pane(&s, &pane, "x");
    assert_eq!(s.p.finish(), ["D x", "OK"]);
}

#[test]
fn inline_off_is_not_asked_in_the_pane_when_the_popup_cant_show() {
    require_tmux!();
    let sb = Sandbox::new();
    let mut s = Setup::new(&sb);
    sb.config("[tmux]\ninline = \"never\"");
    s.tmux.run(&["detach-client", "-t", s.pty().path()]);
    let (pane, _) = asked_from_window(&mut s, "sleep 999", "sleep");
    assert_eq!(err_code(&s.p.finish()), Some(ERR_NO_PIN_ENTRY));
    assert!(!s.tmux.run(&["capture-pane", "-p", "-t", &pane]).contains("PIN:"));
}

#[test]
fn full_screen_program_is_not_asked_when_the_popup_cant_show() {
    require_tmux!();
    let sb = Sandbox::new();
    let mut s = Setup::new(&sb);
    s.tmux.run(&["detach-client", "-t", s.pty().path()]);
    let (pane, _) = asked_from_window(&mut s, "printf '\\033[?1049h'; sleep 999", "sleep");
    assert_eq!(err_code(&s.p.finish()), Some(ERR_NO_PIN_ENTRY));
    assert!(!s.tmux.run(&["capture-pane", "-p", "-t", &pane]).contains("PIN:"));
}
