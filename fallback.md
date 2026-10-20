# Fallback ideas for pit

## Context
Today the chain is: inline on gpg's terminal (outside tmux) → tmux popup → inline in a
tmux pane → "no pinentry" error. The gaps where it gives up or lands badly:
- no tmux client attached and no usable terminal (e.g. gpg from a cron job, an editor
  plugin, a GUI git client, a systemd service)
- the terminal is in raw mode (vim, less, a TUI) and no tmux
- the popup can't open (client already shows one)
- ssh session where gpg-agent doesn't know the terminal

Brainstorm only. No implementation.

## Ideas, roughly in order of payoff

### 1. Hand off to another pinentry (GUI)
Config such as `fallback = "pinentry-qt"`. When pit can't prompt, it runs that program
and proxies the Assuan session to it. pit has already read OPTION/SETDESC/etc., so it
replays them first. gpg-agent sends `OPTION display=` / `putenv` with
DISPLAY/WAYLAND_DISPLAY, so pit can tell when a GUI is reachable.
- Pros: cheap, robust, covers every "no terminal" case on a desktop.
  pinentry-gnome3/qt/gtk/mac already exist.
- Cons: you lose pit's origin title, unless pit puts it in SETTITLE/SETDESC before
  replaying, which works and is a nice touch.

### 2. New tab, window or overlay in the user's terminal emulator
Find the terminal from the origin process's environment (/proc/<owner pid>/environ:
TERM_PROGRAM, KITTY_WINDOW_ID/KITTY_LISTEN_ON, WEZTERM_UNIX_SOCKET, …). Then spawn
`pit` in a "remote prompt" mode that talks back to the pinentry process over a
socket or pipe.
- kitty: `kitten @ launch --type=overlay` covers the current window, so it is the
  closest thing to a tmux popup. `--type=tab/os-window` also works.
- wezterm: `wezterm cli spawn` / `split-pane`
- foot: `footclient`; alacritty: `alacritty msg create-window`; ghostty, konsole and
  gnome-terminal have their own CLI/D-Bus routes
- iTerm2: AppleScript/Python API; Windows Terminal: `wt new-tab`
- generic: `xdg-terminal-exec` or `$TERMINAL -e` opens a new window. Works anywhere
  with a display, and needs no knowledge of the terminal.
- The overlay or split is the one that fixes the raw-mode case: the vim window keeps
  its own tty and the prompt gets a fresh one next to it.

### 3. Other multiplexers, treated as peers of tmux
- zellij: `zellij run --floating`, a floating pane works much like a popup
- GNU screen: `screen -X screen …` opens a new window, plus a message on the status line
- kitty/wezterm used as multiplexers overlap with #2

### 4. More tmux fallbacks before giving up
- popup busy → open a new tmux window or a split instead (`new-window`/`split-window`),
  then close it afterwards
- no client attached → keep the prompt pending until a client attaches (within the
  pinentry timeout) and show it then. Pair this with the hook so a notification says
  "attach to answer".

### 5. Pending prompt any terminal can claim (`pit answer`)
pit listens on a socket in $XDG_RUNTIME_DIR. Any terminal runs `pit answer` (or a
keybinding / shell widget) and the prompt is drawn there. A general last resort that
needs no terminal knowledge, and it works over ssh with a forwarded socket. The hook's
open event already exists to tell the user ("gpg is waiting: run pit answer").
- Prior art: systemd's ask-password agent protocol (`systemd-tty-ask-password-agent`)
  uses the same pattern: a request is posted and any agent can answer it.

### 6. Wait out a raw-mode terminal
If gpg's terminal is in raw mode, poll until it leaves raw mode (the user quits
vim/less), then prompt inline, still within the timeout. Cheap, but only helps if the
user leaves the full-screen program soon.

### 7. Editor integration
Emacs: gpg's `allow-emacs-pinentry` / INSIDE_EMACS protocol (pinentry asks Emacs over
its socket to prompt in the minibuffer). Neovim: a remote call over `$NVIM` could open
a floating prompt. Niche, but it covers the "gpg called from my editor" case well.

### 8. Prompts with no secret, answered elsewhere
CONFIRM/MESSAGE carry no secret, so a desktop notification with action buttons
(`notify-send --action=allow --action=deny`) is enough to answer them. Keep this off
for passphrases.

## Cross-cutting concerns
- Trust and context: a prompt that pops up somewhere else needs the origin in the
  title more than ever. pit already has it, so carry it into every fallback.
- Keystroke safety: any new surface must make sure the prompt has focus and that
  nothing else reads the tty. This is the same rule as raw mode today.
- Env: gpg-agent's environment is thin. Use what gpg-agent passes (OPTION ttyname,
  display, putenv) and the owner pid's environ. Don't rely on pit's own environment.
- Ordering and config: likely an ordered list, e.g.
  `fallback = ["tmux", "terminal", "pinentry-qt", "pending"]`, rather than one flag
  per mechanism. (Superseded for now by the two GUI positions under Decision.)

## Recommendation
Most coverage for the least work: **#1 (delegate to a GUI pinentry)**, then **#5
(claimable pending prompt)**, because between them they cover every case that errors
today. **#2 with a kitty/wezterm overlay** is the polished option that matches the
tmux popup experience. #4's "popup busy → new window" is a small, local win.

## Decision: #1 and #5, with the GUI first or last
Going with #1 and #5. The GUI pinentry takes one of two positions instead of a slot
in a general ordered list. Real setups want either "GUI only when nothing else
works" or "GUI whenever I'm at a desktop", and nothing in between.

```toml
[gui]
pinentry = "pinentry-qt"   # unset: no GUI fallback
when = "last"              # last|first
```

- `last`: inline on gpg's terminal → tmux popup → inline in a pane → GUI → pending.
- `first`: GUI, if a display is reachable → then the same order as `last`, without
  the GUI.
- The pending prompt (#5) is always last, since it needs the user to go and run
  `pit answer`.

### When a display is reachable
- X11: `DISPLAY` is set and its socket exists (`/tmp/.X11-unix/X<n>`). A TCP or
  ssh-forwarded display (`localhost:10`) has no local socket to check, so count it
  as reachable.
- Wayland: `WAYLAND_DISPLAY` is set and `$XDG_RUNTIME_DIR/$WAYLAND_DISPLAY` exists.
- macOS: pinentry-mac doesn't use `DISPLAY`. Treat it as reachable unless it's an
  ssh session with no `DISPLAY` (`SSH_CONNECTION` set).
- Where the values come from: gpg-agent passes `--display` (ignored today) and
  `OPTION display=`. Unknown yet whether `WAYLAND_DISPLAY`/`XDG_RUNTIME_DIR` arrive
  as `OPTION putenv=` or only in pit's environment; log one real session to find
  out. Failing both, use the owner pid's `/proc/<pid>/environ`.

### The hand-off
- Starting the pinentry vs. the user cancelling: if it fails to start or exits
  before its greeting, `first` moves on to the terminal options and `last` moves on
  to the pending prompt. If the user cancels in it, that's the answer; don't ask
  again elsewhere.
- Replay the OPTIONs pit has kept, then SETDESC/SETPROMPT/SETERROR/etc. The origin
  label goes into SETTITLE, so the dialog still says which command asked.
- The hook fires with place `gui <program>`.
- Refuse a `pinentry` that resolves to pit itself (e.g. via a `pinentry` symlink),
  or it loops.
- In the code: a step in `ask()` in src/assuan.rs. For `first` it goes before the
  tty and tmux checks; for `last` it replaces the two "nowhere to ask" errors (no
  terminal, busy pane).

## Verification
None for now. This is ideas only. Any idea we pick gets its own plan with tests (the
existing pty + isolated tmux harness in tests/ can be extended).
