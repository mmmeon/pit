pit: gpg-agent pinentry for terminals and tmux

  bar (default), along the bottom of the client:

    ┌─ gpg · git commit @ work:2.0 ────────────────────────────────────────┐
    │ Please enter the passphrase to unlock the OpenPGP secret key         │
    │ "User <user@example.org>" · 255-bit EDDSA key, ID 3AA5C34371567BD2   │
    │ created 2024-03-01.                                                  │
    │ Passphrase: [•·•·]                                                   │
    └──────────────────────────────────────────────────────────────────────┘
    [work] 0:zsh- 2:git*

  box, centred:

    ┌─ gpg · git commit @ work:2.0 ─────────────────────────────────┐
    │ Please enter the passphrase to unlock the OpenPGP secret key: │
    │ "User <user@example.org>"                                     │
    │ 255-bit EDDSA key, ID 3AA5C34371567BD2,                       │
    │ created 2024-03-01.                                           │
    │                                                               │
    │ Passphrase: [•••·]                                            │
    └───────────────────────────────────────────────────────────────┘

  line, the description summed up in the title, after gpg-agent's note
  when a request is from a remote site:

    ┌─ gpg · User <user@example.org> · git commi… ─┐
    │ Passphrase: [••·•]                           │
    └──────────────────────────────────────────────┘

  wrong passphrase:

    ┌─ gpg · git commit @ work:2.0 ─────────────────────────────────┐
    │ Please enter the passphrase to unlock the OpenPGP secret key: │
    │ "User <user@example.org>"                                     │
    │ 255-bit EDDSA key, ID 3AA5C34371567BD2,                       │
    │ created 2024-03-01.                                           │
    │                                                               │
    │ Bad Passphrase (try 2 of 3)                                   │
    │ Passphrase: [····]                                            │
    └───────────────────────────────────────────────────────────────┘

  new passphrase, after a mismatch:

    ┌─ gpg · git commit @ work:2.0 ────────────────────┐
    │ Please enter a passphrase to protect the new key │
    │                                                  │
    │ does not match - try again                       │
    │ Passphrase: [····]                               │
    └──────────────────────────────────────────────────┘

  confirm:

    ┌─ gpg · git commit @ work:2.0 ──────────────────────┐
    │ An ssh process requested the use of key            │
    │ SHA256:Xg5lV0wHqR6c8eZ9o1C3pJ2bDkF4aT7nYyLmQsUvWiE │
    │ (user@laptop)                                      │
    │ Do you want to allow this?                         │
    │                                                    │
    │ ⏎ Allow   d Deny   esc Cancel                      │
    └────────────────────────────────────────────────────┘

  message:

    ┌─ gpg · git commit @ work:2.0 ────────────┐
    │ No card found. Insert your OpenPGP card. │
    │                                          │
    │ ⏎ OK                                     │
    └──────────────────────────────────────────┘

  in place, on a terminal outside tmux:

    ~/src/notes $ git commit -S -m 'Fix typo'
     Please enter the passphrase to unlock the OpenPGP secret key
     "User <user@example.org>" · 255-bit EDDSA key, ID 3AA5C34371567BD2
     created 2024-03-01.
     Passphrase: [••··]

  pit answer, in any terminal, for a prompt left waiting:

    ~ $ pit answer
     gpg · git commit @ work:2.0
     Please enter the passphrase to unlock the OpenPGP secret key
     "User <user@example.org>" · 255-bit EDDSA key, ID 3AA5C34371567BD2
     created 2024-03-01.
     Passphrase: [••··]


setup
  in ~/.gnupg/gpg-agent.conf:
    pinentry-program /path/to/pit
  then `gpg-connect-agent reloadagent /bye`. For ssh, so the agent knows
  ssh's terminal, at the top of ~/.ssh/config:
    Match host * exec "GPG_TTY=$(tty <&2) gpg-connect-agent UPDATESTARTUPTTY /bye >/dev/null"

terminals
  - a command run outside tmux is asked in place on its terminal, erased
    afterwards, even with a tmux client attached
  - same when no tmux client is attached, or the popup can't open

tmux
  - popup on your most recently active client, sized to fit. Never on a
    read-only client, nor in a shared session on someone else's, who
    could see the prompt and answer it. Needs tmux 3.3 or later
  - your other clients get a status-line note: "pinentry: gpg - prompt
    open on /dev/pts/15"
  - the title names the command and pane that asked, e.g.
    "git commit @ work:2.1"
  - in place in a pane instead, when the command that asked has it to
    itself (see [tmux] inline)
  - closes when gpg-agent kills the pinentry; no leftover files

prompts
  - passphrase, new passphrase with repeat, confirm and message
  - wrong-passphrase and mismatch errors shown in the prompt
  - ssh keys with only a fingerprint get the key's OpenPGP user ID, if gpg
    knows the keygrip; smartcard PINs get the user ID of the key on the card
  - enter submits, esc/ctrl-c cancels, backspace deletes, ctrl-u clears;
    button mnemonics in confirm dialogs
  - honours gpg-agent's pinentry timeout

elsewhere
  - a graphical pinentry, when there's a display (see [gui])
  - waiting for `pit answer` in any terminal (see pending)

config
  $XDG_CONFIG_HOME/pit/config.toml, often ~/.config/pit/config.toml. Read
  for each prompt. TOML, strings only; a key that doesn't parse or isn't
  known is skipped, so a typo never stops the prompt.

    echo = "marker"     # marker, dots, none
    origin = "short"    # short, full
    hook = '<command>'  # see below
    pending = "never"   # never, wait

    [tmux]
    style = "bar"       # bar, box, line
    inline = "auto"     # auto, never

    [gui]
    pinentry = "pinentry-qt"  # none by default
    order = "last"      # last, first

  echo: marker changes on every key without giving away the length; dots
  shows one per character; none shows nothing.

  origin: short names the program, and its subcommand for those known to
  have one ("git commit"); full gives the whole command line, which may
  hold secrets and puts them on screen.

  inline: auto asks in place in a pane when the command that asked is in
  its foreground and nothing full-screen shows there; never always uses
  the popup. A terminal outside tmux is always asked in place.

  gui: another pinentry (pinentry-qt, -gtk, -gnome3), used only when
  there's a display: a Wayland or local X socket, or a remote X display
  (ssh -X). last asks there when there's nowhere on a terminal; first asks
  there before the terminal and tmux. Cancelling it is an answer; if it
  can't show the prompt, pit carries on without it.

  pending: wait leaves a prompt with nowhere to go waiting for `pit answer`,
  up to the agent's pinentry timeout, if it has one. If `pit answer` goes
  away before answering, the prompt waits again. never fails at once.

  hook: run with sh when a prompt opens and closes, in the background,
  with PIT_EVENT (open, close), PIT_TITLE, PIT_ORIGIN (as in the title),
  PIT_ORIGIN_GUESS (1 when it's a guess, behind a proxy) and PIT_WHERE
  ("popup <client tty>", "inline <tty>", "gui <program>", "pending");
  never the passphrase. With origin = "full", think twice before sending
  PIT_ORIGIN anywhere that keeps it. e.g.
    hook = '''
    [ "$PIT_EVENT" = open ] &&
      notify-send "gpg wants a passphrase" "$PIT_TITLE"
    '''
    hook = '''
    [ "$PIT_EVENT/$PIT_WHERE" = open/pending ] &&
      notify-send "gpg is waiting" "run pit answer"
    '''

  hook and [gui] pinentry name programs to run as you, so they're taken
  only from a config file that's yours and that no one else can write.

*awkward scenarios

- a terminal in raw mode (full screen, or reading keys) is never asked: it
  could take some of the passphrase. tmux is used when available,
  otherwise the GUI or a pending prompt, if set, otherwise it fails.
- nor is a terminal where another program in the foreground reads it
  (`cat | gpg -d`), or has opened it to (`gpg -d | ssh host`, asking for a
  password). When gpg-agent doesn't say who asked (an old one, without
  OPTION owner), anything reading there counts, the command itself
  included. Looked for again while the prompt is open: one that turns up
  then cancels it, and gpg is told why.
- behind a proxy in front of gpg-agent (yubikey-touch-detector), who asked
  is the proxy's client. If that isn't clear, the title names only a pane,
  marked "?" (e.g. "work:2.1 ?"), and a terminal is only asked if nothing
  there reads it.
- the popup can't open (the client already has one): asked in place on
  gpg's terminal, or in a pane only with inline auto and nothing
  full-screen showing.
- the popup closed from tmux mid-prompt: cancelled.
- nowhere to ask at all: "No pinentry" error to gpg, saying why.
- a pending prompt nobody answers in the agent's timeout: timeout.

testing
  - cargo test: unit tests, plus the binary driven through ptys and an
    isolated tmux server (skipped if tmux isn't installed)
  - cargo test --test gpg_agent -- --ignored: through a real gpg-agent
  - PIT_TEST_SHOW=1 cargo test -- --nocapture: print the screen at each step
  - PIT_TEST_LIVE=1 cargo test: replay the tests on this terminal, typing
    slowly (PIT_TEST_SLOW=ms per key, default 120)
  - cargo test --test screenshots -- --ignored --nocapture --test-threads=1:
    print the screenshots above
