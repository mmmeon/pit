pit - gpg-agent pinentry that prompts in a tmux popup

tmux
  - popup on the most recently active client, over the current window
  - other attached clients get a status-line note saying where it is
  - popup title names the command that asked and its pane, e.g.
    "git commit @ work:2.1" (from the pid gpg-agent passes as owner): only
    the program and subcommand, unless origin = "full"
  - behind a proxy in front of gpg-agent (yubikey-touch-detector), which
    gpg-agent takes for the owner, the command is the proxy's client. If
    that isn't clear (several at once, none on gpg's terminal), the title
    names only a pane, marked with a "?": the one on gpg's terminal, or the
    one you're looking at, e.g. "work:2.1 ?"
  - sized to fit the prompt
  - styles: see config, [tmux] style
  - in place in a pane, instead of a popup: see config, [tmux] inline
  - passphrase, repeat/confirm-new-passphrase, confirm and message dialogs
  - wrong-passphrase and mismatch errors shown inline
  - prompts that only give a fingerprint (ssh keys without a comment) get
    the key's OpenPGP user ID next to it, if gpg knows the keygrip
  - smartcard PIN prompts, which only give the card number, get the user
    ID of the key with subkeys on that card
  - enter submits, esc/ctrl-c cancels, backspace deletes, ctrl-u clears;
    button mnemonics in confirm dialogs
  - honours gpg-agent's pinentry timeout
  - popup closes when gpg-agent kills the pinentry; no leftover files

config
  ~/.config/pit/config.toml ($XDG_CONFIG_HOME/pit/config.toml), read for
  each prompt. TOML, strings only; a key that doesn't parse or isn't known
  is skipped, so a typo never stops the prompt.

    echo = "marker"     # marker|dots|none (default marker; marker
                        # changes per key without revealing length)
    origin = "short"    # short|full (default short), see below
    hook = '<command>'  # see below

    [tmux]
    style = "bar"       # bar|box|line, the popup (default bar)
    inline = "auto"     # auto|never (default auto)

  inline: auto draws the prompt in place under the command that asked,
  instead of in a popup, when that command is in the foreground of its own
  pane and nothing full-screen is showing there. never doesn't ask in a
  pane at all, even if the popup can't open. Either way, a terminal outside
  tmux is asked inline, even with tmux running.
  A terminal in raw mode (a full-screen program reading keys) is never
  asked: it could take some of the passphrase. Outside tmux that means the
  popup, or no prompt if no client is attached. Nor is one where another
  program in the foreground job reads the terminal (e.g. `cat | gpg -d`, or
  `cat` there while gpg asks from elsewhere), when gpg-agent says who asked.
  Not caught: one that opens /dev/tty itself without raw mode, which is rare.
  Behind a proxy whose client isn't clear, whatever is in the foreground
  can't be told apart from who asked, so a terminal isn't asked unless
  nothing there reads it. When there's nowhere to ask, gpg's error says why.

  origin: how the command that asked is named, in the title and the hook.
  short gives the program and, if the next word looks like a subcommand,
  that too ("git commit", "mysql"); full gives the whole command line,
  which may hold secrets (mysql -p..., a URL with a password) and puts them
  on screen. A guessed origin is only ever a pane.

  hook: run with sh when a prompt opens and closes (once the open run is
  done), in the background, with PIT_EVENT (open|close), PIT_TITLE,
  PIT_ORIGIN (the command and pane that asked, as in the title),
  PIT_ORIGIN_GUESS (1 when PIT_ORIGIN is a guess, behind a proxy; empty
  otherwise) and PIT_WHERE ("popup <client tty>" or "inline <tty>"); never
  the passphrase. With origin = "full" a command line can hold secrets, so
  think twice before sending PIT_ORIGIN anywhere that keeps or shows it (a
  notification history, a lock screen). e.g.
    hook = '''
    [ "$PIT_EVENT" = open ] &&
      notify-send "gpg wants a passphrase" "$PIT_TITLE"
    '''

screenshots
  bar (default), along the bottom of the client:

    ┌─ gpg · git commit -S @ work:2.0 ─────────────────────────────────────┐
    │ Please enter the passphrase to unlock the OpenPGP secret key         │
    │ "User <user@example.org>" · 255-bit EDDSA key, ID 3AA5C34371567BD2   │
    │ created 2024-03-01.                                                  │
    │ Passphrase: [•·•·]                                                   │
    └──────────────────────────────────────────────────────────────────────┘
    [work] 0:zsh- 2:git*

  box, centred:

    ┌─ gpg · git commit -S @ work:2.0 ──────────────────────────────┐
    │ Please enter the passphrase to unlock the OpenPGP secret key: │
    │ "User <user@example.org>"                                     │
    │ 255-bit EDDSA key, ID 3AA5C34371567BD2,                       │
    │ created 2024-03-01.                                           │
    │                                                               │
    │ Passphrase: [•••·]                                            │
    └───────────────────────────────────────────────────────────────┘

  line, the description summed up in the title:

    ┌─ gpg · User <user@example.org> ───┐
    │ Passphrase: [••·•]                │
    └───────────────────────────────────┘

  echo marker, dots, none (after typing 7 characters):

    │ Passphrase: [•··•]               │
    │ Passphrase: •••••••              │
    │ Passphrase:                      │

  wrong passphrase:

    ┌─ gpg · git commit -S @ work:2.0 ──────────────────────────────┐
    │ Please enter the passphrase to unlock the OpenPGP secret key: │
    │ "User <user@example.org>"                                     │
    │ 255-bit EDDSA key, ID 3AA5C34371567BD2,                       │
    │ created 2024-03-01.                                           │
    │                                                               │
    │ Bad Passphrase (try 2 of 3)                                   │
    │ Passphrase: [····]                                            │
    └───────────────────────────────────────────────────────────────┘

  new passphrase, after a mismatch:

    ┌─ gpg · git commit -S @ work:2.0 ─────────────────┐
    │ Please enter a passphrase to protect the new key │
    │                                                  │
    │ does not match - try again                       │
    │ Passphrase: [····]                               │
    └──────────────────────────────────────────────────┘

  confirm:

    ┌─ gpg · git commit -S @ work:2.0 ───────────────────┐
    │ An ssh process requested the use of key            │
    │ SHA256:Xg5lV0wHqR6c8eZ9o1C3pJ2bDkF4aT7nYyLmQsUvWiE │
    │ (user@laptop)                                      │
    │ Do you want to allow this?                         │
    │                                                    │
    │ ⏎ Allow   d Deny   esc Cancel                      │
    └────────────────────────────────────────────────────┘

  message:

    ┌─ gpg · git commit -S @ work:2.0 ─────────┐
    │ No card found. Insert your OpenPGP card. │
    │                                          │
    │ ⏎ OK                                     │
    └──────────────────────────────────────────┘

  status-line note on the other attached clients:

    pinentry: gpg - prompt open on /dev/pts/15

  in place, outside tmux:

    ~/src/notes $ git commit -S -m 'Fix typo'
     Please enter the passphrase to unlock the OpenPGP secret key
     "User <user@example.org>" · 255-bit EDDSA key, ID 3AA5C34371567BD2
     created 2024-03-01.
     Passphrase: [••··]

fallback
  - command run in a terminal outside tmux: prompt drawn in place on that
    terminal and erased afterwards, even if a tmux client is attached
  - no tmux client attached: same, on gpg's terminal
  - popup can't open (e.g. client already has one): same, on gpg's terminal;
    a pane only with inline auto and nothing full-screen showing there
  - ssh: add to ~/.ssh/config so the agent knows ssh's terminal:
      Match host * exec "GPG_TTY=$(tty <&2) gpg-connect-agent UPDATESTARTUPTTY /bye >/dev/null"

error
  - no tmux client and no known terminal: "No pinentry" error to gpg
  - terminal known but unopenable and no tmux client: same error
  - popup closed from tmux mid-prompt: cancelled

testing
  - cargo test: unit tests, plus the binary driven through ptys and an
    isolated tmux server (skipped if tmux isn't installed)
  - cargo test --test gpg_agent -- --ignored: through a real gpg-agent
  - PIT_TEST_SHOW=1 cargo test -- --nocapture: print the screen at each step
  - PIT_TEST_LIVE=1 cargo test: replay the tests on this terminal, at its
    size, one at a time, typing slowly (PIT_TEST_SLOW=ms per key, default 120)
  - cargo test --test screenshots -- --ignored --nocapture --test-threads=1:
    print the screenshots above
