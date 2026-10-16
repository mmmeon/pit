pit - gpg-agent pinentry that prompts in a tmux popup

tmux
  - popup on the most recently active client, over the current window
  - other attached clients get a status-line note saying where it is
  - popup title names the command that asked and its pane, e.g.
    "git commit -S @ work:2.1" (from the pid gpg-agent passes as owner)
  - sized to fit the prompt
  - styles: set -g @pinentry-style bar|box|line   (default bar)
  - echo:   set -g @pit-echo marker|dots|none (default marker;
            marker changes per key without revealing length)
  - inline: set -g @pit-inline auto|never     (default auto)
            auto draws the prompt in place under the command that asked,
            instead of in a popup, when that command is in the foreground
            of its own pane and nothing full-screen is showing there.
            never always uses the popup in panes. Either way, a terminal
            outside tmux is asked inline, even with tmux running.
            A terminal in raw mode (a full-screen program reading keys) is
            never asked: it could take some of the passphrase. Outside
            tmux that means the popup, or no prompt if no client is attached.
            Nor is one where another program in the foreground job reads
            the terminal (e.g. `cat | gpg -d`, or `cat` there while gpg asks
            from elsewhere), when gpg-agent says who asked. Not caught: one
            that opens /dev/tty itself without raw mode, which is rare.
  - hook:   set -g @pit-hook '<command>'
            run with sh when a prompt opens and closes (once the open run
            is done), in the background, with PIT_EVENT (open|close),
            PIT_TITLE, PIT_ORIGIN (the command and pane that asked) and
            PIT_WHERE ("popup <client tty>" or "inline <tty>"); never the
            passphrase. A command line can hold secrets, though, so think
            twice before sending PIT_ORIGIN anywhere that keeps or shows it
            (a notification history, a lock screen). e.g.
              set -g @pit-hook '[ "$PIT_EVENT" = open ] &&
                notify-send "gpg wants a passphrase" "$PIT_TITLE"'
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

screenshots
  bar (default), along the bottom of the client:

    ┌─ gpg · git commit -S @ work:2.0 ─────────────────────────────────────┐
    │ Please enter the passphrase to unlock the OpenPGP secret key         │
    │ "Alice <alice@example.org>" · 255-bit EDDSA key, ID 3AA5C34371567BD2 │
    │ created 2024-03-01.                                                  │
    │ Passphrase: [•·•·]                                                   │
    └──────────────────────────────────────────────────────────────────────┘
    [work] 0:zsh- 2:git*

  box, centred:

    ┌─ gpg · git commit -S @ work:2.0 ──────────────────────────────┐
    │ Please enter the passphrase to unlock the OpenPGP secret key: │
    │ "Alice <alice@example.org>"                                   │
    │ 255-bit EDDSA key, ID 3AA5C34371567BD2,                       │
    │ created 2024-03-01.                                           │
    │                                                               │
    │ Passphrase: [•••·]                                            │
    └───────────────────────────────────────────────────────────────┘

  line, the description summed up in the title:

    ┌─ gpg · Alice <alice@example.org> ───┐
    │ Passphrase: [••·•]                  │
    └─────────────────────────────────────┘

  echo marker, dots, none (after typing 7 characters):

    │ Passphrase: [•··•]                 │
    │ Passphrase: •••••••                │
    │ Passphrase:                        │

  wrong passphrase:

    ┌─ gpg · git commit -S @ work:2.0 ──────────────────────────────┐
    │ Please enter the passphrase to unlock the OpenPGP secret key: │
    │ "Alice <alice@example.org>"                                   │
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
    │ (alice@laptop)                                     │
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
     "Alice <alice@example.org>" · 255-bit EDDSA key, ID 3AA5C34371567BD2
     created 2024-03-01.
     Passphrase: [••··]

fallback
  - command run in a terminal outside tmux: prompt drawn in place on that
    terminal and erased afterwards, even if a tmux client is attached
  - no tmux client attached: same, on gpg's terminal
  - popup can't open (e.g. client already has one): same, on gpg's terminal
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
