pinentry-tmux - gpg-agent pinentry that prompts in a tmux popup

tmux
  - popup on the most recently active client, over the current window
  - sized to fit the prompt
  - styles: set -g @pinentry-style bar|box|line   (default bar)
  - echo:   set -g @pinentry-echo marker|dots|none (default marker;
            marker changes per key without revealing length)
  - passphrase, repeat/confirm-new-passphrase, confirm and message dialogs
  - wrong-passphrase and mismatch errors shown inline
  - prompts that only give a fingerprint (ssh keys without a comment) get
    the key's OpenPGP user ID next to it, if gpg knows the keygrip
  - enter submits, esc/ctrl-c cancels, backspace deletes, ctrl-u clears;
    button mnemonics in confirm dialogs
  - honours gpg-agent's pinentry timeout
  - popup closes when gpg-agent kills the pinentry; no leftover files

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
  - PIN_TEST_SHOW=1 cargo test -- --nocapture: print the screen at each step
  - PIN_TEST_LIVE=1 cargo test: replay the tests on this terminal, at its
    size, one at a time, typing slowly (PIN_TEST_SLOW=ms per key, default 120)
