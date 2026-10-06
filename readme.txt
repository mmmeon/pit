pinentry-tmux - gpg-agent pinentry that prompts in a tmux popup

tmux
  - popup on the most recently active client, over the current window
  - sized to fit the prompt
  - styles: set -g @pinentry-style bar|box|line   (default bar)
  - echo:   set -g @pinentry-echo marker|dots|none (default marker;
            marker changes per key without revealing length)
  - passphrase, repeat/confirm-new-passphrase, confirm and message dialogs
  - wrong-passphrase and mismatch errors shown inline
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
