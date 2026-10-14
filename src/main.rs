//! pit: a pinentry that asks in a tmux popup.
//!
//! Set it as `pinentry-program` in gpg-agent.conf. It speaks the pinentry
//! protocol itself, and when a passphrase or confirmation is needed it opens a
//! popup on the most recently active tmux client, sized to fit the prompt.
//! When the command was run outside tmux, it prompts in place on that
//! terminal instead. For ssh, keep the agent's idea of that terminal current
//! with this at the top of ~/.ssh/config:
//!   Match host * exec "GPG_TTY=$(tty <&2) gpg-connect-agent UPDATESTARTUPTTY /bye >/dev/null"
//!
//! Styles and echo are picked with tmux options:
//!   set -g @pinentry-style bar|box|line   (default: bar)
//!   set -g @pit-echo marker|dots|none   (default: marker)

mod assuan;
mod gpg;
mod origin;
mod sys;
mod tmux;
mod ui;

use std::env;
use std::path::Path;
use std::process::ExitCode;

fn main() -> ExitCode {
    let args: Vec<String> = env::args().skip(1).collect();
    let result = match args.as_slice() {
        [flag, dir] if flag == "--ui" => tmux::ui_main(Path::new(dir)),
        _ => assuan::serve(&args),
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("pit: {e}");
            ExitCode::FAILURE
        }
    }
}
