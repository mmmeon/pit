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
//! With nowhere on a terminal, it can hand the prompt to a graphical
//! pinentry, or leave it waiting for `pit answer` in any terminal.
//!
//! Settings are in ~/.config/pit/config.toml; see config.rs.

mod answer;
mod assuan;
mod config;
mod gpg;
mod gui;
mod origin;
mod sys;
mod tmux;
mod ui;

use std::env;
use std::path::Path;
use std::process::ExitCode;

const HELP: &str = "\
pit: a pinentry that asks in a tmux popup

usage: set it as pinentry-program in ~/.gnupg/gpg-agent.conf:
  pinentry-program /path/to/pit
then run `gpg-connect-agent reloadagent /bye`. gpg-agent starts it and
speaks the pinentry protocol on stdin/stdout.

  pit answer             answer a prompt left waiting (pending = \"wait\"),
                         on this terminal

options:
  -h, --help             print this and exit
  -T, --ttyname FILE     gpg's terminal, to prompt on outside tmux
  -N, --ttytype NAME     that terminal's type
  -D, --display DISPLAY  the X display, for a GUI pinentry ([gui] in settings)
other pinentry options (--timeout, ...) are accepted and ignored.

settings: ~/.config/pit/config.toml ($XDG_CONFIG_HOME/pit/config.toml)
";

fn main() -> ExitCode {
    sys::protect_memory();
    let args: Vec<String> = env::args().skip(1).collect();
    let result = match args.as_slice() {
        [flag, dir] if flag == "--ui" => tmux::ui_main(Path::new(dir)),
        [cmd] if cmd == "answer" => answer::main(),
        [flag] if flag == "--help" || flag == "-h" => {
            print!("{HELP}");
            Ok(())
        }
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
