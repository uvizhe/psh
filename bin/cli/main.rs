use std::process;
use std::thread;
use std::time::Duration;

use clap::Parser;
use clipboard::{ClipboardContext, ClipboardProvider};
use console::Term;

use crate::cli::*;
use psh::Psh;

mod cli;

fn psh() -> Psh {
    let term = Term::stdout();

    let master_password = prompt_master_password();

    let psh = match Psh::new(master_password) {
        Ok(psh) => psh,
        Err(error) => {
            term.write_line(&error.to_string()).unwrap();
            process::exit(1);
        }
    };
    psh
}

fn main() {
    let cli = Cli::parse();
    let term = Term::stdout();

    if cli.list {
        if Psh::has_db() {
            print_aliases(&psh());
            before_cleanup_on_enter_or_timeout(|| {});
        }
    } else if cli.remove {
        let psh = psh();
        let alias = cli.alias
            .expect("Alias is not given");
        match psh.remove_alias_from_db(&alias) {
            Ok(()) => return,
            Err(error) => {
                term.write_line(&error.to_string()).unwrap();
                process::exit(1);
            }
        }
    } else {
        let mut psh = psh();
        let alias =
            if let Some(cli_alias) = cli.alias {
                cli_alias
            } else {
                prompt_alias()
            };

        let charset = Some(
            if psh.alias_is_known(&alias) {
                psh.get_charset(&alias)
            } else {
                prompt_charset()
            });

        let use_secret =
            if psh.alias_is_known(&alias) {
                psh.alias_uses_secret(&alias)
            } else {
                prompt_secret_use()
            };

        let secret =
            if use_secret {
                Some(prompt_secret())
            } else {
                None
            };

        let password = psh.derive_password(&alias, secret, charset);

        let mut output_password = password.clone();
        if cli.paranoid {
            output_password.replace_range(3..13, "**********");
        }
        term.write_line(&output_password)
            .unwrap();

        if !psh.alias_is_known(&alias) {
            psh.append_alias_to_db(&alias, Some(use_secret), charset).unwrap();
        }

        before_cleanup_on_enter_or_timeout(|| {
            if cli.clipboard {
                // TODO: use `x11-clipboard` instead of `clipboard`?
                let mut clipboard: ClipboardContext = ClipboardProvider::new()
                    .expect("Error getting clipboard provider");
                clipboard.set_contents(password.to_string())
                    .expect("Error setting clipboard contents");
                // XXX: Without this sleep clipboard contents don't set for some reason
                thread::sleep(Duration::from_millis(10));
            }
        });
    }
}
