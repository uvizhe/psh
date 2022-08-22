use std::thread;
use std::time::Duration;

use clap::Parser;
use clipboard::{ClipboardProvider, ClipboardContext};
use console::Term;

use psh::Psh;
use psh_cli::*;

fn main() {
    let cli = Cli::parse();
    let term = Term::stdout();

    let master_password = get_or_set_master_password();

    let mut psh = match Psh::new(&master_password) {
        Ok(psh) => psh,
        Err(error) => {
            term.write_line(&error.to_string())
                .expect("Unable to write to terminal");
            return;
        }
    };

    if cli.list {
        print_aliases(&psh);
        cleanup_on_enter_or_timeout(|| {});
    } else {
        let alias =
            if let Some(cli_alias) = cli.alias {
                cli_alias
            } else {
                get_alias()
            };

        let charset =
            if psh.alias_is_known(&alias) {
                psh.get_charset(&alias).unwrap()
            } else {
                get_charset()
            };

        let secret = get_secret();

        let password = psh.construct_password(&alias, &secret, Some(charset));

        // Print password to STDOUT
        let mut output_password = password.clone();
        if cli.paranoid {
            output_password.replace_range(3..13, "**********");
        }

        term.write_line(&output_password).unwrap();

        if !psh.alias_is_known(&alias) {
            psh.write_alias_data_to_db().unwrap();
        }

        cleanup_on_enter_or_timeout(|| {
            if cli.clipboard {
                // TODO: use `x11-clipboard` instead of `clipboard`?
                let mut clipboard: ClipboardContext = ClipboardProvider::new()
                    .expect("Error getting clipboard provider");
                clipboard.set_contents(password.clone())
                    .expect("Error setting clipboard contents");
                // XXX: Without this sleep clipboard contents don't set for some reason
                thread::sleep(Duration::from_millis(10));
            }
        });
    }
}
