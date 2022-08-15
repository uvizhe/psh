use std::fmt;
use std::process;
use std::thread;
use std::time::Duration;

use clap::{AppSettings, ArgGroup, Parser};
use clipboard::{ClipboardProvider, ClipboardContext};
use console::Term;
use dialoguer::{Input, Select, Password, theme::Theme};

use psh::{Psh, CharSet, db_file, MASTER_PASSWORD_MIN_LEN};

const SAFEGUARD_TIMEOUT: u64 = 120;

// TODO: Use `zeroize` to wipe password from memory.

struct PshTheme;

impl Theme for PshTheme {
    fn format_input_prompt_selection(
        &self,
        f: &mut dyn fmt::Write,
        prompt: &str,
        _sel: &str,
    ) -> fmt::Result {
        write!(f, "{}: {}", prompt, "[hidden]")
    }
}

#[derive(Parser)]
#[clap(version)]
#[clap(global_setting(AppSettings::DeriveDisplayOrder))]
#[clap(group(
            ArgGroup::new("interactive")
                .args(&["alias", "clipboard", "paranoid"])
                .multiple(true)
                .conflicts_with("list"),
        ))]
/// Password hasher (compute deterministic passwords from alias and secret)
struct Cli {
    /// Alias to use
    #[clap(value_parser = trim_string)]
    alias: Option<String>,

    /// List all aliases stored in database
    #[clap(short, long)]
    list: bool,

    /// Copy password into clipboard on exit (with Enter key)
    #[clap(short, long)]
    clipboard: bool,

    /// Do not show full password, only first and last 3 characters
    #[clap(short, long)]
    paranoid: bool,
}

fn trim_string(value: &str) -> Result<String, String> {
    if value.trim().is_empty() {
        Err("Empty string".to_string())
    } else {
        Ok(value.to_string())
    }
}

fn get_or_set_master_password() -> String {
    let term = Term::stdout();
    let mut password_prompt = Password::new();
    let master_password_prompt =
        if db_file().exists() {
            password_prompt.with_prompt("Enter master password")
        } else {
            term.write_line(
                "Set master password (it's used to securely store your aliases and hash passwords).")
            .unwrap();
            password_prompt
                .with_prompt(
                    &format!(
                        "Enter password, {} characters minimum",
                        MASTER_PASSWORD_MIN_LEN))
                .with_confirmation("Repeat password", "Passwords mismatch")
        };

    let master_password = master_password_prompt
        .interact()
        .unwrap();

    master_password
}

fn get_alias() -> String {
    let theme = PshTheme;

    let alias = Input::with_theme(&theme)
        .with_prompt("Alias")
        .validate_with(|input: &String| {
            if input.trim().is_empty() {
                Err("Alias cannot be empty")
            } else {
                Ok(())
            }
        })
        .interact_text()
        .unwrap();

    alias
        .trim()
        .to_string()
}

fn get_charset() -> CharSet {
    let charset: CharSet;

    let sets = vec![CharSet::Standard, CharSet::Reduced];
    let charset_choice = Select::new()
        .with_prompt("Looks like you use this alias for the first time.
Please, select preferred character set for passwords for this alias.
NOTE: Standard character set consists of all printable ASCII characters while Reduced set includes only letters and digits")
        .items(&vec!["Standard", "Reduced"])
        .default(0)
        .interact()
        .unwrap();

    charset = sets[charset_choice];

    charset
}

fn get_secret() -> String {
    Password::new()
            .with_prompt("Secret")
            .interact()
            .unwrap()
}

fn print_aliases(psh: &Psh) {
    // TODO: Clear terminal after SAFEGUARD_TIMEOUT
    let aliases: Vec<&str> = psh.aliases().iter().map(|x| x.as_str()).collect();
    let term = Term::stdout();
    term.write_line(&format!("Previously used aliases: {}", aliases.join(" "))).unwrap();
    term.write_line("Hit Enter to exit").unwrap();

    // Handle Ctrl-C
    // Clear last lines (with aliases) before exiting
    ctrlc::set_handler(|| {
        let term = Term::stdout();
        term.clear_last_lines(2).unwrap();
        process::exit(0);
    }).expect("Error setting Ctrl-C handler");

    loop {
        let input = term.read_line().unwrap();
        term.clear_last_lines(1).unwrap();
        if input.is_empty() {
            // Clear last lines (with aliases) before exiting
            term.clear_last_lines(2).unwrap();
            return;
        }
    }
}

fn spawn_user_thread(password: String, use_clipboard: bool) -> thread::JoinHandle<()> {
    thread::spawn(move || {
        let term = Term::stdout();
        term.write_line("Hit Enter to exit").unwrap();

        loop {
            let input = term.read_line().unwrap();
            term.clear_last_lines(1).unwrap();
            if input.is_empty() {
                if use_clipboard {
                    // TODO: use `x11-clipboard` instead of `clipboard`?
                    let mut clipboard: ClipboardContext = ClipboardProvider::new()
                        .expect("Error getting clipboard provider");
                    clipboard.set_contents(password)
                        .expect("Error setting clipboard contents");
                    // XXX: Without this sleep clipboard contents don't set for some reason
                    thread::sleep(Duration::from_millis(10));
                }
                return;
            }
        }
    })
}

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
        return;
    }

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

    // Handle Ctrl-C
    // Clear last lines (with password) before exiting
    ctrlc::set_handler(|| {
        let term = Term::stdout();
        term.clear_last_lines(2).unwrap();
        process::exit(0);
    }).expect("Error setting Ctrl-C handler");

    let user = spawn_user_thread(password, cli.clipboard);
    // Safeguard which clears the screen if no interaction occurs in two minutes
    let timer = thread::spawn(|| {
        thread::sleep(Duration::from_secs(SAFEGUARD_TIMEOUT));
    });

    // Wait for user interaction or a safeguard activation
    loop {
        if user.is_finished() || timer.is_finished() {
            // Clear last lines (with password) before exiting
            term.clear_last_lines(2).unwrap();
            return;
        }
    }
}
