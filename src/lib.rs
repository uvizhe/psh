use std::fmt;
use std::process;
use std::thread;
use std::time::Duration;

use clap::{AppSettings, ArgGroup, Parser};
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
pub struct Cli {
    /// Alias to use
    #[clap(value_parser = trim_string)]
    pub alias: Option<String>,

    /// List all aliases stored in database
    #[clap(short, long)]
    pub list: bool,

    /// Copy password into clipboard on exit (with Enter key)
    #[clap(short, long)]
    pub clipboard: bool,

    /// Do not show full password, only first and last 3 characters
    #[clap(short, long)]
    pub paranoid: bool,
}

fn trim_string(value: &str) -> Result<String, String> {
    if value.trim().is_empty() {
        Err("Empty string".to_string())
    } else {
        Ok(value.to_string())
    }
}

pub fn get_or_set_master_password() -> String {
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

pub fn get_alias() -> String {
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

pub fn get_charset() -> CharSet {
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

pub fn get_secret() -> String {
    Password::new()
            .with_prompt("Secret")
            .interact()
            .unwrap()
}

pub fn print_aliases(psh: &Psh) {
    let aliases: Vec<&str> = psh.aliases().iter().map(|x| x.as_str()).collect();
    let term = Term::stdout();
    term.write_line(&format!("Previously used aliases: {}", aliases.join(" "))).unwrap();
}

pub fn cleanup_on_enter_or_timeout<F>(f: F)
    where F: Fn()
{
    // Handle Ctrl-C
    // Clear last lines (with password/aliases) before exiting
    ctrlc::set_handler(|| {
        let term = Term::stdout();
        term.clear_last_lines(2).unwrap();
        process::exit(0);
    }).expect("Error setting Ctrl-C handler");

    // Safeguard which clears the screen if no interaction occurs in two minutes
    let timer = thread::spawn(|| {
        thread::sleep(Duration::from_secs(SAFEGUARD_TIMEOUT));
    });

    let prompt = thread::spawn(|| {
        let term = Term::stdout();
        term.write_line("Hit Enter to exit").unwrap();
        term.read_line().unwrap();
        term.clear_last_lines(1).unwrap();
    });

    // Wait for user interaction or a safeguard activation
    loop {
        if prompt.is_finished() || timer.is_finished() {
            f();
            // Clear last lines (with password/aliases) before exiting
            let term = Term::stdout();
            term.clear_last_lines(2).unwrap();
            return;
        }
    }
}
