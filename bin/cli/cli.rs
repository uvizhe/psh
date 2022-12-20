use std::fmt;
use std::process;
use std::sync::mpsc::channel;
use std::thread;
use std::time::Duration;

use clap::{AppSettings, ArgGroup, Parser};
use console::Term;
use dialoguer::{
    theme::Theme,
    Confirm, Input, Select, Password,
};

use psh::{CharSet, Psh, ZeroizingString, ALIAS_MAX_BYTES, MASTER_PASSWORD_MIN_LEN};

const SAFEGUARD_TIMEOUT: u64 = 120;

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
    pub alias: Option<ZeroizingString>,

    /// List all aliases stored in database
    #[clap(short, long)]
    pub list: bool,

    /// Remove given alias from database
    #[clap(long, requires = "alias")]
    pub remove: bool,

    /// Copy password into clipboard on exit (with Enter key)
    #[clap(short, long)]
    pub clipboard: bool,

    /// Do not show full password, only first and last 3 characters
    #[clap(short, long)]
    pub paranoid: bool,
}

fn trim_string(value: &str) -> Result<ZeroizingString, String> {
    let value = value.trim();
    if value.is_empty() {
        Err("Empty string".to_string())
    } else if value.len() > ALIAS_MAX_BYTES {
        Err(format!("Alias too long. Must be {} bytes at most", ALIAS_MAX_BYTES))
    } else {
        Ok(ZeroizingString::new(value.to_string()))
    }
}

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

pub fn prompt_master_password() -> ZeroizingString {
    let mut password_prompt = Password::new();
    let master_password_prompt =
        if Psh::has_db() {
            password_prompt.with_prompt("Enter master password")
        } else {
            let term = Term::stdout();
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

    let master_password = ZeroizingString::new(
        master_password_prompt
            .interact()
            .unwrap()
    );

    master_password
}

pub fn prompt_alias() -> ZeroizingString {
    let theme = PshTheme;

    let alias = ZeroizingString::new(
        Input::with_theme(&theme)
            .with_prompt("Alias")
            .validate_with(|input: &String| {
                let input = input.trim();
                if input.is_empty() {
                    Err("Alias cannot be empty".to_string())
                } else if input.len() > ALIAS_MAX_BYTES {
                    Err(format!("Alias too long. Must be {} bytes at most", ALIAS_MAX_BYTES))
                } else {
                    Ok(())
                }
            })
            .interact_text()
            .unwrap(),
    );

    ZeroizingString::new(
        alias
            .trim()
            .to_string()
    )
}

pub fn prompt_charset() -> CharSet {
    let charset: CharSet;
    let sets = vec![CharSet::Standard, CharSet::Reduced, CharSet::RequireAll];

    let choice = Select::new()
        .with_prompt("Looks like you use this alias for the first time.
Please, select preferred character set for passwords for this alias.
NOTE: Standard character set can include all printable ASCII characters while Reduced set includes only letters and digits. RequireAll set guarantees that password will include characters of all types (digit, lowercase letter, uppercase letter and punctuation)")
        .items(&vec!["Standard", "Reduced", "RequireAll"])
        .default(0)
        .interact()
        .unwrap();

    charset = sets[choice];

    charset
}

pub fn prompt_secret_use() -> bool {
    Confirm::new()
        .with_prompt(
            "Do you want to use a secret word for this alias for even higher level of Security?"
        )
        .default(true)
        .interact()
        .unwrap()
}

pub fn prompt_secret() -> ZeroizingString {
    ZeroizingString::new(
        Password::new()
            .with_prompt("Secret")
            .interact()
            .unwrap()
    )
}

pub fn print_aliases(psh: &Psh) {
    let term = Term::stdout();
    let aliases: Vec<&str> = psh.aliases()
        .iter()
        .map(|x| x.as_str())
        .collect();
    term.write_line(&format!("Previously used aliases: {}", aliases.join(", ")))
        .unwrap();
}

pub fn before_cleanup_on_enter_or_timeout<F>(f: F)
where
    F: Fn(),
{
    // Clear last lines (with password/aliases) before exiting
    let cleanup = || {
        let term = Term::stdout();
        term.clear_last_lines(2).unwrap();
    };

    // Handle Ctrl-C
    ctrlc::set_handler(move || {
        cleanup();
        process::exit(0);
    })
    .expect("Error setting Ctrl-C handler");

    let (sender, receiver) = channel();

    thread::spawn(move || {
        let term = Term::stdout();
        term.write_line("Hit Enter to exit").unwrap();
        term.read_line().unwrap();
        term.clear_last_lines(1).unwrap();
        sender.send("finished").unwrap();
    });

    // Wait for user interaction or timeout
    let time = Duration::from_secs(SAFEGUARD_TIMEOUT);
    receiver.recv_timeout(time).ok();

    f();
    cleanup();
}
