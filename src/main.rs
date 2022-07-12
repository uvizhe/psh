use std::fmt;
use std::process;
use std::thread;
use std::time::Duration;

use argon2::{self, Config};
use clipboard::{ClipboardProvider, ClipboardContext};
use console::{self, Term};
use ctrlc;
use dialoguer::{Input, Select, Password, theme::Theme};
use home::home_dir;
use pickledb::{PickleDb, PickleDbDumpPolicy};
use serde::{Deserialize, Serialize};
use sha2::{Sha224, Digest};

const DB_FILE: &str = ".psh.db";
const PASSWORD_LEN: usize = 16;
const COLLECTED_BYTES_LEN: u32 = 64;
const SAFEGUARD_TIMEOUT: u64 = 120;
// TODO: Make global salt/password to add to local salt or secret (so attacker couldn't easily
//       guess inputs).
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

#[derive(Copy, Clone, Serialize, Deserialize)]
enum CharSet {
    Standard,
    Reduced,
}

fn get_db() -> PickleDb {
    let db: PickleDb;

    let mut db_file = home_dir().unwrap();
    db_file.push(DB_FILE);

    if db_file.exists() {
        db = PickleDb::load_json(db_file, PickleDbDumpPolicy::AutoDump).unwrap();
    } else {
        db = PickleDb::new_json(db_file, PickleDbDumpPolicy::AutoDump);
    }

    db
}

fn get_charset(term: &Term, db: &mut PickleDb, alias: &str) -> CharSet {
    let charset: CharSet;

    if let Some(configured) = db.get(alias) {
        charset = configured;
    } else {
        term.write_line("Looks like you use this alias for the first time.
Please, select preferred character set for passwords that'll be generated
for this alias.
Note: Standard character set consists of all printable ASCII characters
while Reduced set includes only letters and digits."
        ).unwrap();

        let sets = vec![CharSet::Standard, CharSet::Reduced];
        let charset_choice = Select::new()
            .items(&vec!["Standard", "Reduced"])
            .default(0)
            .interact()
            .unwrap();

        charset = sets[charset_choice];
    }

    charset
}

// Generates COLLECTED_BYTES_LEN bytes using argon2 hashing algorithm with alias and secret as inputs.
// Alias is used for salt and is hased beforehand with SHA224 to satisfy salt minimum length.
fn collect_bytes(alias: &str, secret: &str, charset: CharSet) -> Vec<u8> {
    let mut config = Config::default();
    config.hash_length = COLLECTED_BYTES_LEN;
    let salt = Sha224::digest(alias.to_owned()); // Make salt satisfy length criterium
    let hash = argon2::hash_raw(secret.as_ref(), &salt, &config).unwrap();

    let mut collected_bytes = Vec::new();
    for byte in hash {
        // ASCII has 94 printable characters (excluding space) starting from 33rd.
        let shifted = (byte as u16) << 8;     // Shift value so it exceeds 94
        let pos_relative = shifted % 94;      // Find relative position of a char in between 94 values
        let pos_absolute = pos_relative + 33; // Shift it to a starting pos of "good" chars
        match charset {
            CharSet::Standard => collected_bytes.push(pos_absolute as u8),
            CharSet::Reduced => {
                if (pos_absolute as u8).is_ascii_alphanumeric() {
                    collected_bytes.push(pos_absolute as u8);
                }
            }
        }
    }
    assert!(collected_bytes.is_ascii());

    collected_bytes
}

// Checks Standard and Reduced set for inclusion of punctuation and numeric characters respectively.
// If the first chunk of `collected_bytes` does not meet the criterium tries to use next and so on.
fn pick_suitable_slice(collected_bytes: Vec<u8>, charset: CharSet) -> Vec<u8> {
    let mut password_slice: Vec<u8> = vec![];
    let slices = collected_bytes.chunks_exact(PASSWORD_LEN);
    for slice in slices {
        match charset {
            CharSet::Standard => {
                // Check if Standard set password include punctuation characters
                // (chance it's not is (62/94)^PASSWORD_LEN)
                if slice.iter().any(|b| b.is_ascii_punctuation()) {
                    password_slice = slice.to_vec();
                    break;
                }
            }
            CharSet::Reduced => {
                // Check if Reduced set password include numeric characters
                // (chance it's not is (52/62)^PASSWORD_LEN)
                if slice.iter().any(|b| b.is_ascii_digit()) {
                    password_slice = slice.to_vec();
                    break;
                }
            }
        }
    }
    if password_slice.is_empty() {
        // Last resort (just take last PASSWORD_LEN bytes from `collected_bytes`)
        let last_chunk_pos = collected_bytes.len() - PASSWORD_LEN;
        password_slice = collected_bytes[last_chunk_pos..].to_vec();
    }
    assert!(password_slice.len() == PASSWORD_LEN);

    password_slice
}

// Completely clears command output on terminal
fn clear_password(term: &Term) {
    term.clear_last_lines(1).unwrap();
}

fn main() {
    let theme = PshTheme;

    let term = Term::stdout();

    let mut db = get_db();

    // Ask user for alias
    let alias: String = Input::with_theme(&theme)
        .with_prompt("Alias")
        .interact_text()
        .unwrap();

    // Get saved charset for an alias or ask user if it is a new alias
    let charset = get_charset(&term, &mut db, &alias);

    // Ask user for secret
    let secret = Password::new()
        .with_prompt("Secret")
        .interact()
        .unwrap();

    let collected_bytes = collect_bytes(&alias, &secret, charset);
    // Pick password bytes to satisfy charset
    let password_slice = pick_suitable_slice(collected_bytes, charset);

    let password = String::from_utf8(password_slice).unwrap();

    // Print password to STDOUT
    term.write_line(&password).unwrap();

    db.set(&alias, &charset).unwrap();

    // Handle Ctrl-C
    // Clear everything before exiting a program
    ctrlc::set_handler(|| {
        let term = Term::stdout();
        clear_password(&term);
        process::exit(0);
    }).unwrap();

    let user = thread::spawn(move || {
        let term = Term::stdout();
        loop {
            let input = term.read_line().unwrap();
            term.clear_last_lines(1).unwrap();
            if input.is_empty() {
                let mut clipboard: ClipboardContext = ClipboardProvider::new().unwrap();
                clipboard.set_contents(password).unwrap();
                thread::sleep(Duration::from_millis(1)); // Without this line clipboard contents don't set for some reason
                break;
            }
        }
    });

    // Safeguard which clears the screen if no interaction occurs in two minutes
    let timer = thread::spawn(|| {
        thread::sleep(Duration::from_secs(SAFEGUARD_TIMEOUT));
    });

    // Wait for user interaction or a safeguard activation
    loop {
        if user.is_finished() || timer.is_finished() {
            clear_password(&term);
            break;
        }
    }
}
