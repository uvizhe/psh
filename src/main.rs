use std::collections::HashMap;
use std::fmt;
use std::io::Write;
use std::path::PathBuf;
use std::process;
use std::thread;
use std::time::Duration;

use aes::cipher::{block_padding::Pkcs7, BlockDecryptMut, BlockEncryptMut, KeyIvInit};
use anyhow::{bail, Context, Result};
use argon2::{
    password_hash::{Output, PasswordHasher, SaltString},
    Algorithm, Argon2, ParamsBuilder, Version
};
use clap::{AppSettings, ArgGroup, Parser};
use clipboard::{ClipboardProvider, ClipboardContext};
use console::Term;
use dialoguer::{Input, Select, Password, theme::Theme};
use home::home_dir;
use pickledb::{PickleDb, PickleDbDumpPolicy};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

const DB_FILE: &str = ".psh.db";
const PASSWORD_LEN: usize = 16;
const COLLECTED_BYTES_LEN: usize = 64;
const SAFEGUARD_TIMEOUT: u64 = 120;
const MASTER_PASSWORD_MEM_COST: u32 = 64 * 1024;
const MASTER_PASSWORD_TIME_COST: u32 = 10;

// TODO: Use `zeroize` to wipe password from memory.

type Aes128CbcDec = cbc::Decryptor<aes::Aes128>;
type Aes128CbcEnc = cbc::Encryptor<aes::Aes128>;

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

#[derive(Copy, Clone, Serialize, Deserialize)]
enum CharSet {
    Standard,
    Reduced,
}

fn db_file() -> PathBuf {
    let mut db_file = home_dir()
        .expect("User has no home directory");
    db_file.push(DB_FILE);

    db_file
}

fn get_db() -> Result<PickleDb> {
    let db: PickleDb;

    let db_file = db_file();
    if db_file.exists() {
        db = PickleDb::load_json(&db_file, PickleDbDumpPolicy::AutoDump)
            .context(format!("Failed to open `{:?}`", db_file))?;
    } else {
        db = PickleDb::new_json(&db_file, PickleDbDumpPolicy::AutoDump);
    }

    Ok(db)
}

fn get_master_password() -> String {
    let term = Term::stdout();
    let mut password_prompt = Password::new();
    let master_password_prompt =
        if db_file().exists() {
            password_prompt.with_prompt("Enter master password")
        } else {
            term.write_line(
                "Set master password (it's used to securely store your aliases and hash passwords)."
            ).unwrap();
            password_prompt.with_prompt("Enter password")
                .with_confirmation("Repeat password", "Passwords mismatch")
        };

    let master_password = master_password_prompt
        .interact()
        .unwrap();

    assert!(master_password.len() >= 8);

    // Remove the prompt
    if db_file().exists() {
        term.clear_last_lines(1).unwrap();
    } else {
        term.clear_last_lines(3).unwrap();
    }

    hash_master_password(&master_password)
}

fn hash_master_password(master_password: &str) -> String {
    let mut argon2_params = ParamsBuilder::new();
    argon2_params.m_cost(MASTER_PASSWORD_MEM_COST).unwrap()
        .t_cost(MASTER_PASSWORD_TIME_COST).unwrap();
    let argon2_params = argon2_params.params().unwrap();
    let salt = SaltString::b64_encode(&master_password.as_ref()).unwrap();
    let argon2 = Argon2::new(Algorithm::default(), Version::default(), argon2_params);
    let hash = argon2.hash_password(&[], &salt)
        .expect("Argon2 is unable to produce hash for the master password");
    hash.hash.unwrap().to_string()
}

fn get_aliases(db: &PickleDb, hashed_mp: &str) -> Result<HashMap<String, String>> {
    let mut aliases = HashMap::new();
    let mut enc_aliases = db.get_all();
    if let Some(nonce) = enc_aliases.iter().position(|x| x == "nonce") {
        enc_aliases.remove(nonce);
    }
    for enc_alias in enc_aliases.iter() {
        let alias = decrypt_alias(enc_alias, hashed_mp)?;
        aliases.insert(alias, enc_alias.to_owned());
    }
    Ok(aliases)
}

fn get_nonce(db: &PickleDb) -> u32 {
    if let Some(nonce) = db.get::<u32>("nonce") {
        nonce + 1
    } else {
        0
    }
}

fn pad_to_30_bytes(string: &str) -> [u8; 30] {
    assert!(string.len() <= 30);
    let mut padded: [u8; 30] = [0; 30];
    let mut bytes = string.as_bytes().to_vec();
    bytes.reverse();
    padded.as_mut_slice().write(&bytes).unwrap();
    padded.reverse();
    padded
}

fn encrypt_alias(alias: &str, hashed_mp: &str, nonce: &u32) -> String {
    let padded_alias = pad_to_30_bytes(&alias);
    let salt = hashed_mp.to_owned() + &nonce.to_string();
    let salt = Sha256::digest(salt);
    // In AES128 key size and iv size are the same, 16 bytes, half of SHA256
    let (key, iv) = salt.split_at(16);
    let mut buf = [0u8; 32];
    let enc = Aes128CbcEnc::new(key.into(), iv.into())
        .encrypt_padded_b2b_mut::<Pkcs7>(&padded_alias, &mut buf)
        .unwrap();
    let enc = &[nonce.to_le_bytes().as_slice(), enc].concat();
    let enc = Output::new(enc).unwrap();
    enc.to_string()
}

fn decrypt_alias(alias: &str, hashed_mp: &str) -> Result<String> {
    let alias =
        if let Ok(alias) = Output::b64_decode(&alias) {
            alias
        } else {
            bail!("Unable to read DB entry `{}`", alias)
        };
    let nonce: [u8; 4] = alias.as_bytes()[0..4].try_into()?;
    let nonce = u32::from_le_bytes(nonce);
    let salt = hashed_mp.to_owned() + &nonce.to_string();
    let salt = Sha256::digest(salt);
    // In AES128 key size and iv size are the same, 16 bytes, half of SHA256
    let (key, iv) = salt.split_at(16);
    let mut buf = [0u8; 32];
    if let Ok(dec) = Aes128CbcDec::new(key.into(), iv.into())
        .decrypt_padded_b2b_mut::<Pkcs7>(&alias.as_bytes()[4..], &mut buf)
    {
        let alias_bytes: Vec<u8> = dec.iter().filter(|x| **x != 0).map(|&x| x).collect();
        assert!(alias_bytes.is_ascii());
        Ok(String::from_utf8(alias_bytes)?)
    } else {
        bail!("Unable to decrypt DB entry `{}`", alias)
    }
}

fn get_charset(db: &PickleDb, alias: &str) -> CharSet {
    let charset: CharSet;

    if let Some(configured) = db.get(alias) {
        charset = configured;
    } else {
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
    }

    charset
}

// Generates COLLECTED_BYTES_LEN bytes using argon2 hashing algorithm with alias and secret as inputs.
// Alias is used for salt and is hased beforehand with SHA256 to satisfy salt minimum length.
fn collect_bytes(hashed_alias: &str, secret: &str, charset: CharSet) -> Vec<u8> {
    let mut argon2_params = ParamsBuilder::new();
    argon2_params.output_len(COLLECTED_BYTES_LEN).unwrap();
    let argon2_params = argon2_params.params().unwrap();
    let argon2 = Argon2::new(Algorithm::default(), Version::default(), argon2_params);
    let hash = argon2.hash_password(secret.as_ref(), hashed_alias).unwrap();
    let hash = hash.hash.unwrap();

    let mut collected_bytes = Vec::new();
    for byte in hash.as_bytes() {
        // ASCII has 94 printable characters (excluding space) starting from 33rd.
        let shifted = (*byte as u16) << 8;     // Shift value so it exceeds 94
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
    let cli = Cli::parse();

    let theme = PshTheme;

    let term = Term::stdout();

    let mut db = get_db().unwrap();

    let (hashed_mp, aliases) = loop {
        // Ask user for master password
        let hashed_mp = get_master_password();

        if let Ok(aliases) = get_aliases(&db, &hashed_mp) {
            break (hashed_mp, aliases);
        } else {
            term.write_line("Wrong master password").unwrap();
        }
    };

    if cli.list {
        let aliases: Vec<&str> = aliases.keys().map(|x| x.as_str()).collect();
        term.write_line(&format!("{}", aliases.join(" "))).unwrap();
        process::exit(0); // TODO: Do this with conditionals
                          // TODO: Hide the list like password
    }

    let alias =
        if let Some(cli_alias) = cli.alias {
            // TODO: Check for non-empty string
            cli_alias
        } else {
            // Ask user for alias
            Input::with_theme(&theme)
                .with_prompt("Alias")
                .interact_text()
                .unwrap()
        };

    let (encrypted_alias, new_nonce) =
        if let Some(existing) = aliases.get(&alias) {
            (existing.to_owned(), None)
        } else {
            let nonce = get_nonce(&db);
            let enc_alias = encrypt_alias(&alias, &hashed_mp, &nonce);
            (enc_alias, Some(nonce))
        };

    // Get saved charset for an alias or ask user if it is a new alias
    let charset = get_charset(&db, &encrypted_alias);

    // Ask user for secret
    let secret = Password::new()
        .with_prompt("Secret")
        .interact()
        .unwrap();

    let collected_bytes = collect_bytes(&encrypted_alias, &secret, charset);
    // Pick password bytes to satisfy charset
    let password_slice = pick_suitable_slice(collected_bytes, charset);

    let password = String::from_utf8(password_slice).unwrap();

    // Print password to STDOUT
    let mut output_password = password.clone();
    if cli.paranoid {
        output_password.replace_range(3..13, "**********");
    }

    term.write_line(&output_password).unwrap();

    if new_nonce.is_some() {
        db.set(&encrypted_alias, &charset).unwrap();
        db.set("nonce", &new_nonce.unwrap()).unwrap();
    }

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
                if cli.clipboard {
                    // TODO: use `x11-clipboard` instead of `clipboard`?
                    let mut clipboard: ClipboardContext = ClipboardProvider::new().unwrap();
                    clipboard.set_contents(password).unwrap();
                    // Without this sleep clipboard contents don't set for some reason
                    thread::sleep(Duration::from_millis(10));
                }
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
