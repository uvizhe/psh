use argon2::{self, Config};
use dialoguer::{Input, Select, Password};
use home::home_dir;
use pickledb::{PickleDb, PickleDbDumpPolicy};
use serde::{Deserialize, Serialize};
use sha2::{Sha224, Digest};

const DB_FILE: &str = ".psh.db";
const PASSWORD_LEN: usize = 16;
// TODO: Add reduced character set password generation ability
// TODO: Make global salt/password to add to local salt or secret (so attacker couldn't easily
//       guess inputs).
// TODO: Show generated password until user hits Ctrl-C to exit program (then crear password from
//       console).
//       Maybe even don't show full password and copy it to clipboard with Ctrl-C

#[derive(Copy, Clone, Serialize, Deserialize)]
enum CharSet {
    Standard,
    Reduced,
}

fn main() {
    let mut db: PickleDb;

    let mut db_file = home_dir().unwrap();
    db_file.push(DB_FILE);

    if db_file.exists() {
        db = PickleDb::load_json(db_file, PickleDbDumpPolicy::AutoDump).unwrap();
    } else {
        db = PickleDb::new_json(db_file, PickleDbDumpPolicy::AutoDump);
    }

    let alias: String = Input::new()
        .with_prompt("Alias")
        .interact_text()
        .unwrap();

    let charset_config: CharSet;
    if let Some(conf) = db.get(&alias) {
        charset_config = conf;
    } else {
        println!("Looks like you use this alias for the first time.
Please, select preferred character set for passwords that'll be generated
for this alias."
        );
        println!("Note: Standard character set consists of all printable ASCII characters
while Reduced set includes only letters and digits."
        );
        let sets = vec![CharSet::Standard, CharSet::Reduced];
        let charset = Select::new()
            .items(&vec!["Standard", "Reduced"])
            .default(0)
            .interact()
            .unwrap();
        db.set(&alias, &sets[charset]).unwrap();
        charset_config = sets[charset];
    }

    let secret = Password::new()
        .with_prompt("Secret")
        .interact()
        .unwrap();

    let salt = Sha224::digest(alias); // Make salt satisfy length criterium
    let mut config = Config::default();
    config.hash_length = 64;
    let hash = argon2::hash_raw(secret.as_ref(), &salt, &config).unwrap();

    let mut collected_bytes = Vec::new();
    for byte in hash {
        // ASCII has 94 printable characters (excluding space) starting from 33rd.
        let shifted = (byte as u16) << 8;     // Shift value so it exceeds 94
        let pos_relative = shifted % 94;      // Find relative position of a char in between 94 values
        let pos_absolute = pos_relative + 33; // Shift it to a starting pos of "good" chars
        match charset_config {
            CharSet::Standard => collected_bytes.push(pos_absolute as u8),
            CharSet::Reduced => {
                if (pos_absolute as u8).is_ascii_alphanumeric() {
                    collected_bytes.push(pos_absolute as u8);
                }
            }
        }
    }
    assert!(collected_bytes.is_ascii());

    // Check Standard and Reduced set for inclusion of punctuation and numeric characters
    // respectively.
    // If the first chunk of `collected_bytes` does not meet the criterium try to use next.
    let mut password_slice: Vec<u8> = vec![];
    let mut remaining_bytes = collected_bytes.clone();
    match charset_config {
        // Check if Standard set password include punctuation characters
        // (chance of opposite is (62/94)^16 = ~0.1%)
        CharSet::Standard => {
            while !remaining_bytes.is_empty() {
                if remaining_bytes.len() >= PASSWORD_LEN {
                    password_slice = remaining_bytes
                        .drain(0..PASSWORD_LEN)
                        .collect();
                    if password_slice.iter().any(|b| b.is_ascii_punctuation()) {
                        break;
                    }
                } else {
                    // last resort
                    collected_bytes.reverse();
                    password_slice = collected_bytes
                        .drain(0..PASSWORD_LEN)
                        .collect();
                    break;
                }
            }
        }
        // Check if Reduced set password include numeric characters
        // (chance of opposite is (52/62)^16 = ~0.4%)
        CharSet::Reduced => {
            while !remaining_bytes.is_empty() {
                if remaining_bytes.len() >= PASSWORD_LEN {
                    password_slice = remaining_bytes
                        .drain(0..PASSWORD_LEN)
                        .collect();
                    if password_slice.iter().any(|b| b.is_ascii_digit()) {
                        break;
                    }
                } else {
                    // last resort
                    collected_bytes.reverse();
                    password_slice = collected_bytes
                        .drain(0..PASSWORD_LEN)
                        .collect();
                    break;
                }
            }
        }
    }
    assert!(password_slice.len() == PASSWORD_LEN);

    let password = String::from_utf8(password_slice).unwrap();
    println!("{}", password);
}
