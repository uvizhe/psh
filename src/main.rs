use argon2::{self, Config};
use dialoguer::{Input, Select, Password};
use home::home_dir;
use pickledb::{PickleDb, PickleDbDumpPolicy};
use serde::{Deserialize, Serialize};
use sha2::{Sha224, Digest};

const DB_FILE: &str = ".psh.db";
// TODO: Add reduced character set password generation ability
// TODO: Make global salt/password to add to local salt or secret (so attacker couldn't easily
//       guess inputs).
// TODO: Show generated password until user hits Ctrl-C to exit program (then crear password from
//       console)

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
    let config = Config::default();
    let hash = argon2::hash_raw(secret.as_ref(), &salt, &config).unwrap();

    let mut ascii_bytes = Vec::new();
    for byte in hash {
        // ASCII has 94 printable characters (excluding space) starting from 33rd.
        let shifted = (byte as u16) << 8;     // Shift value so it exceeds 94
        let pos_relative = shifted % 94;      // Find relative position of a char in between 94 values
        let pos_absolute = pos_relative + 33; // Shift it to a starting pos of "good" chars
        ascii_bytes.push(pos_absolute as u8);
    }
    assert!(ascii_bytes.is_ascii());
    let ascii_hash = String::from_utf8(ascii_bytes).unwrap();
    println!("{}", ascii_hash);
}
