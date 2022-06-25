use argon2::{self, Config};
use dialoguer::{Input, Password};
use sha2::{Sha224, Digest};

// TODO: Add reduced character set password generation ability
// TODO: Make global salt/password to add to local salt or password (so attacker couldn't easily
//       guess inputs).
// TODO: Show generated password until user hits Ctrl-C to exit program (then crear password from
//       console)
fn main() {
    let alias: String = Input::new()
        .with_prompt("Alias")
        .interact_text()
        .unwrap();

    let password = Password::new()
        .with_prompt("Password")
        .interact()
        .unwrap();

    let salt = Sha224::digest(alias); // Make salt satisfy length criterium
    let config = Config::default();
    let hash = argon2::hash_raw(password.as_ref(), &salt, &config).unwrap();

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
