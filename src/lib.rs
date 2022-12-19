use std::collections::BTreeMap;
use std::fmt;
use std::fs::{self, File, Permissions};
use std::io::{BufRead, BufReader, BufWriter, Write};
use std::ops::{Deref, DerefMut};
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;

use anyhow::{bail, Result};
use argon2::{Algorithm, Argon2, Params, ParamsBuilder, Version};
use bitvec::prelude::*;
use thiserror::Error;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

mod alias_data;
use alias_data::{AliasData, Nonce};

pub const ALIAS_MAX_LEN: usize = 79;
pub const MASTER_PASSWORD_MIN_LEN: usize = 8;
const DB_FILE: &str = ".psh.db";
const PASSWORD_LEN: usize = 16;
const COLLECTED_BYTES_LEN: usize = 64;
const MASTER_PASSWORD_MEM_COST: u32 = 64 * 1024;
const MASTER_PASSWORD_TIME_COST: u32 = 10;

const SYMBOLS: [char; 104] = [
    '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', // Skip this line for Standard set
    '0', '1', '2', '3', '4', '5', '6', '7', '8', '9',
    'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M',
    'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U' ,'V', 'W', 'X', 'Y', 'Z',
    'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm',
    'n', 'o', 'p', 'q', 'r', 's', 't', 'u' ,'v', 'w', 'x', 'y', 'z',
    '!', '"', '#', '$', '%', '&', '\'', '(', ')', '*', '+', ',', '-', '.', '/', ':',
    ';', '<', '=', '>', '?', '@', '[', '\\', ']', '^', '_', '`', '{', '|', '}', '~',
];

fn db_file() -> PathBuf {
    let mut db_file = home::home_dir()
        .expect("User has no home directory");
    db_file.push(DB_FILE);

    db_file
}

fn db_tmp_file() -> PathBuf {
    let db_file = db_file();
    let mut db_tmp_file = db_file.into_os_string();
    db_tmp_file.push(".tmp");
    db_tmp_file.into()
}

fn hash_master_password(master_password: ZeroizingString) -> Result<ZeroizingVec> {
    if master_password.chars().count() < MASTER_PASSWORD_MIN_LEN {
        bail!(PshError::MasterPasswordTooShort);
    }
    let mut argon2_params = ParamsBuilder::new();
    argon2_params.m_cost(MASTER_PASSWORD_MEM_COST)
        .expect("Error setting Argon2 memory cost");
    argon2_params.t_cost(MASTER_PASSWORD_TIME_COST)
        .expect("Error setting Argon2 time cost");
    let argon2_params = argon2_params.params()
        .expect("Error getting Argon2 params");

    let salt = [0u8; 16];
    let mut buf = Zeroizing::new([0u8; Params::DEFAULT_OUTPUT_LEN]);
    let argon2 = Argon2::new(Algorithm::default(), Version::default(), argon2_params);
    argon2.hash_password_into(master_password.as_bytes(), &salt, &mut *buf)
        .expect("Error hashing master password");

    let hashed_mp = buf.to_vec();

    Ok(ZeroizingVec::new(hashed_mp))
}

pub struct Psh {
    master_password: ZeroizingVec,
    known_aliases: BTreeMap<ZeroizingString, AliasData>,
    last_nonce: Option<Nonce>,
    new_alias: Option<AliasData>,
}

impl Psh {
    pub fn new(master_password: ZeroizingString) -> Result<Self> {
        let hashed_mp = hash_master_password(master_password)?;

        let mut psh = Self {
            master_password: hashed_mp,
            known_aliases: BTreeMap::new(),
            last_nonce: None,
            new_alias: None,
        };

        psh.get_aliases()?;

        Ok(psh)
    }

    pub fn has_db() -> bool {
        let db = db_file();
        if db.exists() {
            let metadata = fs::metadata(db_file()).unwrap();
            if metadata.len() > 0 {
                return true;
            }
        }
        false
    }

    fn master_password(&self) -> &ZeroizingVec {
        &self.master_password
    }

    fn get_aliases(&mut self) -> Result<()> {
        if Self::has_db() {
            let db = File::open(db_file())?;
            let reader = BufReader::new(db);
            for line in reader.lines() {
                let enc_alias = ZeroizingString::new(line?);
                let alias_data = AliasData::new_known(&enc_alias, self.master_password())?;

                self.last_nonce = Some(alias_data.nonce());

                self.known_aliases.insert(alias_data.alias().clone(), alias_data);
            }
        }

        Ok(())
    }

    pub fn aliases(&self) -> Vec<&ZeroizingString> {
        self.known_aliases.keys().collect()
    }

    pub fn alias_is_known(&self, alias: &ZeroizingString) -> bool {
        self.known_aliases.contains_key(alias)
    }

    /// # Panics
    /// Panics if `alias` is not present in DB.
    pub fn alias_uses_secret(&self, alias: &ZeroizingString) -> bool {
        if let Some(alias_data) = self.known_aliases.get(alias) {
            alias_data.use_secret()
        } else {
            panic!("Unknown alias");
        }
    }

    /// # Panics
    /// Panics if `alias` is not present in DB.
    pub fn get_charset(&self, alias: &ZeroizingString) -> CharSet {
        if let Some(alias_data) = self.known_aliases.get(alias) {
            alias_data.charset()
        } else {
            panic!("Unknown alias");
        }
    }

    pub fn append_alias_to_db(&mut self) -> Result<()> {
        if let Some(alias_data) = &self.new_alias {
            let mut key = alias_data.encrypted_alias()
                .expect("Alias was not encrypted")
                .to_string();
            key.push('\n');

            let mut db = File::options().create(true).append(true).open(db_file())?;
            let user_only_perms = Permissions::from_mode(0o600);
            db.set_permissions(user_only_perms)?;
            db.write_all(&key.as_bytes())?;
            key.zeroize();
        } else {
            bail!("Cannot write uninitialized alias data to DB");
        }
        Ok(())
    }

    pub fn remove_alias_from_db(&self, alias: &ZeroizingString) -> Result<()> {
        if self.alias_is_known(alias) {
            let alias_data = self.known_aliases.get(alias).unwrap();
            let encrypted_alias = alias_data.encrypted_alias().unwrap();

            let db = File::open(db_file())?;
            let db_temp = File::create(db_tmp_file())?;
            let user_only_perms = Permissions::from_mode(0o600);
            db_temp.set_permissions(user_only_perms)?;

            let reader = BufReader::new(&db);
            let mut writer = BufWriter::new(&db_temp);

            for line in reader.lines() {
                let enc_alias = ZeroizingString::new(line?);
                if &enc_alias != encrypted_alias {
                    writeln!(writer, "{}", enc_alias)?;
                }
            }
            fs::rename(db_tmp_file(), db_file())?;
        } else {
            bail!(PshError::DbAliasRemovalError(alias.clone()));
        }
        Ok(())
    }

    /// # Panics
    /// Panics if `alias` is an empty string.
    /// Panics if `alias` is longer than ALIAS_MAX_LEN.
    /// Panics if `alias` expects `secret` but None or empty string is given.
    pub fn derive_password(
        &mut self,
        alias: &ZeroizingString,
        secret: Option<ZeroizingString>,
        charset: Option<CharSet>,
    ) -> ZeroizingString {
        if alias.is_empty() {
            panic!("Alias cannot be empty");
        }
        if alias.len() > ALIAS_MAX_LEN {
            panic!("Alias is too long (more than {} bytes)", ALIAS_MAX_LEN);
        }

        let charset = charset.unwrap_or(CharSet::Standard);
        let use_secret: bool;
        if self.alias_is_known(alias) {
            let alias_data = self.known_aliases.get(alias).unwrap();
            use_secret = alias_data.use_secret();
        } else {
            self.last_nonce = self.last_nonce
                .and_then(|n| Some(n.increment())) // increment nonce if it is initialized
                .or(Some(Nonce::new(0)));          // or initialize it otherwise
            use_secret = secret.is_some();
            let mut alias_data = AliasData::new(
                alias,
                self.last_nonce.unwrap(),
                use_secret,
                charset);
            alias_data.encrypt_alias(self.master_password());
            self.new_alias = Some(alias_data);
        }
        if use_secret && (secret.is_none() || secret.as_ref().unwrap().is_empty()) {
            panic!("Secret must not be empty for this alias");
        }

        let secret = secret.unwrap_or(ZeroizingString::new("".to_string()));
        let mut local_nonce = 0;
        let password = loop {
            let bytes = self.generate_bytes(alias, &secret, local_nonce);
            if let Ok(password_string) = Self::produce_password(charset, bytes) {
                break password_string
            }
            local_nonce += 1;
        };
        password
    }

    // Generates COLLECTED_BYTES_LEN bytes using argon2 hashing algorithm
    // with hashed_mp + alias and secret as inputs.
    fn generate_bytes(
        &self,
        alias: &ZeroizingString,
        secret: &ZeroizingString,
        nonce: usize,
    ) -> ZeroizingVec {
        let mut argon2_params = ParamsBuilder::new();
        argon2_params.output_len(COLLECTED_BYTES_LEN)
            .expect("Error setting Argon2 output length");
        let argon2_params = argon2_params.params()
            .expect("Error getting Argon2 params");

        let salt = [0u8; 16];
        let mut buf = Zeroizing::new([0u8; COLLECTED_BYTES_LEN]);
        let argon2 = Argon2::new(Algorithm::default(), Version::default(), argon2_params);
        let input = Zeroizing::new(
            [
                alias.as_bytes(),
                secret.as_bytes(),
                nonce.to_le_bytes().as_slice(),
                self.master_password(),
            ].concat()
        );
        argon2.hash_password_into(&input, &salt, &mut *buf)
            .expect("Error hashing with Argon2");

        ZeroizingVec::new(buf.to_vec())
    }

    // Iterate over 7-bit windows of input bytes gathering symbols
    // for password using SYMBOLS table.
    fn produce_password(charset: CharSet, bytes: ZeroizingVec) -> Result<ZeroizingString> {
        let mut password_chars: Zeroizing<Vec<char>> = Zeroizing::new(Vec::new());
        let bv = BitSlice::<_, Msb0>::from_slice(&bytes);
        let mut bv_iter = bv.windows(7);
        while let Some(bits) = bv_iter.next() {
            let mut pos: usize = bits.load_be();
            if pos < charset.len() {
                // Skip first 10 (duplicate) symbols for Standard set
                if charset == CharSet::Standard {
                    pos += 10;
                }
                password_chars.push(SYMBOLS[pos]);
                // Skip 6 bits + 1 with iteration = 7 bits of current `bits`
                bv_iter.nth(5);
            } else {
                // If `pos` >= `charset.len()`
                // -for Reduced set we know that MSB 0 = '1' and at least one of MSB 1,2,3 = '1'
                // -for Standard set we know that MSB 0 = '1' and MSB 1 very likely = '1'
                // -for RequireAll set we know that MSB 0,1 = '1' and at least one of MSB 2,3 = '1'
                // So skip 3 bits + 1 with iteration, because they are largely predetermined
                bv_iter.nth(2);
                continue;
            }
            if password_chars.len() == PASSWORD_LEN {
                match charset {
                    CharSet::Reduced | CharSet::Standard => break,
                    CharSet::RequireAll => {
                        if password_chars.iter().any(|b| b.is_ascii_digit())
                                && password_chars.iter().any(|b| b.is_ascii_lowercase())
                                && password_chars.iter().any(|b| b.is_ascii_uppercase())
                                && password_chars.iter().any(|b| b.is_ascii_punctuation()) {
                            break;
                        } else {
                            // Start over
                            password_chars.clear();
                        }
                    }
                }
            }
        }
        if password_chars.len() < PASSWORD_LEN {
            bail!("Not enough input data")
        }
        Ok(ZeroizingString::new(password_chars.iter().collect()))
    }
}

#[derive(Copy, Clone, Debug, PartialEq)]
pub enum CharSet {
    Standard,
    Reduced,
    RequireAll,
}

impl CharSet {
    fn len(&self) -> usize {
        match self {
            Self::Standard => 94,
            Self::Reduced => 72,
            Self::RequireAll => 104,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, ZeroizeOnDrop)]
pub struct ZeroizingString {
    string: String,
}

impl ZeroizingString {
    pub fn new(string: String) -> Self {
        Self {
            string,
        }
    }
}

impl Deref for ZeroizingString {
    type Target = String;

    fn deref(&self) -> &Self::Target {
        &self.string
    }
}

impl DerefMut for ZeroizingString {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.string
    }
}

impl fmt::Display for ZeroizingString {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.string)
    }
}

#[derive(ZeroizeOnDrop)]
pub(crate) struct ZeroizingVec {
    vec: Vec<u8>,
}

impl ZeroizingVec {
    fn new(vec: Vec<u8>) -> Self {
        Self {
            vec,
        }
    }
}

impl Deref for ZeroizingVec {
    type Target = Vec<u8>;

    fn deref(&self) -> &Self::Target {
        &self.vec
    }
}

// End-user facing errors
#[derive(Error, Debug)]
pub enum PshError {
    #[error("Unable to decode alias {0} as Base64: {1}")]
    DbAliasDecodeError(ZeroizingString, base64ct::Error),

    #[error("Cannot remove alias `{0}` from db: alias does not exist")]
    DbAliasRemovalError(ZeroizingString),

    #[error("Master password is too short (less than {} characters)", MASTER_PASSWORD_MIN_LEN)]
    MasterPasswordTooShort,

    #[error("Wrong master password")]
    MasterPasswordWrong,
}

#[cfg(test)]
mod tests {
    use super::*;
    use test_case::test_case;

    #[test]
    fn produce_password_fails_with_not_enough_bytes() {
        let bytes = ZeroizingVec::new([0u8; 13].to_vec()); // not enough bytes to produce password
        let charset = CharSet::Standard;
        let result = Psh::produce_password(charset, bytes);
        assert!(result.is_err());
    }

    #[test_case([0u8; 14], CharSet::Standard => "0000000000000000"; "zeros produce zeros")]
    #[test_case([2,4,8,16,32,64,129,2,4,8,16,32,64,129], CharSet::Standard
        => "1111111111111111"; "boolean 1 every 7 bits gives all 1s")]
    fn produce_password_with_14_bytes(bytes: [u8; 14], charset: CharSet) -> String {
        let bytes = ZeroizingVec::new(bytes.to_vec());
        Psh::produce_password(charset, bytes)
            .unwrap()
            .to_string()
    }

    #[test_case([224,0,65,4,16,65,4,0,0,65,4,16,65,4,0,0], CharSet::Standard
        => "01248GW#01248GW#"; "1st byte out of symbol table range (Standard set)")]
    #[test_case([224,0,65,4,16,65,4,0,0,65,4,16,65,4,0,0], CharSet::Reduced
        => "012486Ms012486Ms"; "1st byte out of symbol table range (Reduced set)")]
    #[test_case([236,0,65,4,16,65,4,0,0,65,4,16,65,4,0,0], CharSet::RequireAll
        => "]12486Ms012486Ms"; "1st byte out of symbol table range (RequireAll set)")]
    #[test_case([204,204,192,0,0,0,0,0,0,0,0,0,0,0,0,0], CharSet::Standard
        => panics "Not enough"; "not enough input data (Standard set)")]
    #[test_case([204,204,192,0,0,0,0,0,0,0,0,0,0,0,0,0], CharSet::Reduced
        => panics "Not enough"; "not enough input data (Reduced set)")]
    #[test_case([0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0], CharSet::RequireAll
        => panics "Not enough"; "not enough input data (RequireAll set)")]
    fn produce_password(bytes: [u8; 16], charset: CharSet) -> String {
        let bytes = ZeroizingVec::new(bytes.to_vec());
        Psh::produce_password(charset, bytes)
            .unwrap()
            .to_string()
    }
}
