use std::collections::HashMap;
use std::io::Write;
use std::path::PathBuf;

use aes::cipher::{block_padding::Pkcs7, BlockDecryptMut, BlockEncryptMut, KeyIvInit};
use anyhow::{bail, Result};
use argon2::{
    password_hash::{Output, PasswordHasher, SaltString},
    Algorithm, Argon2, ParamsBuilder, Version
};
use once_cell::unsync::OnceCell;
use pickledb::{PickleDb, PickleDbDumpPolicy};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

pub const MASTER_PASSWORD_MIN_LEN: usize = 8;
const DB_FILE: &str = ".psh.db";
const PASSWORD_LEN: usize = 16;
const COLLECTED_BYTES_LEN: usize = 64;
const MASTER_PASSWORD_MEM_COST: u32 = 64 * 1024;
const MASTER_PASSWORD_TIME_COST: u32 = 10;

type Aes128CbcDec = cbc::Decryptor<aes::Aes128>;
type Aes128CbcEnc = cbc::Encryptor<aes::Aes128>;

pub fn db_file() -> PathBuf {
    let mut db_file = home::home_dir()
        .expect("User has no home directory");
    db_file.push(DB_FILE);

    db_file
}

fn get_db() -> Result<PickleDb> {
    let db: PickleDb;
    let db_file = db_file();
    if db_file.exists() {
        db = PickleDb::load_json(&db_file, PickleDbDumpPolicy::AutoDump)
            .map_err(|err| PshError::DbOpenError(db_file, err))?;
    } else {
        db = PickleDb::new_json(&db_file, PickleDbDumpPolicy::AutoDump);
    }

    Ok(db)
}

fn hash_master_password(master_password: &str) -> Result<String> {
    if master_password.len() < MASTER_PASSWORD_MIN_LEN {
        bail!(PshError::MasterPasswordTooShort);
    }
    let mut argon2_params = ParamsBuilder::new();
    argon2_params.m_cost(MASTER_PASSWORD_MEM_COST)
        .expect("Error setting Argon2 memory cost");
    argon2_params.t_cost(MASTER_PASSWORD_TIME_COST)
        .expect("Error setting Argon2 time cost");
    let argon2_params = argon2_params.params()
        .expect("Error getting Argon2 params");
    let salt = SaltString::b64_encode(&master_password.as_ref())
        .expect("Error making a salt for master password");
    let argon2 = Argon2::new(Algorithm::default(), Version::default(), argon2_params);
    let hash = argon2.hash_password(&[], &salt)
        .expect("Error hashing master password");

    Ok(hash.hash.unwrap().to_string())
}

fn get_aliases(db: &PickleDb, hashed_mp: &str) -> Result<HashMap<String, AliasData>> {
    let mut aliases = HashMap::new();
    let enc_aliases = db.get_all();
    for enc_alias in enc_aliases.into_iter() {
        let enc_alias = Output::b64_decode(&enc_alias)
            .map_err(|err| PshError::DbAliasDecodeError(enc_alias, err))?;
        let alias_data = AliasData::new_known(enc_alias, hashed_mp)?;
        aliases.insert(alias_data.alias().to_string(), alias_data);
    }

    Ok(aliases)
}

pub struct Psh {
    db: PickleDb,
    master_password: String,
    known_aliases: HashMap<String, AliasData>,
    new_alias: Option<AliasData>,
}

impl Psh {
    pub fn new(master_password: &str) -> Result<Self> {
        let hashed_mp = hash_master_password(master_password)?;
        let db = get_db()?;
        let aliases = get_aliases(&db, &hashed_mp)?;

        let psh = Self {
            db: db,
            master_password: hashed_mp,
            known_aliases: aliases,
            new_alias: None,
        };

        Ok(psh)
    }

    pub fn aliases(&self) -> Vec<&String> {
        self.known_aliases.keys().collect()
    }

    pub fn alias_is_known(&self, alias: &str) -> bool {
        self.known_aliases.contains_key(alias)
    }

    /// # Panics
    /// Panics if `alias` is not present in DB.
    pub fn get_charset(&self, alias: &str) -> CharSet {
        if let Some(alias_data) = self.known_aliases.get(alias) {
            alias_data.charset()
        } else {
            panic!("Unknown alias");
        }
    }

    pub fn write_new_alias_to_db(&mut self) -> Result<()> {
        if let Some(alias_data) = &self.new_alias {
            let key = alias_data.encrypted_alias()
                .expect("Alias was not encrypted")
                .to_string();
            self.db.set(&key, &0)?;
        } else {
            bail!("Cannot write uninitialized alias data to DB");
        }
        Ok(())
    }

    /// # Panics
    /// Panics if `alias` is an empty string.
    /// Panics if `secret` is an empty string.
    pub fn construct_password(&mut self, alias: &str, secret: &str, charset: CharSet) -> String {
        if alias.is_empty() {
            panic!("Alias should not be empty");
        }
        if secret.is_empty() {
            panic!("Secret should not be empty");
        }

        if !self.alias_is_known(alias) {
            let nonce = self.get_new_nonce();
            let mut alias_data = AliasData::new(alias, nonce, charset);
            alias_data.encrypt_alias(&self.master_password);
            self.new_alias = Some(alias_data);
        }

        let collected_bytes = self.collect_bytes(alias, secret, charset);
        // Pick password bytes to satisfy charset
        let password_slice = Self::pick_suitable_slice(charset, collected_bytes);

        String::from_utf8(password_slice)
            .expect("Error producing password string from collected bytes")
    }

    fn get_new_nonce(&self) -> u32 {
        // TODO: Return nonce of last alias + 1
        self.db.total_keys() as u32
    }

    // Generates COLLECTED_BYTES_LEN bytes using argon2 hashing algorithm with hashed_mp + alias and secret as inputs.
    fn collect_bytes(&self, alias: &str, secret: &str, charset: CharSet) -> Vec<u8> {
        let mut argon2_params = ParamsBuilder::new();
        argon2_params.output_len(COLLECTED_BYTES_LEN)
            .expect("Error setting Argon2 output length");
        let argon2_params = argon2_params.params()
            .expect("Error getting Argon2 params");
        let argon2 = Argon2::new(Algorithm::default(), Version::default(), argon2_params);
        let salt = self.master_password.clone() + alias;
        let salt = SaltString::b64_encode(salt.as_bytes())
            .expect("Error making a salt for password");
        let hash = argon2.hash_password(secret.as_ref(), &salt)
            .expect("Error hashing master password");
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

        collected_bytes
    }

    // Checks Standard and Reduced set for inclusion of punctuation and numeric characters respectively.
    // If the first chunk of `collected_bytes` does not meet the criterium tries to use next and so on.
    fn pick_suitable_slice(charset: CharSet, collected_bytes: Vec<u8>) -> Vec<u8> {
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

        password_slice
    }
}

#[derive(Debug)]
struct AliasData {
    alias: String,
    encrypted_alias: OnceCell<Output>,
    nonce: u32,
    charset: CharSet,
}

impl AliasData {
    pub fn new(alias: &str, nonce: u32, charset: CharSet) -> Self {
        Self {
            alias: alias.to_string(),
            encrypted_alias: OnceCell::new(),
            nonce,
            charset,
        }
    }

    pub fn new_known(encrypted_alias: Output, password: &str) -> Result<Self> {
        let nonce = Self::extract_nonce(encrypted_alias);
        let charset = Self::extract_charset(encrypted_alias);

        let alias = Self::decrypt_alias(encrypted_alias, password)?;

        Ok(Self {
            alias,
            encrypted_alias: OnceCell::with_value(encrypted_alias),
            nonce,
            charset,
        })
    }

    pub fn alias(&self) -> &str {
        &self.alias
    }

    pub fn encrypted_alias(&self) -> Option<&Output> {
        self.encrypted_alias.get()
    }

    pub fn charset(&self) -> CharSet {
        self.charset
    }

    fn encode_nonce(&self) -> [u8; 4] {
        self.nonce.to_le_bytes()
    }

    fn encode_charset(&self) -> &[u8] {
        match self.charset {
            CharSet::Standard => &[0],
            CharSet::Reduced => &[1],
        }
    }

    fn extract_nonce(encrypted_alias: Output) -> u32 {
        let nonce: [u8; 4] = encrypted_alias.as_bytes()[0..4].try_into().unwrap();
        u32::from_le_bytes(nonce)
    }

    fn extract_charset(encrypted_alias: Output) -> CharSet {
        let charset: u8 = encrypted_alias.as_bytes()[4].try_into().unwrap();
        match charset {
            0 => CharSet::Standard,
            1 => CharSet::Reduced,
            _ => unreachable!("Unknown CharSet encoded")
        }
    }

    fn pad_to_30_bytes(string: &str) -> [u8; 30] {
        let mut padded: [u8; 30] = [0; 30];
        let mut bytes = string.as_bytes().to_vec();
        bytes.reverse();
        padded.as_mut_slice().write(&bytes).unwrap();
        padded.reverse();
        padded
    }

    fn encrypt_alias(&mut self, password: &str) {
        let padded_alias = Self::pad_to_30_bytes(&self.alias);
        let salt = password.to_string() + &self.nonce.to_string();
        let salt = Sha256::digest(salt);
        // In AES128 key size and iv size are the same, 16 bytes, half of SHA256
        let (key, iv) = salt.split_at(16);
        let mut buf = [0u8; 32];
        let enc = Aes128CbcEnc::new(key.into(), iv.into())
            .encrypt_padded_b2b_mut::<Pkcs7>(&padded_alias, &mut buf)
            .unwrap();
        let enc = &[self.encode_nonce().as_slice(), self.encode_charset(), enc].concat();
        let enc = Output::new(enc).unwrap();
        self.encrypted_alias.set(enc).unwrap();
    }

    fn decrypt_alias(encrypted_alias: Output, password: &str) -> Result<String> {
        let nonce = Self::extract_nonce(encrypted_alias);
        let salt = password.to_string() + &nonce.to_string();
        let salt = Sha256::digest(salt);
        // In AES128 key size and iv size are the same, 16 bytes, half of SHA256
        let (key, iv) = salt.split_at(16);
        let mut buf = [0u8; 32];
        let dec_result = Aes128CbcDec::new(key.into(), iv.into())
            .decrypt_padded_b2b_mut::<Pkcs7>(&encrypted_alias.as_bytes()[5..], &mut buf);
        match dec_result {
            Ok(dec) => {
                let alias_bytes: Vec<u8> = dec.iter().filter(|x| **x != 0).map(|&x| x).collect();
                Ok(String::from_utf8(alias_bytes)?)
            }
            Err(_) => bail!(PshError::MasterPasswordWrong),
        }
    }
}

#[derive(Copy, Clone, Debug, Serialize, Deserialize)]
pub enum CharSet {
    Standard,
    Reduced,
}

#[derive(Error, Debug)]
pub enum PshError {
    #[error("Failed to open {0}: {1}")]
    DbOpenError(PathBuf, pickledb::error::Error),

    #[error("Unable to decode alias {0} as Base64: {1}")]
    DbAliasDecodeError(String, argon2::password_hash::Error),

    #[error("Master password is too short (less than {} chars)", MASTER_PASSWORD_MIN_LEN)]
    MasterPasswordTooShort,

    #[error("Wrong master password")]
    MasterPasswordWrong,
}
