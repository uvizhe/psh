use aes::cipher::{
    block_padding::Pkcs7,
    BlockDecryptMut, BlockEncryptMut, KeyIvInit,
};
use anyhow::{bail, Result};
use argon2::{Argon2, Params};
use base64ct::{Base64, Encoding};
use once_cell::unsync::OnceCell;
use zeroize::Zeroizing;

use super::{
    CharSet, PshError, ZeroizingString, ZeroizingVec,
    ALIAS_MAX_LEN,
};

type Aes128CbcDec = cbc::Decryptor<aes::Aes128>;
type Aes128CbcEnc = cbc::Encryptor<aes::Aes128>;

#[derive(Debug)]
pub(crate) struct AliasData {
    alias: ZeroizingString,
    encrypted_alias: OnceCell<ZeroizingString>,
    nonce: u32,
    use_secret: bool,
    charset: CharSet,
}

impl AliasData {
    pub fn new(alias: &ZeroizingString, nonce: u32, use_secret: bool, charset: CharSet) -> Self {
        Self {
            alias: alias.clone(),
            encrypted_alias: OnceCell::new(),
            nonce,
            use_secret,
            charset,
        }
    }

    pub fn new_known(encrypted_alias: &ZeroizingString, password: &ZeroizingVec) -> Result<Self> {
        Self::decrypt_alias(encrypted_alias, password)
    }

    pub fn alias(&self) -> &ZeroizingString {
        &self.alias
    }

    pub fn encrypted_alias(&self) -> Option<&ZeroizingString> {
        self.encrypted_alias.get()
    }

    pub fn nonce(&self) -> u32 {
        self.nonce
    }

    pub fn use_secret(&self) -> bool {
        self.use_secret
    }

    pub fn charset(&self) -> CharSet {
        self.charset
    }

    // XXX: Is it safe to pad with predictable data?
    fn padded_alias(&self) -> [u8; ALIAS_MAX_LEN] {
        let alias_len = self.alias.len();
        let mut padded = [0u8; ALIAS_MAX_LEN];
        padded[..alias_len].copy_from_slice(self.alias.as_bytes());
        padded
    }

    fn encode_nonce_and_flags(&self) -> Vec<u8> {
        let mut nonce_and_flags = self.nonce;
        nonce_and_flags <<= 2;
        // Lower security choices set flags to 1, defaults (0) are the most secure
        if !self.use_secret {
            nonce_and_flags |= 1;
        }
        if self.charset == CharSet::Reduced {
            nonce_and_flags |= 1 << 1;
        }
        nonce_and_flags.to_le_bytes().to_vec()
    }

    fn extract_nonce(encrypted_alias: &[u8]) -> u32 {
        let nonce: [u8; 4] = encrypted_alias[0..4].try_into().unwrap();
        let nonce = u32::from_le_bytes(nonce);
        nonce >> 2
    }

    fn extract_secret_flag(encrypted_alias: &[u8]) -> bool {
        let bit_flags: u8 = encrypted_alias[0].try_into().unwrap();
        match bit_flags & 1 {
            0 => false, // zero bit isn't set => use secret
            _ => true,  // zero bit is set => do not use secret
        }
    }

    fn extract_charset(encrypted_alias: &[u8]) -> CharSet {
        let bit_flags: u8 = encrypted_alias[0].try_into().unwrap();
        match bit_flags & (1 << 1) {
            0 => CharSet::Standard, // 1st bit isn't set => Standard
            _ => CharSet::Reduced,  // 1st bit is set => Reduced
        }
    }

    pub fn encrypt_alias(&mut self, password: &ZeroizingVec) {
        // Make all aliases the same length by padding them
        let alias = self.padded_alias();

        // From hashed password and nonce derive DEFAULT_OUTPUT_LEN bytes for AES encryption
        let salt = [0u8; 16];
        let mut hasher_buf = Zeroizing::new([0u8; Params::DEFAULT_OUTPUT_LEN]);
        let argon2 = Argon2::default();
        let input = ZeroizingVec::new(
            [
                self.nonce().to_le_bytes().as_slice(),
                password,
            ].concat()
        );
        argon2.hash_password_into(&input, &salt, &mut *hasher_buf)
            .expect("Error hashing with Argon2");

        // In AES128 key size and IV size are the same, 16 bytes, half of default argon2 output len
        let (key, iv) = hasher_buf.split_at(16);
        let mut encrypter_buf = Zeroizing::new([0u8; ALIAS_MAX_LEN * 2]);
        let encrypted = Aes128CbcEnc::new(key.into(), iv.into())
            .encrypt_padded_b2b_mut::<Pkcs7>(&alias, &mut *encrypter_buf)
            .unwrap();

        // Concatenate encrypted alias with service data and encode with base64
        let alias_rec_bytes = Zeroizing::new(
            [&self.encode_nonce_and_flags(), encrypted].concat()
        );
        let mut encoder_buf = Zeroizing::new([0u8; ALIAS_MAX_LEN * 2]);
        let alias_rec = Base64::encode(&alias_rec_bytes, &mut *encoder_buf).unwrap();
        self.encrypted_alias.set(ZeroizingString::new(alias_rec.to_string())).unwrap();
    }

    fn decrypt_alias(encrypted_alias: &ZeroizingString, password: &ZeroizingVec) -> Result<Self> {
        // Decode base64 alias data representation
        let mut decoder_buf = Zeroizing::new([0u8; ALIAS_MAX_LEN * 2]);
        let enc_alias = Base64::decode(&encrypted_alias.as_bytes(), &mut *decoder_buf)
            .map_err(|err| PshError::DbAliasDecodeError(encrypted_alias.clone(), err))?;

        let nonce = Self::extract_nonce(&enc_alias);
        let use_secret = !Self::extract_secret_flag(&enc_alias);
        let charset = Self::extract_charset(&enc_alias);

        // Decrypt alias
        let salt = [0u8; 16];
        let mut hasher_buf = Zeroizing::new([0u8; Params::DEFAULT_OUTPUT_LEN]);
        let argon2 = Argon2::default();
        let input = ZeroizingVec::new(
            [
                nonce.to_le_bytes().as_slice(),
                password,
            ].concat()
        );
        argon2.hash_password_into(&input, &salt, &mut *hasher_buf)
            .expect("Error hashing with Argon2");
        // In AES128 key size and IV size are the same, 16 bytes, half of default argon2 output len
        let (key, iv) = hasher_buf.split_at(16);
        let mut decrypter_buf = Zeroizing::new([0u8; ALIAS_MAX_LEN * 2]);
        let dec_result = Aes128CbcDec::new(key.into(), iv.into())
            .decrypt_padded_b2b_mut::<Pkcs7>(&enc_alias[4..], &mut *decrypter_buf);
        match dec_result {
            Ok(dec) => {
                let alias_bytes = ZeroizingVec::new(
                    dec.iter()
                        .filter(|x| **x != 0x0) // Unpad ZeroPadding
                        .map(|&x| x)
                        .collect()
                );
                let alias = ZeroizingString::new(
                    std::str::from_utf8(&alias_bytes)?
                        .to_string()
                );
                Ok(Self {
                    alias,
                    encrypted_alias: OnceCell::with_value(encrypted_alias.clone()),
                    nonce,
                    use_secret,
                    charset,
                })
            }
            Err(_) => bail!(PshError::MasterPasswordWrong),
        }
    }
}
