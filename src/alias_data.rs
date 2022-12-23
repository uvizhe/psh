use chacha20poly1305::{
    aead::{AeadCore, AeadInPlace, KeyInit, OsRng, heapless::Vec as HVec},
    ChaCha20Poly1305, Nonce,
};
use anyhow::{bail, Result};
use base64ct::{Base64, Encoding};
use once_cell::unsync::OnceCell;
use zeroize::{Zeroize, Zeroizing};

use super::{
    CharSet, PshError, ZeroizingString, ZeroizingVec,
    ALIAS_MAX_BYTES,
};

#[derive(Debug)]
pub(crate) struct AliasData {
    alias: ZeroizingString,
    encrypted_alias: OnceCell<ZeroizingString>,
    use_secret: bool,
    charset: CharSet,
}

impl AliasData {
    pub fn new(alias: &ZeroizingString, use_secret: bool, charset: CharSet) -> Self {
        Self {
            alias: alias.clone(),
            encrypted_alias: OnceCell::new(),
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

    pub fn use_secret(&self) -> bool {
        self.use_secret
    }

    pub fn charset(&self) -> CharSet {
        self.charset
    }

    // XXX: Is it safe to pad with predictable data?
    fn padded_alias(&self) -> [u8; ALIAS_MAX_BYTES] {
        let alias_len = self.alias.len();
        let mut padded = [0u8; ALIAS_MAX_BYTES];
        padded[..alias_len].copy_from_slice(self.alias.as_bytes());
        padded
    }

    fn encode_flags(&self) -> u8 {
        let mut flags = 0u8;
        // There are 8 bits to encode various flags:
        // LSB 0 is for secret flag: whether to use secret or not
        // (1 = use secret, 0 = do not use secret)
        if self.use_secret {
            flags |= 1;
        }
        // CharSet uses LSB 1,2 (00 = Standard, 01 = Reduced, 10 = RequireAll)
        match self.charset {
            CharSet::Standard => {}
            CharSet::Reduced => flags |= 1 << 1,
            CharSet::RequireAll => flags |= 1 << 2,
        }
        flags
    }

    #[allow(clippy::match_like_matches_macro)]
    fn extract_secret_flag(bit_flags: u8) -> bool {
        match bit_flags & 1 {
            0 => false, // zero bit isn't set => do not use secret
            _ => true,  // zero bit is set => use secret
        }
    }

    fn extract_charset(bit_flags: u8) -> CharSet {
        let charset_bits = bit_flags & (3 << 1);
        match charset_bits >> 1 {
            0 => CharSet::Standard,   // 00 => Standard
            1 => CharSet::Reduced,    // 01 => Reduced
            2 => CharSet::RequireAll, // 10 => RequireAll
            _ => unreachable!("Undefined CharSet"),
        }
    }

    pub fn encrypt_alias(&mut self, password: &ZeroizingVec) {
        // Make all aliases the same length by padding them
        let alias = self.padded_alias();

        // Encrypt alias using hashed password as ChaCha20Poly1305 key
        let cipher = ChaCha20Poly1305::new_from_slice(&*password)
            .expect("Invalid key length");
        let nonce = ChaCha20Poly1305::generate_nonce(&mut OsRng); // 96-bits; unique per message
        let mut encrypter_buf = HVec::<u8, 95>::new(); // ALIAS_MAX_BYTES + 16 auth tag
        encrypter_buf.extend_from_slice(&alias)
            .expect("The slice is too big");
        cipher.encrypt_in_place(&nonce, b"", &mut encrypter_buf)
            .expect("Buffer is too small to hold resulting cyphertext");

        // Concatenate encrypted alias with alias flags and nonce
        let db_record_bytes = Zeroizing::new(
            [
                &self.encode_flags().to_le_bytes(),
                nonce.as_slice(),
                &encrypter_buf,
            ]
            .concat()
        );
        encrypter_buf.zeroize();

        // Encode with Base64
        let mut encoder_buf = Zeroizing::new([0u8; 144]); // 108 "full" bytes = 144 bytes of Base64
        match Base64::encode(&db_record_bytes, &mut *encoder_buf) {
            Ok(base64_str) => self.encrypted_alias
                .set(ZeroizingString::new(base64_str.to_owned()))
                .unwrap(),
            Err(e) => panic!("{}", e),
        }
    }

    fn decrypt_alias(encrypted_alias: &ZeroizingString, password: &ZeroizingVec) -> Result<Self> {
        // Decode Base64 alias data representation
        let mut decoder_buf = Zeroizing::new([0u8; 144]);
        let enc_alias = Base64::decode(&encrypted_alias.as_bytes(), &mut *decoder_buf)
            .map_err(|err| PshError::DbAliasDecodeError(encrypted_alias.clone(), err))?;

        let use_secret = Self::extract_secret_flag(enc_alias[0]);
        let charset = Self::extract_charset(enc_alias[0]);

        // Decrypt alias using hashed password as ChaCha20Poly1305 key
        let cipher = ChaCha20Poly1305::new_from_slice(&*password)
            .expect("Invalid key length");
        let nonce = Nonce::from_slice(&enc_alias[1..13]);
        let mut decrypter_buf = HVec::<u8, 128>::new();
        decrypter_buf.extend_from_slice(&enc_alias[13..])
            .expect("The slice is too big");
        match cipher.decrypt_in_place(&nonce, b"", &mut decrypter_buf) {
            Ok(_) => {
                let alias_bytes = ZeroizingVec::new(
                    decrypter_buf.iter()
                        .filter(|x| **x != 0x0) // Unpad ZeroPadding
                        .copied()
                        .collect(),
                );
                decrypter_buf.zeroize();
                let alias = ZeroizingString::new(
                    std::str::from_utf8(&alias_bytes)?
                        .to_string()
                );
                Ok(Self {
                    alias,
                    encrypted_alias: OnceCell::with_value(encrypted_alias.clone()),
                    use_secret,
                    charset,
                })
            }
            Err(_) => bail!(PshError::MasterPasswordWrong)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use test_case::test_case;

    #[test_case(false, CharSet::Standard => 0; "all bits are 0")]
    #[test_case(true, CharSet::Standard => 1; "use secret")]
    #[test_case(false, CharSet::Reduced => 2; "reduced charset")]
    #[test_case(false, CharSet::RequireAll => 4; "require_all charset")]
    #[test_case(true, CharSet::RequireAll => 5; "all bits are 1")]
    fn encode_flags(use_secret: bool, charset: CharSet) -> u8 {
        let alias = ZeroizingString::new("".to_string());
        let alias_data = AliasData::new(&alias, use_secret, charset);
        alias_data.encode_flags()
    }

    #[test_case(0 => false; "all bits are 0")]
    #[test_case(1 => true; "flag is set")]
    #[test_case(255 => true; "all bits are 1")]
    #[test_case(254 => false; "all other bits are 1")]
    fn extract_secret_flag(byte: u8) -> bool {
        AliasData::extract_secret_flag(byte)
    }

    #[test_case(0 => CharSet::Standard; "all bits are 0")]
    #[test_case(249 => CharSet::Standard; "all other bits are 1")]
    #[test_case(2 => CharSet::Reduced; "reduced charset")]
    #[test_case(4 => CharSet::RequireAll; "require_all charset")]
    fn extract_charset(byte: u8) -> CharSet {
        AliasData::extract_charset(byte)
    }
}
