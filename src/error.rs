use alloc::string::String;
use core::fmt;

use crate::{ZeroizingString, MASTER_PASSWORD_MIN_LEN};

/// Error type.
#[derive(Debug)]
pub enum Error {
    /// Error decoding alias from database.
    DbAliasDecodeError(ZeroizingString, String),

    /// Error appending alias to database.
    DbAliasAppendError(ZeroizingString),

    /// Error removing alias from database.
    DbAliasRemoveError(ZeroizingString),

    /// Master password is too short.
    MasterPasswordTooShort,

    /// Wrong master password.
    MasterPasswordWrong,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Error::DbAliasDecodeError(rec, inner) => return write!(
                f, "Unable to decode DB record {} as Base64: {}", rec, inner
            ),
            Error::DbAliasAppendError(rec) => return write!(
                f, "Cannot add alias `{}` to DB: alias already present", rec
            ),
            Error::DbAliasRemoveError(rec) => return write!(
                f, "Cannot remove alias `{}` from DB: alias does not exist", rec
            ),
            Error::MasterPasswordTooShort => return write!(
                f, "Master password is too short (less than {} characters)",
                MASTER_PASSWORD_MIN_LEN
            ),
            Error::MasterPasswordWrong => "Wrong master password",
        })
    }
}
