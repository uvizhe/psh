//! Module defines [`PshStore`] trait and its minimal implementation: [`PshMemDb`].

use anyhow::Result;

use crate::ZeroizingString;

/// Trait for database implementations.
///
/// Methods of this trait are used by Psh for alias storage management. The trait has to be
/// implemented by any custom database driver.
///
/// For examples see two database implementations: [`psh_db::PshDb`] for a plain file
/// storage and [`psh_webdb::PshWebDb`] for a in-browser LocalStorage.
///
/// [`psh_db::PshDb`]: https://docs.rs/psh-db/latest/psh_db/struct.PshDb.html
/// [`psh_webdb::PshWebDb`]: https://docs.rs/psh-webdb/latest/psh_webdb/struct.PshWebDb.html
pub trait PshStore {
    /// Checks if `psh` alias database is present and has any records.
    ///
    /// Note: You should always check this before asking user for a master password.
    /// If the database is empty (e.g., after removal of the last alias), it's important
    /// to ask the password twice to avoid mistyping and hence setting a wrong password.
    fn exists(&self) -> bool;

    /// Iterates over `psh` alias database records.
    fn records(&self) -> Box<dyn Iterator<Item=ZeroizingString>>;

    /// Appends record to `psh` alias database.
    fn append(&mut self, record: &ZeroizingString) -> Result<()>;

    /// Deletes record from `psh` alias database.
    fn delete(&mut self, record: &ZeroizingString) -> Result<()>;
}

/// In-memory alias database storage as simple as possible. Probably the only use-case of it
/// is testing/documenting this crate.
pub struct PshMemDb {
    aliases: Vec<ZeroizingString>,
}

impl PshMemDb {
    pub fn new() -> Self {
        Self { aliases: Vec::new() }
    }
}

impl PshStore for PshMemDb {
    fn exists(&self) -> bool {
        !self.aliases.is_empty()
    }

    fn records(&self) -> Box<dyn Iterator<Item=ZeroizingString>> {
        let aliases = self.aliases.clone();
        Box::new(aliases.into_iter())
    }

    fn append(&mut self, record: &ZeroizingString) -> Result<()> {
        self.aliases.push(record.clone());
        Ok(())
    }

    fn delete(&mut self, record: &ZeroizingString) -> Result<()> {
        if let Some(index) = self.aliases.iter().position(|r| r == record) {
            self.aliases.remove(index);
        }
        Ok(())
    }
}
