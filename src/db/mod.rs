use anyhow::Result;

use crate::ZeroizingString;

#[cfg(not(feature = "web"))]
mod db;
#[cfg(not(feature = "web"))]
pub use db::PshDb;

#[cfg(feature = "web")]
mod web;
#[cfg(feature = "web")]
pub use web::PshWebDb;

pub trait PshStore {
    /// Checks if `psh` alias database is present and has any records.
    fn exists(&self) -> bool;

    /// Iterates over `psh` alias database records.
    fn records(&self) -> Box<dyn Iterator<Item=ZeroizingString>>;

    /// Appends record to `psh` alias database.
    fn append(&mut self, record: &ZeroizingString) -> Result<()>;

    /// Deletes record from `psh` alias database.
    fn delete(&mut self, record: &ZeroizingString) -> Result<()>;
}
