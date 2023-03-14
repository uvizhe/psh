//! This crate provides alias database backend for [`psh`] using LocalStorage Web API
//!
//! This crate is intended to be used along with [`psh`] when building for WASM targets.
//!
//! [`psh`]: https://docs.rs/psh/latest/psh

use std::fmt;

use anyhow::{bail, Result};
use web_sys::{self, Storage};

use psh::{PshStore, ZeroizingString};

/// WASM compatible `psh` alias database.
pub struct PshWebDb {
    local_storage: Storage,
}

impl PshWebDb {
    pub fn new() -> Self {
        let window = web_sys::window().expect("Window not available");
        let local_storage = window.local_storage()
            .expect("LocalStorage not available")
            .expect("LocalStorage not defined");

        Self { local_storage }
    }
}

impl PshStore for PshWebDb {
    fn exists(&self) -> bool {
        self.records().next().is_some()
    }

    fn records(&self) -> Box<dyn Iterator<Item=ZeroizingString>> {
        Box::new(PshWebDbIter::new(self.local_storage.clone()))
    }

    fn append(&mut self, record: &ZeroizingString) -> Result<()> {
        match self.local_storage.set_item(record, "psh") {
            Ok(_) => Ok(()),
            Err(js_err) => bail!(Error::AliasAppendError(
                    ZeroizingString::new(js_err.as_string().unwrap())))
        }
    }

    fn delete(&mut self, record: &ZeroizingString) -> Result<()> {
        match self.local_storage.remove_item(record) {
            Ok(_) => Ok(()),
            Err(js_err) => bail!(Error::AliasRemoveError(
                    ZeroizingString::new(js_err.as_string().unwrap())))
        }
    }
}

struct PshWebDbIter {
    store: Storage,
    index: u32,
}

impl PshWebDbIter {
    pub fn new(store: Storage) -> Self {
        Self {
            store,
            index: 0,
        }
    }
}

impl Iterator for PshWebDbIter {
    type Item = ZeroizingString;

    fn next(&mut self) -> Option<Self::Item> {
        if let Ok(ls_length) = self.store.length() {
            if ls_length > self.index {
                while let Ok(Some(key)) = self.store.key(self.index) {
                    self.index += 1;
                    if let Ok(Some(value)) = self.store.get_item(&key) {
                        if value == "psh" {
                            return Some(ZeroizingString::new(key));
                        }
                    }
                    if self.index == ls_length {
                        break;
                    }
                }
            }
        }
        None
    }
}

/// Error type.
#[derive(Debug)]
enum Error {
    /// Error appending alias to database.
    AliasAppendError(ZeroizingString),

    /// Error removing alias from database.
    AliasRemoveError(ZeroizingString),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::AliasAppendError(err_string) => write!(
                f, "Cannot add alias to DB: {}", err_string
            ),
            Error::AliasRemoveError(err_string) => write!(
                f, "Cannot remove alias from DB: {}", err_string
            ),
        }
    }
}

impl std::error::Error for Error {}
