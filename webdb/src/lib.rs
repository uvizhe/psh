//! This crate provides alias database backend for [`psh`] using LocalStorage Web API
//!
//! This crate is intended to be used along with [`psh`] when building for WASM targets.
//!
//! [`psh`]: ../psh/index.html

use anyhow::Result;
use thiserror::Error;
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
        self.local_storage.set_item(record, "psh")
            .map_err(|js_err| PshWebDbError::AliasAppendError(
                    ZeroizingString::new(js_err.as_string().unwrap())))?;
        Ok(())
    }

    fn delete(&mut self, record: &ZeroizingString) -> Result<()> {
        self.local_storage.remove_item(record)
            .map_err(|js_err| PshWebDbError::AliasRemoveError(
                    ZeroizingString::new(js_err.as_string().unwrap())))?;
        Ok(())
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

/// Error types
#[derive(Error, Debug)]
pub enum PshWebDbError {
    #[error("Cannot add alias to DB: {0}")]
    AliasAppendError(ZeroizingString),

    #[error("Cannot remove alias from DB: {0}")]
    AliasRemoveError(ZeroizingString),
}
