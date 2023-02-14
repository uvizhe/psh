//! This crate provides alias database backend for [`psh`] using plain file as a storage.
//!
//! [`psh`]: ../psh/index.html

use std::fs::{self, File, Permissions};
use std::io::{BufRead, BufReader, BufWriter, Write};
use std::path::{Path, PathBuf};
use std::os::unix::fs::PermissionsExt;

use anyhow::Result;
use zeroize::Zeroize;

use psh::{PshStore, ZeroizingString};

/// Default filename to be used within user home directory unless specified.
pub const DB_FILE: &str = ".psh.db";
const DEBUG_DB_PATH: &str = "/tmp/psh.db";

/// `psh` alias database.
pub struct PshDb {
    path: PathBuf,
}

impl PshDb {
    /// Creates new instance of database with specified `path`. If given `path` is relative,
    /// prepends it with user home directory.
    ///
    /// # Panics
    ///
    /// Panics if user has no [`home directory`].
    ///
    /// [`home directory`]: https://docs.rs/home/latest/home/
    pub fn new(path: &Path) -> Self {
        let db_path =
            if path.has_root() {
                path.to_path_buf()
            } else {
                let mut db_path = home::home_dir()
                    .expect("User has no home directory");
                db_path.push(path);
                db_path
            };

        Self {
            path: db_path,
        }
    }

    fn tmp_path(&self) -> PathBuf {
        let db_path = self.path.clone();
        let mut db_tmp_path = db_path.into_os_string();
        db_tmp_path.push(".tmp");
        db_tmp_path.into()
    }
}

impl Default for PshDb {
    fn default() -> Self {
        let mut db_path = home::home_dir()
            .expect("User has no home directory");
        db_path.push(DB_FILE);

        // Substitute database path for testing purposes in debug builds
        if cfg!(debug_assertions) {
            db_path = PathBuf::from(DEBUG_DB_PATH);
        }

        Self::new(&db_path)
    }
}

impl PshStore for PshDb {
    fn exists(&self) -> bool {
        if self.path.exists() {
            let metadata = fs::metadata(&self.path).unwrap();
            if metadata.len() > 0 {
                return true;
            }
        }
        false
    }

    fn records(&self) -> Box<dyn Iterator<Item=ZeroizingString>> {
        if self.exists() {
            let db = File::open(&self.path).expect("Unable to open file for reading");
            let reader = BufReader::new(db);
            Box::new(PshDbIter { reader })
        } else {
            Box::new(PshDbIter { reader: std::io::empty() })
        }
    }

    fn append(&mut self, record: &ZeroizingString) -> Result<()> {
        let mut db = File::options().create(true).append(true).open(&self.path)?;
        let user_only_perms = Permissions::from_mode(0o600);
        db.set_permissions(user_only_perms)?;

        let mut record = record.to_string();
        record.push('\n');
        db.write_all(record.as_bytes())?;
        record.zeroize();

        Ok(())
    }

    fn delete(&mut self, record: &ZeroizingString) -> Result<()> {
        let db = File::open(&self.path)?;
        let db_temp = File::create(self.tmp_path())?;
        let user_only_perms = Permissions::from_mode(0o600);
        db_temp.set_permissions(user_only_perms)?;

        let mut reader = BufReader::new(&db);
        let mut writer = BufWriter::new(&db_temp);

        let mut buf = String::new();
        loop {
            match reader.read_line(&mut buf) {
                Ok(0) => break,
                Ok(_) => {
                    if **record != buf.trim() {
                        writeln!(writer, "{}", buf.trim())?;
                    }
                    buf.zeroize();
                }
                Err(e) => panic!("Failed to read from file: {}", e),
            }
        }
        buf.zeroize();

        fs::rename(self.tmp_path(), &self.path)?;

        Ok(())
    }
}

struct PshDbIter<T: BufRead> {
    reader: T,
}

impl<T: BufRead> Iterator for PshDbIter<T> {
    type Item = ZeroizingString;

    fn next(&mut self) -> Option<Self::Item> {
        let mut buf = String::new();
        match self.reader.read_line(&mut buf) {
            Ok(0) => None,
            Ok(_) => {
                let item = Some(ZeroizingString::new(buf.trim().to_string()));
                buf.zeroize();
                item
            }
            Err(e) => panic!("Failed to read from file: {}", e),
        }
    }
}
