//! A process lock on a state directory, so two controllers never manage the same plane.

use std::fs::{DirBuilder, File, OpenOptions, TryLockError};
use std::os::unix::fs::DirBuilderExt;
use std::path::PathBuf;

use crate::error::{backend_err, Result};

pub struct StateStore {
    pub directory: PathBuf,
    lock: Option<File>,
}

impl StateStore {
    pub fn new(directory: impl Into<PathBuf>) -> Self {
        StateStore { directory: directory.into(), lock: None }
    }

    pub fn acquire(&mut self) -> Result<()> {
        DirBuilder::new().recursive(true).mode(0o700).create(&self.directory)?;
        let file = OpenOptions::new().create(true).append(true).read(true).open(self.directory.join("daemon.lock"))?;
        match file.try_lock() {
            Ok(()) => {
                self.lock = Some(file);
                Ok(())
            }
            Err(TryLockError::WouldBlock) => backend_err("another daemon holds this state directory lock"),
            Err(TryLockError::Error(e)) => Err(e.into()),
        }
    }

    pub fn close(&mut self) {
        self.lock = None;
    }
}
