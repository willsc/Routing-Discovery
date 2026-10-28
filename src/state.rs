//! A process lock and atomic dampening checkpoint; health is always re-probed.

use std::fs::{DirBuilder, File, OpenOptions, TryLockError};
use std::io::Write;
use std::os::unix::fs::DirBuilderExt;
use std::path::{Path, PathBuf};

use serde_json::{json, Map, Value};

use crate::clock;
use crate::error::{backend_err, Error, Result};
use crate::policy::Policy;

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

    pub fn save(&self, policy: &mut Policy, now: f64) -> Result<()> {
        let h = policy.config.health.clone();
        let mut paths = Map::new();
        for ((prefix, cid), state) in policy.health.iter_mut() {
            state.decay(now, &h);
            paths.insert(
                format!("{prefix}|{cid}"),
                json!({"penalty": state.penalty, "suppressed_age": state.suppressed_since.map(|s| now - s)}),
            );
        }
        let data = json!({"version": 1, "saved_at": clock::wall(), "paths": paths});
        let temporary = self.directory.join("dampening.json.tmp");
        {
            let mut stream = File::create(&temporary)?;
            stream.write_all(serde_json::to_string(&data).map_err(|e| Error::Backend(e.to_string()))?.as_bytes())?;
            stream.sync_all()?;
        }
        std::fs::rename(&temporary, self.directory.join("dampening.json"))?;
        Ok(())
    }

    pub fn restore(&self, policy: &mut Policy, now: f64) -> Result<()> {
        let path = self.directory.join("dampening.json");
        if !path.exists() {
            return Ok(());
        }
        restore_from(&path, policy, now)
    }
}

fn restore_from(path: &Path, policy: &mut Policy, now: f64) -> Result<()> {
    let invalid = || Error::Backend("invalid dampening checkpoint".into());
    let data: Value = serde_json::from_str(&std::fs::read_to_string(path)?).map_err(|_| invalid())?;
    if data.get("version").and_then(Value::as_i64) != Some(1) {
        return backend_err("unsupported dampening checkpoint version");
    }
    let saved_at = data.get("saved_at").and_then(Value::as_f64).ok_or_else(invalid)?;
    let elapsed = (clock::wall() - saved_at).max(0.0);
    if !elapsed.is_finite() {
        return backend_err("invalid checkpoint timestamp");
    }
    let paths = data.get("paths").and_then(Value::as_object).ok_or_else(invalid)?;
    let h = policy.config.health.clone();
    for ((prefix, cid), state) in policy.health.iter_mut() {
        let Some(saved) = paths.get(&format!("{prefix}|{cid}")) else { continue };
        let penalty = saved.get("penalty").and_then(Value::as_f64).ok_or_else(invalid)?;
        let age = match saved.get("suppressed_age") {
            Some(Value::Null) => None,
            Some(v) => Some(v.as_f64().ok_or_else(invalid)?),
            None => return Err(invalid()),
        };
        if !penalty.is_finite() || penalty < 0.0 || age.is_some_and(|a| !a.is_finite() || a < 0.0) {
            return Err(invalid());
        }
        state.penalty = penalty.min(h.dampening_suppress * 4.0) * (-elapsed / h.dampening_half_life).exp2();
        state.penalty_at = Some(now);
        if let Some(age) = age {
            state.suppressed_since = Some(now - age - elapsed);
        }
        state.decay(now, &h);
    }
    Ok(())
}
