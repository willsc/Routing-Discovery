//! Durable route ownership and write intents, recorded before AWS mutation.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use rusqlite::{params, Connection, OptionalExtension};
use serde_json::{json, Value};

use super::config::{permits, ServerConfig};
use super::rib::{Fib, LearnedRoute};
use crate::error::{backend_err, Error, Result};

pub const FILE: &str = "route-server.sqlite3";

pub type Entries = BTreeMap<(String, String), BTreeSet<String>>;

pub struct Journal {
    db: Connection,
}

fn sql(e: rusqlite::Error) -> Error {
    Error::Backend(format!("journal: {e}"))
}

impl Journal {
    /// `None` keeps the journal in memory (dry-run demos and tests).
    pub fn open(config: &ServerConfig, directory: Option<&Path>) -> Result<Self> {
        let db = match directory {
            Some(dir) => Connection::open(dir.join(FILE)),
            None => Connection::open_in_memory(),
        }
        .map_err(sql)?;
        db.execute_batch("PRAGMA synchronous=FULL").map_err(sql)?;
        db.query_row("PRAGMA journal_mode=WAL", [], |_| Ok(())).map_err(sql)?;
        db.execute_batch(
            "CREATE TABLE IF NOT EXISTS metadata (key TEXT PRIMARY KEY, value TEXT NOT NULL);
             CREATE TABLE IF NOT EXISTS routes (table_id TEXT, prefix TEXT, targets TEXT NOT NULL, PRIMARY KEY(table_id,prefix));",
        )
        .map_err(sql)?;
        let identity = json!({"server": config.id, "region": config.region, "vpc": config.vpc_id, "tag": config.owner_tag});
        let journal = Journal { db };
        if let Some(stored) = journal.metadata("identity")? {
            if serde_json::from_str::<Value>(&stored).ok().as_ref() != Some(&identity) {
                return backend_err("state directory belongs to a different route server, region, VPC or ownership tag");
            }
        }
        journal.set_metadata("identity", &identity.to_string())?;
        Ok(journal)
    }

    fn metadata(&self, key: &str) -> Result<Option<String>> {
        self.db.query_row("SELECT value FROM metadata WHERE key=?", [key], |row| row.get(0)).optional().map_err(sql)
    }

    fn set_metadata(&self, key: &str, value: &str) -> Result<()> {
        self.db.execute("INSERT OR REPLACE INTO metadata VALUES (?, ?)", params![key, value]).map_err(sql)?;
        Ok(())
    }

    pub fn entries(&self) -> Result<Entries> {
        let mut statement = self.db.prepare("SELECT table_id, prefix, targets FROM routes").map_err(sql)?;
        let rows = statement
            .query_map([], |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?, row.get::<_, String>(2)?)))
            .map_err(sql)?;
        let mut result = Entries::new();
        for row in rows {
            let (table, prefix, targets) = row.map_err(sql)?;
            let targets: BTreeSet<String> =
                serde_json::from_str(&targets).map_err(|e| Error::Backend(format!("journal: corrupt targets: {e}")))?;
            result.insert((table, prefix), targets);
        }
        Ok(result)
    }

    pub fn intent(&self, table: &str, prefix: &str, target: &str) -> Result<()> {
        let mut targets = self.entries()?.remove(&(table.to_string(), prefix.to_string())).unwrap_or_default();
        targets.insert(target.to_string());
        let encoded = serde_json::to_string(&targets).unwrap_or_default();
        self.db.execute("INSERT OR REPLACE INTO routes VALUES (?,?,?)", params![table, prefix, encoded]).map_err(sql)?;
        Ok(())
    }

    pub fn forget(&self, table: &str, prefix: &str) -> Result<()> {
        self.db.execute("DELETE FROM routes WHERE table_id=? AND prefix=?", params![table, prefix]).map_err(sql)?;
        Ok(())
    }

    pub fn save_fib(&self, selected: &Fib) -> Result<()> {
        self.set_metadata("fib", &serde_json::to_string(selected).unwrap_or_default())
    }

    /// Restore the last FIB, dropping entries the current configuration no longer allows.
    pub fn load_fib(&self, config: &ServerConfig) -> Result<Fib> {
        let Some(raw) = self.metadata("fib")? else { return Ok(Fib::new()) };
        let saved: BTreeMap<String, LearnedRoute> =
            serde_json::from_str(&raw).map_err(|e| Error::Backend(format!("journal: corrupt FIB: {e}")))?;
        Ok(saved
            .into_iter()
            .filter(|(prefix, route)| {
                config.peers.iter().any(|p| {
                    p.id == route.peer
                        && p.eni == route.eni
                        && p.next_hops.contains(&route.next_hop)
                        && permits(prefix, &p.allowed_prefixes)
                })
            })
            .collect())
    }
}
