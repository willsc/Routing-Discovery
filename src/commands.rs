//! Bounded subprocesses with explicit argv; never a shell.

use std::process::Stdio;
use std::time::Duration;

use async_trait::async_trait;
use tokio::process::Command;

use crate::error::{backend_err, Error, Result};

pub const DEFAULT_TIMEOUT: f64 = 5.0;

#[async_trait]
pub trait Runner: Send + Sync {
    async fn run(&self, args: &[String], timeout: f64) -> Result<String>;
}

/// Executes real commands.
#[derive(Clone, Copy, Debug, Default)]
pub struct SystemRunner;

#[async_trait]
impl Runner for SystemRunner {
    async fn run(&self, args: &[String], timeout: f64) -> Result<String> {
        let (program, rest) = args.split_first().ok_or_else(|| Error::Backend("empty command".into()))?;
        let child = Command::new(program)
            .args(rest)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true)
            .spawn()
            .map_err(|e| Error::Backend(format!("{program}: {e}")))?;
        let output = match tokio::time::timeout(Duration::from_secs_f64(timeout), child.wait_with_output()).await {
            Ok(result) => result.map_err(|e| Error::Backend(format!("{program}: {e}")))?,
            // Dropping the future kills the child (kill_on_drop); tokio reaps it.
            Err(_) => return backend_err(format!("{program} timed out")),
        };
        let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
        if !output.status.success() {
            let code = output.status.code().map_or_else(|| "on a signal".to_string(), |c| c.to_string());
            let stderr = String::from_utf8_lossy(&output.stderr);
            return backend_err(format!("{program} exited {code}: {} {}", stderr.trim(), stdout.trim()));
        }
        Ok(stdout)
    }
}

/// Test doubles and harnesses can supply a synchronous closure.
#[async_trait]
impl<F> Runner for F
where
    F: Fn(&[String]) -> Result<String> + Send + Sync,
{
    async fn run(&self, args: &[String], _timeout: f64) -> Result<String> {
        self(args)
    }
}

pub fn argv<I, S>(parts: I) -> Vec<String>
where
    I: IntoIterator<Item = S>,
    S: Into<String>,
{
    parts.into_iter().map(Into::into).collect()
}
