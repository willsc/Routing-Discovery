//! Health-driven routing. Wire-level BGP/BFD belongs to FRR.

pub mod aws;
pub mod backends;
pub mod clock;
pub mod commands;
pub mod config;
pub mod daemon;
pub mod demo;
pub mod error;
pub mod frr_export;
pub mod http;
pub mod policy;
pub mod probes;
pub mod server;
pub mod state;
pub mod supervision;
mod toml_check;

pub use error::{Error, Result};

pub const VERSION: &str = env!("CARGO_PKG_VERSION");
