//! Zero-configuration routing roles. Each discovers its peers and prefixes from the host and AWS,
//! and drives FRR, which speaks the wire protocols:
//! - `bgp`: an EC2 instance peering with VPC Route Server and Transit Gateway Connect;
//! - `dx`: a host outside AWS terminating Direct Connect private and transit VIFs;
//! - `mesh`: every host: a Babel mesh, over GRE tunnels between sites when a registry is given.

pub mod bgp;
pub mod clock;
pub mod commands;
pub mod dx;
pub mod error;
pub mod hash;
pub mod http;
pub mod mesh;
pub mod state;
pub mod supervision;

pub use error::{Error, Result};

pub const VERSION: &str = env!("CARGO_PKG_VERSION");
