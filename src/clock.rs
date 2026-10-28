//! Policy code takes `now` as monotonic seconds so tests can drive it with plain numbers.

use std::sync::OnceLock;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

static ORIGIN: OnceLock<Instant> = OnceLock::new();

/// Monotonic seconds since first use in this process.
pub fn monotonic() -> f64 {
    // Offset keeps "time since start" comparisons positive, like time.monotonic().
    ORIGIN.get_or_init(Instant::now).elapsed().as_secs_f64() + 1_000.0
}

pub fn wall() -> f64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs_f64()).unwrap_or(0.0)
}
