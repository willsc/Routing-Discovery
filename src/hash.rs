//! Stable short hashes for interface names and addresses. Fixed here so names don't change between releases.

/// 32-bit FNV-1a.
pub fn fnv1a(bytes: &[u8]) -> u32 {
    bytes.iter().fold(0x811c_9dc5_u32, |h, b| (h ^ u32::from(*b)).wrapping_mul(0x0100_0193))
}
