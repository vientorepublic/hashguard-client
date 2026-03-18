use js_sys::Date;
use sha2::{Digest, Sha256};
use wasm_bindgen::prelude::*;

/// Returns SHA-256(input) as a 64-character lowercase hex string.
#[wasm_bindgen]
pub fn sha256hex(input: &str) -> String {
    let mut h = Sha256::new();
    h.update(input.as_bytes());
    hex::encode(h.finalize())
}

/// Returns `true` if SHA-256("{challenge_id}:{seed}:{nonce}") <= target_hex.
///
/// Byte-level comparison is equivalent to lexicographic hex-string comparison
/// because both digests and targets are fixed-width (32 bytes / 64 hex chars).
#[wasm_bindgen]
pub fn verify_proof(challenge_id: &str, seed: &str, nonce: &str, target_hex: &str) -> bool {
    let Some(target) = parse_target_bytes(target_hex) else {
        return false;
    };
    let preimage = format!("{challenge_id}:{seed}:{nonce}");
    let mut h = Sha256::new();
    h.update(preimage.as_bytes());
    h.finalize().as_slice() <= target.as_slice()
}

/// Searches for the first nonce satisfying
/// SHA-256("{challenge_id}:{seed}:{nonce}") <= target_hex.
///
/// Return values:
///  >= 0  — winning nonce (cast to i32; safe up to ~2 billion)
///    -1  — `max_attempts` exhausted without a match
///    -2  — wall-clock timeout (`Date.now() - start_ms > timeout_ms`)
///    -3  — `target_hex` is not a valid 64-character hex string
#[wasm_bindgen]
pub fn solve(
    challenge_id: &str,
    seed: &str,
    target_hex: &str,
    max_attempts: u32,
    start_ms: f64,
    timeout_ms: f64,
    progress_interval: u32,
) -> i32 {
    solve_batch(
        challenge_id,
        seed,
        target_hex,
        0,
        max_attempts,
        start_ms,
        timeout_ms,
        progress_interval,
    )
}

/// Searches a nonce batch beginning at `start_nonce` and covering at most
/// `batch_attempts` candidates.
#[wasm_bindgen]
pub fn solve_batch(
    challenge_id: &str,
    seed: &str,
    target_hex: &str,
    start_nonce: u32,
    batch_attempts: u32,
    start_ms: f64,
    timeout_ms: f64,
    progress_interval: u32,
) -> i32 {
    let Some(target) = parse_target_bytes(target_hex) else {
        return -3;
    };

    let prefix = format!("{challenge_id}:{seed}:");
    let check_every = progress_interval.max(1);

    for offset in 0u32..batch_attempts {
        let nonce = start_nonce + offset;
        let preimage = format!("{prefix}{nonce}");
        let mut h = Sha256::new();
        h.update(preimage.as_bytes());
        let hash = h.finalize();

        if hash.as_slice() <= target.as_slice() {
            return nonce as i32;
        }

        // Check wall-clock timeout at the same cadence as the JS solver.
        if offset > 0 && offset % check_every == 0 && Date::now() - start_ms > timeout_ms {
            return -2;
        }
    }

    -1
}

// ── helpers ──────────────────────────────────────────────────────────────────

fn parse_target_bytes(hex_str: &str) -> Option<[u8; 32]> {
    if hex_str.len() != 64 {
        return None;
    }
    let decoded = hex::decode(hex_str).ok()?;
    let mut bytes = [0u8; 32];
    bytes.copy_from_slice(&decoded);
    Some(bytes)
}
