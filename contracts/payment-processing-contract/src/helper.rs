// SPDX-License-Identifier: MIT

extern crate alloc;

use soroban_sdk::{xdr::ToXdr, Address, Bytes, BytesN, Env, Map, String, Vec};

use crate::error::PaymentError;
use crate::storage;
use crate::types::{PaymentFilter, PaymentRecord, PaymentStatus, StatusFilter};

/// Maximum combined size, in bytes, of all keys and values in a
/// [`crate::types::PaymentOrder`] `metadata` map (MISC-013).
pub const MAX_METADATA_SIZE_BYTES: u32 = 1024;

/// Require that `caller` is the contract admin.
pub fn require_admin(env: &Env, caller: &Address) -> Result<(), PaymentError> {
    caller.require_auth();
    let admin = storage::get_admin(env).ok_or(PaymentError::Unauthorized)?;
    if admin != *caller {
        return Err(PaymentError::Unauthorized);
    }
    Ok(())
}

/// Validate that `admin` is not the zero/burn address (SC-016).
///
/// # Limitation
/// The Soroban SDK (as of v22) does not expose a dedicated `Address::is_zero()`
/// or zero-address constant. Stellar accounts are identified by an ed25519
/// public key, and there is no formally specified "burn address" analogous to
/// Ethereum's `0x000…0`. This function therefore uses a best-effort heuristic:
/// it serialises the address to XDR and checks whether every byte of the
/// serialisation is zero. In practice, any real account key produced by a
/// wallet will have at least one non-zero byte, so this check catches
/// accidentally constructed zero-byte keys that would permanently lock all
/// admin-only functions.
///
/// If the Soroban SDK later exposes a dedicated zero-address check or a
/// canonical burn-address constant, this function should be updated to use it.
///
/// # Errors
/// Returns [`PaymentError::InvalidInput`] if the XDR serialisation of
/// `admin` is all-zero bytes.
pub fn validate_admin_address(env: &Env, admin: &Address) -> Result<(), PaymentError> {
    let admin_xdr = admin.clone().to_xdr(env);
    let all_zero = admin_xdr.iter().all(|b| b == 0);
    if all_zero {
        return Err(PaymentError::InvalidInput);
    }
    Ok(())
}

/// Require that `caller` is the registered merchant at `merchant_address`.
pub fn require_merchant(
    env: &Env,
    caller: &Address,
    merchant_address: &Address,
) -> Result<(), PaymentError> {
    caller.require_auth();
    if caller != merchant_address {
        return Err(PaymentError::Unauthorized);
    }
    let m = storage::get_merchant(env, merchant_address).ok_or(PaymentError::MerchantNotFound)?;
    if !m.active {
        return Err(PaymentError::MerchantInactive);
    }
    Ok(())
}

/// Validate that `amount` is positive.
pub fn validate_amount(amount: i128) -> Result<(), PaymentError> {
    if amount <= 0 {
        return Err(PaymentError::InvalidAmount);
    }
    Ok(())
}

/// Validate merchant string fields: name, description, contact_info
pub fn validate_merchant_fields(
    name: &String,
    description: &String,
    contact_info: &String,
) -> Result<(), PaymentError> {
    // name <= 64 bytes
    if name.len() > 64 {
        return Err(PaymentError::InvalidInput);
    }

    // description <= 256 bytes
    if description.len() > 256 {
        return Err(PaymentError::InvalidInput);
    }

    // contact_info <= 128 bytes and printable ASCII only
    let ci_len = contact_info.len() as usize;
    if ci_len > 128 {
        return Err(PaymentError::InvalidInput);
    }
    let mut buf = alloc::vec![0u8; ci_len];
    contact_info.copy_into_slice(&mut buf);
    for &b in buf.iter() {
        if b < 0x20 || b > 0x7E {
            return Err(PaymentError::InvalidInput);
        }
    }

    Ok(())
}

/// Validate that `order_id` is non-empty, at most 64 bytes, and contains only
/// alphanumeric characters plus `-` and `_` (i.e. the character set
/// `[A-Za-z0-9\-_]`).
///
/// # Errors
/// Returns [`PaymentError::InvalidInput`] when:
/// - the byte slice is empty,
/// - the byte slice exceeds 64 bytes, or
/// - any byte is outside the allowed character set.
///
/// Enforcing a maximum length and a restricted character set prevents storage
/// inflation attacks where an attacker submits an arbitrarily long or specially
/// crafted order ID.
pub fn validate_order_id(order_id: &Bytes) -> Result<(), PaymentError> {
    let len = order_id.len() as usize;

    // Rule 1: must be non-empty.
    // Rule 2: must not exceed 64 bytes (SC-014).
    if len == 0 || len > 64 {
        return Err(PaymentError::InvalidInput);
    }

    // Rule 3: only alphanumeric characters, hyphens, and underscores are
    // allowed (SC-014).  We copy the bytes into a stack buffer so we can
    // inspect each byte without heap allocation.
    let mut buf = [0u8; 64];
    order_id.copy_into_slice(&mut buf[..len]);
    for &b in buf[..len].iter() {
        let allowed = b.is_ascii_alphanumeric() || b == b'-' || b == b'_';
        if !allowed {
            return Err(PaymentError::InvalidInput);
        }
    }

    Ok(())
}

/// Validate optional payment metadata (MISC-013).
///
/// Enforces that the combined byte length of every key and value in the map
/// does not exceed [`MAX_METADATA_SIZE_BYTES`]. A missing map (`None`) is
/// always valid and costs nothing.
///
/// # Errors
/// Returns [`PaymentError::InvalidInput`] when the combined size of all keys
/// and values exceeds [`MAX_METADATA_SIZE_BYTES`].
pub fn validate_metadata(metadata: &Option<Map<String, String>>) -> Result<(), PaymentError> {
    let Some(map) = metadata else {
        return Ok(());
    };
    let mut total: u32 = 0;
    for (key, value) in map.iter() {
        total = total
            .checked_add(key.len())
            .and_then(|t| t.checked_add(value.len()))
            .ok_or(PaymentError::ArithmeticError)?;
        if total > MAX_METADATA_SIZE_BYTES {
            return Err(PaymentError::InvalidInput);
        }
    }
    Ok(())
}

/// Verify an ed25519 signature over `payload` using `public_key`.
///
/// Calls `env.crypto().ed25519_verify` in both production and test builds.
/// The Soroban testutils environment provides a real ed25519 implementation,
/// so signature tests are exercised end-to-end without any bypass.
pub fn verify_signature(
    env: &Env,
    public_key: &BytesN<32>,
    payload: &Bytes,
    signature: &BytesN<64>,
) -> Result<(), PaymentError> {
    env.crypto().ed25519_verify(public_key, payload, signature);
    Ok(())
}

/// Apply a filter to a payment record; returns true if the record passes.
pub fn matches_filter(record: &PaymentRecord, filter: &PaymentFilter) -> bool {
    if let Some(start) = filter.date_start {
        if record.paid_at < start {
            return false;
        }
    }
    if let Some(end) = filter.date_end {
        if record.paid_at > end {
            return false;
        }
    }
    if let Some(min) = filter.amount_min {
        if record.amount < min {
            return false;
        }
    }
    if let Some(max) = filter.amount_max {
        if record.amount > max {
            return false;
        }
    }
    if let Some(ref tokens) = filter.tokens {
        // Empty list → no filter (match all). Non-empty → token must be in list.
        if !tokens.is_empty() && !tokens.contains(&record.token) {
            return false;
        }
    }
    match &filter.status {
        StatusFilter::Any => {}
        StatusFilter::Completed => {
            if record.status != PaymentStatus::Completed {
                return false;
            }
        }
        StatusFilter::PartiallyRefunded => {
            if record.status != PaymentStatus::PartiallyRefunded {
                return false;
            }
        }
        StatusFilter::FullyRefunded => {
            if record.status != PaymentStatus::FullyRefunded {
                return false;
            }
        }
    }
    true
}

/// Require that at least `threshold` addresses in `admins` are registered
/// admin addresses and each provides authorization.
///
/// The threshold is read from the stored [`AdminConfig`]. If no config is
/// present the contract falls back to single-admin mode (threshold = 1).
///
/// # Multi-sig semantics
/// - The caller supplies a list of addresses claiming to be admins.
/// - Each address in the list that is a registered admin is asked to
///   `require_auth()` (the Soroban host verifies the signature on-chain).
/// - If the count of successfully-authorized admin addresses meets or
///   exceeds the stored threshold, the call proceeds. Otherwise it is
///   rejected with [`PaymentError::Unauthorized`].
///
/// This implements an N-of-M ("threshold-of-total") multi-sig model where
/// N is the threshold and M is the total number of registered admins.
pub fn require_multi_admin(env: &Env, admins: Vec<Address>) -> Result<(), PaymentError> {
    if let Some(config) = storage::get_admin_config(env) {
        let threshold = config.threshold.max(1) as usize;
        let mut authorized: usize = 0;
        for addr in admins.iter() {
            if config.admins.contains(&addr) {
                addr.require_auth();
                authorized += 1;
                if authorized >= threshold {
                    return Ok(());
                }
            }
        }
        // Not enough authorized admins.
        return Err(PaymentError::Unauthorized);
    }
    // Fall back to single-admin mode (no AdminConfig stored).
    if let Some(admin) = storage::get_admin(env) {
        for addr in admins.iter() {
            if addr == admin {
                addr.require_auth();
                return Ok(());
            }
        }
    }
    Err(PaymentError::Unauthorized)
}

/// Returns true if `ts` falls within the optional [start, end] range.
pub fn in_date_range(ts: u64, start: Option<u64>, end: Option<u64>) -> bool {
    if let Some(s) = start {
        if ts < s {
            return false;
        }
    }
    if let Some(e) = end {
        if ts > e {
            return false;
        }
    }
    true
}
