// SPDX-License-Identifier: MIT

#![no_std]

extern crate alloc;

#[cfg(feature = "scaffold")]
mod archival;
#[cfg(feature = "scaffold")]
mod audit;
#[cfg(feature = "scaffold")]
mod webhook;
mod error;
mod helper;
#[cfg(feature = "scaffold")]
mod request_validation;
mod response_formatting;
mod storage;
mod types;

#[cfg(test)]
mod repro_tests;
#[cfg(test)]
mod prop_tests;
#[cfg(test)]
mod payer_payment_history_tests;

use alloc::vec::Vec as RustVec;
use soroban_sdk::{
    contract, contractimpl, token, xdr::ToXdr, Address, Bytes, BytesN, Env, String, Vec,
};

use error::PaymentError;
use storage::{REFUND_GRACE_BUFFER, REFUND_WINDOW};
use types::{
    DataKey, GlobalStats, Merchant, MerchantCategory, MerchantStats, MerchantTier,
    MultisigPayment, PaymentFilter, PaymentOrder, PaymentPage, PaymentRecord, PaymentStatus,
    RefundRecord, RefundStatus, SortField, SortOrder,
};

#[contract]
pub struct PaymentContract;

#[contractimpl]
impl PaymentContract {
    // ── Admin ─────────────────────────────────────────────────────────────────

    /// One-time admin initialisation. Stores the first admin address.
    pub fn set_admin(env: Env, admins: Vec<Address>, threshold: u32) -> Result<(), PaymentError> {
        storage::bump_instance_ttl(&env);
        if storage::get_admin_config(&env).is_some() || storage::get_admin(&env).is_some() {
            return Err(PaymentError::AdminAlreadySet);
        }
        if admins.is_empty() {
            return Err(PaymentError::InvalidInput);
        }
        let first = admins.get(0).unwrap();
        helper::validate_admin_address(&env, &first)?;
        first.require_auth();
        storage::set_admin(&env, &first);
        storage::set_admin_config(&env, &types::AdminConfig { admins, threshold });
        storage::set_contract_version(&env, 1);
        env.events()
            .publish((DataKey::Admin,), (String::from_str(&env, "admin_set"), first));
        Ok(())
    }

    /// Transfer admin authority to a new address (two-step handoff).
    ///
    /// Both the current admin and the new admin must authorise this call,
    /// ensuring the new admin key is live and in possession of the caller.
    ///
    /// # Parameters
    /// - `current_admin` — The existing admin address; must be authenticated
    ///   and must match the stored admin.
    /// - `new_admin` — The incoming admin address; must also authenticate,
    ///   proving key possession before the transfer is committed.
    ///
    /// # Events
    /// Emits `admin_transferred` with payload `(current_admin, new_admin)`.
    ///
    /// # Errors
    /// - [`PaymentError::Unauthorized`] if `current_admin` is not the stored admin.
    /// - [`PaymentError::InvalidInput`] if `new_admin` is the zero/burn address.
    pub fn transfer_admin(
        env: Env,
        current_admin: Address,
        new_admin: Address,
    ) -> Result<(), PaymentError> {
        storage::bump_instance_ttl(&env);
        // Require auth from both parties — proves the new key is live.
        current_admin.require_auth();
        new_admin.require_auth();
        helper::validate_admin_address(&env, &new_admin)?;
        // Verify current_admin is actually the stored admin.
        let stored = storage::get_admin(&env).ok_or(PaymentError::Unauthorized)?;
        if stored != current_admin {
            return Err(PaymentError::Unauthorized);
        }
        // Update single-admin storage.
        storage::set_admin(&env, &new_admin);
        // If a multi-admin config exists, replace the old admin entry with the new one.
        if let Some(mut config) = storage::get_admin_config(&env) {
            let mut new_admins = Vec::new(&env);
            for addr in config.admins.iter() {
                if addr == current_admin {
                    new_admins.push_back(new_admin.clone());
                } else {
                    new_admins.push_back(addr);
                }
            }
            config.admins = new_admins;
            storage::set_admin_config(&env, &config);
        }
        env.events().publish(
            (String::from_str(&env, "admin_transferred"),),
            (current_admin, new_admin),
        );
        Ok(())
    }

    pub fn upgrade(env: Env, admin: Address, new_wasm_hash: BytesN<32>) -> Result<(), PaymentError> {
        storage::bump_instance_ttl(&env);
        helper::require_admin(&env, &admin)?;
        env.deployer().update_current_contract_wasm(new_wasm_hash);
        Ok(())
    }

    /// Update the admin set and signing threshold.
    ///
    /// Requires the existing threshold of currently-registered admins to
    /// authorise the change (i.e., the change itself must pass multi-sig).
    /// This prevents a single compromised key from unilaterally replacing
    /// the full admin set.
    ///
    /// # Parameters
    /// - `current_admins` — Addresses of the admins authorising this change.
    ///   Must satisfy the current threshold.
    /// - `new_admins` — The new admin address list.
    /// - `new_threshold` — The new signing threshold (1 ≤ threshold ≤ len(new_admins)).
    ///
    /// # Errors
    /// - [`PaymentError::Unauthorized`] if `current_admins` does not satisfy
    ///   the current threshold.
    /// - [`PaymentError::InvalidInput`] if `new_admins` is empty, or
    ///   `new_threshold` is zero or greater than the number of new admins.
    pub fn update_admin_config(
        env: Env,
        current_admins: Vec<Address>,
        new_admins: Vec<Address>,
        new_threshold: u32,
    ) -> Result<(), PaymentError> {
        storage::bump_instance_ttl(&env);
        // The change must be authorised by the existing multi-sig.
        helper::require_multi_admin(&env, current_admins)?;
        if new_admins.is_empty() {
            return Err(PaymentError::InvalidInput);
        }
        if new_threshold == 0 || new_threshold as usize > new_admins.len() as usize {
            return Err(PaymentError::InvalidInput);
        }
        let first = new_admins.get(0).unwrap();
        // Keep single-admin pointer in sync with the first new admin.
        storage::set_admin(&env, &first);
        storage::set_admin_config(&env, &types::AdminConfig {
            admins: new_admins.clone(),
            threshold: new_threshold,
        });
        env.events().publish(
            (String::from_str(&env, "admin_config_updated"),),
            (new_admins, new_threshold),
        );
        Ok(())
    }

    /// Return the current admin configuration (admin list and threshold).
    pub fn get_admin_config(env: Env) -> Result<types::AdminConfig, PaymentError> {
        storage::bump_instance_ttl(&env);
        storage::get_admin_config(&env).ok_or(PaymentError::Unauthorized)
    }

    pub fn get_version(env: Env) -> u32 {
        storage::bump_instance_ttl(&env);
        storage::get_contract_version(&env)
    }

    /// Extend the instance storage TTL so the contract never goes dormant.
    ///
    /// Instance storage holds Admin, GlobalStats, CleanupPeriod, and
    /// DefaultMultisigExpiry. If the contract goes dormant and instance storage
    /// expires the contract becomes unusable. This function is callable by
    /// anyone and should be invoked periodically to keep the contract alive.
    pub fn bump_instance_ttl(env: Env) {
        storage::bump_instance_ttl(&env);
    }

    // ── Emergency stop (SEC-010) ──────────────────────────────────────────────

    /// Pause the contract, blocking all state-mutating operations.
    ///
    /// Use this as an emergency stop when a critical vulnerability is discovered
    /// post-deployment. Read-only query functions remain accessible while paused.
    /// Only the admin may call this function.
    ///
    /// # Errors
    /// - [`PaymentError::Unauthorized`] if `admin` is not the stored admin.
    pub fn pause(env: Env, admin: Address) -> Result<(), PaymentError> {
        storage::bump_instance_ttl(&env);
        helper::require_admin(&env, &admin)?;
        storage::set_paused(&env, true);
        env.events().publish(
            (String::from_str(&env, "contract_paused"),),
            admin,
        );
        Ok(())
    }

    /// Resume the contract after it has been paused.
    ///
    /// Re-enables all state-mutating operations. Only the admin may call this.
    ///
    /// # Errors
    /// - [`PaymentError::Unauthorized`] if `admin` is not the stored admin.
    pub fn unpause(env: Env, admin: Address) -> Result<(), PaymentError> {
        storage::bump_instance_ttl(&env);
        helper::require_admin(&env, &admin)?;
        storage::set_paused(&env, false);
        env.events().publish(
            (String::from_str(&env, "contract_unpaused"),),
            admin,
        );
        Ok(())
    }

    /// Returns `true` if the contract is currently paused.
    pub fn is_paused(env: Env) -> bool {
        storage::bump_instance_ttl(&env);
        storage::is_paused(&env)
    }

    // ── Merchant management ───────────────────────────────────────────────────

    /// Register a new merchant on the contract.
    ///
    /// # Parameters
    /// - `merchant_address` — The address that will own this merchant profile.
    /// - `name` — Display name (max 64 bytes).
    /// - `description` — Short description (max 256 bytes).
    /// - `contact_info` — Printable ASCII contact string (max 128 bytes).
    /// - `category` — Merchant category enum.
    /// - `signing_public_key` — Optional ed25519 public key used to verify
    ///   payment signatures. Pass `None` to skip signature verification.
    ///
    /// # Errors
    /// - [`PaymentError::MerchantAlreadyRegistered`] if the address is already registered.
    /// - [`PaymentError::Unauthorized`] if whitelist mode is on and the address is not approved.
    /// - [`PaymentError::InvalidInput`] if any string field exceeds its length limit.
    pub fn register_merchant(
        env: Env,
        merchant_address: Address,
        name: String,
        description: String,
        contact_info: String,
        category: MerchantCategory,
        signing_public_key: Option<BytesN<32>>,
    ) -> Result<(), PaymentError> {
        storage::bump_instance_ttl(&env);
        if storage::is_paused(&env) { return Err(PaymentError::ContractPaused); }
        merchant_address.require_auth();
        if storage::get_merchant(&env, &merchant_address).is_some() {
            return Err(PaymentError::MerchantAlreadyRegistered);
        }
        if storage::is_whitelist_enabled(&env)
            && !storage::is_whitelisted(&env, &merchant_address)
        {
            return Err(PaymentError::Unauthorized);
        }
        helper::validate_merchant_fields(&name, &description, &contact_info)?;
        let merchant = Merchant {
            address: merchant_address.clone(),
            name,
            description,
            contact_info,
            category,
            active: true,
            registered_at: env.ledger().timestamp(),
            signing_public_key,
            tier: MerchantTier::Unverified,
        };
        storage::save_merchant(&env, &merchant);
        env.events().publish(
            (String::from_str(&env, "merchant_registered"),),
            merchant_address,
        );
        Ok(())
    }

    /// Assign a KYC / verification tier to a merchant (MISC-012).
    ///
    /// All merchants start at [`MerchantTier::Unverified`] at registration.
    /// Only an admin (via the multi-sig threshold) may upgrade or downgrade
    /// a merchant's tier, after completing the corresponding off-chain KYC
    /// process. See `docs/MERCHANT_TIERS.md` for tier criteria and the
    /// upgrade process.
    ///
    /// # Parameters
    /// - `admins` — Admin addresses satisfying the multi-sig threshold.
    /// - `merchant_address` — The merchant whose tier is being changed.
    /// - `tier` — The new tier to assign.
    ///
    /// # Errors
    /// - [`PaymentError::Unauthorized`] if the admin multi-sig check fails.
    /// - [`PaymentError::MerchantNotFound`] if the merchant does not exist.
    ///
    /// # Events
    /// Emits `merchant_tier_set` with payload `(merchant_address, tier)`.
    pub fn set_merchant_tier(
        env: Env,
        admins: Vec<Address>,
        merchant_address: Address,
        tier: MerchantTier,
    ) -> Result<(), PaymentError> {
        storage::bump_instance_ttl(&env);
        helper::require_multi_admin(&env, admins)?;
        let mut merchant = storage::get_merchant(&env, &merchant_address)
            .ok_or(PaymentError::MerchantNotFound)?;
        merchant.tier = tier.clone();
        storage::save_merchant(&env, &merchant);
        env.events().publish(
            (String::from_str(&env, "merchant_tier_set"),),
            (merchant_address, tier),
        );
        Ok(())
    }

    /// Returns the merchant's current KYC / verification tier (MISC-012).
    ///
    /// # Errors
    /// - [`PaymentError::MerchantNotFound`] if the merchant does not exist.
    pub fn get_merchant_tier(env: Env, merchant_address: Address) -> Result<MerchantTier, PaymentError> {
        storage::bump_instance_ttl(&env);
        let merchant = storage::get_merchant(&env, &merchant_address)
            .ok_or(PaymentError::MerchantNotFound)?;
        Ok(merchant.tier)
    }

    /// Enable or disable admin-whitelist mode for merchant registration.
    ///
    /// # Anti-spam mechanism (SEC-003)
    /// When whitelist mode is **enabled**, `register_merchant` requires the
    /// merchant address to be pre-approved by an admin before registration
    /// succeeds. This prevents unrestricted storage spam — an attacker cannot
    /// register unlimited merchants without admin approval, making large-scale
    /// storage-inflation attacks economically and operationally infeasible.
    ///
    /// When disabled (default), any address may register freely. Enable this
    /// mode on mainnet deployments where open registration is not desired.
    ///
    /// # Parameters
    /// - `admins` — Admin addresses satisfying the multi-sig threshold.
    /// - `enabled` — `true` to require pre-approval; `false` for open registration.
    ///
    /// # Errors
    /// - [`PaymentError::Unauthorized`] if the admin multi-sig check fails.
    pub fn set_whitelist_mode(
        env: Env,
        admins: Vec<Address>,
        enabled: bool,
    ) -> Result<(), PaymentError> {
        storage::bump_instance_ttl(&env);
        helper::require_multi_admin(&env, admins)?;
        storage::set_whitelist_enabled(&env, enabled);
        Ok(())
    }

    /// Pre-approve a merchant address for registration when whitelist mode is on.
    ///
    /// Must be called by an admin before the merchant calls `register_merchant`.
    /// Has no effect when whitelist mode is disabled (pre-approval is always
    /// accepted in that case, acting as an early-approval for future use).
    ///
    /// # Parameters
    /// - `admins` — Admin addresses satisfying the multi-sig threshold.
    /// - `merchant_address` — Address to whitelist.
    ///
    /// # Errors
    /// - [`PaymentError::Unauthorized`] if the admin multi-sig check fails.
    pub fn approve_merchant_registration(
        env: Env,
        admins: Vec<Address>,
        merchant_address: Address,
    ) -> Result<(), PaymentError> {
        storage::bump_instance_ttl(&env);
        helper::require_multi_admin(&env, admins)?;
        storage::set_whitelisted(&env, &merchant_address, true);
        Ok(())
    }

    // ── Token allowlist management (SEC-009) ──────────────────────────────────

    /// Enable or disable enforcement of the token allowlist.
    ///
    /// When enabled, any payment whose `order.token` is not on the allowlist
    /// will be rejected with [`PaymentError::TokenNotAllowed`].
    /// When disabled (default), any token contract address is accepted.
    ///
    /// Use `add_allowed_token` to populate the allowlist before enabling it.
    ///
    /// # Errors
    /// - [`PaymentError::Unauthorized`] if the admin multi-sig check fails.
    pub fn set_token_allowlist_mode(
        env: Env,
        admins: Vec<Address>,
        enabled: bool,
    ) -> Result<(), PaymentError> {
        storage::bump_instance_ttl(&env);
        helper::require_multi_admin(&env, admins)?;
        storage::set_token_allowlist_enabled(&env, enabled);
        env.events().publish(
            (String::from_str(&env, "token_allowlist_mode_set"),),
            enabled,
        );
        Ok(())
    }

    /// Add a token contract address to the admin-managed allowlist.
    ///
    /// Has no effect if the token is already on the allowlist.
    /// The allowlist is only enforced when `set_token_allowlist_mode(true)`
    /// has been called.
    ///
    /// # Errors
    /// - [`PaymentError::Unauthorized`] if the admin multi-sig check fails.
    pub fn add_allowed_token(
        env: Env,
        admins: Vec<Address>,
        token: Address,
    ) -> Result<(), PaymentError> {
        storage::bump_instance_ttl(&env);
        helper::require_multi_admin(&env, admins)?;
        storage::set_token_allowed(&env, &token, true);
        env.events().publish(
            (String::from_str(&env, "token_allowed"),),
            token,
        );
        Ok(())
    }

    /// Remove a token contract address from the admin-managed allowlist.
    ///
    /// After removal, payments using this token will be rejected when the
    /// allowlist is enabled.
    ///
    /// # Errors
    /// - [`PaymentError::Unauthorized`] if the admin multi-sig check fails.
    pub fn remove_allowed_token(
        env: Env,
        admins: Vec<Address>,
        token: Address,
    ) -> Result<(), PaymentError> {
        storage::bump_instance_ttl(&env);
        helper::require_multi_admin(&env, admins)?;
        storage::set_token_allowed(&env, &token, false);
        env.events().publish(
            (String::from_str(&env, "token_removed"),),
            token,
        );
        Ok(())
    }

    /// Returns `true` when `token` is on the allowlist.
    pub fn is_token_allowed(env: Env, token: Address) -> bool {
        storage::bump_instance_ttl(&env);
        storage::is_token_allowed(&env, &token)
    }

    /// Deactivate a merchant, preventing new payments from being processed.
    ///
    /// Can be called by the merchant themselves or by the admin multi-sig.
    ///
    /// # Parameters
    /// - `caller` — The address initiating the deactivation; must be authenticated.
    ///   If `admin_authorizers` is `None`, `caller` must equal `merchant_address`.
    /// - `merchant_address` — The merchant to deactivate.
    /// - `admin_authorizers` — If `Some`, the call is treated as an admin
    ///   action and the provided addresses must satisfy the multi-sig threshold.
    ///   If `None`, `caller` must be the merchant and must authorise the call directly.
    ///
    /// # Events
    /// Emits `merchant_deactivated` with payload `(merchant_address, caller)`.
    ///
    /// # Errors
    /// - [`PaymentError::MerchantNotFound`] if the merchant does not exist.
    /// - [`PaymentError::Unauthorized`] if neither the merchant nor a valid
    ///   admin multi-sig authorises the call.
    pub fn deactivate_merchant(
        env: Env,
        caller: Address,
        merchant_address: Address,
        admin_authorizers: Option<Vec<Address>>,
    ) -> Result<(), PaymentError> {
        storage::bump_instance_ttl(&env);
        if storage::is_paused(&env) { return Err(PaymentError::ContractPaused); }
        if let Some(admins) = admin_authorizers {
            helper::require_multi_admin(&env, admins)?;
        } else {
            caller.require_auth();
            if caller != merchant_address {
                return Err(PaymentError::Unauthorized);
            }
        }
        let mut merchant =
            storage::get_merchant(&env, &merchant_address).ok_or(PaymentError::MerchantNotFound)?;
        merchant.active = false;
        storage::save_merchant(&env, &merchant);
        env.events().publish(
            (String::from_str(&env, "merchant_deactivated"),),
            (merchant_address, caller),
        );
        Ok(())
    }

    /// Reactivate a previously deactivated merchant.
    ///
    /// Allows an admin or the merchant themselves to restore an inactive merchant
    /// to active status, preserving all existing payment history.
    ///
    /// # Parameters
    /// - `merchant_address` — The merchant to reactivate.
    /// - `admin_authorizers` — If `Some`, the call is treated as an admin
    ///   action and the provided addresses must satisfy the multi-sig threshold.
    ///   If `None`, `merchant_address` must authorise the call directly.
    ///
    /// # Errors
    /// - [`PaymentError::MerchantNotFound`] if the merchant does not exist.
    /// - [`PaymentError::MerchantAlreadyActive`] if the merchant is already active.
    /// - [`PaymentError::Unauthorized`] if neither the merchant nor a valid
    ///   admin multi-sig authorises the call.
    pub fn reactivate_merchant(
        env: Env,
        merchant_address: Address,
        admin_authorizers: Option<Vec<Address>>,
    ) -> Result<(), PaymentError> {
        storage::bump_instance_ttl(&env);
        if let Some(admins) = admin_authorizers {
            helper::require_multi_admin(&env, admins)?;
        } else {
            merchant_address.require_auth();
        }
        let mut merchant =
            storage::get_merchant(&env, &merchant_address).ok_or(PaymentError::MerchantNotFound)?;
        if merchant.active {
            return Err(PaymentError::MerchantAlreadyActive);
        }
        merchant.active = true;
        storage::save_merchant(&env, &merchant);
        env.events().publish(
            (String::from_str(&env, "merchant_reactivated"),),
            merchant_address,
        );
        Ok(())
    }

    /// Retrieve a merchant's profile by address.
    ///
    /// # Parameters
    /// - `merchant_address` — The address of the merchant to look up.
    ///
    /// # Returns
    /// The [`Merchant`] struct if found.
    ///
    /// # Errors
    /// - [`PaymentError::MerchantNotFound`] if no merchant is registered at
    ///   `merchant_address`.
    pub fn get_merchant(env: Env, merchant_address: Address) -> Result<Merchant, PaymentError> {
        storage::bump_instance_ttl(&env);
        storage::get_merchant(&env, &merchant_address).ok_or(PaymentError::MerchantNotFound)
    }

    /// Update mutable profile fields of an existing merchant.
    /// Only the merchant themselves may call this.
    /// Immutable fields (address, registered_at, signing_public_key, active) are preserved.
    pub fn update_merchant(
        env: Env,
        merchant_address: Address,
        name: String,
        description: String,
        contact_info: String,
    ) -> Result<(), PaymentError> {
        storage::bump_instance_ttl(&env);
        merchant_address.require_auth();
        helper::validate_merchant_fields(&name, &description, &contact_info)?;
        let mut merchant =
            storage::get_merchant(&env, &merchant_address).ok_or(PaymentError::MerchantNotFound)?;
        merchant.name = name.clone();
        merchant.description = description.clone();
        merchant.contact_info = contact_info.clone();
        storage::save_merchant(&env, &merchant);
        env.events().publish(
            (String::from_str(&env, "merchant_updated"),),
            (merchant_address, name, description, contact_info),
        );
        Ok(())
    }

    /// Bind or update the ed25519 signing key for a registered merchant.
    ///
    /// Separates key management from profile registration so that merchants can
    /// rotate their signing key without re-registering. Only the merchant
    /// themselves may call this function.
    ///
    /// `process_payment_with_signature` always verifies signatures against the
    /// on-chain stored key, so updating this binding takes immediate effect.
    ///
    /// # Parameters
    /// - `merchant_address` — The merchant updating their key; must be authenticated.
    /// - `signing_public_key` — The new ed25519 public key to store. Pass `None`
    ///   to clear the key and disable signature verification for this merchant.
    ///
    /// # Errors
    /// - [`PaymentError::MerchantNotFound`] if no merchant is registered.
    /// - [`PaymentError::MerchantInactive`] if the merchant is deactivated.
    pub fn set_merchant_signing_key(
        env: Env,
        merchant_address: Address,
        signing_public_key: Option<BytesN<32>>,
    ) -> Result<(), PaymentError> {
        storage::bump_instance_ttl(&env);
        merchant_address.require_auth();
        let mut merchant =
            storage::get_merchant(&env, &merchant_address).ok_or(PaymentError::MerchantNotFound)?;
        if !merchant.active {
            return Err(PaymentError::MerchantInactive);
        }
        merchant.signing_public_key = signing_public_key;
        storage::save_merchant(&env, &merchant);
        env.events().publish(
            (String::from_str(&env, "merchant_signing_key_updated"),),
            merchant_address,
        );
        Ok(())
    }

    // ── Payment processing ────────────────────────────────────────────────────

    pub fn process_payment_with_signature(
        env: Env,
        payer: Address,
        order: PaymentOrder,
        signature: BytesN<64>,
        merchant_public_key: BytesN<32>,
    ) -> Result<(), PaymentError> {
        storage::bump_instance_ttl(&env);
        if storage::is_paused(&env) { return Err(PaymentError::ContractPaused); }
        payer.require_auth();
        if order.payer != payer {
            return Err(PaymentError::InvalidInput);
        }
        helper::validate_amount(order.amount)?;
        helper::validate_order_id(&order.order_id)?;
        if storage::get_payment(&env, &order.order_id).is_some() {
            return Err(PaymentError::PaymentAlreadyExists);
        }
        let now = env.ledger().timestamp();
        if order.expires_at > 0 && now > order.expires_at {
            return Err(PaymentError::PaymentExpired);
        }
        // SEC-009: enforce token allowlist when enabled
        if storage::is_token_allowlist_enabled(&env)
            && !storage::is_token_allowed(&env, &order.token)
        {
            return Err(PaymentError::TokenNotAllowed);
        }
        let merchant = storage::get_merchant(&env, &order.merchant_address)
            .ok_or(PaymentError::MerchantNotFound)?;
        if !merchant.active {
            return Err(PaymentError::MerchantInactive);
        }
        let stored_key = merchant
            .signing_public_key
            .unwrap_or_else(|| BytesN::from_array(&env, &[0u8; 32]));
        let zero_key = BytesN::from_array(&env, &[0u8; 32]);
        if stored_key != zero_key {
            let payload = order.clone().to_xdr(&env);
            helper::verify_signature(&env, &stored_key, &payload, &signature)?;
        }
        let record = PaymentRecord {
            order_id: order.order_id.clone(),
            merchant_address: order.merchant_address.clone(),
            payer: payer.clone(),
            token: order.token.clone(),
            amount: order.amount,
            refunded_amount: 0,
            pending_refund_amount: 0,
            status: PaymentStatus::Completed,
            paid_at: now,
            description: order.description.clone(),
        };
        storage::save_payment(&env, &record);
        storage::push_merchant_payment_id(&env, &order.merchant_address, &order.order_id);
        storage::push_payer_payment_id(&env, &payer, &order.order_id);
        storage::push_global_payment_id(&env, &order.order_id);
        storage::increment_payment_stats(&env, order.amount)?;

        // ── Re-entrancy model (SC-011) ───────────────────────────────────────
        // All state mutations (payment record, index updates, stats) are
        // committed to persistent storage BEFORE the external token transfer
        // call below. This follows the Checks-Effects-Interactions (CEI)
        // pattern and is the primary defence against re-entrancy.
        //
        // Why Soroban further limits re-entrancy risk:
        // Soroban's execution model enforces contract-level authorisation at
        // the VM boundary. A re-entrant call from a malicious token contract
        // back into THIS contract would require a fresh authorisation context
        // that is not present in the current transaction. In practice:
        //   1. `payer.require_auth()` has already been consumed for this
        //      invocation; the same auth cannot be reused.
        //   2. Soroban does not support call-stack re-entry into the same
        //      contract instance within a single transaction in the same
        //      authorisation scope.
        //
        // Taken together, the CEI ordering plus the Soroban execution model
        // means that even if the token contract attempts a re-entrant call,
        // the state it observes will already reflect the completed payment,
        // causing any duplicate `process_payment_with_signature` call to fail
        // with `PaymentAlreadyExists`.
        let token_client = token::Client::new(&env, &order.token);
        // Pre-check balance to return a typed error instead of a host trap.
        if token_client.balance(&payer) < order.amount {
            return Err(PaymentError::InsufficientBalance);
        }
        token_client.transfer(&payer, &order.merchant_address, &order.amount);
        env.events().publish(
            (String::from_str(&env, "payment_processed"),),
            (order.order_id, payer, order.merchant_address, order.amount),
        );
        Ok(())
    }

    // ── Payment queries ───────────────────────────────────────────────────────

    /// Retrieve a single payment record by its order ID.
    ///
    /// Only the payer, the merchant, or an admin may view a payment record.
    ///
    /// # Parameters
    /// - `caller` — The address requesting the record; must be authenticated.
    /// - `order_id` — The unique order identifier.
    ///
    /// # Returns
    /// The [`PaymentRecord`] if found and the caller is authorised.
    ///
    /// # Errors
    /// - [`PaymentError::PaymentNotFound`] if no payment exists for `order_id`.
    /// - [`PaymentError::Unauthorized`] if `caller` is not the payer, merchant,
    ///   or an admin.
    pub fn get_payment_by_id(
        env: Env,
        caller: Address,
        order_id: Bytes,
    ) -> Result<PaymentRecord, PaymentError> {
        storage::bump_instance_ttl(&env);
        caller.require_auth();
        let record = storage::get_payment(&env, &order_id).ok_or(PaymentError::PaymentNotFound)?;
        let is_admin = if let Some(config) = storage::get_admin_config(&env) {
            config.admins.contains(&caller)
        } else if let Some(admin) = storage::get_admin(&env) {
            admin == caller
        } else {
            false
        };
        if caller != record.payer && caller != record.merchant_address && !is_admin {
            return Err(PaymentError::Unauthorized);
        }
        Ok(record)
    }

    /// Return a paginated, filtered, and sorted list of payments for a merchant.
    ///
    /// # Parameters
    /// - `merchant` — The merchant address; must be authenticated.
    /// - `cursor` — Optional order ID to resume pagination from.
    /// - `limit` — Maximum number of records to return (capped at 100).
    /// - `filter` — Optional [`PaymentFilter`] to narrow results.
    /// - `sort_field` — Sort by [`SortField::Date`] or [`SortField::Amount`].
    /// - `sort_order` — [`SortOrder::Ascending`] or [`SortOrder::Descending`].
    ///
    /// # Returns
    /// A [`PaymentPage`] containing the matching records, a next-page cursor,
    /// and the total count of matching records.
    ///
    /// # Errors
    /// - [`PaymentError::Unauthorized`] if `merchant` is not authenticated or
    ///   is not an active registered merchant.
    pub fn get_merchant_payment_history(
        env: Env,
        merchant: Address,
        cursor: Option<Bytes>,
        limit: u32,
        filter: Option<PaymentFilter>,
        sort_field: SortField,
        sort_order: SortOrder,
    ) -> Result<PaymentPage, PaymentError> {
        storage::bump_instance_ttl(&env);
        helper::require_merchant(&env, &merchant, &merchant)?;
        let ids = storage::get_merchant_payment_ids(&env, &merchant);
        Self::paginate_payments(&env, ids, cursor, limit, filter, sort_field, sort_order)
    }

    /// Return a paginated, filtered, and sorted list of payments made by a payer.
    ///
    /// # Parameters
    /// - `payer` — The payer address; must be authenticated.
    /// - `cursor` — Optional order ID to resume pagination from.
    /// - `limit` — Maximum number of records to return (capped at 100).
    /// - `filter` — Optional [`PaymentFilter`] to narrow results.
    /// - `sort_field` — Sort by [`SortField::Date`] or [`SortField::Amount`].
    /// - `sort_order` — [`SortOrder::Ascending`] or [`SortOrder::Descending`].
    ///
    /// # Returns
    /// A [`PaymentPage`] containing the matching records, a next-page cursor,
    /// and the total count of matching records.
    ///
    /// # Errors
    /// - [`PaymentError::Unauthorized`] if `payer` is not authenticated.
    pub fn get_payer_payment_history(
        env: Env,
        payer: Address,
        cursor: Option<Bytes>,
        limit: u32,
        filter: Option<PaymentFilter>,
        sort_field: SortField,
        sort_order: SortOrder,
    ) -> Result<PaymentPage, PaymentError> {
        storage::bump_instance_ttl(&env);
        payer.require_auth();
        let ids = storage::get_payer_payment_ids(&env, &payer);
        Self::paginate_payments(&env, ids, cursor, limit, filter, sort_field, sort_order)
    }

    /// Return aggregate payment and refund statistics. Admin only.
    ///
    /// When `date_start` and `date_end` are both `None` the pre-computed
    /// counters are returned directly (O(1)). When either date bound is
    /// provided the function performs a scan-based fallback that filters
    /// the global payment and refund indexes by timestamp (O(n)).
    ///
    /// Fixes SC-003: previously `date_start` and `date_end` were silently
    /// discarded (`let _ = (date_start, date_end)`) so callers always
    /// received all-time totals regardless of the requested window.
    ///
    /// # Parameters
    /// - `admins` — Admin addresses that together satisfy the multi-sig threshold.
    /// - `date_start` — Optional Unix timestamp lower bound (inclusive).
    ///   `None` means no lower bound.
    /// - `date_end` — Optional Unix timestamp upper bound (inclusive).
    ///   `None` means no upper bound.
    /// - Both `None` → returns cached all-time totals.
    ///
    /// # Returns
    /// A [`GlobalStats`] struct with total payment/refund counts and volumes.
    ///
    /// # Errors
    /// - [`PaymentError::Unauthorized`] if the provided addresses do not satisfy
    ///   the admin multi-sig threshold.
    /// - [`PaymentError::ArithmeticError`] on volume overflow.
    pub fn get_global_payment_stats(
        env: Env,
        admins: Vec<Address>,
        date_start: Option<u64>,
        date_end: Option<u64>,
    ) -> Result<GlobalStats, PaymentError> {
        storage::bump_instance_ttl(&env);
        helper::require_multi_admin(&env, admins)?;
        if date_start.is_none() && date_end.is_none() {
            return Ok(storage::get_global_stats(&env));
        }
        let mut stats = GlobalStats {
            total_payments: 0,
            total_volume: 0,
            total_refunds: 0,
            total_refund_volume: 0,
        };
        for id in storage::get_global_payment_ids(&env).iter() {
            if let Some(record) = storage::get_payment(&env, &id) {
                if helper::in_date_range(record.paid_at, date_start, date_end) {
                    stats.total_payments += 1;
                    stats.total_volume = stats
                        .total_volume
                        .checked_add(record.amount)
                        .ok_or(PaymentError::ArithmeticError)?;
                }
            }
        }
        for id in storage::get_all_refund_ids(&env).iter() {
            if let Some(record) = storage::get_refund(&env, &id) {
                if helper::in_date_range(record.initiated_at, date_start, date_end) {
                    stats.total_refunds += 1;
                    stats.total_refund_volume = stats
                        .total_refund_volume
                        .checked_add(record.amount)
                        .ok_or(PaymentError::ArithmeticError)?;
                }
            }
        }
        Ok(stats)
    }

    pub fn get_merchant_stats(
        env: Env,
        caller: Address,
        merchant: Address,
        date_start: Option<u64>,
        date_end: Option<u64>,
    ) -> Result<MerchantStats, PaymentError> {
        caller.require_auth();
        // Merchant can query their own stats, or admin can query any merchant
        if caller != merchant {
            let mut admins = Vec::new(&env);
            admins.push_back(caller.clone());
            helper::require_multi_admin(&env, admins)?;
        }

        // If no date filter, return cached stats
        if date_start.is_none() && date_end.is_none() {
            return Ok(storage::get_merchant_stats(&env, &merchant));
        }

        // Compute filtered stats by iterating merchant's payments
        let mut stats = MerchantStats {
            merchant_address: merchant.clone(),
            total_payments: 0,
            total_volume: 0,
            total_refunds: 0,
            total_refund_volume: 0,
        };

        let p_ids = storage::get_merchant_payment_ids(&env, &merchant);
        for id in p_ids.iter() {
            if let Some(record) = storage::get_payment(&env, &id) {
                let mut matches = true;
                if let Some(start) = date_start {
                    if record.paid_at < start {
                        matches = false;
                    }
                }
                if let Some(end) = date_end {
                    if record.paid_at > end {
                        matches = false;
                    }
                }
                if matches {
                    stats.total_payments += 1;
                    stats.total_volume = stats
                        .total_volume
                        .checked_add(record.amount)
                        .ok_or(PaymentError::ArithmeticError)?;
                    if record.refunded_amount > 0 {
                        stats.total_refunds += 1;
                        stats.total_refund_volume = stats
                            .total_refund_volume
                            .checked_add(record.refunded_amount)
                            .ok_or(PaymentError::ArithmeticError)?;
                    }
                }
            }
        }

        Ok(stats)
    }

    // ── Payment management ────────────────────────────────────────────────────

    /// Stub retained for ABI compatibility — always returns `InvalidInput`.
    ///
    /// Refund state must be modified exclusively through the refund workflow
    /// (`initiate_refund` → `approve_refund` → `execute_refund`). Direct
    /// status mutation is intentionally disabled.
    ///
    /// # Errors
    /// Always returns [`PaymentError::InvalidInput`].
    pub fn update_payment_status(
        env: Env,
        _caller: Address,
        _order_id: Bytes,
        _refunded_amount: i128,
    ) -> Result<(), PaymentError> {
        // Intentionally disabled: refund state is managed exclusively via the
        // initiate/approve/execute refund workflow.
        Err(PaymentError::InvalidInput)
    }

    /// Permanently remove a payment record from storage. Admin only.
    ///
    /// Also removes the record from the merchant, payer, and global payment
    /// index lists. This operation is irreversible.
    ///
    /// # Parameters
    /// - `admins` — Admin addresses that together satisfy the multi-sig threshold.
    /// - `order_id` — The order ID of the payment to archive.
    ///
    /// # Errors
    /// - [`PaymentError::Unauthorized`] if the admin multi-sig check fails.
    /// - [`PaymentError::PaymentNotFound`] if no payment exists for `order_id`.
    pub fn archive_payment_record(
        env: Env,
        admins: Vec<Address>,
        order_id: Bytes,
    ) -> Result<(), PaymentError> {
        storage::bump_instance_ttl(&env);
        if storage::is_paused(&env) { return Err(PaymentError::ContractPaused); }
        helper::require_multi_admin(&env, admins)?;
        let record = storage::get_payment(&env, &order_id).ok_or(PaymentError::PaymentNotFound)?;
        // Mark the order_id as archived (tombstone) to prevent replay
        storage::set_archived_payment(&env, &order_id);
        storage::remove_payment(&env, &order_id);
        storage::remove_merchant_payment_id(&env, &record.merchant_address, &order_id);
        storage::remove_payer_payment_id(&env, &record.payer, &order_id);
        storage::remove_global_payment_id(&env, &order_id);
        // Decrement global payment stats so aggregate counts stay accurate.
        storage::decrement_payment_stats(&env, record.amount);
        // Walk the global refund index and decrement stats for every completed
        // refund that was associated with this payment.
        for rid in storage::get_all_refund_ids(&env).iter() {
            if let Some(refund) = storage::get_refund(&env, &rid) {
                if refund.order_id == order_id && refund.status == RefundStatus::Completed {
                    storage::decrement_refund_stats(&env, refund.amount);
                }
            }
        }
        Ok(())
    }

    /// Remove payment records older than the configured cleanup period. Admin only.
    ///
    /// Iterates the global payment index (`GlobalPaymentIndex`) and deletes any
    /// record whose `paid_at` timestamp is older than `now - cleanup_period`.
    /// The global index is updated in place to remove deleted IDs.
    ///
    /// Fixes SC-002: previously this function was a no-op that always returned 0.
    /// It now correctly scans the `GlobalPaymentIndex`, removes expired records
    /// from persistent storage, and returns the actual count of removed records.
    ///
    /// # Parameters
    /// - `admins` — Admin addresses that together satisfy the multi-sig threshold.
    ///
    /// # Returns
    /// The number of payment records that were deleted.
    ///
    /// # Errors
    /// - [`PaymentError::Unauthorized`] if the admin multi-sig check fails.
    pub fn cleanup_expired_payments(env: Env, admins: Vec<Address>) -> Result<u32, PaymentError> {
        storage::bump_instance_ttl(&env);
        if storage::is_paused(&env) { return Err(PaymentError::ContractPaused); }
        helper::require_multi_admin(&env, admins)?;
        let period = storage::get_cleanup_period(&env);
        let now = env.ledger().timestamp();
        let cutoff = now.saturating_sub(period);
        let ids = storage::get_global_payment_ids(&env);
        let mut new_ids = Vec::new(&env);
        let mut count = 0u32;
        for id in ids.iter() {
            if let Some(record) = storage::get_payment(&env, &id) {
                if record.paid_at < cutoff {
                    storage::remove_payment(&env, &id);
                    count += 1;
                } else {
                    new_ids.push_back(id);
                }
            }
        }
        if count > 0 {
            storage::set_global_payment_ids(&env, &new_ids);
        }
        Ok(count)
    }

    /// Set the period after which payment records are eligible for cleanup. Admin only.
    ///
    /// # Parameters
    /// - `admins` — Admin addresses that together satisfy the multi-sig threshold.
    /// - `period` — Cleanup period in seconds. Must be greater than zero.
    ///
    /// # Errors
    /// - [`PaymentError::Unauthorized`] if the admin multi-sig check fails.
    /// - [`PaymentError::InvalidInput`] if `period` is zero.
    pub fn set_payment_cleanup_period(
        env: Env,
        admins: Vec<Address>,
        period: u64,
    ) -> Result<(), PaymentError> {
        storage::bump_instance_ttl(&env);
        if storage::is_paused(&env) { return Err(PaymentError::ContractPaused); }
        helper::require_multi_admin(&env, admins)?;
        if period == 0 {
            return Err(PaymentError::InvalidInput);
        }
        storage::set_cleanup_period(&env, period);
        Ok(())
    }

    /// Set the default expiry duration for new multi-sig payments. Admin only.
    ///
    /// # Parameters
    /// - `admins` — Admin addresses that together satisfy the multi-sig threshold.
    /// - `expiry` — Expiry duration in seconds. Must be at least 3600 (1 hour).
    ///
    /// # Errors
    /// - [`PaymentError::Unauthorized`] if the admin multi-sig check fails.
    /// - [`PaymentError::InvalidInput`] if `expiry` is less than 3600.
    pub fn set_default_multisig_expiry(
        env: Env,
        admins: Vec<Address>,
        expiry: u64,
    ) -> Result<(), PaymentError> {
        storage::bump_instance_ttl(&env);
        if storage::is_paused(&env) { return Err(PaymentError::ContractPaused); }
        helper::require_multi_admin(&env, admins)?;
        if expiry < 3600 {
            return Err(PaymentError::InvalidInput);
        }
        storage::set_default_multisig_expiry(&env, expiry);
        Ok(())
    }

    // ── Refunds ───────────────────────────────────────────────────────────────

    /// Initiate a refund request for a completed payment.
    ///
    /// Either the payer or the merchant may initiate a refund. The refund must
    /// be initiated within the refund window (30 days from payment).
    ///
    /// # Parameters
    /// - `caller` — The address initiating the refund; must be authenticated.
    /// - `refund_id` — A unique identifier for this refund request.
    /// - `order_id` — The order ID of the payment to refund.
    /// - `amount` — The amount to refund. Must be positive and must not cause
    ///   total refunds to exceed the original payment amount.
    /// - `reason` — A human-readable reason string (max 256 bytes).
    ///
    /// # Errors
    /// - [`PaymentError::PaymentNotFound`] if the payment does not exist.
    /// - [`PaymentError::Unauthorized`] if `caller` is neither the payer nor
    ///   the merchant.
    /// - [`PaymentError::RefundWindowExpired`] if the refund window has passed.
    /// - [`PaymentError::RefundAmountExceedsPayment`] if the requested amount
    ///   would exceed the original payment.
    /// - [`PaymentError::RefundAlreadyExists`] if `refund_id` is already in use.
    /// - [`PaymentError::InvalidAmount`] if `amount` is not positive.
    /// - [`PaymentError::InvalidInput`] if `reason` exceeds 256 bytes.
    pub fn initiate_refund(
        env: Env,
        caller: Address,
        refund_id: Bytes,
        order_id: Bytes,
        amount: i128,
        reason: String,
    ) -> Result<(), PaymentError> {
        storage::bump_instance_ttl(&env);
        if storage::is_paused(&env) { return Err(PaymentError::ContractPaused); }
        caller.require_auth();
        helper::validate_amount(amount)?;
        if reason.len() > 256 {
            return Err(PaymentError::InvalidInput);
        }

        let mut record =
            storage::get_payment(&env, &order_id).ok_or(PaymentError::PaymentNotFound)?;
        if caller != record.payer && caller != record.merchant_address {
            return Err(PaymentError::Unauthorized);
        }
        let now = env.ledger().timestamp();
        // Deadline = paid_at + 30-day window + 1-hour grace buffer.
        // The grace buffer absorbs minor ledger timestamp drift near the boundary
        // so that legitimate refunds submitted just before the deadline are not
        // rejected due to a few seconds of validator clock variance.
        // See storage::REFUND_WINDOW and storage::REFUND_GRACE_BUFFER for the
        // full trust-model rationale.
        if now > record.paid_at + REFUND_WINDOW + REFUND_GRACE_BUFFER {
            return Err(PaymentError::RefundWindowExpired);
        }
        let new_total = record.refunded_amount + record.pending_refund_amount + amount;
        if new_total > record.amount {
            return Err(PaymentError::RefundAmountExceedsPayment);
        }
        if storage::get_refund(&env, &refund_id).is_some() {
            return Err(PaymentError::RefundAlreadyExists);
        }

        if storage::get_order_refund_count(&env, &order_id) >= storage::MAX_PENDING_REFUNDS {
            return Err(PaymentError::InvalidInput);
        }

        let refund = RefundRecord {
            refund_id: refund_id.clone(),
            order_id: order_id.clone(),
            amount,
            reason,
            status: RefundStatus::Pending,
            initiated_by: caller.clone(),
            initiated_at: now,
            dispute_reason: String::from_str(&env, ""),
        };
        storage::save_refund(&env, &refund);
        storage::increment_order_refund_count(&env, &order_id);

        record.pending_refund_amount += amount;
        storage::save_payment(&env, &record);
        env.events().publish(
            (String::from_str(&env, "refund_initiated"),),
            (refund_id, caller, amount),
        );
        Ok(())
    }

    /// Approve a pending refund request.
    ///
    /// Can be approved by the merchant (directly) or by the admin multi-sig.
    /// Once approved the refund can be executed by the merchant.
    ///
    /// # Parameters
    /// - `caller` — The address approving the refund; must be authenticated.
    /// - `refund_id` — The unique identifier of the refund to approve.
    /// - `admin_authorizers` — If `Some`, the call is treated as an admin
    ///   action. If `None`, `caller` must be the merchant.
    ///
    /// # Errors
    /// - [`PaymentError::RefundNotFound`] if the refund does not exist.
    /// - [`PaymentError::PaymentNotFound`] if the associated payment is missing.
    /// - [`PaymentError::Unauthorized`] if neither the merchant nor a valid
    ///   admin multi-sig authorises the call.
    /// - [`PaymentError::RefundAlreadyCompleted`] if the refund is not pending.
    pub fn approve_refund(
        env: Env,
        caller: Address,
        refund_id: Bytes,
        admin_authorizers: Option<Vec<Address>>,
    ) -> Result<(), PaymentError> {
        storage::bump_instance_ttl(&env);
        if storage::is_paused(&env) { return Err(PaymentError::ContractPaused); }
        let mut refund =
            storage::get_refund(&env, &refund_id).ok_or(PaymentError::RefundNotFound)?;
        let record =
            storage::get_payment(&env, &refund.order_id).ok_or(PaymentError::PaymentNotFound)?;
        let is_authorized = if let Some(admins) = admin_authorizers {
            helper::require_multi_admin(&env, admins).is_ok()
        } else {
            helper::require_merchant(&env, &caller, &record.merchant_address).is_ok()
        };
        if !is_authorized {
            return Err(PaymentError::Unauthorized);
        }
        if refund.status != RefundStatus::Pending {
            return Err(PaymentError::RefundAlreadyCompleted);
        }
        refund.status = RefundStatus::Approved;
        storage::save_refund(&env, &refund);
        env.events()
            .publish((String::from_str(&env, "refund_approved"),), refund_id);
        Ok(())
    }

    /// Reject a pending refund request.
    ///
    /// Can be rejected by the merchant (directly) or by the admin multi-sig.
    /// Rejecting a refund releases the reserved pending refund amount back to
    /// the payment record.
    ///
    /// # Parameters
    /// - `caller` — The address rejecting the refund; must be authenticated.
    /// - `refund_id` — The unique identifier of the refund to reject.
    /// - `admin_authorizers` — If `Some`, the call is treated as an admin
    ///   action. If `None`, `caller` must be the merchant.
    ///
    /// # Errors
    /// - [`PaymentError::RefundNotFound`] if the refund does not exist.
    /// - [`PaymentError::PaymentNotFound`] if the associated payment is missing.
    /// - [`PaymentError::Unauthorized`] if neither the merchant nor a valid
    ///   admin multi-sig authorises the call.
    /// - [`PaymentError::RefundAlreadyCompleted`] if the refund is not pending.
    pub fn reject_refund(
        env: Env,
        caller: Address,
        refund_id: Bytes,
        admin_authorizers: Option<Vec<Address>>,
    ) -> Result<(), PaymentError> {
        storage::bump_instance_ttl(&env);
        if storage::is_paused(&env) { return Err(PaymentError::ContractPaused); }
        let mut refund =
            storage::get_refund(&env, &refund_id).ok_or(PaymentError::RefundNotFound)?;
        let record =
            storage::get_payment(&env, &refund.order_id).ok_or(PaymentError::PaymentNotFound)?;
        let is_authorized = if let Some(admins) = admin_authorizers {
            helper::require_multi_admin(&env, admins).is_ok()
        } else {
            helper::require_merchant(&env, &caller, &record.merchant_address).is_ok()
        };
        if !is_authorized {
            return Err(PaymentError::Unauthorized);
        }
        if refund.status != RefundStatus::Pending {
            return Err(PaymentError::RefundAlreadyCompleted);
        }
        refund.status = RefundStatus::Rejected;
        storage::save_refund(&env, &refund);
        let mut record = storage::get_payment(&env, &refund.order_id)
            .ok_or(PaymentError::PaymentNotFound)?;
        record.pending_refund_amount = record.pending_refund_amount.saturating_sub(refund.amount);
        storage::save_payment(&env, &record);
        storage::decrement_order_refund_count(&env, &refund.order_id);

        env.events()
            .publish((String::from_str(&env, "refund_rejected"),), refund_id);
        Ok(())
    }

    /// Execute an approved refund, transferring tokens back to the payer.
    ///
    /// Only the merchant may execute a refund. The refund must be in
    /// `Approved` status. The token transfer is performed after all state
    /// updates to reduce re-entrancy risk.
    ///
    /// Fixes SC-004: previously the function signature took no `caller`
    /// parameter, meaning any account could invoke the function before the
    /// `require_auth` on `merchant_address` was reached. The fix adds an
    /// explicit `caller: Address` parameter, calls `caller.require_auth()`
    /// immediately, and then verifies `caller == record.merchant_address`
    /// before any state is mutated or funds transferred.
    ///
    /// # Parameters
    /// - `caller` — The merchant address; must be authenticated. Rejected with
    ///   `Unauthorized` if it does not match the payment's merchant.
    /// - `refund_id` — The unique identifier of the refund to execute.
    ///
    /// # Errors
    /// - [`PaymentError::RefundNotFound`] if the refund does not exist.
    /// - [`PaymentError::RefundNotApproved`] if the refund is not in `Approved` status.
    /// - [`PaymentError::PaymentNotFound`] if the associated payment is missing.
    /// - [`PaymentError::Unauthorized`] if `caller` is not the merchant.
    pub fn execute_refund(env: Env, caller: Address, refund_id: Bytes) -> Result<(), PaymentError> {
        storage::bump_instance_ttl(&env);
        if storage::is_paused(&env) { return Err(PaymentError::ContractPaused); }
        caller.require_auth();
        let mut refund =
            storage::get_refund(&env, &refund_id).ok_or(PaymentError::RefundNotFound)?;
        if refund.status != RefundStatus::Approved {
            return Err(PaymentError::RefundNotApproved);
        }
        let mut record = storage::get_payment(&env, &refund.order_id)
            .ok_or(PaymentError::PaymentNotFound)?;
        if caller != record.merchant_address {
            return Err(PaymentError::Unauthorized);
        }
        let new_total = record.refunded_amount + refund.amount;
        record.refunded_amount = new_total;
        record.pending_refund_amount = record.pending_refund_amount.saturating_sub(refund.amount);
        record.status = if new_total == record.amount {
            PaymentStatus::FullyRefunded
        } else {
            PaymentStatus::PartiallyRefunded
        };
        storage::save_payment(&env, &record);
        refund.status = RefundStatus::Completed;
        storage::save_refund(&env, &refund);
        storage::push_all_refund_id(&env, &refund_id);
        storage::decrement_order_refund_count(&env, &refund.order_id);
        storage::increment_refund_stats(&env, refund.amount)?;

        // ── Re-entrancy model (SC-011) ───────────────────────────────────────
        // All state mutations (payment record update, refund status, stats)
        // are committed to persistent storage BEFORE the external token
        // transfer below. This is the CEI (Checks-Effects-Interactions)
        // pattern. If a malicious token contract attempts to re-enter
        // execute_refund, the refund status is already Completed and the
        // call will fail with RefundNotApproved. See the identical comment
        // in process_payment_with_signature for a full explanation of the
        // Soroban execution model and why re-entrancy is further constrained
        // at the VM level.
        let token_client = token::Client::new(&env, &record.token);
        // Pre-check merchant balance to return a typed error instead of a host trap.
        if token_client.balance(&record.merchant_address) < refund.amount {
            return Err(PaymentError::InsufficientBalance);
        }
        token_client.transfer(&record.merchant_address, &record.payer, &refund.amount);
        env.events().publish(
            (String::from_str(&env, "refund_executed"),),
            (refund_id, refund.amount),
        );
        env.events().publish(
            (String::from_str(&env, "payment_status_updated"),),
            (record.order_id, record.status, caller),
        );
        Ok(())
    }

    pub fn get_refund_status(env: Env, refund_id: Bytes) -> Result<RefundStatus, PaymentError> {
        let refund =
            storage::get_refund(&env, &refund_id).ok_or(PaymentError::RefundNotFound)?;
        Ok(refund.status)
    }

    /// Mark a refund as Disputed. Callable by payer or merchant while refund is Pending/Approved.
    // Replaced by the full dispute_refund below (with reason param + proper auth).

    /// Admin resolves a disputed refund (approve or reject). Checks dispute_deadline.
    // Replaced by the full resolve_dispute below (multi-admin aware).

    // ── Multi-signature payments ───────────────────────────────────────────────

    /// Initiate a multi-signature payment, locking funds in contract escrow.
    ///
    /// Funds are transferred from `initiator` to the contract address
    /// immediately. The payment is only released to the merchant once all
    /// required signers have signed and `execute_multisig_payment` is called.
    ///
    /// # Parameters
    /// - `initiator` — The address funding the escrow; must be authenticated.
    /// - `payment_id` — A unique identifier for this multi-sig payment.
    /// - `order` — The [`PaymentOrder`] describing the payment details.
    /// - `required_signers` — List of addresses that must sign before execution
    ///   (1 to `MAX_SIGNERS` entries, no duplicates).
    ///
    /// # Errors
    /// - [`PaymentError::PaymentAlreadyExists`] if `payment_id` is already in use.
    /// - [`PaymentError::MerchantNotFound`] if the merchant does not exist.
    /// - [`PaymentError::MerchantInactive`] if the merchant is deactivated.
    /// - [`PaymentError::InvalidInput`] if `required_signers` is empty, exceeds
    ///   `MAX_SIGNERS`, or contains duplicates.
    /// - [`PaymentError::InvalidAmount`] if the order amount is not positive.
    pub fn initiate_multisig_payment(
        env: Env,
        initiator: Address,
        payment_id: Bytes,
        order: PaymentOrder,
        required_signers: Vec<Address>,
    ) -> Result<(), PaymentError> {
        storage::bump_instance_ttl(&env);
        if storage::is_paused(&env) { return Err(PaymentError::ContractPaused); }
        initiator.require_auth();
        helper::validate_amount(order.amount)?;
        if storage::get_multisig(&env, &payment_id).is_some() {
            return Err(PaymentError::PaymentAlreadyExists);
        }
        if required_signers.is_empty() || required_signers.len() > storage::MAX_SIGNERS {
            return Err(PaymentError::InvalidInput);
        }
        // SEC-009: enforce token allowlist when enabled
        if storage::is_token_allowlist_enabled(&env)
            && !storage::is_token_allowed(&env, &order.token)
        {
            return Err(PaymentError::TokenNotAllowed);
        }
        let merchant = storage::get_merchant(&env, &order.merchant_address)
            .ok_or(PaymentError::MerchantNotFound)?;
        if !merchant.active {
            return Err(PaymentError::MerchantInactive);
        }
        // T-008: Reject duplicate signers so a single address cannot satisfy
        // the full threshold alone.
        // See: https://github.com/queenannaE/pulsar-contracts/issues/38
        let mut unique_signers = Vec::new(&env);
        for signer in required_signers.iter() {
            if unique_signers.contains(&signer) {
                return Err(PaymentError::InvalidInput);
            }
            unique_signers.push_back(signer);
        }
        let now = env.ledger().timestamp();
        let expires_at = now + storage::get_default_multisig_expiry(&env);
        let ms = MultisigPayment {
            payment_id: payment_id.clone(),
            order,
            required_signers,
            signatures: Vec::new(&env),
            executed: false,
            expires_at,
            created_at: now,
        };
        let token_client = token::Client::new(&env, &ms.order.token);
        let contract_addr = env.current_contract_address();
        token_client.transfer(&initiator, &contract_addr, &ms.order.amount);
        storage::save_multisig(&env, &ms);
        env.events().publish(
            (String::from_str(&env, "multisig_initiated"),),
            (payment_id, initiator),
        );
        Ok(())
    }

    /// Add a signature to a pending multi-sig payment.
    ///
    /// The signer must be in the `required_signers` list and must not have
    /// already signed. The payment must not be expired or already executed.
    ///
    /// # Parameters
    /// - `signer` — The address adding their signature; must be authenticated.
    /// - `payment_id` — The unique identifier of the multi-sig payment.
    ///
    /// # Errors
    /// - [`PaymentError::MultisigNotFound`] if the payment does not exist.
    /// - [`PaymentError::MultisigAlreadyExecuted`] if the payment was already executed.
    /// - [`PaymentError::PaymentExpired`] if the payment has expired.
    /// - [`PaymentError::Unauthorized`] if `signer` is not in `required_signers`.
    /// - [`PaymentError::MultisigAlreadySigned`] if `signer` has already signed.
    pub fn sign_multisig_payment(
        env: Env,
        signer: Address,
        payment_id: Bytes,
    ) -> Result<(), PaymentError> {
        storage::bump_instance_ttl(&env);
        if storage::is_paused(&env) { return Err(PaymentError::ContractPaused); }
        signer.require_auth();
        let mut ms =
            storage::get_multisig(&env, &payment_id).ok_or(PaymentError::MultisigNotFound)?;
        if ms.executed {
            return Err(PaymentError::MultisigAlreadyExecuted);
        }
        if env.ledger().timestamp() > ms.expires_at {
            return Err(PaymentError::PaymentExpired);
        }
        if !ms.required_signers.contains(&signer) {
            return Err(PaymentError::Unauthorized);
        }
        if ms.signatures.contains(&signer) {
            return Err(PaymentError::MultisigAlreadySigned);
        }
        ms.signatures.push_back(signer.clone());
        storage::save_multisig(&env, &ms);
        env.events().publish(
            (String::from_str(&env, "multisig_signed"),),
            (payment_id, signer),
        );
        Ok(())
    }

    /// Execute a fully-signed multi-sig payment, releasing escrow to the merchant.
    ///
    /// All required signers must have signed before this can be called. Funds
    /// are transferred from the contract escrow to the merchant. A
    /// [`PaymentRecord`] is created and indexed.
    ///
    /// # Parameters
    /// - `executor` — The address triggering execution; must be authenticated.
    /// - `payment_id` — The unique identifier of the multi-sig payment.
    ///
    /// # Errors
    /// - [`PaymentError::MultisigNotFound`] if the payment does not exist.
    /// - [`PaymentError::MultisigAlreadyExecuted`] if the payment was already executed.
    /// - [`PaymentError::PaymentExpired`] if the payment or its order has expired.
    /// - [`PaymentError::InsufficientSignatures`] if not all required signers have signed.
    pub fn execute_multisig_payment(
        env: Env,
        executor: Address,
        payment_id: Bytes,
    ) -> Result<(), PaymentError> {
        storage::bump_instance_ttl(&env);
        if storage::is_paused(&env) { return Err(PaymentError::ContractPaused); }
        executor.require_auth();
        let mut ms =
            storage::get_multisig(&env, &payment_id).ok_or(PaymentError::MultisigNotFound)?;
        if ms.executed {
            return Err(PaymentError::MultisigAlreadyExecuted);
        }
        let now = env.ledger().timestamp();
        if now > ms.expires_at {
            return Err(PaymentError::PaymentExpired);
        }
        if ms.signatures.len() < ms.required_signers.len() {
            return Err(PaymentError::InsufficientSignatures);
        }
        let order = &ms.order;
        if order.expires_at > 0 && now > order.expires_at {
            return Err(PaymentError::PaymentExpired);
        }
        let token_client = token::Client::new(&env, &order.token);
        let contract_addr = env.current_contract_address();
        token_client.transfer(&contract_addr, &order.merchant_address, &order.amount);
        let record = PaymentRecord {
            order_id: order.order_id.clone(),
            merchant_address: order.merchant_address.clone(),
            payer: ms.order.payer.clone(),
            token: order.token.clone(),
            amount: order.amount,
            refunded_amount: 0,
            pending_refund_amount: 0,
            status: PaymentStatus::Completed,
            paid_at: now,
            description: order.description.clone(),
        };
        storage::save_payment(&env, &record);
        storage::push_merchant_payment_id(&env, &order.merchant_address, &order.order_id);
        storage::push_payer_payment_id(&env, &executor, &order.order_id);
        storage::push_global_payment_id(&env, &order.order_id);
        storage::increment_payment_stats(&env, order.amount)?;

        ms.executed = true;
        storage::save_multisig(&env, &ms);
        env.events().publish(
            (String::from_str(&env, "multisig_executed"),),
            (payment_id, executor, order.amount),
        );
        Ok(())
    }

    // ── Dispute resolution ────────────────────────────────────────────────────

    /// Escalate a merchant-rejected refund to admin arbitration.
    ///
    /// Only the original payer may call this, and only when the refund is in
    /// `Rejected` state. Transitions the refund to `Disputed` and persists the
    /// dispute reason. Emits `refund_disputed`.
    pub fn dispute_refund(
        env: Env,
        caller: Address,
        refund_id: Bytes,
        reason: String,
    ) -> Result<(), PaymentError> {
        if storage::is_paused(&env) { return Err(PaymentError::ContractPaused); }
        caller.require_auth();

        if reason.len() > 256 {
            return Err(PaymentError::InvalidInput);
        }

        let mut refund =
            storage::get_refund(&env, &refund_id).ok_or(PaymentError::RefundNotFound)?;

        // Only the original payer may dispute.
        if caller != refund.initiated_by {
            return Err(PaymentError::DisputeUnauthorized);
        }

        // Refund must be in Rejected state.
        if refund.status != RefundStatus::Rejected {
            return Err(PaymentError::RefundNotRejected);
        }

        refund.status = RefundStatus::Disputed;
        refund.dispute_reason = reason.clone();
        storage::save_refund(&env, &refund);

        env.events().publish(
            (String::from_str(&env, "refund_disputed"),),
            (refund_id, caller, reason),
        );
        Ok(())
    }

    /// Admin-only: resolve a disputed refund.
    ///
    /// - `approve = true`  → override the merchant rejection, execute payout to
    ///   payer, and mark the refund `Completed`.
    /// - `approve = false` → uphold the merchant rejection, mark the refund
    ///   `Rejected` (closed), no payout.
    ///
    /// Emits `dispute_resolved` with the resolver identity and outcome.
    pub fn resolve_dispute(
        env: Env,
        admins: Vec<Address>,
        refund_id: Bytes,
        approve: bool,
    ) -> Result<(), PaymentError> {
        if storage::is_paused(&env) { return Err(PaymentError::ContractPaused); }
        helper::require_multi_admin(&env, admins.clone())?;

        let mut refund =
            storage::get_refund(&env, &refund_id).ok_or(PaymentError::RefundNotFound)?;

        if refund.status != RefundStatus::Disputed {
            return Err(PaymentError::RefundNotDisputed);
        }

        let mut record = storage::get_payment(&env, &refund.order_id)
            .ok_or(PaymentError::PaymentNotFound)?;

        // Identify the resolving admin for event metadata.
        let resolver = admins.get(0).unwrap();

        if approve {
            // Execute payout: merchant → payer.
            let new_total = record.refunded_amount + refund.amount;
            record.refunded_amount = new_total;
            record.status = if new_total == record.amount {
                PaymentStatus::FullyRefunded
            } else {
                PaymentStatus::PartiallyRefunded
            };
            storage::save_payment(&env, &record);

            refund.status = RefundStatus::Completed;
            storage::save_refund(&env, &refund);
            storage::push_all_refund_id(&env, &refund_id);
            storage::increment_refund_stats(&env, refund.amount)?;

            let token_client = token::Client::new(&env, &record.token);
            token_client.transfer(&record.merchant_address, &record.payer, &refund.amount);
        } else {
            // Uphold rejection — close the dispute with no payout.
            refund.status = RefundStatus::Rejected;
            storage::save_refund(&env, &refund);
        }

        env.events().publish(
            (String::from_str(&env, "dispute_resolved"),),
            (refund_id, resolver, approve),
        );
        Ok(())
    }

    // ── Internal helpers ──────────────────────────────────────────────────────

    fn paginate_payments(
        env: &Env,
        ids: Vec<Bytes>,
        cursor: Option<Bytes>,
        limit: u32,
        filter: Option<PaymentFilter>,
        sort_field: SortField,
        sort_order: SortOrder,
    ) -> Result<PaymentPage, PaymentError> {
        let cap = limit.min(100) as usize;
        // Collect and filter all matching records first.
        let mut records: RustVec<PaymentRecord> = RustVec::new();
        for id in ids.iter() {
            if let Some(record) = storage::get_payment(env, &id) {
                let passes = filter
                    .as_ref()
                    .map(|f| helper::matches_filter(&record, f))
                    .unwrap_or(true);
                if passes {
                    records.push(record);
                }
            }
        }
        // Sort all matching records.
        //
        // SC-008: We use Rust's standard slice::sort_by (O(n log n) Timsort) on
        // a native Vec<PaymentRecord> collected above. The original implementation
        // performed an in-place insertion sort directly on a soroban_sdk::Vec,
        // which is O(n²) and would exceed Soroban's instruction budget for
        // merchants with hundreds of payments. By collecting into a RustVec first
        // and using sort_by we stay well within instruction limits for the
        // MAX_PAYMENT_IDS_PER_KEY cap (10 000 entries).
        records.sort_by(|a, b| {
            let (v1, v2) = match sort_field {
                SortField::Date => (a.paid_at as i128, b.paid_at as i128),
                SortField::Amount => (a.amount, b.amount),
            };
            match sort_order {
                SortOrder::Ascending => v1.cmp(&v2),
                SortOrder::Descending => v2.cmp(&v1),
            }
        });
        let total = records.len() as u32;
        // Apply cursor: start after the record whose order_id matches the cursor.
        let start = if let Some(ref cur) = cursor {
            records
                .iter()
                .position(|r| &r.order_id == cur)
                .map(|p| p + 1)
                .unwrap_or(records.len())
        } else {
            0
        };
        let slice = &records[start..];
        let next_cursor = if slice.len() > cap {
            slice.get(cap - 1).map(|r| r.order_id.clone())
        } else {
            None
        };
        let mut page: Vec<PaymentRecord> = Vec::new(env);
        for i in 0..(slice.len().min(cap)) {
            page.push_back(slice[i].clone());
        }

        Ok(PaymentPage {
            records: page,
            next_cursor,
            total,
        })
    }

    // ── Subscriptions ──────────────────────────────────────────────────────────

    /// Create a new recurring subscription between a payer and a merchant.
    ///
    /// The subscription defines the token, amount, and interval for recurring
    /// charges. The first payment is not made at creation — it is collected on
    /// the first call to `process_subscription_payment`.
    ///
    /// # Parameters
    /// - `payer` — The address that will be charged at each interval; must be authenticated.
    /// - `merchant` — The merchant receiving the recurring payments.
    /// - `subscription_id` — Caller-supplied unique ID for this subscription.
    /// - `plan` — Recurring payment terms (token, amount, interval in seconds).
    ///
    /// # Errors
    /// - [`PaymentError::SubscriptionAlreadyExists`] if the ID is already in use.
    /// - [`PaymentError::MerchantNotFound`] if the merchant is not registered.
    /// - [`PaymentError::MerchantInactive`] if the merchant has been deactivated.
    /// - [`PaymentError::InvalidInput`] if `plan.interval` is zero or `plan.amount` ≤ 0.
    pub fn create_subscription(
        env: Env,
        payer: Address,
        merchant: Address,
        subscription_id: Bytes,
        plan: types::SubscriptionPlan,
    ) -> Result<(), PaymentError> {
        storage::bump_instance_ttl(&env);
        if storage::is_paused(&env) { return Err(PaymentError::ContractPaused); }
        payer.require_auth();
        if plan.interval == 0 {
            return Err(PaymentError::InvalidInput);
        }
        helper::validate_amount(plan.amount)?;
        if storage::get_subscription(&env, &subscription_id).is_some() {
            return Err(PaymentError::SubscriptionAlreadyExists);
        }
        let m = storage::get_merchant(&env, &merchant).ok_or(PaymentError::MerchantNotFound)?;
        if !m.active {
            return Err(PaymentError::MerchantInactive);
        }
        let now = env.ledger().timestamp();
        let sub = types::SubscriptionState {
            subscription_id: subscription_id.clone(),
            payer,
            merchant: merchant.clone(),
            plan,
            status: types::SubscriptionStatus::Active,
            created_at: now,
            last_charged_at: 0,
        };
        storage::save_subscription(&env, &sub);
        storage::push_merchant_subscription_id(&env, &merchant, &subscription_id);
        env.events().publish(
            (String::from_str(&env, "subscription_created"),),
            subscription_id,
        );
        Ok(())
    }

    /// Cancel an active subscription. Only the payer may cancel.
    ///
    /// # Parameters
    /// - `caller` — Must equal the subscription's payer; must be authenticated.
    /// - `subscription_id` — The subscription to cancel.
    ///
    /// # Errors
    /// - [`PaymentError::SubscriptionNotFound`] if the ID does not exist.
    /// - [`PaymentError::Unauthorized`] if `caller` is not the payer.
    /// - [`PaymentError::SubscriptionNotActive`] if already cancelled.
    pub fn cancel_subscription(
        env: Env,
        caller: Address,
        subscription_id: Bytes,
    ) -> Result<(), PaymentError> {
        storage::bump_instance_ttl(&env);
        if storage::is_paused(&env) { return Err(PaymentError::ContractPaused); }
        caller.require_auth();
        let mut sub = storage::get_subscription(&env, &subscription_id)
            .ok_or(PaymentError::SubscriptionNotFound)?;
        if caller != sub.payer {
            return Err(PaymentError::Unauthorized);
        }
        if sub.status != types::SubscriptionStatus::Active {
            return Err(PaymentError::SubscriptionNotActive);
        }
        sub.status = types::SubscriptionStatus::Cancelled;
        storage::save_subscription(&env, &sub);
        env.events().publish(
            (String::from_str(&env, "subscription_cancelled"),),
            subscription_id,
        );
        Ok(())
    }

    /// Collect one recurring payment for an active subscription.
    ///
    /// Transfers `plan.amount` of `plan.token` from the payer to the merchant.
    /// The caller (typically the off-chain scheduler) must be the subscription's
    /// payer. The interval guard ensures the payment cannot be collected twice
    /// within the same billing cycle.
    ///
    /// # Parameters
    /// - `caller` — Must equal the subscription's payer; must be authenticated.
    /// - `subscription_id` — The subscription to charge.
    ///
    /// # Errors
    /// - [`PaymentError::SubscriptionNotFound`] if the ID does not exist.
    /// - [`PaymentError::SubscriptionNotActive`] if the subscription is cancelled.
    /// - [`PaymentError::Unauthorized`] if `caller` is not the payer.
    /// - [`PaymentError::SubscriptionIntervalNotElapsed`] if the interval has not
    ///   passed since the last successful charge.
    pub fn process_subscription_payment(
        env: Env,
        caller: Address,
        subscription_id: Bytes,
    ) -> Result<(), PaymentError> {
        storage::bump_instance_ttl(&env);
        if storage::is_paused(&env) { return Err(PaymentError::ContractPaused); }
        caller.require_auth();
        let mut sub = storage::get_subscription(&env, &subscription_id)
            .ok_or(PaymentError::SubscriptionNotFound)?;
        if caller != sub.payer {
            return Err(PaymentError::Unauthorized);
        }
        if sub.status != types::SubscriptionStatus::Active {
            return Err(PaymentError::SubscriptionNotActive);
        }
        let now = env.ledger().timestamp();
        // Interval guard: last_charged_at == 0 means never charged; first charge
        // is always allowed. Subsequent charges require the full interval to have
        // elapsed.
        if sub.last_charged_at > 0 && now < sub.last_charged_at + sub.plan.interval {
            return Err(PaymentError::SubscriptionIntervalNotElapsed);
        }
        // SEC-009: enforce token allowlist when enabled
        if storage::is_token_allowlist_enabled(&env)
            && !storage::is_token_allowed(&env, &sub.plan.token)
        {
            return Err(PaymentError::TokenNotAllowed);
        }
        // Transfer funds from payer to merchant before updating state so that a
        // failed transfer leaves the subscription record unchanged.
        let token_client = token::Client::new(&env, &sub.plan.token);
        token_client.transfer(&sub.payer, &sub.merchant, &sub.plan.amount);
        sub.last_charged_at = now;
        storage::save_subscription(&env, &sub);
        env.events().publish(
            (String::from_str(&env, "subscription_charged"),),
            (subscription_id, sub.plan.amount),
        );
        Ok(())
    }

    /// Retrieve a single subscription by ID.
    ///
    /// # Errors
    /// - [`PaymentError::SubscriptionNotFound`] if the ID does not exist.
    pub fn get_subscription(
        env: Env,
        subscription_id: Bytes,
    ) -> Result<types::SubscriptionState, PaymentError> {
        storage::bump_instance_ttl(&env);
        storage::get_subscription(&env, &subscription_id)
            .ok_or(PaymentError::SubscriptionNotFound)
    }

    /// List all subscriptions for a merchant, with optional cursor-based pagination.
    ///
    /// # Parameters
    /// - `merchant` — The merchant whose subscriptions to list.
    /// - `cursor` — Opaque cursor from a previous response; omit for the first page.
    /// - `limit` — Maximum results per page (capped at 100).
    ///
    /// # Returns
    /// A [`types::SubscriptionPage`] containing the records and an optional
    /// `next_cursor` for the next page.
    pub fn list_subscriptions_by_merchant(
        env: Env,
        merchant: Address,
        cursor: Option<Bytes>,
        limit: u32,
    ) -> Result<types::SubscriptionPage, PaymentError> {
        storage::bump_instance_ttl(&env);
        let ids = storage::get_merchant_subscription_ids(&env, &merchant);
        let cap = (limit.min(100)) as usize;
        // Collect all subscription records for this merchant.
        let mut records: alloc::vec::Vec<types::SubscriptionState> = alloc::vec::Vec::new();
        for id in ids.iter() {
            if let Some(sub) = storage::get_subscription(&env, &id) {
                records.push(sub);
            }
        }
        let total = records.len() as u32;
        // Apply cursor: start after the entry whose subscription_id matches.
        let start = if let Some(ref cur) = cursor {
            records
                .iter()
                .position(|s| &s.subscription_id == cur)
                .map(|p| p + 1)
                .unwrap_or(records.len())
        } else {
            0
        };
        let slice = &records[start..];
        let next_cursor = if slice.len() > cap {
            slice.get(cap - 1).map(|s| s.subscription_id.clone())
        } else {
            None
        };
        let mut page: Vec<types::SubscriptionState> = Vec::new(&env);
        for i in 0..(slice.len().min(cap)) {
            page.push_back(slice[i].clone());
        }
        Ok(types::SubscriptionPage {
            records: page,
            next_cursor,
            total,
        })
    }
}
