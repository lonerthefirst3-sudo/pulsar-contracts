// SPDX-License-Identifier: MIT

use soroban_sdk::{contracttype, Address, Bytes, BytesN, Map, String, Vec};

// ── Merchant ──────────────────────────────────────────────────────────────────

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum MerchantCategory {
    Retail,
    Food,
    Services,
    Digital,
    Other,
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Merchant {
    pub address: Address,
    pub name: String,
    pub description: String,
    pub contact_info: String,
    pub category: MerchantCategory,
    pub active: bool,
    pub registered_at: u64,
    pub signing_public_key: Option<BytesN<32>>,
}

// ── Payment ───────────────────────────────────────────────────────────────────

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PaymentStatus {
    Completed,
    PartiallyRefunded,
    FullyRefunded,
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PaymentOrder {
    pub order_id: Bytes,
    pub merchant_address: Address,
    pub payer: Address,
    pub token: Address,
    pub amount: i128,
    pub description: String,
    /// Unix timestamp (seconds) when the order expires. A value of `0`
    /// is treated as "never expires" (an order that does not expire).
    /// This special-case is relied upon by existing integrations and is
    /// intentionally accepted by the contract.
    pub expires_at: u64,
    /// Optional structured metadata (e.g. customer ID, product SKU) that
    /// merchants can attach to a payment for off-chain reconciliation.
    /// The combined size of all keys and values is capped at
    /// `helper::MAX_METADATA_SIZE_BYTES` (see MISC-013).
    pub metadata: Option<Map<String, String>>,
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PaymentRecord {
    pub order_id: Bytes,
    pub merchant_address: Address,
    pub payer: Address,
    pub token: Address,
    pub amount: i128,
    pub refunded_amount: i128,
    pub pending_refund_amount: i128,
    pub status: PaymentStatus,
    pub paid_at: u64,
    pub description: String,
    /// Metadata carried over from the originating [`PaymentOrder`], if any.
    pub metadata: Option<Map<String, String>>,
}

// ── Refund ────────────────────────────────────────────────────────────────────

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RefundStatus {
    Pending,
    Approved,
    Rejected,
    Completed,
    /// Payer has escalated a merchant-rejected refund for admin resolution.
    Disputed,
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RefundRecord {
    pub refund_id: Bytes,
    pub order_id: Bytes,
    pub amount: i128,
    pub reason: String,
    pub status: RefundStatus,
    pub initiated_by: Address,
    pub initiated_at: u64,
    /// Set when the payer disputes a merchant rejection. Empty string if not disputed.
    pub dispute_reason: String,
}

// ── Multisig ──────────────────────────────────────────────────────────────────

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MultisigPayment {
    pub payment_id: Bytes,
    pub order: PaymentOrder,
    pub required_signers: Vec<Address>,
    pub signatures: Vec<Address>,
    pub executed: bool,
    pub expires_at: u64,
    pub created_at: u64,
}

// ── Subscriptions ───────────────────────────────────────────────────────────
// Full SubscriptionState, SubscriptionPlan, SubscriptionStatus definitions
// are below (search "Subscription" section lower in this file).

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SubscriptionPage {
    pub records: Vec<SubscriptionState>,
    /// Opaque pagination cursor pointing to the last returned subscription id.
    pub next_cursor: Option<Bytes>,
    pub total: u32,
}

// ── Query helpers ─────────────────────────────────────────────────────────────

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SortField {
    Date,
    Amount, // .
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SortOrder {
    Ascending,
    Descending,
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum StatusFilter {
    Any,
    Completed,
    PartiallyRefunded,
    FullyRefunded,
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PaymentFilter {
    pub date_start: Option<u64>,
    pub date_end: Option<u64>,
    pub amount_min: Option<i128>,
    pub amount_max: Option<i128>,
    /// Filter by one or more token contract addresses. `None` matches all tokens.
    /// An empty list also matches all tokens (treated as no filter).
    pub tokens: Option<Vec<Address>>,
    pub status: StatusFilter,
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PaymentPage {
    pub records: Vec<PaymentRecord>,
    /// Opaque pagination cursor pointing to the last record on the page.
    ///
    /// Current format: raw `order_id` bytes of the last record. Callers that
    /// transport the cursor over textual channels (CLI, HTTP) should encode
    /// it (for example as base64). The contract treats the cursor as an opaque
    /// `Bytes` value and will start the next page after the matching `order_id`.
    ///
    /// NOTE: changing this format is a breaking change. Any future change
    /// should use a versioned encoding and include a migration note in an ADR.
    pub next_cursor: Option<Bytes>,
    pub total: u32,
}

// ── Stats ─────────────────────────────────────────────────────────────────────

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GlobalStats {
    pub total_payments: u64,
    pub total_volume: i128,
    pub total_refunds: u64,
    pub total_refund_volume: i128,
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MerchantStats {
    pub merchant_address: Address,
    pub total_payments: u64,
    pub total_volume: i128,
    pub total_refunds: u64,
    pub total_refund_volume: i128,
}

// ── Admin ─────────────────────────────────────────────────────────────────────

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AdminConfig {
    pub admins: Vec<Address>,
    pub threshold: u32,
}

// ── Subscription ──────────────────────────────────────────────────────────────

/// Defines the recurring payment terms for a subscription.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SubscriptionPlan {
    /// Payment interval in seconds (e.g. 2_592_000 for 30 days).
    pub interval: u64,
    /// Amount charged per interval, in the smallest token unit.
    pub amount: i128,
    /// Token contract address used for recurring charges.
    pub token: Address,
}

/// Lifecycle state of a subscription.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SubscriptionStatus {
    Active,
    Cancelled,
}

/// Persisted state for a single payer–merchant subscription.
///
/// # Off-chain scheduler requirement
/// Soroban contracts cannot autonomously schedule execution. An off-chain
/// scheduler service MUST call `process_subscription_payment` at each interval
/// boundary. The contract enforces correctness (idempotency, interval guard,
/// status checks) but relies on the scheduler for timely invocation.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SubscriptionState {
    /// Unique subscription identifier (caller-supplied).
    pub subscription_id: Bytes,
    pub payer: Address,
    pub merchant: Address,
    pub plan: SubscriptionPlan,
    pub status: SubscriptionStatus,
    /// Ledger timestamp when the subscription was created.
    pub created_at: u64,
    /// Ledger timestamp of the most recent successful payment (0 if none yet).
    pub last_charged_at: u64,
}

// ── Storage keys ──────────────────────────────────────────────────────────────

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DataKey {
    Admin,
    AdminConfig,
    ContractVersion,
    Merchant(Address),
    Payment(Bytes),
    MerchantPaymentChunk(Address, u32),
    MerchantPaymentCount(Address),
    PayerPaymentChunk(Address, u32),
    PayerPaymentCount(Address),
    /// Flat payment index list per merchant (replaces chunked approach).
    MerchantPayments(Address),
    /// Flat payment index list per payer.
    PayerPayments(Address),
    /// Global flat payment index.
    GlobalPaymentIndex,
    Refund(Bytes),
    Multisig(Bytes),
    CleanupPeriod,
    DefaultMultisigExpiry,
    GlobalStats,
    AllRefunds,
    WhitelistEnabled,
    Whitelist(Address),
    OrderRefundCount(Bytes),
    ArchivedPayment(Bytes),
    TokenAllowlistEnabled,
    AllowedToken(Address),
    Subscription(Bytes),
    /// Index of subscription IDs per merchant for list queries.
    MerchantSubscriptions(Address),
    MerchantStats(Address),
    // Connection pooling storage keys
    PoolConfig,
    PoolStats,
    PoolConnection(u32),
    /// Emergency stop flag (SEC-010). When `true`, all state-mutating functions
    /// return `ContractPaused`. Read-only functions are unaffected.
    Paused,
}
