# Merchant KYC / Verification Tiers (MISC-012)

## Background

Prior to this change, every registered merchant was trusted identically
regardless of transaction volume or whether any off-chain identity
verification had been performed. High-volume merchants, or merchants
operating in regulated markets, may need a tiered trust model so that admins
can distinguish a freshly registered address from one that has completed
KYC.

## The `MerchantTier` enum

Defined in
[`contracts/payment-processing-contract/src/types.rs`](../contracts/payment-processing-contract/src/types.rs):

```rust
pub enum MerchantTier {
    Unverified,
    Verified,
    Premium,
}
```

Every `Merchant` record carries a `tier: MerchantTier` field.
`register_merchant` always sets a new merchant's tier to `Unverified` — a
merchant cannot self-assign a higher tier.

## Tier criteria

| Tier | Criteria | Typical use |
|------|----------|--------------|
| `Unverified` | Default on registration. No off-chain KYC performed. | Low-volume / experimental merchants. |
| `Verified` | Merchant has completed baseline off-chain identity verification (e.g. business registration documents, contact confirmation) reviewed by the operating admin team. | General production merchants. |
| `Premium` | Merchant has completed enhanced verification appropriate for high-volume or regulated-market operation (e.g. AML/KYC provider check, in regulated jurisdictions a licensed-business check). | High-volume merchants; a future revision may use this tier to unlock higher per-transaction limits. |

KYC review itself is performed off-chain (outside the smart contract) by
whoever operates the admin keys for a given deployment; the contract only
records the *result* of that review as a tier.

## Upgrade / downgrade process

1. The admin team completes off-chain verification for the merchant address
   at the level required for the target tier.
2. An admin (or quorum of admins, depending on the deployment's multi-sig
   threshold — see `set_admin` / `helper::require_multi_admin`) calls:

   ```text
   set_merchant_tier(admins: Vec<Address>, merchant_address: Address, tier: MerchantTier)
   ```

   This requires the same multi-sig admin authorization as other admin-only
   calls (`set_whitelist_mode`, `approve_merchant_registration`, etc.) and
   fails with `PaymentError::Unauthorized` if the threshold is not met, or
   `PaymentError::MerchantNotFound` if the merchant does not exist.
3. The contract emits a `merchant_tier_set` event with payload
   `(merchant_address, tier)` so the change is auditable off-chain.
4. A merchant's current tier can be read at any time with:

   ```text
   get_merchant_tier(merchant_address: Address) -> MerchantTier
   ```

Downgrades (e.g. `Premium` → `Unverified`) are permitted via the same call,
for cases such as a merchant failing a periodic re-verification.

## Current scope

This revision introduces the tier field, the admin-only setter, and the
getter, with no behavioral gating yet — all tiers can transact identically
today. Using `tier` to unlock higher per-transaction limits for `Verified` /
`Premium` merchants is listed as optional future work in issue MISC-012 and
is intentionally left for a follow-up change, since it would need its own
limit schedule and acceptance criteria.
