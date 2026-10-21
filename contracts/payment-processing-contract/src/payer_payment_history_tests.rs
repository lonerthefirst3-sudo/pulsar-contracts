// SPDX-License-Identifier: MIT
//! Tests for `get_payer_payment_history` — resolves T-003 / issue #33
//!
//! Acceptance criteria:
//!   1. Tests cover: no payments, single payment, multiple payments
//!   2. Tests cover all filter fields (date range, amount range, token, status)
//!   3. Tests cover both sort fields (Date, Amount) and both orders (Asc, Desc)
//!   4. Tests cover multi-page pagination

#![cfg(test)]

extern crate alloc;
use alloc::vec;

use soroban_sdk::{
    testutils::{Address as _, Ledger},
    token::StellarAssetClient,
    Address, Bytes, BytesN, Env, Map, String, Vec,
};

use ed25519_dalek::{Signer, SigningKey};

use crate::{
    error::PaymentError,
    types::{
        MerchantCategory, PaymentFilter, PaymentOrder, PaymentStatus, SortField, SortOrder,
        StatusFilter,
    },
    PaymentContract, PaymentContractClient,
};

// ── helpers ───────────────────────────────────────────────────────────────────

fn setup() -> (Env, PaymentContractClient<'static>) {
    let env = Env::default();
    env.mock_all_auths();
    let contract_id = env.register(PaymentContract, ());
    let client = PaymentContractClient::new(&env, &contract_id);
    (env, client)
}

fn create_token(env: &Env, admin: &Address) -> Address {
    env.register_stellar_asset_contract_v2(admin.clone()).address()
}

fn mint(env: &Env, token: &Address, to: &Address, amount: i128) {
    StellarAssetClient::new(env, token).mint(to, &amount);
}

fn s(env: &Env, v: &str) -> String {
    String::from_str(env, v)
}

fn b(env: &Env, v: &str) -> Bytes {
    Bytes::from_slice(env, v.as_bytes())
}

fn zero_key(env: &Env) -> BytesN<32> {
    BytesN::from_array(env, &[0u8; 32])
}

fn admin_vec(env: &Env, admin: &Address) -> Vec<Address> {
    vec![env, admin.clone()]
}

fn sign_order(env: &Env, order: &PaymentOrder) -> (BytesN<32>, BytesN<64>) {
    let signing_key = SigningKey::from_bytes(&[1u8; 32]);
    let public_key = signing_key.verifying_key();
    let payload = order.order_id.clone();
    let mut payload_bytes = alloc::vec![0u8; payload.len() as usize];
    payload.copy_into_slice(&mut payload_bytes);
    let signature = signing_key.sign(&payload_bytes);
    (
        BytesN::from_array(env, &public_key.to_bytes()),
        BytesN::from_array(env, &signature.to_bytes()),
    )
}

/// No-filter helper: returns payer history sorted by Date Ascending.
fn get_history(
    env: &Env,
    client: &PaymentContractClient,
    payer: &Address,
) -> crate::types::PaymentPage {
    client.get_payer_payment_history(
        payer,
        &None,
        &100,
        &None,
        &SortField::Date,
        &SortOrder::Ascending,
    )
}

/// Register admin + merchant, mint tokens, process `n` payments with given
/// amounts. Returns `(admin, merchant, payer, token)`.
fn setup_payer_payments(
    env: &Env,
    client: &PaymentContractClient,
    amounts: &[i128],
) -> (Address, Address, Address, Address) {
    let admin = Address::generate(env);
    let merchant = Address::generate(env);
    let payer = Address::generate(env);
    let token = create_token(env, &admin);

    client.set_admin(&admin_vec(env, &admin), &1);
    client.register_merchant(
        &merchant,
        &s(env, "Store"),
        &s(env, "desc"),
        &s(env, "c@c.com"),
        &MerchantCategory::Retail,
        &None,
    );

    let total: i128 = amounts.iter().sum::<i128>() + 1_000;
    mint(env, &token, &payer, total);

    for (i, &amount) in amounts.iter().enumerate() {
        let id = alloc::format!("PH_{:03}", i);
        let order = PaymentOrder {
            order_id: Bytes::from_slice(env, id.as_bytes()),
            merchant_address: merchant.clone(),
            payer: payer.clone(),
            token: token.clone(),
            amount,
            description: s(env, "d"),
            expires_at: 0,
                metadata: None,
        };
        let (_pk, sig) = sign_order(env, &order);
        client.process_payment_with_signature(&payer, &order, &sig, &zero_key(env));
    }

    (admin, merchant, payer, token)
}

// ── 1. No payments, single payment, multiple payments ────────────────────────

/// Payer with no payment history returns empty page.
#[test]
fn test_t003_no_payments_returns_empty() {
    let (env, client) = setup();
    let payer = Address::generate(&env);

    let page = get_history(&env, &client, &payer);

    assert_eq!(page.total, 0);
    assert_eq!(page.records.len(), 0);
    assert!(page.next_cursor.is_none());
}

/// Payer with exactly one payment returns that single record.
#[test]
fn test_t003_single_payment_returned() {
    let (env, client) = setup();
    let (_admin, _merchant, payer, _token) = setup_payer_payments(&env, &client, &[750]);

    let page = get_history(&env, &client, &payer);

    assert_eq!(page.total, 1);
    assert_eq!(page.records.get(0).unwrap().amount, 750);
    assert!(page.next_cursor.is_none());
}

/// Payer with multiple payments returns all of them.
#[test]
fn test_t003_multiple_payments_returned() {
    let (env, client) = setup();
    let (_admin, _merchant, payer, _token) =
        setup_payer_payments(&env, &client, &[100, 200, 300, 400]);

    let page = get_history(&env, &client, &payer);

    assert_eq!(page.total, 4);
    assert_eq!(page.records.len(), 4);
}

// ── 2a. Filter: date range ────────────────────────────────────────────────────

/// Only payments whose `paid_at` falls within the date window are returned.
#[test]
fn test_t003_filter_date_range() {
    let (env, client) = setup();
    let admin = Address::generate(&env);
    let merchant = Address::generate(&env);
    let payer = Address::generate(&env);
    let token = create_token(&env, &admin);

    client.set_admin(&admin_vec(&env, &admin), &1);
    client.register_merchant(
        &merchant,
        &s(&env, "Store"),
        &s(&env, "desc"),
        &s(&env, "c@c.com"),
        &MerchantCategory::Retail,
        &None,
    );
    mint(&env, &token, &payer, 10_000);

    // Payment at timestamp 1_000
    env.ledger().with_mut(|l| l.timestamp = 1_000);
    let o1 = PaymentOrder {
        order_id: b(&env, "DR_001"),
        merchant_address: merchant.clone(),
        payer: payer.clone(),
        token: token.clone(),
        amount: 100,
        description: s(&env, "d"),
        expires_at: 0,
        metadata: None,
    };
    let (_pk1, sig1) = sign_order(&env, &o1);
    client.process_payment_with_signature(&payer, &o1, &sig1, &zero_key(&env));

    // Payment at timestamp 8_000
    env.ledger().with_mut(|l| l.timestamp = 8_000);
    let o2 = PaymentOrder {
        order_id: b(&env, "DR_002"),
        merchant_address: merchant.clone(),
        payer: payer.clone(),
        token: token.clone(),
        amount: 200,
        description: s(&env, "d"),
        expires_at: 0,
        metadata: None,
    };
    let (_pk2, sig2) = sign_order(&env, &o2);
    client.process_payment_with_signature(&payer, &o2, &sig2, &zero_key(&env));

    // Filter: window 500..=3_000 — only first payment should match
    let filter = PaymentFilter {
        date_start: Some(500),
        date_end: Some(3_000),
        amount_min: None,
        amount_max: None,
        tokens: None,
        status: StatusFilter::Any,
    };
    let page = client.get_payer_payment_history(
        &payer, &None, &10, &Some(filter), &SortField::Date, &SortOrder::Ascending,
    );
    assert_eq!(page.total, 1);
    assert_eq!(page.records.get(0).unwrap().amount, 100);
}

// ── 2b. Filter: amount range ──────────────────────────────────────────────────

/// Only payments within the amount range are returned.
#[test]
fn test_t003_filter_amount_range() {
    let (env, client) = setup();
    let (_admin, _merchant, payer, _token) =
        setup_payer_payments(&env, &client, &[50, 150, 300, 600]);

    let filter = PaymentFilter {
        date_start: None,
        date_end: None,
        amount_min: Some(100),
        amount_max: Some(350),
        tokens: None,
        status: StatusFilter::Any,
    };
    let page = client.get_payer_payment_history(
        &payer, &None, &10, &Some(filter), &SortField::Amount, &SortOrder::Ascending,
    );
    assert_eq!(page.total, 2);
    assert_eq!(page.records.get(0).unwrap().amount, 150);
    assert_eq!(page.records.get(1).unwrap().amount, 300);
}

/// `amount_min` with no upper bound returns all payments ≥ min.
#[test]
fn test_t003_filter_amount_min_only() {
    let (env, client) = setup();
    let (_admin, _merchant, payer, _token) =
        setup_payer_payments(&env, &client, &[100, 200, 500]);

    let filter = PaymentFilter {
        date_start: None,
        date_end: None,
        amount_min: Some(200),
        amount_max: None,
        tokens: None,
        status: StatusFilter::Any,
    };
    let page = client.get_payer_payment_history(
        &payer, &None, &10, &Some(filter), &SortField::Amount, &SortOrder::Ascending,
    );
    assert_eq!(page.total, 2);
}

// ── 2c. Filter: token ─────────────────────────────────────────────────────────

/// Filtering by a specific token returns only payments made with that token.
#[test]
fn test_t003_filter_by_token() {
    let (env, client) = setup();
    let admin = Address::generate(&env);
    let merchant = Address::generate(&env);
    let payer = Address::generate(&env);
    let token_a = create_token(&env, &admin);
    let token_b = create_token(&env, &admin);

    client.set_admin(&admin_vec(&env, &admin), &1);
    client.register_merchant(
        &merchant,
        &s(&env, "Store"),
        &s(&env, "desc"),
        &s(&env, "c@c.com"),
        &MerchantCategory::Retail,
        &None,
    );
    mint(&env, &token_a, &payer, 5_000);
    mint(&env, &token_b, &payer, 5_000);

    // Pay with token_a
    let oa = PaymentOrder {
        order_id: b(&env, "TOK_A_001"),
        merchant_address: merchant.clone(),
        payer: payer.clone(),
        token: token_a.clone(),
        amount: 100,
        description: s(&env, "d"),
        expires_at: 0,
        metadata: None,
    };
    let (_pk_a, sig_a) = sign_order(&env, &oa);
    client.process_payment_with_signature(&payer, &oa, &sig_a, &zero_key(&env));

    // Pay with token_b
    let ob = PaymentOrder {
        order_id: b(&env, "TOK_B_001"),
        merchant_address: merchant.clone(),
        payer: payer.clone(),
        token: token_b.clone(),
        amount: 200,
        description: s(&env, "d"),
        expires_at: 0,
        metadata: None,
    };
    let (_pk_b, sig_b) = sign_order(&env, &ob);
    client.process_payment_with_signature(&payer, &ob, &sig_b, &zero_key(&env));

    // Filter to token_b only
    let filter = PaymentFilter {
        date_start: None,
        date_end: None,
        amount_min: None,
        amount_max: None,
        tokens: Some(Vec::from_array(&env, [token_b.clone()])),
        status: StatusFilter::Any,
    };
    let page = client.get_payer_payment_history(
        &payer, &None, &10, &Some(filter), &SortField::Date, &SortOrder::Ascending,
    );
    assert_eq!(page.total, 1);
    assert_eq!(page.records.get(0).unwrap().token, token_b);
}

// ── 2d. Filter: status ────────────────────────────────────────────────────────

/// Filtering by `StatusFilter::Completed` returns only payments with no refund.
#[test]
fn test_t003_filter_status_completed() {
    let (env, client) = setup();
    let (_admin, merchant, payer, _token) =
        setup_payer_payments(&env, &client, &[500, 600]);

    // Partially refund the first payment (PH_000)
    client.initiate_refund(
        &payer,
        &b(&env, "RF_T003_1"),
        &b(&env, "PH_000"),
        &100,
        &s(&env, "reason"),
    );
    client.approve_refund(&merchant, &b(&env, "RF_T003_1"), &None);
    client.execute_refund(&merchant, &b(&env, "RF_T003_1"));

    let filter = PaymentFilter {
        date_start: None,
        date_end: None,
        amount_min: None,
        amount_max: None,
        tokens: None,
        status: StatusFilter::Completed,
    };
    let page = client.get_payer_payment_history(
        &payer, &None, &10, &Some(filter), &SortField::Amount, &SortOrder::Ascending,
    );
    assert_eq!(page.total, 1);
    assert_eq!(
        page.records.get(0).unwrap().status,
        PaymentStatus::Completed
    );
}

/// Filtering by `StatusFilter::PartiallyRefunded` returns only partial refunds.
#[test]
fn test_t003_filter_status_partially_refunded() {
    let (env, client) = setup();
    let (_admin, merchant, payer, _token) =
        setup_payer_payments(&env, &client, &[500, 600]);

    client.initiate_refund(
        &payer,
        &b(&env, "RF_T003_2"),
        &b(&env, "PH_000"),
        &100,
        &s(&env, "partial"),
    );
    client.approve_refund(&merchant, &b(&env, "RF_T003_2"), &None);
    client.execute_refund(&merchant, &b(&env, "RF_T003_2"));

    let filter = PaymentFilter {
        date_start: None,
        date_end: None,
        amount_min: None,
        amount_max: None,
        tokens: None,
        status: StatusFilter::PartiallyRefunded,
    };
    let page = client.get_payer_payment_history(
        &payer, &None, &10, &Some(filter), &SortField::Date, &SortOrder::Ascending,
    );
    assert_eq!(page.total, 1);
    assert_eq!(
        page.records.get(0).unwrap().status,
        PaymentStatus::PartiallyRefunded
    );
}

/// `StatusFilter::Any` returns all payments regardless of status.
#[test]
fn test_t003_filter_status_any_returns_all() {
    let (env, client) = setup();
    let (_admin, _merchant, payer, _token) =
        setup_payer_payments(&env, &client, &[100, 200, 300]);

    let filter = PaymentFilter {
        date_start: None,
        date_end: None,
        amount_min: None,
        amount_max: None,
        tokens: None,
        status: StatusFilter::Any,
    };
    let page = client.get_payer_payment_history(
        &payer, &None, &10, &Some(filter), &SortField::Date, &SortOrder::Ascending,
    );
    assert_eq!(page.total, 3);
}

// ── 3. Sort fields and orders ─────────────────────────────────────────────────

/// Sort by Date Ascending: oldest payment first.
#[test]
fn test_t003_sort_by_date_ascending() {
    let (env, client) = setup();
    let admin = Address::generate(&env);
    let merchant = Address::generate(&env);
    let payer = Address::generate(&env);
    let token = create_token(&env, &admin);

    client.set_admin(&admin_vec(&env, &admin), &1);
    client.register_merchant(
        &merchant,
        &s(&env, "Store"),
        &s(&env, "desc"),
        &s(&env, "c@c.com"),
        &MerchantCategory::Retail,
        &None,
    );
    mint(&env, &token, &payer, 10_000);

    // Create payments at different timestamps
    for (ts, id, amt) in [(100u64, "SD_001", 300i128), (200, "SD_002", 100), (300, "SD_003", 200)] {
        env.ledger().with_mut(|l| l.timestamp = ts);
        let order = PaymentOrder {
            order_id: b(&env, id),
            merchant_address: merchant.clone(),
            payer: payer.clone(),
            token: token.clone(),
            amount: amt,
            description: s(&env, "d"),
            expires_at: 0,
                metadata: None,
        };
        let (_pk, sig) = sign_order(&env, &order);
        client.process_payment_with_signature(&payer, &order, &sig, &zero_key(&env));
    }

    let page = client.get_payer_payment_history(
        &payer, &None, &10, &None, &SortField::Date, &SortOrder::Ascending,
    );
    // Oldest first: ts=100 (amount=300) → ts=200 (100) → ts=300 (200)
    assert_eq!(page.records.get(0).unwrap().paid_at, 100);
    assert_eq!(page.records.get(2).unwrap().paid_at, 300);
}

/// Sort by Date Descending: newest payment first.
#[test]
fn test_t003_sort_by_date_descending() {
    let (env, client) = setup();
    let admin = Address::generate(&env);
    let merchant = Address::generate(&env);
    let payer = Address::generate(&env);
    let token = create_token(&env, &admin);

    client.set_admin(&admin_vec(&env, &admin), &1);
    client.register_merchant(
        &merchant,
        &s(&env, "Store"),
        &s(&env, "desc"),
        &s(&env, "c@c.com"),
        &MerchantCategory::Retail,
        &None,
    );
    mint(&env, &token, &payer, 10_000);

    for (ts, id, amt) in [(100u64, "DD_001", 300i128), (200, "DD_002", 100), (300, "DD_003", 200)] {
        env.ledger().with_mut(|l| l.timestamp = ts);
        let order = PaymentOrder {
            order_id: b(&env, id),
            merchant_address: merchant.clone(),
            payer: payer.clone(),
            token: token.clone(),
            amount: amt,
            description: s(&env, "d"),
            expires_at: 0,
                metadata: None,
        };
        let (_pk, sig) = sign_order(&env, &order);
        client.process_payment_with_signature(&payer, &order, &sig, &zero_key(&env));
    }

    let page = client.get_payer_payment_history(
        &payer, &None, &10, &None, &SortField::Date, &SortOrder::Descending,
    );
    // Newest first: ts=300, ts=200, ts=100
    assert_eq!(page.records.get(0).unwrap().paid_at, 300);
    assert_eq!(page.records.get(2).unwrap().paid_at, 100);
}

/// Sort by Amount Ascending: smallest payment first.
#[test]
fn test_t003_sort_by_amount_ascending() {
    let (env, client) = setup();
    let (_admin, _merchant, payer, _token) =
        setup_payer_payments(&env, &client, &[500, 100, 300]);

    let page = client.get_payer_payment_history(
        &payer, &None, &10, &None, &SortField::Amount, &SortOrder::Ascending,
    );
    assert_eq!(page.records.get(0).unwrap().amount, 100);
    assert_eq!(page.records.get(1).unwrap().amount, 300);
    assert_eq!(page.records.get(2).unwrap().amount, 500);
}

/// Sort by Amount Descending: largest payment first.
#[test]
fn test_t003_sort_by_amount_descending() {
    let (env, client) = setup();
    let (_admin, _merchant, payer, _token) =
        setup_payer_payments(&env, &client, &[500, 100, 300]);

    let page = client.get_payer_payment_history(
        &payer, &None, &10, &None, &SortField::Amount, &SortOrder::Descending,
    );
    assert_eq!(page.records.get(0).unwrap().amount, 500);
    assert_eq!(page.records.get(1).unwrap().amount, 300);
    assert_eq!(page.records.get(2).unwrap().amount, 100);
}

// ── 4. Pagination ─────────────────────────────────────────────────────────────

/// Two-page fetch: page 1 provides a cursor; page 2 continues from it.
#[test]
fn test_t003_pagination_two_pages() {
    let (env, client) = setup();
    let (_admin, _merchant, payer, _token) =
        setup_payer_payments(&env, &client, &[100, 200, 300, 400, 500]);

    // Page 1: limit = 2
    let page1 = client.get_payer_payment_history(
        &payer, &None, &2, &None, &SortField::Amount, &SortOrder::Ascending,
    );
    assert_eq!(page1.records.len(), 2);
    assert!(page1.next_cursor.is_some(), "page1 should have a cursor");
    assert_eq!(page1.records.get(0).unwrap().amount, 100);
    assert_eq!(page1.records.get(1).unwrap().amount, 200);

    // Page 2: use cursor from page 1
    let page2 = client.get_payer_payment_history(
        &payer, &page1.next_cursor, &2, &None, &SortField::Amount, &SortOrder::Ascending,
    );
    assert_eq!(page2.records.len(), 2);
    // Page 2 must start after page 1's last record
    assert!(
        page2.records.get(0).unwrap().amount > page1.records.get(1).unwrap().amount,
        "page 2 should continue after page 1"
    );
    assert!(page2.next_cursor.is_some(), "page2 should have a cursor for page 3");
}

/// Third page: exhausts remaining records, next_cursor is None.
#[test]
fn test_t003_pagination_last_page_no_cursor() {
    let (env, client) = setup();
    let (_admin, _merchant, payer, _token) =
        setup_payer_payments(&env, &client, &[100, 200, 300, 400, 500]);

    let page1 = client.get_payer_payment_history(
        &payer, &None, &2, &None, &SortField::Amount, &SortOrder::Ascending,
    );
    let page2 = client.get_payer_payment_history(
        &payer, &page1.next_cursor, &2, &None, &SortField::Amount, &SortOrder::Ascending,
    );
    let page3 = client.get_payer_payment_history(
        &payer, &page2.next_cursor, &2, &None, &SortField::Amount, &SortOrder::Ascending,
    );
    // Only 1 record left on the last page
    assert_eq!(page3.records.len(), 1);
    assert!(page3.next_cursor.is_none(), "last page should have no cursor");
}

/// Full page fetch with limit larger than total returns all records in one page.
#[test]
fn test_t003_pagination_single_page_all_records() {
    let (env, client) = setup();
    let (_admin, _merchant, payer, _token) =
        setup_payer_payments(&env, &client, &[10, 20, 30]);

    let page = client.get_payer_payment_history(
        &payer, &None, &50, &None, &SortField::Date, &SortOrder::Ascending,
    );
    assert_eq!(page.total, 3);
    assert_eq!(page.records.len(), 3);
    assert!(page.next_cursor.is_none());
}

/// No records match the filter → empty page with no cursor.
#[test]
fn test_t003_filter_no_match_empty_result() {
    let (env, client) = setup();
    let (_admin, _merchant, payer, _token) =
        setup_payer_payments(&env, &client, &[100, 200]);

    // Filter for amounts > 10_000 — no payment qualifies
    let filter = PaymentFilter {
        date_start: None,
        date_end: None,
        amount_min: Some(10_000),
        amount_max: None,
        tokens: None,
        status: StatusFilter::Any,
    };
    let page = client.get_payer_payment_history(
        &payer, &None, &10, &Some(filter), &SortField::Amount, &SortOrder::Descending,
    );
    assert_eq!(page.total, 0);
    assert_eq!(page.records.len(), 0);
    assert!(page.next_cursor.is_none());
}

// MISC-013: PaymentOrder.metadata — optional structured metadata for
// off-chain reconciliation (e.g. customer ID, product SKU).
//
// A payment processed with metadata attached must carry that metadata
// through to the stored PaymentRecord and be returned unchanged in history
// queries such as `get_payer_payment_history`.
#[test]
fn test_misc013_payment_metadata_roundtrip_in_history() {
    let (env, client) = setup();
    let admin = Address::generate(&env);
    let merchant = Address::generate(&env);
    let payer = Address::generate(&env);
    let token = create_token(&env, &admin);
    client.set_admin(&admin_vec(&env, &admin), &1);
    client.register_merchant(
        &merchant,
        &s(&env, "Store"),
        &s(&env, "desc"),
        &s(&env, "c@c.com"),
        &MerchantCategory::Retail,
        &None,
    );
    mint(&env, &token, &payer, 1_000);

    let mut metadata = Map::new(&env);
    metadata.set(s(&env, "customer_id"), s(&env, "CUST-42"));
    metadata.set(s(&env, "sku"), s(&env, "SKU-7"));

    let order = PaymentOrder {
        order_id: b(&env, "META_001"),
        merchant_address: merchant.clone(),
        payer: payer.clone(),
        token: token.clone(),
        amount: 500,
        description: s(&env, "with metadata"),
        expires_at: 0,
        metadata: Some(metadata.clone()),
    };
    let (_pk, sig) = sign_order(&env, &order);
    client.process_payment_with_signature(&payer, &order, &sig, &zero_key(&env));

    let page = client.get_payer_payment_history(
        &payer, &None, &10, &None, &SortField::Date, &SortOrder::Ascending,
    );
    assert_eq!(page.records.len(), 1);
    let record = page.records.get(0).unwrap();
    assert_eq!(record.metadata, Some(metadata));
}

/// A payment processed with no metadata must round-trip as `None`, not an
/// empty map, so callers can distinguish "no metadata supplied" from
/// "metadata supplied but empty".
#[test]
fn test_misc013_payment_without_metadata_is_none() {
    let (env, client) = setup();
    let (_admin, _merchant, payer, _token) =
        setup_payer_payments(&env, &client, &[42]);

    let page = client.get_payer_payment_history(
        &payer, &None, &10, &None, &SortField::Date, &SortOrder::Ascending,
    );
    assert_eq!(page.records.len(), 1);
    assert_eq!(page.records.get(0).unwrap().metadata, None);
}

/// Metadata whose combined key+value size exceeds the 1 KB cap must be
/// rejected with `InvalidInput` rather than silently stored.
#[test]
fn test_misc013_oversized_metadata_rejected() {
    let (env, client) = setup();
    let admin = Address::generate(&env);
    let merchant = Address::generate(&env);
    let payer = Address::generate(&env);
    let token = create_token(&env, &admin);
    client.set_admin(&admin_vec(&env, &admin), &1);
    client.register_merchant(
        &merchant,
        &s(&env, "Store"),
        &s(&env, "desc"),
        &s(&env, "c@c.com"),
        &MerchantCategory::Retail,
        &None,
    );
    mint(&env, &token, &payer, 1_000);

    // A single value just over 1024 bytes pushes the combined size over the cap.
    let big_value: alloc::string::String = core::iter::repeat('x').take(1025).collect();
    let mut metadata = Map::new(&env);
    metadata.set(s(&env, "k"), s(&env, &big_value));

    let order = PaymentOrder {
        order_id: b(&env, "META_BIG"),
        merchant_address: merchant.clone(),
        payer: payer.clone(),
        token: token.clone(),
        amount: 500,
        description: s(&env, "oversized metadata"),
        expires_at: 0,
        metadata: Some(metadata),
    };
    let (_pk, sig) = sign_order(&env, &order);
    assert_eq!(
        client.try_process_payment_with_signature(&payer, &order, &sig, &zero_key(&env)),
        Err(Ok(PaymentError::InvalidInput))
    );
}
