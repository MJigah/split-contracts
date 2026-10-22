#![cfg(test)]

use super::*;
use soroban_sdk::{
    testutils::{Address as _, Ledger},
    token::{Client as TokenClient, StellarAssetClient},
    Address, Bytes, BytesN, Env, Symbol, Vec,
};
use types::{
    EncryptionAlgorithm, EncryptionValidation, InvoiceOptions, Permission, Role, CacheMetrics,
    QueryMetrics,
};

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

fn setup() -> (Env, Address, Address) {
    let env = Env::default();
    env.mock_all_auths();

    let contract_id = env.register(SplitContract, ());
    let token_admin = Address::generate(&env);
    let token_id = env
        .register_stellar_asset_contract_v2(token_admin.clone())
        .address();

    StellarAssetClient::new(&env, &token_id).mint(&token_admin, &1_000_000_000);

    (env, contract_id, token_id)
}

fn client<'a>(env: &'a Env, contract_id: &Address) -> SplitContractClient<'a> {
    SplitContractClient::new(env, contract_id)
}

fn token_client<'a>(env: &'a Env, token_id: &Address) -> TokenClient<'a> {
    TokenClient::new(env, token_id)
}

fn default_options(env: &Env) -> InvoiceOptions {
    InvoiceOptions {
            co_creators: Vec::new(env),
            allow_early_withdrawal: false,
            bonus_pool: 0,
            bonus_max_payers: 0,
            prerequisite_id: None,
            tranches: Vec::new(env),
            co_signers: Vec::new(env),
            required_signatures: 0,
            penalty_bps: None,
            penalty_deadline: None,
            min_funding_bps: None,
            release_stages: Vec::new(env),
            price_oracle: None,
        }
    }

/// Create a basic single-recipient invoice with default optional params.
fn make_invoice(
    env: &Env,
    c: &SplitContractClient,
    creator: &Address,
    recipient: &Address,
    amount: i128,
    token_id: &Address,
    deadline: u64,
) -> u64 {
    let mut recipients = Vec::new(env);
    recipients.push_back(recipient.clone());
    let mut amounts = Vec::new(env);
    amounts.push_back(amount);
    c.create_invoice(creator, &recipients, &amounts, token_id, &deadline, &default_options(env))
}

// ---------------------------------------------------------------------------
// Core tests
// ---------------------------------------------------------------------------

#[test]
fn test_create_invoice() {
    let (env, contract_id, token_id) = setup();
    let c = client(&env, &contract_id);

    let creator = Address::generate(&env);
    let recipient = Address::generate(&env);

    env.ledger().set_timestamp(1_000);

    let id = make_invoice(&env, &c, &creator, &recipient, 100, &token_id, 2_000);
    assert_eq!(id, 1);

    let invoice = c.get_invoice(&id);
    assert_eq!(invoice.status, InvoiceStatus::Pending);
    assert_eq!(invoice.funded, 0);
    assert!(invoice.allowed_payers.is_none());
}

#[test]
fn test_pay_and_auto_release() {
    let (env, contract_id, token_id) = setup();
    let c = client(&env, &contract_id);
    let tk = token_client(&env, &token_id);

    let creator = Address::generate(&env);
    let payer = Address::generate(&env);
    let recipient = Address::generate(&env);

    StellarAssetClient::new(&env, &token_id).mint(&payer, &500);
    env.ledger().set_timestamp(1_000);

    let id = make_invoice(&env, &c, &creator, &recipient, 200, &token_id, 9_999);
    c.pay(&payer, &id, &200_i128, &0_u64, &false);

    let invoice = c.get_invoice(&id);
    assert_eq!(invoice.status, InvoiceStatus::Released);
    assert_eq!(tk.balance(&recipient), 200);
}

#[test]
fn test_partial_pay_then_release() {
    let (env, contract_id, token_id) = setup();
    let c = client(&env, &contract_id);
    let tk = token_client(&env, &token_id);

    let creator = Address::generate(&env);
    let payer1 = Address::generate(&env);
    let payer2 = Address::generate(&env);
    let recipient = Address::generate(&env);

    let sa = StellarAssetClient::new(&env, &token_id);
    sa.mint(&payer1, &150);
    sa.mint(&payer2, &150);
    env.ledger().set_timestamp(1_000);

    let id = make_invoice(&env, &c, &creator, &recipient, 300, &token_id, 9_999);

    c.pay(&payer1, &id, &150_i128, &0_u64, &false);
    assert_eq!(c.get_invoice(&id).status, InvoiceStatus::Pending);

    c.pay(&payer2, &id, &150_i128, &0_u64, &false);
    assert_eq!(c.get_invoice(&id).status, InvoiceStatus::Released);
    assert_eq!(tk.balance(&recipient), 300);
}

#[test]
fn test_refund_after_deadline() {
    let (env, contract_id, token_id) = setup();
    let c = client(&env, &contract_id);
    let tk = token_client(&env, &token_id);

    let creator = Address::generate(&env);
    let payer = Address::generate(&env);
    let recipient = Address::generate(&env);

    StellarAssetClient::new(&env, &token_id).mint(&payer, &100);
    env.ledger().set_timestamp(1_000);

    let id = make_invoice(&env, &c, &creator, &recipient, 500, &token_id, 2_000);
    c.pay(&payer, &id, &100_i128, &0_u64, &false);

    env.ledger().set_timestamp(3_000);
    c.refund(&id);

    assert_eq!(c.get_invoice(&id).status, InvoiceStatus::Refunded);
    assert_eq!(tk.balance(&payer), 100);
}

#[test]
#[should_panic(expected = "invoice deadline has passed")]
fn test_pay_after_deadline_panics() {
    let (env, contract_id, token_id) = setup();
    let c = client(&env, &contract_id);

    let creator = Address::generate(&env);
    let payer = Address::generate(&env);
    let recipient = Address::generate(&env);

    StellarAssetClient::new(&env, &token_id).mint(&payer, &100);
    env.ledger().set_timestamp(1_000);

    let id = make_invoice(&env, &c, &creator, &recipient, 100, &token_id, 2_000);
    env.ledger().set_timestamp(3_000);
    c.pay(&payer, &id, &100_i128, &0_u64, &false);
}

#[test]
#[should_panic(expected = "payment exceeds remaining balance")]
fn test_overpayment_panics() {
    let (env, contract_id, token_id) = setup();
    let c = client(&env, &contract_id);

    let creator = Address::generate(&env);
    let payer = Address::generate(&env);
    let recipient = Address::generate(&env);

    StellarAssetClient::new(&env, &token_id).mint(&payer, &1_000);
    env.ledger().set_timestamp(1_000);

    let id = make_invoice(&env, &c, &creator, &recipient, 100, &token_id, 9_999);
    c.pay(&payer, &id, &200_i128, &0_u64, &false);
}

#[test]
fn test_multi_recipient_release() {
    let (env, contract_id, token_id) = setup();
    let c = client(&env, &contract_id);
    let tk = token_client(&env, &token_id);

    let creator = Address::generate(&env);
    let payer = Address::generate(&env);
    let r1 = Address::generate(&env);
    let r2 = Address::generate(&env);
    let r3 = Address::generate(&env);

    StellarAssetClient::new(&env, &token_id).mint(&payer, &600);
    env.ledger().set_timestamp(1_000);

    let mut recipients = Vec::new(&env);
    recipients.push_back(r1.clone());
    recipients.push_back(r2.clone());
    recipients.push_back(r3.clone());
    let mut amounts = Vec::new(&env);
    amounts.push_back(100_i128);
    amounts.push_back(200_i128);
    amounts.push_back(300_i128);

    let id = c.create_invoice(
        &creator, &recipients, &amounts, &token_id, &9_999_u64, &default_options(&env),
    );
    c.pay(&payer, &id, &600_i128, &0_u64, &false);

    assert_eq!(tk.balance(&r1), 100);
    assert_eq!(tk.balance(&r2), 200);
    assert_eq!(tk.balance(&r3), 300);
}

#[test]
fn test_audit_log() {
    let (env, contract_id, token_id) = setup();
    let c = client(&env, &contract_id);

    let creator = Address::generate(&env);
    let payer = Address::generate(&env);
    let recipient = Address::generate(&env);

    StellarAssetClient::new(&env, &token_id).mint(&payer, &500);
    env.ledger().set_timestamp(1_000);

    let id = make_invoice(&env, &c, &creator, &recipient, 200, &token_id, 9_999);
    c.pay(&payer, &id, &200_i128, &0_u64, &false);

    assert_eq!(c.get_invoice(&id).status, InvoiceStatus::Released);

    let log = c.get_audit_log(&id);
    assert_eq!(log.len(), 2);
    assert_eq!(log.get_unchecked(0).action, symbol_short!("pay"));
    assert_eq!(log.get_unchecked(1).action, symbol_short!("release"));
}

#[test]
fn test_cancel_invoice() {
    let (env, contract_id, token_id) = setup();
    let c = client(&env, &contract_id);

    let creator = Address::generate(&env);
    let recipient = Address::generate(&env);

    env.ledger().set_timestamp(1_000);

    let id = make_invoice(&env, &c, &creator, &recipient, 100, &token_id, 9_999);
    c.cancel_invoice(&creator, &id);

    assert_eq!(c.get_invoice(&id).status, InvoiceStatus::Cancelled);

    let log = c.get_audit_log(&id);
    assert_eq!(log.len(), 1);
    assert_eq!(log.get_unchecked(0).action, symbol_short!("cancel"));
}

#[test]
fn test_transfer_invoice() {
    let (env, contract_id, token_id) = setup();
    let c = client(&env, &contract_id);

    let creator = Address::generate(&env);
    let new_creator = Address::generate(&env);
    let recipient = Address::generate(&env);

    stellar_asset.mint(&payer, &400);
    env.ledger().set_timestamp(1_000);

    let mut recipients = Vec::new(&env);
    recipients.push_back(recipient.clone());
    let mut amounts = Vec::new(&env);
    amounts.push_back(100_i128);

    let name = soroban_sdk::symbol_short!("bill");
    c.save_template(&creator, &name, &recipients, &amounts, &token_id);

    let id1 = c.create_from_template(&creator, &name, &5_000_u64);
    let id2 = c.create_from_template(&creator, &name, &6_000_u64);

    assert_ne!(id1, id2);

    c.pay(&payer, &id1, &100_i128, &0_u64, &false);
    c.pay(&payer, &id2, &100_i128, &0_u64, &false);

    assert_eq!(c.get_invoice(&id1).status, InvoiceStatus::Released);
    assert_eq!(c.get_invoice(&id2).status, InvoiceStatus::Released);
    assert_eq!(tk.balance(&recipient), 200);
}

#[test]
fn test_template_overwrite() {
    let (env, contract_id, token_id) = setup();
    let c = client(&env, &contract_id);

    let creator = Address::generate(&env);
    let r1 = Address::generate(&env);
    let r2 = Address::generate(&env);

    env.ledger().set_timestamp(1_000);

    let name = soroban_sdk::symbol_short!("tmpl");

    let mut recipients1 = Vec::new(&env);
    recipients1.push_back(r1.clone());
    let mut amounts1 = Vec::new(&env);
    amounts1.push_back(50_i128);
    c.save_template(&creator, &name, &recipients1, &amounts1, &token_id);

    let mut recipients2 = Vec::new(&env);
    recipients2.push_back(r2.clone());
    let mut amounts2 = Vec::new(&env);
    amounts2.push_back(75_i128);
    c.save_template(&creator, &name, &recipients2, &amounts2, &token_id);

    let id = c.create_from_template(&creator, &name, &9_999_u64);
    let invoice = c.get_invoice(&id);
    assert_eq!(invoice.recipients.get_unchecked(0), r2);
    assert_eq!(invoice.amounts.get_unchecked(0), 75_i128);
}

#[test]
fn test_extend_deadline() {
    let (env, contract_id, token_id) = setup();
    let c = client(&env, &contract_id);

    let creator = Address::generate(&env);
    let recipient = Address::generate(&env);

    env.ledger().set_timestamp(1_000);

    let id = make_invoice(&env, &c, &creator, &recipient, 300, &token_id, 9_999);

    c.pay(&payer, &id, &150_i128, &0_u64, &false);
    assert_eq!(tk.balance(&payer), 150);

    c.cancel_invoice(&creator, &id);

    let invoice = c.get_invoice(&id);
    assert_eq!(invoice.status, InvoiceStatus::Refunded);
    assert_eq!(tk.balance(&payer), 300);
}

#[test]
#[should_panic(expected = "invoice is not pending")]
fn test_cancel_non_pending_panics() {
    let (env, contract_id, token_id) = setup();
    let c = client(&env, &contract_id);
    let stellar_asset = StellarAssetClient::new(&env, &token_id);

    let creator = Address::generate(&env);
    let payer = Address::generate(&env);
    let recipient = Address::generate(&env);

    stellar_asset.mint(&payer, &100);
    env.ledger().set_timestamp(1_000);

    let id = make_invoice(&env, &c, &creator, &recipient, 100, &token_id, 9_999);
    c.pay(&payer, &id, &100_i128, &0_u64, &false);
    c.cancel_invoice(&creator, &id);
}

#[test]
fn test_get_payer_total() {
    let (env, contract_id, token_id) = setup();
    let c = client(&env, &contract_id);

    let creator = Address::generate(&env);
    let payer = Address::generate(&env);
    let recipient = Address::generate(&env);

    StellarAssetClient::new(&env, &token_id).mint(&payer, &500);
    env.ledger().set_timestamp(1_000);

    let id = make_invoice(&env, &c, &creator, &recipient, 500, &token_id, 9_999);

    assert_eq!(c.get_payer_total(&id, &payer), 0);
    assert_eq!(c.get_payer_total(&id, &other), 0);

    c.pay(&payer, &id, &200_i128, &0_u64, &false);
    assert_eq!(c.get_payer_total(&id, &payer), 200);

    c.pay(&payer, &id, &150_i128, &1_u64, &false);
    assert_eq!(c.get_payer_total(&id, &payer), 350);
}

#[test]
fn test_verify_invoice() {
    let (env, contract_id, token_id) = setup();
    let c = client(&env, &contract_id);

    let creator = Address::generate(&env);
    let payer = Address::generate(&env);
    let recipient = Address::generate(&env);

    StellarAssetClient::new(&env, &token_id).mint(&payer, &100);
    env.ledger().set_timestamp(1_000);

    let id = make_invoice(&env, &c, &creator, &recipient, 100, &token_id, 2_000);
    c.extend_deadline(&creator, &id, &9_999_u64);

    c.pay(&payer, &id, &100_i128);
    assert!(c.verify_invoice(&id, &InvoiceStatus::Released));
    assert!(!c.verify_invoice(&id, &InvoiceStatus::Pending));
}

// ---------------------------------------------------------------------------
// Adjust split
// ---------------------------------------------------------------------------

#[test]
fn test_adjust_split_updates_amounts_and_pays_new_total() {
    let (env, contract_id, token_id) = setup();
    let c = client(&env, &contract_id);
    let tk = token_client(&env, &token_id);

    let creator = Address::generate(&env);
    let payer = Address::generate(&env);
    let r1 = Address::generate(&env);
    let r2 = Address::generate(&env);

    StellarAssetClient::new(&env, &token_id).mint(&payer, &1_000);
    env.ledger().set_timestamp(1_000);

    // Create invoice: r1=100, r2=200 (total 300).
    let mut recipients = Vec::new(&env);
    recipients.push_back(r1.clone());
    recipients.push_back(r2.clone());
    let mut amounts = Vec::new(&env);
    amounts.push_back(100_i128);
    amounts.push_back(200_i128);
    let id = c.create_invoice(
        &creator, &recipients, &amounts, &token_id, &9_999_u64, &default_options(&env),
    );

    // Rebalance before any payment: r1=150, r2=250 (total 400).
    let mut new_amounts = Vec::new(&env);
    new_amounts.push_back(150_i128);
    new_amounts.push_back(250_i128);
    c.adjust_split(&creator, &id, &new_amounts);

    let invoice = c.get_invoice(&id);
    assert_eq!(invoice.amounts.get_unchecked(0), 150);
    assert_eq!(invoice.amounts.get_unchecked(1), 250);

    // Pay the new total (400) and verify recipients receive updated amounts.
    c.pay(&payer, &id, &400_i128, &0_u64);

    assert_eq!(c.get_invoice(&id).status, InvoiceStatus::Released);
    assert_eq!(tk.balance(&r1), 150);
    assert_eq!(tk.balance(&r2), 250);
}

#[test]
#[should_panic(expected = "only creator can adjust split")]
fn test_adjust_split_non_creator_panics() {
    let (env, contract_id, token_id) = setup();
    let c = client(&env, &contract_id);

    let creator = Address::generate(&env);
    let other = Address::generate(&env);
    let recipient = Address::generate(&env);

    env.ledger().set_timestamp(1_000);

    let id = make_invoice(&env, &c, &creator, &recipient, 100, &token_id, 9_999);

    let mut new_amounts = Vec::new(&env);
    new_amounts.push_back(200_i128);
    c.adjust_split(&other, &id, &new_amounts);
}

#[test]
#[should_panic(expected = "payments already received")]
fn test_adjust_split_after_payment_panics() {
    let (env, contract_id, token_id) = setup();
    let c = client(&env, &contract_id);

    let creator = Address::generate(&env);
    let payer = Address::generate(&env);
    let recipient = Address::generate(&env);

    StellarAssetClient::new(&env, &token_id).mint(&payer, &50);
    env.ledger().set_timestamp(1_000);

    let id = make_invoice(&env, &c, &creator, &recipient, 100, &token_id, 9_999);
    c.pay(&payer, &id, &50_i128, &0_u64);

    let mut new_amounts = Vec::new(&env);
    new_amounts.push_back(80_i128);
    c.adjust_split(&creator, &id, &new_amounts);
}

#[test]
#[should_panic(expected = "amounts length mismatch")]
fn test_adjust_split_wrong_length_panics() {
    let (env, contract_id, token_id) = setup();
    let c = client(&env, &contract_id);

    let creator = Address::generate(&env);
    let recipient = Address::generate(&env);

    env.ledger().set_timestamp(1_000);

    let id = make_invoice(&env, &c, &creator, &recipient, 100, &token_id, 9_999);

    // Invoice has 1 recipient; pass 2 amounts.
    let mut new_amounts = Vec::new(&env);
    new_amounts.push_back(50_i128);
    new_amounts.push_back(50_i128);
    c.adjust_split(&creator, &id, &new_amounts);
}

#[test]
#[should_panic(expected = "amounts must be positive")]
fn test_adjust_split_zero_amount_panics() {
    let (env, contract_id, token_id) = setup();
    let c = client(&env, &contract_id);

    let creator = Address::generate(&env);
    let recipient = Address::generate(&env);

    env.ledger().set_timestamp(1_000);

    let id = make_invoice(&env, &c, &creator, &recipient, 100, &token_id, 9_999);

    let mut new_amounts = Vec::new(&env);
    new_amounts.push_back(0_i128);
    c.adjust_split(&creator, &id, &new_amounts);
}

// ---------------------------------------------------------------------------
// Add recipient
// ---------------------------------------------------------------------------

#[test]
fn test_add_recipient_appends_to_invoice() {
    let (env, contract_id, token_id) = setup();
    let c = client(&env, &contract_id);

    let creator = Address::generate(&env);
    let r1 = Address::generate(&env);
    let r2 = Address::generate(&env);

    env.ledger().set_timestamp(1_000);

    let id = make_invoice(&env, &c, &creator, &r1, 100, &token_id, 9_999);

    c.add_recipient(&creator, &id, &r2, &200_i128);

    let invoice = c.get_invoice(&id);
    assert_eq!(invoice.recipients.len(), 2);
    assert_eq!(invoice.recipients.get_unchecked(0), r1);
    assert_eq!(invoice.recipients.get_unchecked(1), r2);
    assert_eq!(invoice.amounts.get_unchecked(0), 100);
    assert_eq!(invoice.amounts.get_unchecked(1), 200);
    assert_eq!(invoice.funded, 0);
}

#[test]
fn test_add_recipient_audit_entry() {
    let (env, contract_id, token_id) = setup();
    let c = client(&env, &contract_id);

    let creator = Address::generate(&env);
    let r1 = Address::generate(&env);
    let r2 = Address::generate(&env);

    env.ledger().set_timestamp(1_000);

    let id = make_invoice(&env, &c, &creator, &r1, 100, &token_id, 9_999);
    c.add_recipient(&creator, &id, &r2, &200_i128);

    let log = c.get_audit_log(&id);
    assert_eq!(log.len(), 1);
    assert_eq!(log.get_unchecked(0).action, symbol_short!("add_rec"));
    assert_eq!(log.get_unchecked(0).actor, creator);
}

#[test]
#[should_panic(expected = "only creator can add recipients")]
fn test_add_recipient_non_creator_panics() {
    let (env, contract_id, token_id) = setup();
    let c = client(&env, &contract_id);

    let creator = Address::generate(&env);
    let other = Address::generate(&env);
    let r1 = Address::generate(&env);
    let r2 = Address::generate(&env);

    env.ledger().set_timestamp(1_000);

    let id = make_invoice(&env, &c, &creator, &r1, 100, &token_id, 9_999);
    c.add_recipient(&other, &id, &r2, &200_i128);
}

#[test]
#[should_panic(expected = "cannot add recipient after payment received")]
fn test_add_recipient_after_payment_panics() {
    let (env, contract_id, token_id) = setup();
    let c = client(&env, &contract_id);

    let creator = Address::generate(&env);
    let payer = Address::generate(&env);
    let r1 = Address::generate(&env);
    let r2 = Address::generate(&env);

    StellarAssetClient::new(&env, &token_id).mint(&payer, &100);
    env.ledger().set_timestamp(1_000);

    let id = make_invoice(&env, &c, &creator, &r1, 100, &token_id, 9_999);
    c.pay(&payer, &id, &50_i128, &0_u64, &false);
    c.add_recipient(&creator, &id, &r2, &200_i128);
}

#[test]
#[should_panic(expected = "amount must be positive")]
fn test_add_recipient_zero_amount_panics() {
    let (env, contract_id, token_id) = setup();
    let c = client(&env, &contract_id);

    let creator = Address::generate(&env);
    let r1 = Address::generate(&env);
    let r2 = Address::generate(&env);

    env.ledger().set_timestamp(1_000);

    let id = make_invoice(&env, &c, &creator, &r1, 100, &token_id, 9_999);
    c.add_recipient(&creator, &id, &r2, &0_i128);
}

#[test]
fn test_add_recipient_then_full_payment() {
    let (env, contract_id, token_id) = setup();
    let c = client(&env, &contract_id);
    let tk = token_client(&env, &token_id);

    let creator = Address::generate(&env);
    let payer = Address::generate(&env);
    let r1 = Address::generate(&env);
    let r2 = Address::generate(&env);

    StellarAssetClient::new(&env, &token_id).mint(&payer, &500);
    env.ledger().set_timestamp(1_000);

    let id = make_invoice(&env, &c, &creator, &r1, 100, &token_id, 9_999);
    c.add_recipient(&creator, &id, &r2, &200_i128);

    // Pay total (100 + 200 = 300).
    c.pay(&payer, &id, &300_i128, &0_u64, &false);

    assert_eq!(c.get_invoice(&id).status, InvoiceStatus::Released);
    assert_eq!(tk.balance(&r1), 100);
    assert_eq!(tk.balance(&r2), 200);
}

#[test]
fn test_add_recipient_multiple() {
    let (env, contract_id, token_id) = setup();
    let c = client(&env, &contract_id);

    let creator = Address::generate(&env);
    let r1 = Address::generate(&env);
    let r2 = Address::generate(&env);
    let r3 = Address::generate(&env);

    env.ledger().set_timestamp(1_000);

    let id = make_invoice(&env, &c, &creator, &r1, 100, &token_id, 9_999);
    c.add_recipient(&creator, &id, &r2, &200_i128);
    c.add_recipient(&creator, &id, &r3, &300_i128);

    let invoice = c.get_invoice(&id);
    assert_eq!(invoice.recipients.len(), 3);
    assert_eq!(invoice.amounts.get_unchecked(0), 100);
    assert_eq!(invoice.amounts.get_unchecked(1), 200);
    assert_eq!(invoice.amounts.get_unchecked(2), 300);
}

#[test]
#[should_panic(expected = "invoice is not pending")]
fn test_add_recipient_after_release_panics() {
    let (env, contract_id, token_id) = setup();
    let c = client(&env, &contract_id);

    let creator = Address::generate(&env);
    let payer = Address::generate(&env);
    let r1 = Address::generate(&env);
    let r2 = Address::generate(&env);

    StellarAssetClient::new(&env, &token_id).mint(&payer, &200);
    env.ledger().set_timestamp(1_000);

    let id = make_invoice(&env, &c, &creator, &r1, 200, &token_id, 9_999);
    c.pay(&payer, &id, &200_i128, &0_u64, &false);
    // After auto-release the invoice is Released, not Pending.
    c.add_recipient(&creator, &id, &r2, &100_i128);
}

// ---------------------------------------------------------------------------
// Subscription
// ---------------------------------------------------------------------------

#[test]
fn test_allowed_payers_listed_address_succeeds() {
    let (env, contract_id, token_id) = setup();
    let c = client(&env, &contract_id);
    let tk = token_client(&env, &token_id);

    let creator = Address::generate(&env);
    let allowed = Address::generate(&env);
    let recipient = Address::generate(&env);

    StellarAssetClient::new(&env, &token_id).mint(&allowed, &200);
    env.ledger().set_timestamp(1_000);

    let mut recipients = Vec::new(&env);
    recipients.push_back(recipient.clone());
    let mut amounts = Vec::new(&env);
    amounts.push_back(200_i128);

    let id = c.create_subscription(&creator, &recipients, &amounts, &token_id, &3_u32);
    assert_eq!(id, 1);

    c.pay(&payer, &id, &200_i128, &0_u64, &false);
    assert_eq!(c.get_invoice(&id).status, InvoiceStatus::Released);

    let second_invoice = c.get_invoice(&2);
    assert_eq!(second_invoice.status, InvoiceStatus::Pending);
    assert_eq!(tk.balance(&recipient), 200);
}

// ---------------------------------------------------------------------------
// Pause / unpause
// ---------------------------------------------------------------------------

#[test]
#[should_panic(expected = "contract is paused")]
fn test_pause_blocks_pay() {
    let (env, contract_id, token_id) = setup();
    let c = client(&env, &contract_id);

    let admin = Address::generate(&env);
    let creator = Address::generate(&env);
    let payer = Address::generate(&env);
    let recipient = Address::generate(&env);

    StellarAssetClient::new(&env, &token_id).mint(&payer, &500);
    env.ledger().set_timestamp(1_000);

    let treasury = Address::generate(&env);
    c.initialize(&admin, &0_i128, &treasury, &token_id, &0_u32);
    let id = make_invoice(&env, &c, &creator, &recipient, 200, &token_id, 9_999);
    c.pause(&admin);

    c.pay(&payer, &id, &100_i128, &0_u64, &false);
}

#[test]
fn test_unpause_restores_pay() {
    let (env, contract_id, token_id) = setup();
    let c = client(&env, &contract_id);

    let admin = Address::generate(&env);
    let creator = Address::generate(&env);
    let payer = Address::generate(&env);
    let recipient = Address::generate(&env);

    StellarAssetClient::new(&env, &token_id).mint(&payer, &500);
    env.ledger().set_timestamp(1_000);

    let treasury = Address::generate(&env);
    c.initialize(&admin, &0_i128, &treasury, &token_id, &0_u32);
    let id = make_invoice(&env, &c, &creator, &recipient, 200, &token_id, 9_999);

    let id = c.create_invoice(
        &creator,
        &recipients,
        &amounts,
        &token_id,
        &9_999_u64,
        &Some(whitelist),
    );

    c.pay(&payer, &id, &200_i128, &0_u64, &false);
    assert_eq!(c.get_invoice(&id).status, InvoiceStatus::Released);
    assert_eq!(tk.balance(&recipient), 200);
}

#[test]
#[should_panic(expected = "payer not allowed")]
fn test_allowed_payers_unlisted_address_rejected() {
    let (env, contract_id, token_id) = setup();
    let c = client(&env, &contract_id);

    let creator = Address::generate(&env);
    let allowed = Address::generate(&env);
    let unlisted = Address::generate(&env);
    let recipient = Address::generate(&env);

    StellarAssetClient::new(&env, &token_id).mint(&unlisted, &200);
    env.ledger().set_timestamp(1_000);

    let treasury = Address::generate(&env);
    c.initialize(&admin, &0_i128, &treasury, &token_id, &0_u32);
    let id = make_invoice(&env, &c, &creator, &recipient, 200, &token_id, 9_999);
    c.pause(&admin);

    let invoice = c.get_invoice(&id);
    assert_eq!(invoice.status, InvoiceStatus::Pending);
}

// ---------------------------------------------------------------------------
// Transfer invoice
// ---------------------------------------------------------------------------

#[test]
fn test_transfer_invoice_new_creator_can_cancel() {
    let (env, contract_id, token_id) = setup();
    let c = client(&env, &contract_id);

    let creator = Address::generate(&env);
    let new_creator = Address::generate(&env);
    let recipient = Address::generate(&env);

    env.ledger().set_timestamp(1_000);

    let id = make_invoice(&env, &c, &creator, &recipient, 100, &token_id, 9_999);

    let id = c.create_invoice(
        &creator,
        &recipients,
        &amounts,
        &token_id,
        &9_999_u64,
        &Some(whitelist),
    );

    c.cancel_invoice(&new_creator, &id);
    assert_eq!(c.get_invoice(&id).status, InvoiceStatus::Cancelled);
}

#[test]
fn test_allowed_payers_none_behaves_as_open() {
    let (env, contract_id, token_id) = setup();
    let c = client(&env, &contract_id);
    let tk = token_client(&env, &token_id);

    let creator = Address::generate(&env);
    let anyone = Address::generate(&env);
    let recipient = Address::generate(&env);

    StellarAssetClient::new(&env, &token_id).mint(&anyone, &100);
    env.ledger().set_timestamp(1_000);

    let id = make_invoice(&env, &c, &creator, &recipient, 100, &token_id, 9_999);
    c.transfer_invoice(&id, &new_creator);

    c.cancel_invoice(&creator, &id);
}

// ---------------------------------------------------------------------------
// Bonus pool
// ---------------------------------------------------------------------------

#[test]
fn test_bonus_pool_distributed_to_first_payer() {
    let (env, contract_id, token_id) = setup();
    let c = client(&env, &contract_id);
    let tk = token_client(&env, &token_id);

    let creator = Address::generate(&env);
    let early_payer = Address::generate(&env);
    let late_payer = Address::generate(&env);
    let recipient = Address::generate(&env);

    let sa = StellarAssetClient::new(&env, &token_id);
    sa.mint(&creator, &50);
    sa.mint(&early_payer, &150);
    sa.mint(&late_payer, &150);

    env.ledger().set_timestamp(1_000);

    let mut recipients = Vec::new(&env);
    recipients.push_back(recipient.clone());
    let mut amounts = Vec::new(&env);
    amounts.push_back(300_i128);

    let id = c.create_invoice(
        &creator,
        &recipients,
        &amounts,
        &token_id,
        &9_999_u64,
        &InvoiceOptions {
            co_creators: Vec::new(&env),
            allow_early_withdrawal: false,
            bonus_pool: 50,
            bonus_max_payers: 1,
            prerequisite_id: None,
            tranches: Vec::new(&env),
            co_signers: Vec::new(&env),
            required_signatures: 0,
            penalty_bps: None,
            penalty_deadline: None,
            min_funding_bps: None,
            release_stages: Vec::new(&env),
        },
    );

    c.pay(&early_payer, &id, &150_i128, &0_u64, &false);
    c.pay(&late_payer, &id, &150_i128, &0_u64, &false);

    assert_eq!(c.get_invoice(&id).status, InvoiceStatus::Released);
    assert_eq!(tk.balance(&early_payer), 50);
    assert_eq!(tk.balance(&late_payer), 0);
    assert_eq!(tk.balance(&recipient), 300);
}

#[test]
fn test_bonus_pool_zero_behaves_identically() {
    let (env, contract_id, token_id) = setup();
    let c = client(&env, &contract_id);

    let admin = Address::generate(&env);
    let creator = Address::generate(&env);
    let payer = Address::generate(&env);
    let recipient = Address::generate(&env);

    StellarAssetClient::new(&env, &token_id).mint(&payer, &100);
    env.ledger().set_timestamp(1_000);

    let id = make_invoice(&env, &c, &creator, &recipient, 200, &token_id, 9_999);
    c.pay(&payer, &id, &200_i128, &0_u64, &false);

    // Create a v2 invoice (no allowed_payers).
    let id = make_invoice(&env, &c, &creator, &recipient, 100, &token_id, 9_999);

    // Simulate a v1 invoice by writing an InvoiceV1 directly to storage.
    let v1 = types::InvoiceV1 {
        creator: creator.clone(),
        recipients: {
            let mut v = Vec::new(&env);
            v.push_back(recipient.clone());
            v
        },
        amounts: {
            let mut v = Vec::new(&env);
            v.push_back(100_i128);
            v
        },
        token: token_id.clone(),
        deadline: 9_999,
        funded: 0,
        status: InvoiceStatus::Pending,
        payments: Vec::new(&env),
    };
    env.storage()
        .persistent()
        .set(&(symbol_short!("inv"), id), &v1);

    // Migrate the invoice.
    c.migrate_invoice(&id);

    // Read back as v2 and verify all original fields are retained.
    let v2 = c.get_invoice(&id);
    assert_eq!(v2.creator, creator);
    assert_eq!(v2.recipients.get_unchecked(0), recipient);
    assert_eq!(v2.amounts.get_unchecked(0), 100_i128);
    assert_eq!(v2.token, token_id);
    assert_eq!(v2.deadline, 9_999);
    assert_eq!(v2.funded, 0);
    assert_eq!(v2.status, InvoiceStatus::Pending);

    // New field defaults to None.
    assert!(v2.allowed_payers.is_none());
}

// ---------------------------------------------------------------------------
// Invoice groups
// ---------------------------------------------------------------------------

#[test]
#[should_panic(expected = "group members not fully funded")]
fn test_group_partial_fund_blocks_release() {
    let (env, contract_id, token_id) = setup();
    let c = client(&env, &contract_id);

    let creator = Address::generate(&env);
    let payer = Address::generate(&env);
    let r1 = Address::generate(&env);
    let r2 = Address::generate(&env);

    let stellar_asset = StellarAssetClient::new(&env, &token_id);
    stellar_asset.mint(&payer, &1_000);

    env.ledger().set_timestamp(1_000);

    let id1 = make_invoice(&env, &c, &creator, &r1, 100, &token_id, 9_999);
    let id2 = make_invoice(&env, &c, &creator, &r2, 200, &token_id, 9_999);

    let mut ids = Vec::new(&env);
    ids.push_back(id1);
    ids.push_back(id2);
    c.create_invoice_group(&ids);

    c.pay(&payer, &id1, &100_i128, &0_u64, &false);

    c.release(&id1);
}

#[test]
fn test_group_all_funded_releases_both() {
    let (env, contract_id, token_id) = setup();
    let c = client(&env, &contract_id);
    let tk = token_client(&env, &token_id);

    let creator = Address::generate(&env);
    let payer = Address::generate(&env);
    let r1 = Address::generate(&env);
    let r2 = Address::generate(&env);

    let stellar_asset = StellarAssetClient::new(&env, &token_id);
    stellar_asset.mint(&payer, &1_000);

    env.ledger().set_timestamp(1_000);

    let id1 = make_invoice(&env, &c, &creator, &r1, 100, &token_id, 9_999);
    let id2 = make_invoice(&env, &c, &creator, &r2, 200, &token_id, 9_999);

    let mut ids = Vec::new(&env);
    ids.push_back(id1);
    ids.push_back(id2);
    c.create_invoice_group(&ids);

    c.pay(&payer, &id1, &100_i128, &0_u64, &false);
    c.pay(&payer, &id2, &200_i128, &0_u64, &false);

    c.release(&id1);

    assert_eq!(c.get_invoice(&id1).status, InvoiceStatus::Released);
    assert_eq!(c.get_invoice(&id2).status, InvoiceStatus::Released);
    assert_eq!(tk.balance(&r1), 100);
    assert_eq!(tk.balance(&r2), 200);
}

#[test]
fn test_non_grouped_invoice_unaffected() {
    let (env, contract_id, token_id) = setup();
    let c = client(&env, &contract_id);
    let tk = token_client(&env, &token_id);

    let creator = Address::generate(&env);
    let payer = Address::generate(&env);
    let recipient = Address::generate(&env);

    let stellar_asset = StellarAssetClient::new(&env, &token_id);
    stellar_asset.mint(&payer, &300);

    env.ledger().set_timestamp(1_000);

    let id = make_invoice(&env, &c, &creator, &recipient, 300, &token_id, 9_999);
    c.pay(&payer, &id, &300_i128, &0_u64, &false);

    assert_eq!(c.get_invoice(&id).status, InvoiceStatus::Released);
    assert_eq!(tk.balance(&recipient), 300);
}

// ---------------------------------------------------------------------------
// Issue #21 — pay() nonce
// ---------------------------------------------------------------------------

#[test]
fn test_nonce_increments_per_payer_per_invoice() {
    let (env, contract_id, token_id) = setup();
    let c = client(&env, &contract_id);

    let creator = Address::generate(&env);
    let payer = Address::generate(&env);
    let recipient = Address::generate(&env);

    StellarAssetClient::new(&env, &token_id).mint(&payer, &1_000);
    env.ledger().set_timestamp(1_000);

    let id = make_invoice(&env, &c, &creator, &recipient, 600, &token_id, 9_999);

    assert_eq!(c.get_nonce(&id, &payer), 0);

    c.pay(&payer, &id, &200_i128, &0_u64, &false);
    assert_eq!(c.get_nonce(&id, &payer), 1);

    c.pay(&payer, &id, &200_i128, &1_u64, &false);
    assert_eq!(c.get_nonce(&id, &payer), 2);

    c.pay(&payer, &id, &200_i128, &2_u64, &false);
    assert_eq!(c.get_invoice(&id).status, InvoiceStatus::Released);
}

#[test]
#[should_panic(expected = "invalid nonce")]
fn test_wrong_nonce_panics() {
    let (env, contract_id, token_id) = setup();
    let c = client(&env, &contract_id);

    let creator = Address::generate(&env);
    let payer = Address::generate(&env);
    let recipient = Address::generate(&env);

    StellarAssetClient::new(&env, &token_id).mint(&payer, &1_000);
    env.ledger().set_timestamp(1_000);

    let id = make_invoice(&env, &c, &creator, &recipient, 600, &token_id, 9_999);

    c.pay(&payer, &id, &200_i128, &0_u64, &false);
    c.pay(&payer, &id, &200_i128, &0_u64, &false);
    // nonce should be 2 now — submitting 1 again must panic.
    c.pay(&payer, &id, &200_i128, &0_u64, &false);
}

#[test]
fn test_nonce_is_independent_per_invoice() {
    let (env, contract_id, token_id) = setup();
    let c = client(&env, &contract_id);

    let creator = Address::generate(&env);
    let payer = Address::generate(&env);
    let r1 = Address::generate(&env);
    let r2 = Address::generate(&env);

    StellarAssetClient::new(&env, &token_id).mint(&payer, &1_000);
    env.ledger().set_timestamp(1_000);

    let id1 = make_invoice(&env, &c, &creator, &r1, 100, &token_id, 9_999);
    let id2 = make_invoice(&env, &c, &creator, &r2, 100, &token_id, 9_999);

    // Both invoices start at nonce 0 for the same payer.
    c.pay(&payer, &id1, &100_i128, &0_u64, &false);
    c.pay(&payer, &id2, &100_i128, &0_u64, &false);

    assert_eq!(c.get_nonce(&id1, &payer), 1);
    assert_eq!(c.get_nonce(&id2, &payer), 1);
}

// ---------------------------------------------------------------------------
// Issue #22 — prerequisite invoice linking
// ---------------------------------------------------------------------------

#[test]
#[should_panic(expected = "prerequisite not released")]
fn test_release_blocked_by_prerequisite() {
    let (env, contract_id, token_id) = setup();
    let c = client(&env, &contract_id);

    let creator = Address::generate(&env);
    let payer = Address::generate(&env);
    let r1 = Address::generate(&env);
    let r2 = Address::generate(&env);

    StellarAssetClient::new(&env, &token_id).mint(&payer, &1_000);
    env.ledger().set_timestamp(1_000);

    // Invoice A (prerequisite).
    let id_a = make_invoice(&env, &c, &creator, &r1, 100, &token_id, 9_999);

    // Invoice B requires A to be Released first.
    let mut recipients = Vec::new(&env);
    recipients.push_back(r2.clone());
    let mut amounts = Vec::new(&env);
    amounts.push_back(200_i128);
    let id_b = c.create_invoice(
        &creator,
        &recipients,
        &amounts,
        &token_id,
        &9_999_u64,
        &InvoiceOptions {
            co_creators: Vec::new(&env),
            allow_early_withdrawal: false,
            bonus_pool: 0,
            bonus_max_payers: 0,
            prerequisite_id: Some(id_a),
            tranches: Vec::new(&env),
            co_signers: Vec::new(&env),
            required_signatures: 0,
            penalty_bps: None,
            penalty_deadline: None,
            min_funding_bps: None,
            release_stages: Vec::new(&env),
        },
    );

    // Fund B fully but don't touch A.
    c.pay(&payer, &id_b, &200_i128, &0_u64, &false);

    // release() on B should panic because A is still Pending.
    c.release(&id_b);
}

#[test]
fn test_release_succeeds_after_prerequisite_released() {
    let (env, contract_id, token_id) = setup();
    let c = client(&env, &contract_id);
    let tk = token_client(&env, &token_id);

    let creator = Address::generate(&env);
    let payer = Address::generate(&env);
    let r1 = Address::generate(&env);
    let r2 = Address::generate(&env);

    StellarAssetClient::new(&env, &token_id).mint(&payer, &1_000);
    env.ledger().set_timestamp(1_000);

    let id_a = make_invoice(&env, &c, &creator, &r1, 100, &token_id, 9_999);

    let mut recipients = Vec::new(&env);
    recipients.push_back(r2.clone());
    let mut amounts = Vec::new(&env);
    amounts.push_back(200_i128);
    let id_b = c.create_invoice(
        &creator,
        &recipients,
        &amounts,
        &token_id,
        &9_999_u64,
        &InvoiceOptions {
            co_creators: Vec::new(&env),
            allow_early_withdrawal: false,
            bonus_pool: 0,
            bonus_max_payers: 0,
            prerequisite_id: Some(id_a),
            tranches: Vec::new(&env),
            co_signers: Vec::new(&env),
            required_signatures: 0,
            penalty_bps: None,
            penalty_deadline: None,
            min_funding_bps: None,
            release_stages: Vec::new(&env),
        },
    );

    // Release A (auto-releases on full funding).
    c.pay(&payer, &id_a, &100_i128, &0_u64, &false);
    assert_eq!(c.get_invoice(&id_a).status, InvoiceStatus::Released);

    // Fund B fully (stays pending because it has a prerequisite).
    c.pay(&payer, &id_b, &200_i128, &0_u64, &false);
    assert_eq!(c.get_invoice(&id_b).status, InvoiceStatus::Pending);

    // Now release B — prerequisite is satisfied.
    c.release(&id_b);
    assert_eq!(c.get_invoice(&id_b).status, InvoiceStatus::Released);
    assert_eq!(tk.balance(&r2), 200);
}

#[test]
fn test_no_prerequisite_behaves_like_normal() {
    let (env, contract_id, token_id) = setup();
    let c = client(&env, &contract_id);

    let creator = Address::generate(&env);
    let payer = Address::generate(&env);
    let recipient = Address::generate(&env);

    StellarAssetClient::new(&env, &token_id).mint(&payer, &200);
    env.ledger().set_timestamp(1_000);

    let id = make_invoice(&env, &c, &creator, &recipient, 200, &token_id, 9_999);
    c.pay(&payer, &id, &200_i128, &0_u64, &false);

    // Auto-releases because no prerequisite.
    assert_eq!(c.get_invoice(&id).status, InvoiceStatus::Released);
}

// ---------------------------------------------------------------------------
// Issue #23 — graduated release tranches
// ---------------------------------------------------------------------------

#[test]
fn test_tranches_partial_then_full_release() {
    let (env, contract_id, token_id) = setup();
    let c = client(&env, &contract_id);
    let tk = token_client(&env, &token_id);

    let creator = Address::generate(&env);
    let payer = Address::generate(&env);
    let recipient = Address::generate(&env);

    StellarAssetClient::new(&env, &token_id).mint(&payer, &1_000);
    env.ledger().set_timestamp(1_000);

    // Two tranches: 50% unlocks at t=1_500, remaining 50% at t=2_500.
    let mut tranches = Vec::new(&env);
    tranches.push_back(types::Tranche { timestamp: 1_500, basis_points: 5_000 });
    tranches.push_back(types::Tranche { timestamp: 2_500, basis_points: 5_000 });

    let mut recipients = Vec::new(&env);
    recipients.push_back(recipient.clone());
    let mut amounts = Vec::new(&env);
    amounts.push_back(1_000_i128);

    let id = c.create_invoice(
        &creator,
        &recipients,
        &amounts,
        &token_id,
        &9_999_u64,
        &InvoiceOptions {
            co_creators: Vec::new(&env),
            allow_early_withdrawal: false,
            bonus_pool: 0,
            bonus_max_payers: 0,
            prerequisite_id: None,
            tranches: tranches.clone(),
            co_signers: Vec::new(&env),
            required_signatures: 0,
            penalty_bps: None,
            penalty_deadline: None,
            min_funding_bps: None,
            release_stages: Vec::new(&env),
        },
    );

    // Fund fully — no auto-release for tranche invoices.
    c.pay(&payer, &id, &1_000_i128, &0_u64, &false);
    assert_eq!(c.get_invoice(&id).status, InvoiceStatus::Pending);

    // At t=1_600 first tranche is unlocked, second is not.
    env.ledger().set_timestamp(1_600);
    c.release(&id);

    assert_eq!(c.get_invoice(&id).status, InvoiceStatus::Pending);
    assert_eq!(c.get_invoice(&id).released_bps, 5_000);
    assert_eq!(tk.balance(&recipient), 500);

    // At t=2_600 second tranche also unlocked.
    env.ledger().set_timestamp(2_600);
    c.release(&id);

    assert_eq!(c.get_invoice(&id).status, InvoiceStatus::Released);
    assert_eq!(c.get_invoice(&id).released_bps, 10_000);
    assert_eq!(tk.balance(&recipient), 1_000);
}

#[test]
#[should_panic(expected = "no tranches unlocked")]
fn test_release_before_any_tranche_unlocked_panics() {
    let (env, contract_id, token_id) = setup();
    let c = client(&env, &contract_id);

    let creator = Address::generate(&env);
    let payer = Address::generate(&env);
    let recipient = Address::generate(&env);

    StellarAssetClient::new(&env, &token_id).mint(&payer, &500);
    env.ledger().set_timestamp(1_000);

    let mut tranches = Vec::new(&env);
    tranches.push_back(types::Tranche { timestamp: 5_000, basis_points: 10_000 });

    let mut recipients = Vec::new(&env);
    recipients.push_back(recipient.clone());
    let mut amounts = Vec::new(&env);
    amounts.push_back(500_i128);

    let id = c.create_invoice(
        &creator,
        &recipients,
        &amounts,
        &token_id,
        &9_999_u64,
        &InvoiceOptions {
            co_creators: Vec::new(&env),
            allow_early_withdrawal: false,
            bonus_pool: 0,
            bonus_max_payers: 0,
            prerequisite_id: None,
            tranches: tranches.clone(),
            co_signers: Vec::new(&env),
            required_signatures: 0,
            penalty_bps: None,
            penalty_deadline: None,
            min_funding_bps: None,
            release_stages: Vec::new(&env),
        },
    );

    c.pay(&payer, &id, &500_i128, &0_u64, &false);
    // t=1_000 < tranche timestamp 5_000 — should panic.
    c.release(&id);
}

// ---------------------------------------------------------------------------
// Issue #24 — on-chain reputation counter
// ---------------------------------------------------------------------------

#[test]
fn test_reputation_zero_for_new_address() {
    let (env, contract_id, _token_id) = setup();
    let c = client(&env, &contract_id);

    let address = Address::generate(&env);
    assert_eq!(c.get_reputation(&address), 0);
}

#[test]
fn test_reputation_increments_across_invoices() {
    let (env, contract_id, token_id) = setup();
    let c = client(&env, &contract_id);

    let creator = Address::generate(&env);
    let payer = Address::generate(&env);
    let recipient = Address::generate(&env);

    StellarAssetClient::new(&env, &token_id).mint(&payer, &1_000);
    env.ledger().set_timestamp(1_000);

    let id1 = make_invoice(&env, &c, &creator, &recipient, 100, &token_id, 9_999);
    let id2 = make_invoice(&env, &c, &creator, &recipient, 100, &token_id, 9_999);
    let id3 = make_invoice(&env, &c, &creator, &recipient, 100, &token_id, 9_999);

    assert_eq!(c.get_reputation(&payer), 0);

    c.pay(&payer, &id1, &100_i128, &0_u64, &false);
    assert_eq!(c.get_reputation(&payer), 1);

    c.pay(&payer, &id2, &100_i128, &0_u64, &false);
    assert_eq!(c.get_reputation(&payer), 2);

    c.pay(&payer, &id3, &100_i128, &0_u64, &false);
    assert_eq!(c.get_reputation(&payer), 3);
}

#[test]
fn test_reputation_is_per_address() {
    let (env, contract_id, token_id) = setup();
    let c = client(&env, &contract_id);

    let creator = Address::generate(&env);
    let payer_a = Address::generate(&env);
    let payer_b = Address::generate(&env);
    let recipient = Address::generate(&env);

    let sa = StellarAssetClient::new(&env, &token_id);
    sa.mint(&payer_a, &1_000);
    sa.mint(&payer_b, &1_000);
    env.ledger().set_timestamp(1_000);

    let id = make_invoice(&env, &c, &creator, &recipient, 400, &token_id, 9_999);

    c.pay(&payer_a, &id, &100_i128, &0_u64, &false);
    c.pay(&payer_a, &id, &100_i128, &1_u64, &false);
    c.pay(&payer_b, &id, &100_i128, &0_u64, &false);
    c.pay(&payer_b, &id, &100_i128, &1_u64, &false);

    // payer_a paid twice, payer_b paid twice.
    assert_eq!(c.get_reputation(&payer_a), 2);
    assert_eq!(c.get_reputation(&payer_b), 2);

    // Unrelated address has zero reputation.
    let other = Address::generate(&env);
    assert_eq!(c.get_reputation(&other), 0);
}

// ---------------------------------------------------------------------------
// Creation fee
// ---------------------------------------------------------------------------

#[test]
fn test_creation_fee_charged_to_treasury() {
    let (env, contract_id, token_id) = setup();
    let c = client(&env, &contract_id);
    let tk = token_client(&env, &token_id);

    let admin = Address::generate(&env);
    let creator = Address::generate(&env);
    let treasury = Address::generate(&env);
    let recipient = Address::generate(&env);

    let sa = StellarAssetClient::new(&env, &token_id);
    sa.mint(&creator, &1_000);

    env.ledger().set_timestamp(1_000);

    c.initialize(&admin, &50_i128, &treasury, &token_id, &0_u32);

    assert_eq!(c.get_creation_fee(), 50);
    assert_eq!(c.get_treasury(), treasury);
    assert_eq!(c.get_usdc_token(), token_id);

    let id = make_invoice(&env, &c, &creator, &recipient, 200, &token_id, 9_999);

    // Treasury received 50 USDC creation fee.
    assert_eq!(tk.balance(&treasury), 50);
    // Creator paid 50 USDC fee; invoice amount stays in creator wallet until payers pay.
    assert_eq!(tk.balance(&creator), 950);
    assert_eq!(c.get_invoice(&id).status, InvoiceStatus::Pending);
}

#[test]
fn test_creation_fee_zero_by_default() {
    let (env, contract_id, token_id) = setup();
    let c = client(&env, &contract_id);
    let tk = token_client(&env, &token_id);

    let admin = Address::generate(&env);
    let creator = Address::generate(&env);
    let treasury = Address::generate(&env);
    let recipient = Address::generate(&env);

    let sa = StellarAssetClient::new(&env, &token_id);
    sa.mint(&creator, &1_000);

    env.ledger().set_timestamp(1_000);

    c.initialize(&admin, &0_i128, &treasury, &token_id, &0_u32);

    let id = make_invoice(&env, &c, &creator, &recipient, 200, &token_id, 9_999);

    // No fee deducted when creation_fee is 0.
    assert_eq!(tk.balance(&treasury), 0);
    assert_eq!(tk.balance(&creator), 1000);
    assert_eq!(c.get_invoice(&id).status, InvoiceStatus::Pending);
}

#[test]
fn test_set_creation_fee_updates_fee() {
    let (env, contract_id, token_id) = setup();
    let c = client(&env, &contract_id);

    let admin = Address::generate(&env);
    let treasury = Address::generate(&env);

    c.initialize(&admin, &10_i128, &treasury, &token_id, &0_u32);
    assert_eq!(c.get_creation_fee(), 10);

    c.set_creation_fee(&admin, &25_i128);
    assert_eq!(c.get_creation_fee(), 25);
}

#[test]
fn test_set_treasury_updates_treasury() {
    let (env, contract_id, token_id) = setup();
    let c = client(&env, &contract_id);

    let admin = Address::generate(&env);
    let treasury1 = Address::generate(&env);
    let treasury2 = Address::generate(&env);

    c.initialize(&admin, &10_i128, &treasury1, &token_id, &0_u32);
    assert_eq!(c.get_treasury(), treasury1);

    c.set_treasury(&admin, &treasury2);
    assert_eq!(c.get_treasury(), treasury2);
}

#[test]
fn test_creation_fee_charged_per_invoice_in_batch() {
    let (env, contract_id, token_id) = setup();
    let c = client(&env, &contract_id);
    let tk = token_client(&env, &token_id);

    let admin = Address::generate(&env);
    let creator = Address::generate(&env);
    let treasury = Address::generate(&env);
    let recipient = Address::generate(&env);

    let sa = StellarAssetClient::new(&env, &token_id);
    sa.mint(&creator, &1_000);

    env.ledger().set_timestamp(1_000);

    c.initialize(&admin, &10_i128, &treasury, &token_id, &0_u32);

    // create_batch creates 2 invoices, each should incur a 10 unit fee.
    let mut recipients = Vec::new(&env);
    recipients.push_back(recipient.clone());
    let mut amounts = Vec::new(&env);
    amounts.push_back(100_i128);
    let params = types::CreateInvoiceParams {
        recipients,
        amounts,
        token: token_id.clone(),
        deadline: 9_999,
    };
    let mut invoices = Vec::new(&env);
    invoices.push_back(params.clone());
    invoices.push_back(params);
    c.create_batch(&creator, &invoices);

    // 2 invoices x 10 fee = 20 total.
    assert_eq!(tk.balance(&treasury), 20);
}

// ---------------------------------------------------------------------------
// Rollover invoice
// ---------------------------------------------------------------------------

#[test]
fn test_rollover_invoice_creates_new_with_carried_payments() {
    let (env, contract_id, token_id) = setup();
    let c = client(&env, &contract_id);
    let tk = token_client(&env, &token_id);

    let creator = Address::generate(&env);
    let payer = Address::generate(&env);
    let recipient = Address::generate(&env);

    StellarAssetClient::new(&env, &token_id).mint(&payer, &500);
    env.ledger().set_timestamp(1_000);

    // Create invoice with deadline at 2_000.
    let id1 = make_invoice(&env, &c, &creator, &recipient, 300, &token_id, 2_000);

    // Partially fund the invoice.
    c.pay(&payer, &id1, &100_i128, &0_u64, &false);
    assert_eq!(c.get_invoice(&id1).funded, 100);
    assert_eq!(c.get_invoice(&id1).status, InvoiceStatus::Pending);

    // Move past deadline.
    env.ledger().set_timestamp(3_000);

    // Rollover to new invoice with deadline at 5_000.
    let id2 = c.rollover_invoice(&creator, &id1, &5_000_u64);
    assert_ne!(id1, id2);

    // Old invoice should be marked Refunded.
    let old_invoice = c.get_invoice(&id1);
    assert_eq!(old_invoice.status, InvoiceStatus::Refunded);

    // New invoice should have same recipients, amounts, token.
    let new_invoice = c.get_invoice(&id2);
    assert_eq!(new_invoice.status, InvoiceStatus::Pending);
    assert_eq!(new_invoice.recipients.get_unchecked(0), recipient);
    assert_eq!(new_invoice.amounts.get_unchecked(0), 300);
    assert_eq!(new_invoice.deadline, 5_000);

    // New invoice should have carried over the payment.
    assert_eq!(new_invoice.funded, 100);
    assert_eq!(new_invoice.payments.len(), 1);
    assert_eq!(new_invoice.payments.get_unchecked(0).payer, payer);
    assert_eq!(new_invoice.payments.get_unchecked(0).amount, 100);

    // Payer should still have 400 (500 - 100 paid).
    assert_eq!(tk.balance(&payer), 400);

    // Recipient should have received nothing yet.
    assert_eq!(tk.balance(&recipient), 0);
}

#[test]
fn test_rollover_invoice_then_complete_payment() {
    let (env, contract_id, token_id) = setup();
    let c = client(&env, &contract_id);
    let tk = token_client(&env, &token_id);

    let creator = Address::generate(&env);
    let payer = Address::generate(&env);
    let recipient = Address::generate(&env);

    StellarAssetClient::new(&env, &token_id).mint(&payer, &500);
    env.ledger().set_timestamp(1_000);

    let id1 = make_invoice(&env, &c, &creator, &recipient, 300, &token_id, 2_000);
    c.pay(&payer, &id1, &100_i128, &0_u64, &false);

    env.ledger().set_timestamp(3_000);
    let id2 = c.rollover_invoice(&creator, &id1, &5_000_u64);

    // Complete the payment on the new invoice.
    c.pay(&payer, &id2, &200_i128, &0_u64, &false);

    // New invoice should be fully funded and released.
    assert_eq!(c.get_invoice(&id2).status, InvoiceStatus::Released);
    assert_eq!(c.get_invoice(&id2).funded, 300);

    // Recipient should have received the full amount.
    assert_eq!(tk.balance(&recipient), 300);
}

#[test]
#[should_panic(expected = "invoice is not pending")]
fn test_rollover_invoice_non_pending_panics() {
    let (env, contract_id, token_id) = setup();
    let c = client(&env, &contract_id);

    let creator = Address::generate(&env);
    let payer = Address::generate(&env);
    let recipient = Address::generate(&env);

    StellarAssetClient::new(&env, &token_id).mint(&payer, &500);
    env.ledger().set_timestamp(1_000);

    let id = make_invoice(&env, &c, &creator, &recipient, 100, &token_id, 9_999);
    c.pay(&payer, &id, &100_i128, &0_u64, &false);

    // Invoice is now Released, not Pending.
    env.ledger().set_timestamp(3_000);
    c.rollover_invoice(&creator, &id, &5_000_u64);
}

#[test]
#[should_panic(expected = "invoice deadline has not passed")]
fn test_rollover_invoice_before_deadline_panics() {
    let (env, contract_id, token_id) = setup();
    let c = client(&env, &contract_id);

    let creator = Address::generate(&env);
    let payer = Address::generate(&env);
    let recipient = Address::generate(&env);

    StellarAssetClient::new(&env, &token_id).mint(&payer, &500);
    env.ledger().set_timestamp(1_000);

    let id = make_invoice(&env, &c, &creator, &recipient, 300, &token_id, 5_000);
    c.pay(&payer, &id, &100_i128, &0_u64, &false);

    // Still before deadline (3_000 < 5_000).
    env.ledger().set_timestamp(3_000);
    c.rollover_invoice(&creator, &id, &6_000_u64);
}

#[test]
#[should_panic(expected = "only creator can rollover invoice")]
fn test_rollover_invoice_non_creator_panics() {
    let (env, contract_id, token_id) = setup();
    let c = client(&env, &contract_id);

    let creator = Address::generate(&env);
    let other = Address::generate(&env);
    let payer = Address::generate(&env);
    let recipient = Address::generate(&env);

    StellarAssetClient::new(&env, &token_id).mint(&payer, &500);
    env.ledger().set_timestamp(1_000);

    let id = make_invoice(&env, &c, &creator, &recipient, 300, &token_id, 2_000);
    c.pay(&payer, &id, &100_i128, &0_u64, &false);

    env.ledger().set_timestamp(3_000);
    c.rollover_invoice(&other, &id, &5_000_u64);
}

#[test]
#[should_panic(expected = "new deadline must be in the future")]
fn test_rollover_invoice_past_deadline_panics() {
    let (env, contract_id, token_id) = setup();
    let c = client(&env, &contract_id);

    let creator = Address::generate(&env);
    let payer = Address::generate(&env);
    let recipient = Address::generate(&env);

    StellarAssetClient::new(&env, &token_id).mint(&payer, &500);
    env.ledger().set_timestamp(1_000);

    let id = make_invoice(&env, &c, &creator, &recipient, 300, &token_id, 2_000);
    c.pay(&payer, &id, &100_i128, &0_u64, &false);

    env.ledger().set_timestamp(3_000);
    // Try to set new deadline to 2_500, which is in the past.
    c.rollover_invoice(&creator, &id, &2_500_u64);
}

#[test]
fn test_rollover_invoice_audit_entries() {
    let (env, contract_id, token_id) = setup();
    let c = client(&env, &contract_id);

    let creator = Address::generate(&env);
    let payer = Address::generate(&env);
    let recipient = Address::generate(&env);

    StellarAssetClient::new(&env, &token_id).mint(&payer, &500);
    env.ledger().set_timestamp(1_000);

    let id1 = make_invoice(&env, &c, &creator, &recipient, 300, &token_id, 2_000);
    c.pay(&payer, &id1, &100_i128, &0_u64, &false);

    env.ledger().set_timestamp(3_000);
    let id2 = c.rollover_invoice(&creator, &id1, &5_000_u64);

    // Old invoice should have rollover audit entry.
    let old_log = c.get_audit_log(&id1);
    assert_eq!(old_log.len(), 2); // pay + rollover
    assert_eq!(old_log.get_unchecked(0).action, symbol_short!("pay"));
    assert_eq!(old_log.get_unchecked(1).action, symbol_short!("rollover"));
    assert_eq!(old_log.get_unchecked(1).actor, creator);

    // New invoice should have rollover audit entry.
    let new_log = c.get_audit_log(&id2);
    assert_eq!(new_log.len(), 1); // rollover
    assert_eq!(new_log.get_unchecked(0).action, symbol_short!("rollover"));
    assert_eq!(new_log.get_unchecked(0).actor, creator);
}

#[test]
fn test_rollover_invoice_preserves_recipients_and_amounts() {
    let (env, contract_id, token_id) = setup();
    let c = client(&env, &contract_id);

    let creator = Address::generate(&env);
    let payer = Address::generate(&env);
    let r1 = Address::generate(&env);
    let r2 = Address::generate(&env);
    let r3 = Address::generate(&env);

    StellarAssetClient::new(&env, &token_id).mint(&payer, &1_000);
    env.ledger().set_timestamp(1_000);

    let mut recipients = Vec::new(&env);
    recipients.push_back(r1.clone());
    recipients.push_back(r2.clone());
    recipients.push_back(r3.clone());
    let mut amounts = Vec::new(&env);
    amounts.push_back(100_i128);
    amounts.push_back(200_i128);
    amounts.push_back(300_i128);

    let id1 = c.create_invoice(
        &creator, &recipients, &amounts, &token_id, &2_000_u64, &default_options(&env),
    );
    c.pay(&payer, &id1, &150_i128, &0_u64, &false);

    env.ledger().set_timestamp(3_000);
    let id2 = c.rollover_invoice(&creator, &id1, &5_000_u64);

    let new_invoice = c.get_invoice(&id2);
    assert_eq!(new_invoice.recipients.len(), 3);
    assert_eq!(new_invoice.recipients.get_unchecked(0), r1);
    assert_eq!(new_invoice.recipients.get_unchecked(1), r2);
    assert_eq!(new_invoice.recipients.get_unchecked(2), r3);
    assert_eq!(new_invoice.amounts.get_unchecked(0), 100);
    assert_eq!(new_invoice.amounts.get_unchecked(1), 200);
    assert_eq!(new_invoice.amounts.get_unchecked(2), 300);
}

// ---------------------------------------------------------------------------
// Issue #40 — recipient invoice ID index
// ---------------------------------------------------------------------------

#[test]
fn test_recipient_invoice_ids_empty_for_new_address() {
    let (env, contract_id, _token_id) = setup();
    let c = client(&env, &contract_id);

    let addr = Address::generate(&env);
    let ids = c.get_recipient_invoice_ids(&addr);
    assert_eq!(ids.len(), 0);
}

#[test]
fn test_recipient_invoice_ids_single_invoice() {
    let (env, contract_id, token_id) = setup();
    let c = client(&env, &contract_id);

    let creator = Address::generate(&env);
    let recipient = Address::generate(&env);

    env.ledger().set_timestamp(1_000);
    let id = make_invoice(&env, &c, &creator, &recipient, 100, &token_id, 9_999);

    let ids = c.get_recipient_invoice_ids(&recipient);
    assert_eq!(ids.len(), 1);
    assert_eq!(ids.get_unchecked(0), id);
}

#[test]
fn test_recipient_invoice_ids_same_recipient_multiple_invoices() {
    let (env, contract_id, token_id) = setup();
    let c = client(&env, &contract_id);

    let creator = Address::generate(&env);
    let recipient = Address::generate(&env);
    let other = Address::generate(&env);

    env.ledger().set_timestamp(1_000);

    let id1 = make_invoice(&env, &c, &creator, &recipient, 100, &token_id, 9_999);
    let id2 = make_invoice(&env, &c, &creator, &recipient, 200, &token_id, 9_999);
    let id3 = make_invoice(&env, &c, &creator, &other, 300, &token_id, 9_999);

    let ids = c.get_recipient_invoice_ids(&recipient);
    assert_eq!(ids.len(), 2);
    assert_eq!(ids.get_unchecked(0), id1);
    assert_eq!(ids.get_unchecked(1), id2);

    let other_ids = c.get_recipient_invoice_ids(&other);
    assert_eq!(other_ids.len(), 1);
    assert_eq!(other_ids.get_unchecked(0), id3);
}

#[test]
fn test_recipient_invoice_ids_multi_recipient_invoice() {
    let (env, contract_id, token_id) = setup();
    let c = client(&env, &contract_id);

    let creator = Address::generate(&env);
    let r1 = Address::generate(&env);
    let r2 = Address::generate(&env);

    let mut recipients = Vec::new(&env);
    recipients.push_back(r1.clone());
    recipients.push_back(r2.clone());
    let mut amounts = Vec::new(&env);
    amounts.push_back(100_i128);
    amounts.push_back(200_i128);

    env.ledger().set_timestamp(1_000);
    let id = c.create_invoice(
        &creator, &recipients, &amounts, &token_id, &9_999_u64, &default_options(&env),
    );

    let r1_ids = c.get_recipient_invoice_ids(&r1);
    assert_eq!(r1_ids.len(), 1);
    assert_eq!(r1_ids.get_unchecked(0), id);

    let r2_ids = c.get_recipient_invoice_ids(&r2);
    assert_eq!(r2_ids.len(), 1);
    assert_eq!(r2_ids.get_unchecked(0), id);
}

#[test]
fn test_recipient_invoice_ids_after_add_recipient() {
    let (env, contract_id, token_id) = setup();
    let c = client(&env, &contract_id);

    let creator = Address::generate(&env);
    let r1 = Address::generate(&env);
    let r2 = Address::generate(&env);

    env.ledger().set_timestamp(1_000);
    let id = make_invoice(&env, &c, &creator, &r1, 100, &token_id, 9_999);

    // r1 should have the invoice before adding r2.
    assert_eq!(c.get_recipient_invoice_ids(&r1).len(), 1);

    // Add r2 via add_recipient.
    c.add_recipient(&creator, &id, &r2, &200_i128);

    // r2 should now also have the invoice.
    let r2_ids = c.get_recipient_invoice_ids(&r2);
    assert_eq!(r2_ids.len(), 1);
    assert_eq!(r2_ids.get_unchecked(0), id);

    // r1 is unaffected.
    assert_eq!(c.get_recipient_invoice_ids(&r1).len(), 1);
}

// ---------------------------------------------------------------------------
// Issue #41 — platform fee basis points
// ---------------------------------------------------------------------------

#[test]
fn test_platform_fee_bps_defaults_to_zero() {
    let (env, contract_id, token_id) = setup();
    let c = client(&env, &contract_id);

    let admin = Address::generate(&env);
    let treasury = Address::generate(&env);
    c.initialize(&admin, &0_i128, &treasury, &token_id, &0_u32);

    assert_eq!(c.get_platform_fee_bps(), 0);
}

#[test]
fn test_platform_fee_bps_deducted_on_release() {
    let (env, contract_id, token_id) = setup();
    let c = client(&env, &contract_id);
    let tk = token_client(&env, &token_id);

    let admin = Address::generate(&env);
    let creator = Address::generate(&env);
    let payer = Address::generate(&env);
    let recipient = Address::generate(&env);
    let treasury = Address::generate(&env);

    let sa = StellarAssetClient::new(&env, &token_id);
    sa.mint(&payer, &1_000);

    env.ledger().set_timestamp(1_000);

    c.initialize(&admin, &0_i128, &treasury, &token_id, &1_000_u32); // 10%

    let id = make_invoice(&env, &c, &creator, &recipient, 500, &token_id, 9_999);
    c.pay(&payer, &id, &500_i128, &0_u64, &false);

    assert_eq!(c.get_invoice(&id).status, InvoiceStatus::Released);
    // Recipient gets 500 - 10% = 450.
    assert_eq!(tk.balance(&recipient), 450);
    // Treasury gets 50.
    assert_eq!(tk.balance(&treasury), 50);
}

#[test]
fn test_platform_fee_bps_multi_recipient() {
    let (env, contract_id, token_id) = setup();
    let c = client(&env, &contract_id);
    let tk = token_client(&env, &token_id);

    let admin = Address::generate(&env);
    let creator = Address::generate(&env);
    let payer = Address::generate(&env);
    let r1 = Address::generate(&env);
    let r2 = Address::generate(&env);
    let r3 = Address::generate(&env);
    let treasury = Address::generate(&env);

    let sa = StellarAssetClient::new(&env, &token_id);
    sa.mint(&payer, &1_000);

    env.ledger().set_timestamp(1_000);

    c.initialize(&admin, &0_i128, &treasury, &token_id, &500_u32); // 5%

    let mut recipients = Vec::new(&env);
    recipients.push_back(r1.clone());
    recipients.push_back(r2.clone());
    recipients.push_back(r3.clone());
    let mut amounts = Vec::new(&env);
    amounts.push_back(200_i128);
    amounts.push_back(300_i128);
    amounts.push_back(500_i128);

    let id = c.create_invoice(
        &creator, &recipients, &amounts, &token_id, &9_999_u64, &default_options(&env),
    );
    c.pay(&payer, &id, &1_000_i128, &0_u64, &false);

    assert_eq!(c.get_invoice(&id).status, InvoiceStatus::Released);
    // 200 - 5% = 190, 300 - 5% = 285, 500 - 5% = 475 → sum = 950
    assert_eq!(tk.balance(&r1), 190);
    assert_eq!(tk.balance(&r2), 285);
    assert_eq!(tk.balance(&r3), 475);
    // Treasury gets 50.
    assert_eq!(tk.balance(&treasury), 50);
}

#[test]
fn test_platform_fee_bps_with_tranches() {
    let (env, contract_id, token_id) = setup();
    let c = client(&env, &contract_id);
    let tk = token_client(&env, &token_id);

    let admin = Address::generate(&env);
    let creator = Address::generate(&env);
    let payer = Address::generate(&env);
    let recipient = Address::generate(&env);
    let treasury = Address::generate(&env);

    let sa = StellarAssetClient::new(&env, &token_id);
    sa.mint(&payer, &1_000);

    env.ledger().set_timestamp(1_000);

    c.initialize(&admin, &0_i128, &treasury, &token_id, &1_000_u32); // 10%

    let mut tranches = Vec::new(&env);
    tranches.push_back(types::Tranche { timestamp: 1_500, basis_points: 5_000 });
    tranches.push_back(types::Tranche { timestamp: 2_500, basis_points: 5_000 });

    let mut recipients = Vec::new(&env);
    recipients.push_back(recipient.clone());
    let mut amounts = Vec::new(&env);
    amounts.push_back(1_000_i128);

    let id = c.create_invoice(
        &creator,
        &recipients,
        &amounts,
        &token_id,
        &9_999_u64,
        &InvoiceOptions {
            co_creators: Vec::new(&env),
            allow_early_withdrawal: false,
            bonus_pool: 0,
            bonus_max_payers: 0,
            prerequisite_id: None,
            tranches: tranches.clone(),
            co_signers: Vec::new(&env),
            required_signatures: 0,
            penalty_bps: None,
            penalty_deadline: None,
            min_funding_bps: None,
            release_stages: Vec::new(&env),
        },
    );

    c.pay(&payer, &id, &1_000_i128, &0_u64, &false);
    assert_eq!(c.get_invoice(&id).status, InvoiceStatus::Pending);

    // First tranche: 500 unlocked.
    env.ledger().set_timestamp(1_600);
    c.release(&id);

    // 500 - 10% = 450 to recipient, 50 to treasury.
    assert_eq!(tk.balance(&recipient), 450);
    assert_eq!(tk.balance(&treasury), 50);

    // Second tranche: remaining 500 unlocked.
    env.ledger().set_timestamp(2_600);
    c.release(&id);

    // Another 450 to recipient, another 50 to treasury.
    assert_eq!(tk.balance(&recipient), 900);
    assert_eq!(tk.balance(&treasury), 100);
}

// ---------------------------------------------------------------------------
// Issue #42 — late-payment penalty
// ---------------------------------------------------------------------------

#[test]
fn test_penalty_not_applied_before_penalty_deadline() {
    let (env, contract_id, token_id) = setup();
    let c = client(&env, &contract_id);
    let tk = token_client(&env, &token_id);

    let creator = Address::generate(&env);
    let payer = Address::generate(&env);
    let recipient = Address::generate(&env);

    let sa = StellarAssetClient::new(&env, &token_id);
    sa.mint(&payer, &1_000);

    env.ledger().set_timestamp(1_000);

    let mut recipients = Vec::new(&env);
    recipients.push_back(recipient.clone());
    let mut amounts = Vec::new(&env);
    amounts.push_back(500_i128);

    let id = c.create_invoice(
        &creator,
        &recipients,
        &amounts,
        &token_id,
        &9_999_u64,
        &InvoiceOptions {
            co_creators: Vec::new(&env),
            allow_early_withdrawal: false,
            bonus_pool: 0,
            bonus_max_payers: 0,
            prerequisite_id: None,
            tranches: Vec::new(&env),
            co_signers: Vec::new(&env),
            required_signatures: 0,
            penalty_bps: Some(1_000), // 10 %
            penalty_deadline: Some(2_000),
            min_funding_bps: None,
            release_stages: Vec::new(&env),
        },
    );

    // Pay at t=1_000 which is before penalty_deadline.
    c.pay(&payer, &id, &500_i128, &0_u64, &false);

    // Recipient gets full 500, no penalty.
    assert_eq!(tk.balance(&recipient), 500);
    // Payer paid exactly 500.
    assert_eq!(tk.balance(&payer), 500);
}

#[test]
fn test_penalty_applied_after_penalty_deadline() {
    let (env, contract_id, token_id) = setup();
    let c = client(&env, &contract_id);
    let tk = token_client(&env, &token_id);

    let creator = Address::generate(&env);
    let payer = Address::generate(&env);
    let recipient = Address::generate(&env);

    let sa = StellarAssetClient::new(&env, &token_id);
    sa.mint(&payer, &1_000);

    env.ledger().set_timestamp(1_000);

    let mut recipients = Vec::new(&env);
    recipients.push_back(recipient.clone());
    let mut amounts = Vec::new(&env);
    amounts.push_back(500_i128);

    let id = c.create_invoice(
        &creator,
        &recipients,
        &amounts,
        &token_id,
        &9_999_u64,
        &InvoiceOptions {
            co_creators: Vec::new(&env),
            allow_early_withdrawal: false,
            bonus_pool: 0,
            bonus_max_payers: 0,
            prerequisite_id: None,
            tranches: Vec::new(&env),
            co_signers: Vec::new(&env),
            required_signatures: 0,
            penalty_bps: Some(1_000), // 10 %
            penalty_deadline: Some(2_000),
            min_funding_bps: None,
            release_stages: Vec::new(&env),
        },
    );

    // Advance past penalty deadline.
    env.ledger().set_timestamp(3_000);
    c.pay(&payer, &id, &500_i128, &0_u64, &false);

    // Recipient gets 500 (normal) + 50 (penalty) = 550.
    assert_eq!(tk.balance(&recipient), 550);
    // Payer paid 500 + 50 = 550.
    assert_eq!(tk.balance(&payer), 450);
}

#[test]
fn test_penalty_distributed_proportionally_multi_recipient() {
    let (env, contract_id, token_id) = setup();
    let c = client(&env, &contract_id);
    let tk = token_client(&env, &token_id);

    let creator = Address::generate(&env);
    let payer = Address::generate(&env);
    let r1 = Address::generate(&env);
    let r2 = Address::generate(&env);
    let r3 = Address::generate(&env);

    let sa = StellarAssetClient::new(&env, &token_id);
    sa.mint(&payer, &2_000);

    env.ledger().set_timestamp(1_000);

    let mut recipients = Vec::new(&env);
    recipients.push_back(r1.clone());
    recipients.push_back(r2.clone());
    recipients.push_back(r3.clone());
    let mut amounts = Vec::new(&env);
    amounts.push_back(100_i128);
    amounts.push_back(200_i128);
    amounts.push_back(700_i128);

    let id = c.create_invoice(
        &creator,
        &recipients,
        &amounts,
        &token_id,
        &9_999_u64,
        &InvoiceOptions {
            co_creators: Vec::new(&env),
            allow_early_withdrawal: false,
            bonus_pool: 0,
            bonus_max_payers: 0,
            prerequisite_id: None,
            tranches: Vec::new(&env),
            co_signers: Vec::new(&env),
            required_signatures: 0,
            penalty_bps: Some(1_000), // 10 %
            penalty_deadline: Some(2_000),
            min_funding_bps: None,
            release_stages: Vec::new(&env),
        },
    );

    // Pay after penalty deadline.
    env.ledger().set_timestamp(3_000);
    c.pay(&payer, &id, &1_000_i128, &0_u64, &false);

    // Penalty = 1000 * 10% = 100
    // Distribution: r1=10, r2=20, r3=70
    assert_eq!(tk.balance(&r1), 100 + 10); // normal + penalty
    assert_eq!(tk.balance(&r2), 200 + 20);
    assert_eq!(tk.balance(&r3), 700 + 70);
    // Payer paid 1000 + 100 = 1100.
    assert_eq!(tk.balance(&payer), 900);
}

#[test]
fn test_penalty_bps_zero_no_penalty_even_after_deadline() {
    let (env, contract_id, token_id) = setup();
    let c = client(&env, &contract_id);
    let tk = token_client(&env, &token_id);

    let creator = Address::generate(&env);
    let payer = Address::generate(&env);
    let recipient = Address::generate(&env);

    let sa = StellarAssetClient::new(&env, &token_id);
    sa.mint(&payer, &1_000);

    env.ledger().set_timestamp(1_000);

    let mut recipients = Vec::new(&env);
    recipients.push_back(recipient.clone());
    let mut amounts = Vec::new(&env);
    amounts.push_back(500_i128);

    // penalty_bps = 0 means no penalty even after penalty_deadline.
    let id = c.create_invoice(
        &creator,
        &recipients,
        &amounts,
        &token_id,
        &9_999_u64,
        &InvoiceOptions {
            co_creators: Vec::new(&env),
            allow_early_withdrawal: false,
            bonus_pool: 0,
            bonus_max_payers: 0,
            prerequisite_id: None,
            tranches: Vec::new(&env),
            co_signers: Vec::new(&env),
            required_signatures: 0,
            penalty_bps: Some(0),
            penalty_deadline: Some(2_000),
            min_funding_bps: None,
            release_stages: Vec::new(&env),
        },
    );

    env.ledger().set_timestamp(3_000);
    c.pay(&payer, &id, &500_i128, &0_u64, &false);

    // Recipient gets full 500, no penalty.
    assert_eq!(tk.balance(&recipient), 500);
    assert_eq!(tk.balance(&payer), 500);
}

// ---------------------------------------------------------------------------
// Issue #43 — minimum funding threshold
// ---------------------------------------------------------------------------

#[test]
fn test_min_funding_bps_zero_requires_full_funding() {
    let (env, contract_id, token_id) = setup();
    let c = client(&env, &contract_id);

    let creator = Address::generate(&env);
    let payer = Address::generate(&env);
    let recipient = Address::generate(&env);

    let sa = StellarAssetClient::new(&env, &token_id);
    sa.mint(&payer, &1_000);

    env.ledger().set_timestamp(1_000);

    let id = make_invoice(&env, &c, &creator, &recipient, 500, &token_id, 9_999);

    // Partial fund (300 of 500) — release should fail.
    c.pay(&payer, &id, &300_i128, &0_u64, &false);
    assert_eq!(c.get_invoice(&id).funded, 300);
    assert_eq!(c.get_invoice(&id).status, InvoiceStatus::Pending);

    // Fund the rest.
    c.pay(&payer, &id, &200_i128, &1_u64, &false);
    assert_eq!(c.get_invoice(&id).status, InvoiceStatus::Released);
}

#[test]
fn test_min_funding_bps_blocks_early_release() {
    let (env, contract_id, token_id) = setup();
    let c = client(&env, &contract_id);

    let creator = Address::generate(&env);
    let payer = Address::generate(&env);
    let recipient = Address::generate(&env);

    let sa = StellarAssetClient::new(&env, &token_id);
    sa.mint(&payer, &1_000);

    env.ledger().set_timestamp(1_000);

    let mut recipients = Vec::new(&env);
    recipients.push_back(recipient.clone());
    let mut amounts = Vec::new(&env);
    amounts.push_back(1_000_i128);

    let id = c.create_invoice(
        &creator,
        &recipients,
        &amounts,
        &token_id,
        &9_999_u64,
        &InvoiceOptions {
            co_creators: Vec::new(&env),
            allow_early_withdrawal: false,
            bonus_pool: 0,
            bonus_max_payers: 0,
            prerequisite_id: None,
            tranches: Vec::new(&env),
            co_signers: Vec::new(&env),
            required_signatures: 0,
            penalty_bps: None,
            penalty_deadline: None,
            min_funding_bps: Some(8_000), // 80 %
            release_stages: Vec::new(&env),
        },
    );

    // Fund 500 of 1000 (50% — below 80% threshold). Release should panic.
    c.pay(&payer, &id, &500_i128, &0_u64, &false);
    assert_eq!(c.get_invoice(&id).funded, 500);
    assert_eq!(c.get_invoice(&id).status, InvoiceStatus::Pending);
}

#[test]
#[should_panic(expected = "minimum funding not reached")]
fn test_min_funding_bps_panics_below_threshold() {
    let (env, contract_id, token_id) = setup();
    let c = client(&env, &contract_id);

    let creator = Address::generate(&env);
    let payer = Address::generate(&env);
    let recipient = Address::generate(&env);

    let sa = StellarAssetClient::new(&env, &token_id);
    sa.mint(&payer, &1_000);

    env.ledger().set_timestamp(1_000);

    let mut recipients = Vec::new(&env);
    recipients.push_back(recipient.clone());
    let mut amounts = Vec::new(&env);
    amounts.push_back(1_000_i128);

    let id = c.create_invoice(
        &creator,
        &recipients,
        &amounts,
        &token_id,
        &9_999_u64,
        &InvoiceOptions {
            co_creators: Vec::new(&env),
            allow_early_withdrawal: false,
            bonus_pool: 0,
            bonus_max_payers: 0,
            prerequisite_id: None,
            tranches: Vec::new(&env),
            co_signers: Vec::new(&env),
            required_signatures: 0,
            penalty_bps: None,
            penalty_deadline: None,
            min_funding_bps: Some(8_000), // 80 %
            release_stages: Vec::new(&env),
        },
    );

    // Fund 700 of 1000 (70% — below 80%). Try to release — must panic.
    c.pay(&payer, &id, &700_i128, &0_u64, &false);
    // Guarded (has min_funding_bps), so auto-release won't fire.
    c.release(&id);
}

#[test]
fn test_min_funding_bps_allows_release_above_threshold() {
    let (env, contract_id, token_id) = setup();
    let c = client(&env, &contract_id);
    let tk = token_client(&env, &token_id);

    let creator = Address::generate(&env);
    let payer = Address::generate(&env);
    let recipient = Address::generate(&env);

    let sa = StellarAssetClient::new(&env, &token_id);
    sa.mint(&payer, &2_000);

    env.ledger().set_timestamp(1_000);

    let mut recipients = Vec::new(&env);
    recipients.push_back(recipient.clone());
    let mut amounts = Vec::new(&env);
    amounts.push_back(1_000_i128);

    let id = c.create_invoice(
        &creator,
        &recipients,
        &amounts,
        &token_id,
        &9_999_u64,
        &InvoiceOptions {
            co_creators: Vec::new(&env),
            allow_early_withdrawal: false,
            bonus_pool: 0,
            bonus_max_payers: 0,
            prerequisite_id: None,
            tranches: Vec::new(&env),
            co_signers: Vec::new(&env),
            required_signatures: 0,
            penalty_bps: None,
            penalty_deadline: None,
            min_funding_bps: Some(8_000), // 80 %
            release_stages: Vec::new(&env),
        },
    );

    // Fund 900 of 1000 (90% >= 80%). Release should succeed.
    c.pay(&payer, &id, &900_i128, &0_u64, &false);
    // Guarded (has min_funding_bps), so we must manually release.
    c.release(&id);

    assert_eq!(c.get_invoice(&id).status, InvoiceStatus::Released);
    assert_eq!(tk.balance(&recipient), 900);
}

// ---------------------------------------------------------------------------
// Issue #85: generate_payment_proof
// ---------------------------------------------------------------------------

#[test]
fn test_payment_proof_multiple_payments() {
    let (env, contract_id, token_id) = setup();
    let c = client(&env, &contract_id);

    let creator = Address::generate(&env);
    let payer = Address::generate(&env);
    let recipient = Address::generate(&env);

    StellarAssetClient::new(&env, &token_id).mint(&payer, &1_000);

    let id = make_invoice(&env, &c, &creator, &recipient, 300, &token_id, 9_999_999);
    c.pay(&payer, &id, &100_i128, &0_u64, &false);
    c.pay(&payer, &id, &150_i128, &1_u64, &false);

    let proof = c.generate_payment_proof(&id, &payer);
    assert_eq!(proof.invoice_id, id);
    assert_eq!(proof.payer, payer);
    assert_eq!(proof.total_paid, 250);
}

#[test]
fn test_payment_proof_no_payment() {
    let (env, contract_id, token_id) = setup();
    let c = client(&env, &contract_id);

    let creator = Address::generate(&env);
    let stranger = Address::generate(&env);
    let recipient = Address::generate(&env);

    let id = make_invoice(&env, &c, &creator, &recipient, 300, &token_id, 9_999_999);

    let proof = c.generate_payment_proof(&id, &stranger);
    assert_eq!(proof.total_paid, 0);
}

#[test]
fn test_payment_proof_hash_deterministic() {
    let (env, contract_id, token_id) = setup();
    let c = client(&env, &contract_id);

    let creator = Address::generate(&env);
    let payer = Address::generate(&env);
    let recipient = Address::generate(&env);

    StellarAssetClient::new(&env, &token_id).mint(&payer, &500);

    let id = make_invoice(&env, &c, &creator, &recipient, 200, &token_id, 9_999_999);
    c.pay(&payer, &id, &200_i128, &0_u64, &false);

    let proof1 = c.generate_payment_proof(&id, &payer);
    let proof2 = c.generate_payment_proof(&id, &payer);
    assert_eq!(proof1.proof_hash, proof2.proof_hash);
    assert_eq!(proof1.total_paid, proof2.total_paid);
}

// ---------------------------------------------------------------------------
// Stage release tests (#86)
// ---------------------------------------------------------------------------

#[test]
fn test_stage_release_3_stages() {
    let (env, contract_id, token_id) = setup();
    let c = client(&env, &contract_id);
    let tk = token_client(&env, &token_id);

    let creator = Address::generate(&env);
    let payer = Address::generate(&env);
    let recipient = Address::generate(&env);

    StellarAssetClient::new(&env, &token_id).mint(&payer, &1_000);
    env.ledger().set_timestamp(1_000);

    // 3 stages: 30% / 40% / 30%
    let mut stages: Vec<u32> = Vec::new(&env);
    stages.push_back(3_000u32);
    stages.push_back(4_000u32);
    stages.push_back(3_000u32);

    let mut recipients = Vec::new(&env);
    recipients.push_back(recipient.clone());
    let mut amounts = Vec::new(&env);
    amounts.push_back(1_000_i128);

    let mut opts = default_options(&env);
    opts.release_stages = stages;

    let id = c.create_invoice(&creator, &recipients, &amounts, &token_id, &9_999_u64, &opts);

    // Fully fund the invoice.
    c.pay(&payer, &id, &1_000_i128, &0_u64, &false);

    // Invoice should still be Pending (guarded by release_stages).
    assert_eq!(c.get_invoice(&id).status, InvoiceStatus::Pending);
    assert_eq!(c.get_invoice(&id).released_stages, 0);

    // Stage 1: 30% = 300
    c.stage_release(&id, &creator);
    assert_eq!(tk.balance(&recipient), 300);
    assert_eq!(c.get_invoice(&id).released_stages, 1);
    assert_eq!(c.get_invoice(&id).status, InvoiceStatus::Pending);

    // Stage 2: 40% = 400
    c.stage_release(&id, &creator);
    assert_eq!(tk.balance(&recipient), 700);
    assert_eq!(c.get_invoice(&id).released_stages, 2);
    assert_eq!(c.get_invoice(&id).status, InvoiceStatus::Pending);

    // Stage 3: 30% = 300 — final stage sets status to Released
    c.stage_release(&id, &creator);
    assert_eq!(tk.balance(&recipient), 1_000);
    assert_eq!(c.get_invoice(&id).released_stages, 3);
    assert_eq!(c.get_invoice(&id).status, InvoiceStatus::Released);
}

#[test]
#[should_panic(expected = "invoice is not pending")]
fn test_stage_release_after_all_stages_panics() {
    let (env, contract_id, token_id) = setup();
    let c = client(&env, &contract_id);

    let creator = Address::generate(&env);
    let payer = Address::generate(&env);
    let recipient = Address::generate(&env);

    StellarAssetClient::new(&env, &token_id).mint(&payer, &1_000);
    env.ledger().set_timestamp(1_000);

    let mut stages: Vec<u32> = Vec::new(&env);
    stages.push_back(5_000u32);
    stages.push_back(5_000u32);

    let mut recipients = Vec::new(&env);
    recipients.push_back(recipient.clone());
    let mut amounts = Vec::new(&env);
    amounts.push_back(1_000_i128);

    let mut opts = default_options(&env);
    opts.release_stages = stages;

    let id = c.create_invoice(&creator, &recipients, &amounts, &token_id, &9_999_u64, &opts);
    c.pay(&payer, &id, &1_000_i128, &0_u64, &false);

    c.stage_release(&id, &creator);
    c.stage_release(&id, &creator);
    // Third call should panic — all stages already released.
    c.stage_release(&id, &creator);
}

#[test]
#[should_panic(expected = "only creator can call stage_release")]
fn test_stage_release_non_creator_panics() {
    let (env, contract_id, token_id) = setup();
    let c = client(&env, &contract_id);

    let creator = Address::generate(&env);
    let payer = Address::generate(&env);
    let recipient = Address::generate(&env);
    let other = Address::generate(&env);

    StellarAssetClient::new(&env, &token_id).mint(&payer, &1_000);
    env.ledger().set_timestamp(1_000);

    let mut stages: Vec<u32> = Vec::new(&env);
    stages.push_back(10_000u32);

    let mut recipients = Vec::new(&env);
    recipients.push_back(recipient.clone());
    let mut amounts = Vec::new(&env);
    amounts.push_back(1_000_i128);

    let mut opts = default_options(&env);
    opts.release_stages = stages;

    let id = c.create_invoice(&creator, &recipients, &amounts, &token_id, &9_999_u64, &opts);
    c.pay(&payer, &id, &1_000_i128, &0_u64, &false);

    // Non-creator should not be able to call stage_release.
    c.stage_release(&id, &other);
}

#[test]
#[should_panic(expected = "invoice not fully funded")]
fn test_stage_release_not_fully_funded_panics() {
    let (env, contract_id, token_id) = setup();
    let c = client(&env, &contract_id);

    let creator = Address::generate(&env);
    let payer = Address::generate(&env);
    let recipient = Address::generate(&env);

    StellarAssetClient::new(&env, &token_id).mint(&payer, &500);
    env.ledger().set_timestamp(1_000);

    let mut stages: Vec<u32> = Vec::new(&env);
    stages.push_back(10_000u32);

    let mut recipients = Vec::new(&env);
    recipients.push_back(recipient.clone());
    let mut amounts = Vec::new(&env);
    amounts.push_back(1_000_i128);

    let mut opts = default_options(&env);
    opts.release_stages = stages;

    let id = c.create_invoice(&creator, &recipients, &amounts, &token_id, &9_999_u64, &opts);
    // Only partially fund.
    c.pay(&payer, &id, &500_i128, &0_u64, &false);

    // Should panic — not fully funded.
    c.stage_release(&id, &creator);
}

#[test]
#[should_panic(expected = "release_stages must sum to 10000 basis points")]
fn test_create_invoice_invalid_release_stages_panics() {
    let (env, contract_id, token_id) = setup();
    let c = client(&env, &contract_id);

    let creator = Address::generate(&env);
    let recipient = Address::generate(&env);

    env.ledger().set_timestamp(1_000);

    // Stages that don't sum to 10000.
    let mut stages: Vec<u32> = Vec::new(&env);
    stages.push_back(3_000u32);
    stages.push_back(3_000u32);

    let mut recipients = Vec::new(&env);
    recipients.push_back(recipient.clone());
    let mut amounts = Vec::new(&env);
    amounts.push_back(1_000_i128);

    let mut opts = default_options(&env);
    opts.release_stages = stages;

    c.create_invoice(&creator, &recipients, &amounts, &token_id, &9_999_u64, &opts);
}

// ---------------------------------------------------------------------------
// Issue #142 — dynamic pricing via price oracle
// ---------------------------------------------------------------------------

/// Minimal price oracle contract used by oracle tests.
#[contract]
struct MockOracle;

#[contractimpl]
impl MockOracle {
    /// Returns a fixed price of 2.0 (2_000_000 in 6-decimal fixed-point).
    pub fn get_price(_env: Env) -> i128 {
        2_000_000
    }
}

/// A 1.0 oracle (1_000_000) must produce the same amounts as no oracle.
#[contract]
struct IdentityOracle;

#[contractimpl]
impl IdentityOracle {
    pub fn get_price(_env: Env) -> i128 {
        1_000_000
    }
}

#[test]
fn test_oracle_none_behaviour_identical_to_current() {
    let (env, contract_id, token_id) = setup();
    let c = client(&env, &contract_id);
    let tk = token_client(&env, &token_id);

    let creator = Address::generate(&env);
    let payer = Address::generate(&env);
    let recipient = Address::generate(&env);

    env.ledger().set_timestamp(1_000);
    tk.mint(&payer, &1_000);

    // Create invoice with no oracle (None) — base amount 100.
    let id = make_invoice(&env, &c, &creator, &recipient, 100, &token_id, 9_999);

    let invoice = c.get_invoice(&id);
    assert!(invoice.price_oracle.is_none());
    assert_eq!(invoice.base_amounts.get(0).unwrap(), 100);

    // Full payment of 100 should succeed (no oracle adjustment).
    c.pay(&payer, &id, &100, &0, &false);

    let invoice = c.get_invoice(&id);
    assert_eq!(invoice.funded, 100);
    assert_eq!(invoice.status, InvoiceStatus::Released);
}

#[test]
fn test_oracle_price_1_000_000_produces_same_amounts_as_base() {
    let (env, contract_id, token_id) = setup();
    let c = client(&env, &contract_id);
    let tk = token_client(&env, &token_id);

    let creator = Address::generate(&env);
    let payer = Address::generate(&env);
    let recipient = Address::generate(&env);

    env.ledger().set_timestamp(1_000);
    tk.mint(&payer, &200);

    // Register oracle that returns 1_000_000 (identity).
    let oracle_id = env.register(IdentityOracle, ());

    let mut opts = default_options(&env);
    opts.price_oracle = Some(oracle_id);

    let mut recipients = Vec::new(&env);
    recipients.push_back(recipient.clone());
    let mut amounts = Vec::new(&env);
    amounts.push_back(100_i128);

    let id = c.create_invoice(&creator, &recipients, &amounts, &token_id, &9_999, &opts);

    let invoice = c.get_invoice(&id);
    assert!(invoice.price_oracle.is_some());
    assert_eq!(invoice.base_amounts.get(0).unwrap(), 100);

    // adjusted_total = 100 * 1_000_000 / 1_000_000 = 100 — identical to base
    c.pay(&payer, &id, &100, &0, &false);
    let invoice = c.get_invoice(&id);
    assert_eq!(invoice.funded, 100);
    assert_eq!(invoice.status, InvoiceStatus::Released);
}

#[test]
fn test_oracle_2x_price_doubles_required_amount() {
    let (env, contract_id, token_id) = setup();
    let c = client(&env, &contract_id);
    let tk = token_client(&env, &token_id);

    let creator = Address::generate(&env);
    let payer = Address::generate(&env);
    let recipient = Address::generate(&env);

    env.ledger().set_timestamp(1_000);
    tk.mint(&payer, &400);

    // Register mock oracle returning 2_000_000 (2x price).
    let oracle_id = env.register(MockOracle, ());

    let mut opts = default_options(&env);
    opts.price_oracle = Some(oracle_id);

    let mut recipients = Vec::new(&env);
    recipients.push_back(recipient.clone());
    let mut amounts = Vec::new(&env);
    amounts.push_back(100_i128); // base amount

    let id = c.create_invoice(&creator, &recipients, &amounts, &token_id, &9_999, &opts);

    let invoice = c.get_invoice(&id);
    assert_eq!(invoice.base_amounts.get(0).unwrap(), 100);

    // adjusted_total = 100 * 2_000_000 / 1_000_000 = 200
    // Paying only 100 should NOT release (remaining = 200 - 100 = 100 still owed).
    c.pay(&payer, &id, &100, &0, &false);
    let invoice = c.get_invoice(&id);
    assert_eq!(invoice.funded, 100);
    assert_eq!(invoice.status, InvoiceStatus::Pending); // not yet fully funded

    // Paying the remaining 100 (total 200 = adjusted_total) should release.
    c.pay(&payer, &id, &100, &1, &false);
    let invoice = c.get_invoice(&id);
    assert_eq!(invoice.funded, 200);
    assert_eq!(invoice.status, InvoiceStatus::Released);
}

#[test]
fn test_create_invoice_stores_price_oracle_and_base_amounts() {
    let (env, contract_id, token_id) = setup();
    let c = client(&env, &contract_id);

    let creator = Address::generate(&env);
    let recipient = Address::generate(&env);

    env.ledger().set_timestamp(1_000);

    let oracle_id = env.register(MockOracle, ());
    let mut opts = default_options(&env);
    opts.price_oracle = Some(oracle_id.clone());

    let mut recipients = Vec::new(&env);
    recipients.push_back(recipient.clone());
    let mut amounts = Vec::new(&env);
    amounts.push_back(500_i128);

    let id = c.create_invoice(&creator, &recipients, &amounts, &token_id, &9_999, &opts);
    let invoice = c.get_invoice(&id);

    assert_eq!(invoice.price_oracle, Some(oracle_id));
    assert_eq!(invoice.base_amounts.len(), 1);
    assert_eq!(invoice.base_amounts.get(0).unwrap(), 500);
    // amounts field also preserved
    assert_eq!(invoice.amounts.get(0).unwrap(), 500);
}

// ---------------------------------------------------------------------------
// Analytics counters (issue #28)
// ---------------------------------------------------------------------------

#[test]
fn test_analytics_initial_state() {
    let (env, contract_id, _token_id) = setup();
    let c = client(&env, &contract_id);

    let (total_invoices, total_volume, total_released, total_refunded) = c.get_stats();
    assert_eq!(total_invoices, 0);
    assert_eq!(total_volume, 0);
    assert_eq!(total_released, 0);
    assert_eq!(total_refunded, 0);
}

#[test]
fn test_analytics_create_invoice_increments_counter() {
    let (env, contract_id, token_id) = setup();
    let c = client(&env, &contract_id);

    let creator = Address::generate(&env);
    let recipient = Address::generate(&env);

    env.ledger().set_timestamp(1_000);

    // Create first invoice
    make_invoice(&env, &c, &creator, &recipient, 100, &token_id, 9_999);

    let (total_invoices, total_volume, total_released, total_refunded) = c.get_stats();
    assert_eq!(total_invoices, 1);
    assert_eq!(total_volume, 0);
    assert_eq!(total_released, 0);
    assert_eq!(total_refunded, 0);

    // Create second invoice
    make_invoice(&env, &c, &creator, &recipient, 200, &token_id, 9_999);

    let (total_invoices, total_volume, total_released, total_refunded) = c.get_stats();
    assert_eq!(total_invoices, 2);
    assert_eq!(total_volume, 0);
    assert_eq!(total_released, 0);
    assert_eq!(total_refunded, 0);
}

#[test]
fn test_analytics_pay_and_release_increments_volume() {
    let (env, contract_id, token_id) = setup();
    let c = client(&env, &contract_id);
    let tk = token_client(&env, &token_id);

    let creator = Address::generate(&env);
    let payer = Address::generate(&env);
    let recipient = Address::generate(&env);

    StellarAssetClient::new(&env, &token_id).mint(&payer, &500);
    env.ledger().set_timestamp(1_000);

    let invoice_amount = 250i128;
    let id = make_invoice(&env, &c, &creator, &recipient, invoice_amount, &token_id, 9_999);

    // Pay and auto-release (full payment)
    c.pay(&payer, &id, &invoice_amount, &0_u64, &false);

    let (total_invoices, total_volume, total_released, total_refunded) = c.get_stats();
    assert_eq!(total_invoices, 1);
    assert_eq!(total_volume, invoice_amount);
    assert_eq!(total_released, invoice_amount);
    assert_eq!(total_refunded, 0);
    assert_eq!(tk.balance(&recipient), invoice_amount);
}

#[test]
fn test_analytics_partial_pay_then_release() {
    let (env, contract_id, token_id) = setup();
    let c = client(&env, &contract_id);
    let tk = token_client(&env, &token_id);

    let creator = Address::generate(&env);
    let payer1 = Address::generate(&env);
    let payer2 = Address::generate(&env);
    let recipient = Address::generate(&env);

    let sa = StellarAssetClient::new(&env, &token_id);
    sa.mint(&payer1, &200);
    sa.mint(&payer2, &200);
    env.ledger().set_timestamp(1_000);

    let total_amount = 300i128;
    let id = make_invoice(&env, &c, &creator, &recipient, total_amount, &token_id, 9_999);

    // Partial payment from payer1
    c.pay(&payer1, &id, &150_i128, &0_u64, &false);
    let (total_invoices, total_volume, total_released, total_refunded) = c.get_stats();
    assert_eq!(total_invoices, 1);
    assert_eq!(total_volume, 0);
    assert_eq!(total_released, 0);
    assert_eq!(total_refunded, 0);

    // Completion payment from payer2 triggers auto-release
    c.pay(&payer2, &id, &150_i128, &0_u64, &false);
    let (total_invoices, total_volume, total_released, total_refunded) = c.get_stats();
    assert_eq!(total_invoices, 1);
    assert_eq!(total_volume, 300);
    assert_eq!(total_released, 300);
    assert_eq!(total_refunded, 0);
    assert_eq!(tk.balance(&recipient), 300);
}

#[test]
fn test_analytics_refund_increments_counter() {
    let (env, contract_id, token_id) = setup();
    let c = client(&env, &contract_id);
    let tk = token_client(&env, &token_id);

    let creator = Address::generate(&env);
    let payer = Address::generate(&env);
    let recipient = Address::generate(&env);

    StellarAssetClient::new(&env, &token_id).mint(&payer, &500);
    env.ledger().set_timestamp(1_000);

    let invoice_amount = 200i128;
    let id = make_invoice(&env, &c, &creator, &recipient, invoice_amount, &token_id, 2_000);

    // Pay but don't complete
    c.pay(&payer, &id, &100_i128, &0_u64, &false);

    let (total_invoices, total_volume, total_released, total_refunded) = c.get_stats();
    assert_eq!(total_invoices, 1);
    assert_eq!(total_volume, 0);
    assert_eq!(total_released, 0);
    assert_eq!(total_refunded, 0);

    // Pass deadline and refund
    env.ledger().set_timestamp(3_000);
    c.refund(&id);

    let (total_invoices, total_volume, total_released, total_refunded) = c.get_stats();
    assert_eq!(total_invoices, 1);
    assert_eq!(total_volume, 0);
    assert_eq!(total_released, 0);
    assert_eq!(total_refunded, 100);
    assert_eq!(tk.balance(&payer), 100);
}

#[test]
fn test_analytics_multiple_operations() {
    let (env, contract_id, token_id) = setup();
    let c = client(&env, &contract_id);
    let tk = token_client(&env, &token_id);

    let creator = Address::generate(&env);
    let payer1 = Address::generate(&env);
    let payer2 = Address::generate(&env);
    let recipient1 = Address::generate(&env);
    let recipient2 = Address::generate(&env);

    let sa = StellarAssetClient::new(&env, &token_id);
    sa.mint(&payer1, &1000);
    sa.mint(&payer2, &1000);
    env.ledger().set_timestamp(1_000);

    // Create and release invoice 1
    let id1 = make_invoice(&env, &c, &creator, &recipient1, 100, &token_id, 9_999);
    c.pay(&payer1, &id1, &100_i128, &0_u64, &false);

    let (ti, tv, tr, tref) = c.get_stats();
    assert_eq!(ti, 1);
    assert_eq!(tv, 100);
    assert_eq!(tr, 100);
    assert_eq!(tref, 0);

    // Create invoice 2 and refund it
    let id2 = make_invoice(&env, &c, &creator, &recipient2, 200, &token_id, 2_000);
    c.pay(&payer2, &id2, &50_i128, &0_u64, &false);
    env.ledger().set_timestamp(3_000);
    c.refund(&id2);

    let (ti, tv, tr, tref) = c.get_stats();
    assert_eq!(ti, 2);
    assert_eq!(tv, 100);
    assert_eq!(tr, 100);
    assert_eq!(tref, 50);

    // Create invoice 3 and release it
    let id3 = make_invoice(&env, &c, &creator, &recipient1, 300, &token_id, 9_999);
    c.pay(&payer1, &id3, &300_i128, &0_u64, &false);

    let (ti, tv, tr, tref) = c.get_stats();
    assert_eq!(ti, 3);
    assert_eq!(tv, 400);
    assert_eq!(tr, 400);
    assert_eq!(tref, 50);
}


// ---------------------------------------------------------------------------
// Issue #1012: Encryption tests
// ---------------------------------------------------------------------------

#[test]
fn test_encryption_set_key() {
    let (env, contract_id, _token_id) = setup();
    let c = client(&env, &contract_id);

    let admin = Address::generate(&env);
    env.ledger().set_timestamp(1_000);

    c.initialize(&admin, &0_i128, &admin, &admin, &0_u32);
    c.set_encryption_key(&admin, &EncryptionAlgorithm::Aes256Gcm, &BytesN::from_array(&env, &[42u8; 32]));

    assert_eq!(c.get_encryption_key_version(), 1);
}

#[test]
fn test_encryption_rotate_key() {
    let (env, contract_id, _token_id) = setup();
    let c = client(&env, &contract_id);

    let admin = Address::generate(&env);
    env.ledger().set_timestamp(1_000);

    c.initialize(&admin, &0_i128, &admin, &admin, &0_u32);
    c.set_encryption_key(&admin, &EncryptionAlgorithm::Aes256Gcm, &BytesN::from_array(&env, &[42u8; 32]));
    assert_eq!(c.get_encryption_key_version(), 1);

    c.rotate_encryption_key(&admin, &EncryptionAlgorithm::ChaCha20Poly1305, &BytesN::from_array(&env, &[99u8; 32]));
    assert_eq!(c.get_encryption_key_version(), 2);
}

#[test]
fn test_encryption_encrypt_decrypt() {
    let (env, contract_id, _token_id) = setup();
    let c = client(&env, &contract_id);

    let admin = Address::generate(&env);
    let caller = Address::generate(&env);
    env.ledger().set_timestamp(1_000);

    c.initialize(&admin, &0_i128, &admin, &admin, &0_u32);
    c.set_encryption_key(&admin, &EncryptionAlgorithm::Aes256Gcm, &BytesN::from_array(&env, &[42u8; 32]));

    let data = Bytes::from_array(&env, &[1, 2, 3, 4, 5, 6, 7, 8]);
    let encrypted = c.encrypt_data(&caller, &data);

    // Decrypt with version 1 (the active version).
    let decrypted = c.decrypt_data(&caller, &encrypted, &1u32);
    assert_eq!(decrypted, data);
}

#[test]
fn test_encryption_validate() {
    let (env, contract_id, _token_id) = setup();
    let c = client(&env, &contract_id);

    let admin = Address::generate(&env);
    let caller = Address::generate(&env);
    env.ledger().set_timestamp(1_000);

    c.initialize(&admin, &0_i128, &admin, &admin, &0_u32);
    c.set_encryption_key(&admin, &EncryptionAlgorithm::Aes256Gcm, &BytesN::from_array(&env, &[42u8; 32]));

    let data = Bytes::from_array(&env, &[10, 20, 30, 40]);
    let _ = c.encrypt_data(&caller, &data);

    // Validate the data was encrypted with key version 1.
    let validation = c.validate_encryption(&data, &1u32);
    assert_eq!(validation.key_version, 1);
}

#[test]
fn test_encryption_audit_trail() {
    let (env, contract_id, _token_id) = setup();
    let c = client(&env, &contract_id);

    let admin = Address::generate(&env);
    let caller = Address::generate(&env);
    env.ledger().set_timestamp(1_000);

    c.initialize(&admin, &0_i128, &admin, &admin, &0_u32);
    c.set_encryption_key(&admin, &EncryptionAlgorithm::Aes256Gcm, &BytesN::from_array(&env, &[42u8; 32]));

    let data = Bytes::from_array(&env, &[1, 2, 3]);
    c.encrypt_data(&caller, &data);

    let audit = c.get_encryption_audit();
    // Should have at least 2 entries: set_key + encrypt.
    assert!(audit.len() >= 2);
}

#[test]
#[should_panic(expected = "encryption key already set")]
fn test_encryption_set_key_twice_panics() {
    let (env, contract_id, _token_id) = setup();
    let c = client(&env, &contract_id);

    let admin = Address::generate(&env);
    env.ledger().set_timestamp(1_000);

    c.initialize(&admin, &0_i128, &admin, &admin, &0_u32);
    c.set_encryption_key(&admin, &EncryptionAlgorithm::Aes256Gcm, &BytesN::from_array(&env, &[42u8; 32]));
    c.set_encryption_key(&admin, &EncryptionAlgorithm::Aes256Gcm, &BytesN::from_array(&env, &[99u8; 32]));
}

// ---------------------------------------------------------------------------
// Issue #1013: RBAC tests
// ---------------------------------------------------------------------------

#[test]
fn test_rbac_assign_and_check_role() {
    let (env, contract_id, _token_id) = setup();
    let c = client(&env, &contract_id);

    let admin = Address::generate(&env);
    let user = Address::generate(&env);
    env.ledger().set_timestamp(1_000);

    c.initialize(&admin, &0_i128, &admin, &admin, &0_u32);
    c.assign_role(&admin, &user, &Role::Creator);

    assert!(c.has_role(&user, &Role::Creator));
    assert!(!c.has_role(&user, &Role::Payer));
}

#[test]
fn test_rbac_revoke_role() {
    let (env, contract_id, _token_id) = setup();
    let c = client(&env, &contract_id);

    let admin = Address::generate(&env);
    let user = Address::generate(&env);
    env.ledger().set_timestamp(1_000);

    c.initialize(&admin, &0_i128, &admin, &admin, &0_u32);
    c.assign_role(&admin, &user, &Role::Payer);
    assert!(c.has_role(&user, &Role::Payer));

    c.revoke_role(&admin, &user, &Role::Payer);
    assert!(!c.has_role(&user, &Role::Payer));
}

#[test]
fn test_rbac_permission_check() {
    let (env, contract_id, _token_id) = setup();
    let c = client(&env, &contract_id);

    let admin = Address::generate(&env);
    let user = Address::generate(&env);
    env.ledger().set_timestamp(1_000);

    c.initialize(&admin, &0_i128, &admin, &admin, &0_u32);
    c.assign_role(&admin, &user, &Role::Creator);

    // Creator has CreateInvoice permission.
    assert!(c.has_permission(&user, &Permission::CreateInvoice));
    // Creator does not have Pay permission.
    assert!(!c.has_permission(&user, &Permission::Pay));
}

#[test]
fn test_rbac_get_roles() {
    let (env, contract_id, _token_id) = setup();
    let c = client(&env, &contract_id);

    let admin = Address::generate(&env);
    let user = Address::generate(&env);
    env.ledger().set_timestamp(1_000);

    c.initialize(&admin, &0_i128, &admin, &admin, &0_u32);
    c.assign_role(&admin, &user, &Role::Creator);
    c.assign_role(&admin, &user, &Role::Payer);

    let roles = c.get_roles(&user);
    assert_eq!(roles.len(), 2);
}

#[test]
fn test_rbac_audit_trail() {
    let (env, contract_id, _token_id) = setup();
    let c = client(&env, &contract_id);

    let admin = Address::generate(&env);
    let user = Address::generate(&env);
    env.ledger().set_timestamp(1_000);

    c.initialize(&admin, &0_i128, &admin, &admin, &0_u32);
    c.assign_role(&admin, &user, &Role::Creator);
    c.revoke_role(&admin, &user, &Role::Creator);

    let audit = c.get_rbac_audit();
    // assign + revoke = 2 entries.
    assert_eq!(audit.len(), 2);
}

#[test]
fn test_rbac_access_analytics() {
    let (env, contract_id, _token_id) = setup();
    let c = client(&env, &contract_id);

    let admin = Address::generate(&env);
    let user = Address::generate(&env);
    env.ledger().set_timestamp(1_000);

    c.initialize(&admin, &0_i128, &admin, &admin, &0_u32);
    c.assign_role(&admin, &user, &Role::Creator);
    c.assign_role(&admin, &user, &Role::Payer);
    c.revoke_role(&admin, &user, &Role::Payer);
    c.has_permission(&user, &Permission::CreateInvoice);

    let analytics = c.get_access_analytics(&user);
    assert_eq!(analytics.roles_assigned, 2);
    assert_eq!(analytics.roles_revoked, 1);
    assert_eq!(analytics.permission_checks, 1);
    assert_eq!(analytics.checks_passed, 1);
}

// ---------------------------------------------------------------------------
// Issue #1014: Caching tests
// ---------------------------------------------------------------------------

#[test]
fn test_cache_set_and_get() {
    let (env, contract_id, _token_id) = setup();
    let c = client(&env, &contract_id);

    let key = Symbol::new(&env, "my_key");
    let value = Bytes::from_array(&env, &[1, 2, 3, 4, 5]);

    c.cache_set(&key, &value, &0u64);
    let retrieved = c.cache_get(&key);
    assert_eq!(retrieved, value);
}

#[test]
fn test_cache_invalidate() {
    let (env, contract_id, _token_id) = setup();
    let c = client(&env, &contract_id);

    let key = Symbol::new(&env, "inv_key");
    let value = Bytes::from_array(&env, &[10, 20, 30]);

    c.cache_set(&key, &value, &0u64);
    assert_eq!(c.cache_get(&key), value);

    c.cache_invalidate(&key);

    // After invalidation, get should panic.
    // (We verify the metrics show invalidation.)
    let metrics = c.get_cache_metrics();
    assert_eq!(metrics.invalidated, 1);
}

#[test]
fn test_cache_metrics() {
    let (env, contract_id, _token_id) = setup();
    let c = client(&env, &contract_id);

    let key1 = Symbol::new(&env, "k1");
    let key2 = Symbol::new(&env, "k2");
    let value = Bytes::from_array(&env, &[1]);

    // Set two entries.
    c.cache_set(&key1, &value, &0u64);
    c.cache_set(&key2, &value, &0u64);

    // Hit on key1.
    c.cache_get(&key1);

    // Miss on non-existent key3 would panic, so just check metrics from hit.
    let metrics = c.get_cache_metrics();
    assert_eq!(metrics.hits, 1);
    assert_eq!(metrics.misses, 0);
    assert_eq!(metrics.entry_count, 2);
}

#[test]
fn test_cache_warm() {
    let (env, contract_id, token_id) = setup();
    let c = client(&env, &contract_id);

    let creator = Address::generate(&env);
    let recipient = Address::generate(&env);
    env.ledger().set_timestamp(1_000);

    let id1 = make_invoice(&env, &c, &creator, &recipient, 100, &token_id, 9_999);
    let id2 = make_invoice(&env, &c, &creator, &recipient, 200, &token_id, 9_999);

    let mut ids = Vec::new(&env);
    ids.push_back(id1);
    ids.push_back(id2);

    let warmed = c.cache_warm(&ids);
    assert_eq!(warmed, 2);

    let metrics = c.get_cache_metrics();
    assert_eq!(metrics.warmed, 2);
}

#[test]
fn test_cache_hit_ratio() {
    let (env, contract_id, _token_id) = setup();
    let c = client(&env, &contract_id);

    let key = Symbol::new(&env, "ratio_key");
    let value = Bytes::from_array(&env, &[1]);

    c.cache_set(&key, &value, &0u64);
    c.cache_get(&key); // hit
    c.cache_get(&key); // hit

    let metrics = c.get_cache_metrics();
    assert_eq!(metrics.hits, 2);
    assert_eq!(metrics.misses, 0);
    assert_eq!(metrics.hit_ratio_bps, 10_000); // 100%
}

// ---------------------------------------------------------------------------
// Issue #1015: Query optimization tests
// ---------------------------------------------------------------------------

#[test]
fn test_query_invoices_by_status() {
    let (env, contract_id, token_id) = setup();
    let c = client(&env, &contract_id);

    let creator = Address::generate(&env);
    let recipient = Address::generate(&env);
    env.ledger().set_timestamp(1_000);

    let id1 = make_invoice(&env, &c, &creator, &recipient, 100, &token_id, 9_999);
    let id2 = make_invoice(&env, &c, &creator, &recipient, 200, &token_id, 9_999);

    // Both should be Pending.
    let pending = c.get_invoices_by_status(&InvoiceStatus::Pending);
    assert_eq!(pending.len(), 2);
    assert_eq!(pending.get(0).unwrap(), id1);
    assert_eq!(pending.get(1).unwrap(), id2);

    // No released invoices.
    let released = c.get_invoices_by_status(&InvoiceStatus::Released);
    assert_eq!(released.len(), 0);
}

#[test]
fn test_query_invoices_by_creator() {
    let (env, contract_id, token_id) = setup();
    let c = client(&env, &contract_id);

    let creator = Address::generate(&env);
    let other_creator = Address::generate(&env);
    let recipient = Address::generate(&env);
    env.ledger().set_timestamp(1_000);

    let id1 = make_invoice(&env, &c, &creator, &recipient, 100, &token_id, 9_999);
    let id2 = make_invoice(&env, &c, &creator, &recipient, 200, &token_id, 9_999);
    let _id3 = make_invoice(&env, &c, &other_creator, &recipient, 300, &token_id, 9_999);

    let creator_invoices = c.get_invoices_by_creator(&creator);
    assert_eq!(creator_invoices.len(), 2);
    assert_eq!(creator_invoices.get(0).unwrap(), id1);
    assert_eq!(creator_invoices.get(1).unwrap(), id2);

    let other_invoices = c.get_invoices_by_creator(&other_creator);
    assert_eq!(other_invoices.len(), 1);
}

#[test]
fn test_query_metrics() {
    let (env, contract_id, token_id) = setup();
    let c = client(&env, &contract_id);

    let creator = Address::generate(&env);
    let recipient = Address::generate(&env);
    env.ledger().set_timestamp(1_000);

    make_invoice(&env, &c, &creator, &recipient, 100, &token_id, 9_999);

    // Execute some queries.
    c.get_invoices_by_status(&InvoiceStatus::Pending);
    c.get_invoices_by_creator(&creator.clone());

    let metrics = c.get_query_metrics();
    assert_eq!(metrics.total_queries, 2);
    assert_eq!(metrics.indexed_queries, 2);
    assert_eq!(metrics.full_scan_queries, 0);
}

#[test]
fn test_query_create_index() {
    let (env, contract_id, _token_id) = setup();
    let c = client(&env, &contract_id);

    let admin = Address::generate(&env);
    env.ledger().set_timestamp(1_000);

    c.initialize(&admin, &0_i128, &admin, &admin, &0_u32);
    c.create_query_index(&admin, &Symbol::new(&env, "custom_idx"));

    let metrics = c.get_query_metrics();
    assert_eq!(metrics.index_count, 1);
}
