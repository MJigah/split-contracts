use soroban_sdk::{symbol_short, Address, BytesN, Env, Symbol, Vec};

use types::{EncryptionAlgorithm, Role};

/// Emitted when a new invoice is created.
pub fn invoice_created(env: &Env, invoice_id: u64, creator: &Address, total: i128) {
    env.events().publish(
        (symbol_short!("inv_crt"), invoice_id),
        (creator.clone(), total),
    );
}

/// Emitted when a payment is received toward an invoice.
pub fn payment_received(env: &Env, invoice_id: u64, payer: &Address, amount: i128) {
    env.events().publish(
        (symbol_short!("inv_pay"), invoice_id),
        (payer.clone(), amount),
    );
}

/// Emitted when an invoice is fully funded and funds are released.
pub fn invoice_released(env: &Env, invoice_id: u64, recipients: &Vec<Address>) {
    env.events().publish(
        (symbol_short!("inv_rel"), invoice_id),
        recipients.clone(),
    );
}

/// Emitted when an invoice is refunded after deadline.
pub fn invoice_refunded(env: &Env, invoice_id: u64) {
    env.events()
        .publish((symbol_short!("inv_ref"), invoice_id), ());
}

/// Emitted once per payer when their refund is transferred.
pub fn payer_refunded(env: &Env, invoice_id: u64, payer: &Address, amount: i128) {
    env.events().publish(
        (symbol_short!("pay_ref"), invoice_id),
        (payer.clone(), amount),
    );
}

/// Emitted when a recipient is added to a pending invoice.
pub fn recipient_added(env: &Env, invoice_id: u64, recipient: &Address, amount: i128) {
    env.events().publish(
        (symbol_short!("add_rec"), invoice_id),
        (recipient.clone(), amount),
    );
}

/// Emitted when the creator adjusts recipient split amounts.
pub fn split_adjusted(env: &Env, invoice_id: u64, creator: &Address) {
    env.events().publish(
        (symbol_short!("adj_spl"), invoice_id),
        creator.clone(),
    );
}

// ---------------------------------------------------------------------------
// Issue #1012: Encryption events
// ---------------------------------------------------------------------------

/// Emitted when a new encryption key is set or rotated.
pub fn encryption_key_set(env: &Env, version: u32, algorithm: &EncryptionAlgorithm, actor: &Address) {
    env.events().publish(
        (symbol_short!("enc_key"), version),
        (algorithm.clone(), actor.clone()),
    );
}

/// Emitted when data is encrypted.
pub fn data_encrypted(env: &Env, key_version: u32, data_hash: &BytesN<32>, actor: &Address) {
    env.events().publish(
        (symbol_short!("enc_dat"), key_version),
        (data_hash.clone(), actor.clone()),
    );
}

/// Emitted when data is decrypted.
pub fn data_decrypted(env: &Env, key_version: u32, data_hash: &BytesN<32>, actor: &Address) {
    env.events().publish(
        (symbol_short!("dec_dat"), key_version),
        (data_hash.clone(), actor.clone()),
    );
}

/// Emitted when encryption validation is performed.
pub fn encryption_validated(env: &Env, version: u32, valid: bool) {
    env.events().publish(
        (symbol_short!("enc_val"), version),
        valid,
    );
}

// ---------------------------------------------------------------------------
// Issue #1013: RBAC events
// ---------------------------------------------------------------------------

/// Emitted when a role is assigned to an address.
pub fn role_assigned(env: &Env, address: &Address, role: &Role, assigned_by: &Address) {
    env.events().publish(
        (symbol_short!("rol_asg"), address.clone()),
        (role.clone(), assigned_by.clone()),
    );
}

/// Emitted when a role is revoked from an address.
pub fn role_revoked(env: &Env, address: &Address, role: &Role, revoked_by: &Address) {
    env.events().publish(
        (symbol_short!("rol_rev"), address.clone()),
        (role.clone(), revoked_by.clone()),
    );
}

/// Emitted when a permission check is performed.
pub fn permission_checked(env: &Env, address: &Address, allowed: bool) {
    env.events().publish(
        (symbol_short!("perm_chk"), address.clone()),
        allowed,
    );
}

// ---------------------------------------------------------------------------
// Issue #1014: Caching events
// ---------------------------------------------------------------------------

/// Emitted when a cache entry is set or updated.
pub fn cache_set(env: &Env, key: &Symbol, expires_at: u64) {
    env.events().publish(
        (symbol_short!("cache_set"), key.clone()),
        expires_at,
    );
}

/// Emitted when a cache entry is invalidated.
pub fn cache_invalidated(env: &Env, key: &Symbol) {
    env.events().publish(
        (symbol_short!("cache_inv"), key.clone()),
        (),
    );
}

/// Emitted when the cache is warmed (pre-populated).
pub fn cache_warmed(env: &Env, entry_count: u32) {
    env.events().publish(
        (symbol_short!("cache_wrm"), entry_count),
        (),
    );
}

// ---------------------------------------------------------------------------
// Issue #1015: Query optimization events
// ---------------------------------------------------------------------------

/// Emitted when a query index is created.
pub fn query_index_created(env: &Env, index_type: &Symbol) {
    env.events().publish(
        (symbol_short!("qidx_crt"), index_type.clone()),
        (),
    );
}

/// Emitted when an indexed query is executed.
pub fn query_executed(env: &Env, index_type: &Symbol, result_count: u32) {
    env.events().publish(
        (symbol_short!("qry_exe"), index_type.clone()),
        result_count,
    );
}
