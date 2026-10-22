use soroban_sdk::{contracttype, Address, BytesN, Env, Symbol, Vec};

#[contracttype]
#[derive(Clone, Debug, PartialEq)]
pub enum InvoiceStatus {
    Pending,
    Released,
    Refunded,
    Cancelled,
}

#[contracttype]
#[derive(Clone, Debug)]
pub struct Payment {
    pub payer: Address,
    pub amount: i128,
    pub tip: i128,
}

#[contracttype]
#[derive(Clone, Debug)]
pub struct AuditEntry {
    pub action: Symbol,
    pub actor: Address,
    pub timestamp: u64,
}

#[contracttype]
#[derive(Clone, Debug)]
pub struct SubscriptionParams {
    pub creator: Address,
    pub recipients: Vec<Address>,
    pub amounts: Vec<i128>,
    pub tokens: Vec<Address>,
}

#[contracttype]
#[derive(Clone, Debug)]
pub struct CompletionProof {
    pub id: u64,
    pub status: InvoiceStatus,
    pub funded: i128,
    pub timestamp: u64,
    pub hash: BytesN<32>,
}

#[contracttype]
#[derive(Clone, Debug)]
pub struct PaymentProof {
    pub invoice_id: u64,
    pub payer: Address,
    pub total_paid: i128,
    pub proof_hash: BytesN<32>,
}

#[contracttype]
#[derive(Clone, Debug)]
pub struct InvoiceTemplate {
    pub recipients: Vec<Address>,
    pub amounts: Vec<i128>,
    pub token: Address,
    /// Unix timestamp after which unfunded invoices can be refunded.
    pub deadline: u64,
    /// Total amount collected so far.
    pub funded: i128,
    /// Current lifecycle status.
    pub status: InvoiceStatus,
    /// All payments made toward this invoice.
    pub payments: Vec<Payment>,
    /// Optional whitelist of addresses allowed to pay this invoice.
    /// When None, any address may pay.
    pub allowed_payers: Option<Vec<Address>>,
}

#[contracttype]
#[derive(Clone, Debug)]
pub struct CreateInvoiceParams {
    pub recipients: Vec<Address>,
    pub amounts: Vec<i128>,
    pub token: Address,
    pub deadline: u64,
}

/// A single graduated release tranche: `basis_points` out of 10 000 of the
/// invoice total becomes releasable once the ledger time reaches `timestamp`.
#[contracttype]
#[derive(Clone, Debug)]
pub struct Tranche {
    pub timestamp: u64,
    pub basis_points: u32,
}

/// Optional parameters for `create_invoice`, grouped to keep the function
/// within Soroban's 10-parameter limit.
#[contracttype]
#[derive(Clone, Debug)]
pub struct InvoiceOptions {
    pub co_creators: Vec<Address>,
    pub allow_early_withdrawal: bool,
    pub bonus_pool: i128,
    pub bonus_max_payers: u32,
    /// Issue #22: block release until this invoice is Released.
    pub prerequisite_id: Option<u64>,
    /// Issue #23: graduated release schedule; empty = release all at once.
    pub tranches: Vec<Tranche>,
    /// Co-signers whose approval is required before release.
    pub co_signers: Vec<Address>,
    /// How many co-signer approvals are needed (≤ `co_signers.len()`).
    pub required_signatures: u32,
    /// Penalty basis points for late payments (issue #42).
    pub penalty_bps: Option<u32>,
    /// Soft deadline timestamp; payments after this incur a penalty (issue #42).
    pub penalty_deadline: Option<u64>,
    /// Minimum funding threshold in basis points (issue #43).
    pub min_funding_bps: Option<u32>,
    /// Issue #86: creator-triggered staged release schedule; each entry is
    /// basis points (must sum to 10 000 when non-empty).
    pub release_stages: Vec<u32>,
    /// Issue #142: optional price oracle contract for dynamic pricing.
    pub price_oracle: Option<Address>,
}

/// Legacy invoice layout used by stored invoices created before the `version`
/// field was added. Kept for on-chain migration so old data can be
/// deserialised and re-saved in the current schema.
#[contracttype]
#[derive(Clone, Debug)]
pub struct LegacyInvoice {
    pub creator: Address,
    pub co_creators: Vec<Address>,
    pub recipients: Vec<Address>,
    pub amounts: Vec<i128>,
    pub tokens: Vec<Address>,
    pub deadline: u64,
    pub funded: i128,
    pub status: InvoiceStatus,
    pub payments: Vec<Payment>,
    pub drip_duration: Option<u64>,
    pub release_timestamp: Option<u64>,
    pub claimed: Vec<i128>,
    pub frozen: bool,
    pub completion_time: Option<u64>,
    pub allow_early_withdrawal: bool,
    pub bonus_pool: i128,
    pub bonus_max_payers: u32,
    pub prerequisite_id: Option<u64>,
    pub tranches: Vec<Tranche>,
    pub released_bps: u32,
    pub stake_amount: i128,
    pub referrer: Option<Address>,
}

#[contracttype]
#[derive(Clone, Debug)]
pub struct Invoice {
    /// Schema version (0 for legacy, 1 for current).
    pub version: u32,
    pub creator: Address,
    pub co_creators: Vec<Address>,
    pub recipients: Vec<Address>,
    pub amounts: Vec<i128>,
    /// Token per recipient (parallel to `recipients`); in practice all entries
    /// are the same token set at creation time.
    pub tokens: Vec<Address>,
    pub deadline: u64,
    pub funded: i128,
    pub status: InvoiceStatus,
    pub payments: Vec<Payment>,
    pub drip_duration: Option<u64>,
    pub release_timestamp: Option<u64>,
    pub claimed: Vec<i128>,
    pub frozen: bool,
    pub completion_time: Option<u64>,
    pub allow_early_withdrawal: bool,
    pub bonus_pool: i128,
    pub bonus_max_payers: u32,
    /// Issue #22: if set, `release()` will fail until this invoice is Released.
    pub prerequisite_id: Option<u64>,
    /// Issue #23: graduated release schedule; empty means release all at once.
    pub tranches: Vec<Tranche>,
    /// Issue #23: cumulative basis points already distributed (0–10 000).
    pub released_bps: u32,
    /// Co-signers that must approve release before funds can be distributed.
    /// If non-empty, `required_signatures` of them must call `sign_release()`.
    pub co_signers: Vec<Address>,
    /// How many co-signer approvals are required to unlock release.
    /// Must be ≤ `co_signers.len()`.
    pub required_signatures: u32,
    /// Co-signers that have already approved release.
    pub signatures: Vec<Address>,
    /// Optional approver address that must approve before release (issue #25).
    pub approver: Option<Address>,
    /// Whether the approver has approved the invoice (issue #25).
    pub approved: bool,
    /// Penalty basis points for payments after `penalty_deadline` (issue #42).
    pub penalty_bps: u32,
    /// Soft deadline; payments after this timestamp incur a penalty (issue #42).
    pub penalty_deadline: u64,
    /// Minimum funding threshold in basis points (issue #43); 0 means 100%.
    pub min_funding_bps: u32,
    /// Issue #86: creator-triggered staged release schedule (basis points per stage).
    pub release_stages: Vec<u32>,
    /// Issue #86: number of stages already released.
    pub released_stages: u32,
    /// Optional whitelist of addresses allowed to pay this invoice (mirrors InvoiceTemplate).
    pub allowed_payers: Option<Vec<Address>>,
    /// Issue #142: optional price oracle contract; when set, pay() queries it for the current price.
    pub price_oracle: Option<Address>,
    /// Issue #142: base amounts recorded at creation; used to compute oracle-adjusted totals.
    pub base_amounts: Vec<i128>,
}

impl Invoice {
    /// Upgrade a legacy (pre-version) invoice to the current schema.
    /// New fields are filled with their default (empty / zero) values.
    pub fn from_legacy(old: LegacyInvoice, env: &Env) -> Self {
        Invoice {
            version: 2,
            creator: old.creator,
            co_creators: old.co_creators,
            recipients: old.recipients,
            base_amounts: old.amounts.clone(),
            amounts: old.amounts,
            tokens: old.tokens,
            deadline: old.deadline,
            funded: old.funded,
            status: old.status,
            payments: old.payments,
            drip_duration: old.drip_duration,
            release_timestamp: old.release_timestamp,
            claimed: old.claimed,
            frozen: old.frozen,
            completion_time: old.completion_time,
            allow_early_withdrawal: old.allow_early_withdrawal,
            bonus_pool: old.bonus_pool,
            bonus_max_payers: old.bonus_max_payers,
            prerequisite_id: old.prerequisite_id,
            tranches: old.tranches,
            released_bps: old.released_bps,
            co_signers: Vec::new(env),
            required_signatures: 0,
            signatures: Vec::new(env),
            approver: None,
            approved: false,
            penalty_bps: 0,
            penalty_deadline: 0,
            min_funding_bps: 0,
            release_stages: Vec::new(env),
            released_stages: 0,
            allowed_payers: None,
            price_oracle: None,
        }
    }
}


// ---------------------------------------------------------------------------
// Issue #1012: Encryption types
// ---------------------------------------------------------------------------

/// Encryption algorithm identifier.
#[contracttype]
#[derive(Clone, Debug, PartialEq)]
pub enum EncryptionAlgorithm {
    /// AES-256-GCM authenticated encryption.
    Aes256Gcm,
    /// ChaCha20-Poly1305 authenticated encryption.
    ChaCha20Poly1305,
}

/// A managed encryption key with version tracking for rotation.
#[contracttype]
#[derive(Clone, Debug)]
pub struct EncryptionKey {
    /// Algorithm used with this key.
    pub algorithm: EncryptionAlgorithm,
    /// Monotonically increasing version number (starts at 1).
    pub version: u32,
    /// The raw key material (32 bytes for AES-256 or ChaCha20).
    pub key_data: BytesN<32>,
    /// Ledger timestamp when the key was created.
    pub created_at: u64,
    /// Whether this key is active (true) or retired (false).
    pub active: bool,
}

/// An entry in the encryption audit trail.
#[contracttype]
#[derive(Clone, Debug)]
pub struct EncryptionAuditEntry {
    /// Action performed: set_key, rotate, encrypt, decrypt, validate.
    pub action: Symbol,
    /// Address that performed the action.
    pub actor: Address,
    /// Key version involved.
    pub key_version: u32,
    /// Ledger timestamp.
    pub timestamp: u64,
    /// Hash of the data involved (for verification).
    pub data_hash: BytesN<32>,
}

/// Result of an encryption validation check.
#[contracttype]
#[derive(Clone, Debug)]
pub struct EncryptionValidation {
    /// Whether the validation passed.
    pub valid: bool,
    /// Key version that was validated.
    pub key_version: u32,
    /// Timestamp of the validation.
    pub timestamp: u64,
    /// Error message if validation failed (empty string on success).
    pub error: Symbol,
}

// ---------------------------------------------------------------------------
// Issue #1013: RBAC types
// ---------------------------------------------------------------------------

/// Role in the access control system.
#[contracttype]
#[derive(Clone, Debug, PartialEq)]
pub enum Role {
    /// Full contract administrator.
    Admin,
    /// Can create and manage invoices.
    Creator,
    /// Can pay toward invoices.
    Payer,
    /// Can approve invoices for release.
    Approver,
    /// Can audit contract state (read-only).
    Auditor,
}

/// Permission flags that can be granted to roles.
#[contracttype]
#[derive(Clone, Debug, PartialEq)]
pub enum Permission {
    /// Create new invoices.
    CreateInvoice,
    /// Pay toward invoices.
    Pay,
    /// Release invoice funds.
    Release,
    /// Refund invoice payments.
    Refund,
    /// Cancel invoices.
    Cancel,
    /// Manage roles (assign/revoke).
    ManageRoles,
    /// View audit logs.
    ViewAudit,
    /// Encrypt or decrypt sensitive data.
    ManageEncryption,
}

/// Role assignment record.
#[contracttype]
#[derive(Clone, Debug)]
pub struct RoleAssignment {
    /// The role assigned.
    pub role: Role,
    /// Address the role is assigned to.
    pub address: Address,
    /// Address that granted the role.
    pub assigned_by: Address,
    /// Ledger timestamp of assignment.
    pub assigned_at: u64,
}

/// An entry in the RBAC audit trail.
#[contracttype]
#[derive(Clone, Debug)]
pub struct RbacAuditEntry {
    /// Action performed: assign, revoke, check.
    pub action: Symbol,
    /// Address that performed the action.
    pub actor: Address,
    /// Target address (the one whose role was changed/checked).
    pub target: Address,
    /// Role involved.
    pub role: Role,
    /// Permission checked (if applicable).
    pub permission: Option<Permission>,
    /// Whether the check passed (for check actions).
    pub allowed: bool,
    /// Ledger timestamp.
    pub timestamp: u64,
}

/// Access analytics summary for a given address.
#[contracttype]
#[derive(Clone, Debug)]
pub struct AccessAnalytics {
    /// Total number of role assignments for this address.
    pub roles_assigned: u32,
    /// Total number of role revocations for this address.
    pub roles_revoked: u32,
    /// Total permission checks performed.
    pub permission_checks: u32,
    /// Number of permission checks that passed.
    pub checks_passed: u32,
    /// Number of permission checks that failed.
    pub checks_failed: u32,
    /// Last active timestamp.
    pub last_active: u64,
}

// ---------------------------------------------------------------------------
// Issue #1014: Caching types
// ---------------------------------------------------------------------------

/// A cached contract state entry.
#[contracttype]
#[derive(Clone, Debug)]
pub struct CacheEntry {
    /// The cached value (serialized).
    pub value: Bytes,
    /// Ledger timestamp when the entry was cached.
    pub cached_at: u64,
    /// Ledger timestamp when the entry expires (0 = no expiry).
    pub expires_at: u64,
    /// Number of times this entry has been read.
    pub read_count: u64,
    /// Whether the entry is valid (false = invalidated).
    pub valid: bool,
}

/// Cache performance metrics.
#[contracttype]
#[derive(Clone, Debug)]
pub struct CacheMetrics {
    /// Total cache hits.
    pub hits: u64,
    /// Total cache misses.
    pub misses: u64,
    /// Total entries invalidated.
    pub invalidated: u64,
    /// Total entries warmed (pre-populated).
    pub warmed: u64,
    /// Current number of entries in the cache.
    pub entry_count: u64,
    /// Hit ratio in basis points (0–10 000).
    pub hit_ratio_bps: u32,
}

// ---------------------------------------------------------------------------
// Issue #1015: Query optimization types
// ---------------------------------------------------------------------------

/// Index types for optimized queries.
#[contracttype]
#[derive(Clone, Debug, PartialEq)]
pub enum QueryIndex {
    /// Index by invoice status.
    ByStatus,
    /// Index by creator address.
    ByCreator,
    /// Index by recipient address.
    ByRecipient,
}

/// Query performance metrics.
#[contracttype]
#[derive(Clone, Debug)]
pub struct QueryMetrics {
    /// Total queries executed.
    pub total_queries: u64,
    /// Queries served from index (fast path).
    pub indexed_queries: u64,
    /// Queries that required full scan.
    pub full_scan_queries: u64,
    /// Total query time in ledger "ticks" (accumulated).
    pub total_query_time: u64,
    /// Average query time (total / total_queries).
    pub avg_query_time: u64,
    /// Number of indexes currently maintained.
    pub index_count: u32,
}
