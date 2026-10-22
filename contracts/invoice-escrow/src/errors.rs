//! Error variants for the invoice-escrow contract.
//!
//! Discriminants are stable — never reorder, only append.

use soroban_sdk::{contracterror, contracttype, Env, String};

#[contracterror]
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
#[repr(u32)]
pub enum Error {
    /// Caller is not the contract admin.
    NotAdmin = 1,
    /// No pending admin transfer exists to accept or cancel.
    NoPendingAdmin = 2,
    /// Caller is not the pending admin (for accept_admin).
    Unauthorized = 3,
    /// Contract has already been initialized.
    AlreadyInitialized = 4,
    /// Contract has not been initialized yet.
    NotInitialized = 5,
    /// Invoice ID was not found in storage.
    InvoiceNotFound = 6,
    /// The invoice deadline has already passed.
    DeadlinePassed = 7,
    /// The invoice is in a state that does not allow this operation.
    InvalidStatus = 8,
    /// Amount must be greater than zero.
    InvalidAmount = 9,
    /// Total amount must be greater than zero.
    InvalidTotalAmount = 10,
    /// Deposit would exceed the invoice total; partial overflow not accepted.
    OverFunded = 11,
    /// The invoice is not yet fully funded; release is not permitted.
    InsufficientFunding = 12,
    /// The deadline has not yet passed; refund is not permitted.
    DeadlineNotPassed = 13,
    /// Recipient and amount vectors must be the same length and non-empty.
    InvalidRecipients = 14,
    /// Payer is blacklisted and cannot interact with invoices.
    PayerBlacklisted = 15,
    /// The blacklist appeal window has expired.
    AppealWindowExpired = 16,
    /// The payer is not blacklisted; cannot submit appeal or finalise.
    NotBlacklisted = 17,
    /// The blacklist entry has already been finalised.
    AlreadyFinalised = 18,
    /// Caller is not the blacklisted payer.
    NotBlacklistedPayer = 19,
    /// Co-signer list is empty, has duplicates, exceeds the maximum, or the
    /// threshold is outside `1..=signers.len()`.
    InvalidCosignerConfig = 20,
    /// Caller is not one of the invoice's configured co-signers.
    NotCosigner = 21,
    /// Co-signer has already approved or rejected this invoice.
    AlreadyVoted = 22,
    /// Release requires co-signer approval that has not yet reached threshold.
    ApprovalRequired = 23,
    /// Co-signers rejected the release; threshold can no longer be reached.
    ApprovalRejected = 24,
    /// Co-signer has not voted, so there is nothing to revoke.
    NotVoted = 25,
    /// Co-signer configuration cannot change once voting has started.
    CosignersLocked = 26,
    /// No co-signer approval is configured for this invoice.
    NoCosigners = 27,
    /// Oracle condition is malformed (non-positive threshold, zero staleness
    /// window, or fallback identical to the primary oracle).
    InvalidOracleConfig = 28,
    /// No oracle could be reached or none returned a price for the asset.
    OracleUnavailable = 29,
    /// The oracle price is older than the condition's staleness window.
    OracleStalePrice = 30,
    /// The oracle returned a non-positive price or a future timestamp.
    OracleInvalidPrice = 31,
    /// The oracle price does not satisfy the release condition.
    OracleConditionNotMet = 32,
    /// No oracle condition is configured for this invoice.
    NoOracleCondition = 33,
    /// Schedule is malformed: `release_at` not in the future, or the ledger
    /// delay exceeds the maximum / overflows.
    InvalidSchedule = 34,
    /// The scheduled release time has not been reached yet.
    ReleaseNotYetDue = 35,
    /// The scheduled minimum ledger count has not elapsed yet.
    ScheduleLedgerNotReached = 36,
    /// No active release schedule exists for this invoice.
    ScheduleNotFound = 37,
    /// The refund grace period is still running; refund is not permitted yet.
    RefundGraceActive = 38,
    /// Grace period exceeds `MAX_REFUND_GRACE_SECS`.
    InvalidGracePeriod = 39,
    /// The refund grace period has already elapsed or been waived.
    RefundGraceElapsed = 40,
}

/// Returns a human-readable recovery suggestion for the given error.
///
/// The suggestion describes how a caller can recover from the failure or
/// what state the contract is in, so clients can surface actionable guidance.
pub fn get_recovery_suggestion(error: Error) -> String {
    match error {
        Error::NotAdmin => String::from_str(
            &Env::default(),
            "Only the contract admin may perform this action; retry from the admin account.",
        ),
        Error::NoPendingAdmin => String::from_str(
            &Env::default(),
            "No admin transfer is pending; start a transfer with propose_admin first.",
        ),
        Error::Unauthorized => String::from_str(
            &Env::default(),
            "Caller is not authorized; retry from the pending admin account.",
        ),
        Error::AlreadyInitialized => String::from_str(
            &Env::default(),
            "Contract is already initialized; no further initialization is required.",
        ),
        Error::NotInitialized => String::from_str(
            &Env::default(),
            "Contract is not initialized; call initialize before any other operation.",
        ),
        Error::InvoiceNotFound => String::from_str(
            &Env::default(),
            "Invoice does not exist; verify the invoice ID or create the invoice first.",
        ),
        Error::DeadlinePassed => String::from_str(
            &Env::default(),
            "Invoice deadline has passed; create a new invoice or request a refund.",
        ),
        Error::InvalidStatus => String::from_str(
            &Env::default(),
            "Invoice is in the wrong state for this operation; check the current status and retry when valid.",
        ),
        Error::InvalidAmount => String::from_str(
            &Env::default(),
            "Amount must be greater than zero; retry with a positive amount.",
        ),
        Error::InvalidTotalAmount => String::from_str(
            &Env::default(),
            "Total amount must be greater than zero; retry with a positive total.",
        ),
        Error::OverFunded => String::from_str(
            &Env::default(),
            "Deposit would exceed the invoice total; reduce the deposit to the remaining balance.",
        ),
        Error::InsufficientFunding => String::from_str(
            &Env::default(),
            "Invoice is not fully funded; fund the remaining balance before releasing.",
        ),
        Error::DeadlineNotPassed => String::from_str(
            &Env::default(),
            "Deadline has not passed yet; wait until the deadline before requesting a refund.",
        ),
        Error::InvalidRecipients => String::from_str(
            &Env::default(),
            "Recipients and amounts must be non-empty and equal in length; correct the inputs and retry.",
        ),
        Error::PayerBlacklisted => String::from_str(
            &Env::default(),
            "Payer is blacklisted; submit an appeal or wait for the appeal window to resolve.",
        ),
        Error::AppealWindowExpired => String::from_str(
            &Env::default(),
            "Appeal window has expired; no further appeals can be submitted.",
        ),
        Error::NotBlacklisted => String::from_str(
            &Env::default(),
            "Payer is not blacklisted; no appeal or finalisation is needed.",
        ),
        Error::AlreadyFinalised => String::from_str(
            &Env::default(),
            "Blacklist entry is already finalised; no further action is possible.",
        ),
        Error::NotBlacklistedPayer => String::from_str(
            &Env::default(),
            "Only the blacklisted payer may perform this action; retry from the payer account.",
        ),
    }
}

/// Maps a raw error code to its `Error` variant, if it is a known code.
pub fn error_from_code(code: u32) -> Option<Error> {
    match code {
        1 => Some(Error::NotAdmin),
        2 => Some(Error::NoPendingAdmin),
        3 => Some(Error::Unauthorized),
        4 => Some(Error::AlreadyInitialized),
        5 => Some(Error::NotInitialized),
        6 => Some(Error::InvoiceNotFound),
        7 => Some(Error::DeadlinePassed),
        8 => Some(Error::InvalidStatus),
        9 => Some(Error::InvalidAmount),
        10 => Some(Error::InvalidTotalAmount),
        11 => Some(Error::OverFunded),
        12 => Some(Error::InsufficientFunding),
        13 => Some(Error::DeadlineNotPassed),
        14 => Some(Error::InvalidRecipients),
        15 => Some(Error::PayerBlacklisted),
        16 => Some(Error::AppealWindowExpired),
        17 => Some(Error::NotBlacklisted),
        18 => Some(Error::AlreadyFinalised),
        19 => Some(Error::NotBlacklistedPayer),
        _ => None,
    }
}

/// Storage key for the recovery-suggestion entrypoint's last queried code.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RecoveryKey {
    /// Last error code queried through the recovery entrypoint.
    LastErrorCode,
}
