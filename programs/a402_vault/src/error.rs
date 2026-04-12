use anchor_lang::prelude::*;

#[error_code]
pub enum VaultError {
    #[msg("Vault is not active")]
    VaultInactive,

    #[msg("Vault is paused")]
    VaultPaused,

    #[msg("Vault is already paused")]
    VaultAlreadyPaused,

    #[msg("Vault is retired")]
    VaultRetired,

    #[msg("Vault is already retired")]
    VaultAlreadyRetired,

    #[msg("Vault is migrating")]
    VaultMigrating,

    #[msg("Exit deadline has been exceeded")]
    ExitDeadlineExceeded,

    #[msg("Exit deadline has not been reached")]
    ExitDeadlineNotReached,

    #[msg("Vault is insolvent")]
    VaultInsolvent,

    #[msg("Invalid vault signer")]
    InvalidVaultSigner,

    #[msg("Invalid participant receipt signature")]
    InvalidParticipantReceipt,

    #[msg("Invalid receipt message")]
    InvalidReceiptMessage,

    #[msg("Stale receipt nonce")]
    StaleReceiptNonce,

    #[msg("Dispute window is still active")]
    DisputeWindowActive,

    #[msg("Dispute window has expired")]
    DisputeWindowExpired,

    #[msg("Withdraw nonce already used")]
    NonceAlreadyUsed,

    #[msg("Withdrawal authorization expired")]
    WithdrawExpired,

    #[msg("Batch chunk hash mismatch")]
    AtomicChunkHashMismatch,

    #[msg("Batch ID mismatch")]
    BatchIdMismatch,

    #[msg("Audit record index out of order")]
    AuditRecordIndexOutOfOrder,

    #[msg("record_audit must be paired with settle_vault")]
    RecordAuditWithoutSettle,

    #[msg("settle_vault must be paired with record_audit")]
    SettleVaultWithoutAudit,

    #[msg("Invalid amount")]
    InvalidAmount,

    #[msg("Arithmetic overflow")]
    ArithmeticOverflow,

    #[msg("Invalid Ed25519 instruction")]
    InvalidEd25519Instruction,

    #[msg("Force settle request already resolved")]
    AlreadyResolved,

    #[msg("Invalid status transition")]
    InvalidStatusTransition,

    #[msg("Too many settlements in batch")]
    TooManySettlements,
}
