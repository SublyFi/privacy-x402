use anchor_lang::prelude::*;

use crate::constants::{
    ARCIUM_STATUS_DISABLED, ARCIUM_STATUS_ENFORCED, ARCIUM_STATUS_MIRROR, ARCIUM_STATUS_PAUSED,
};
use crate::error::VaultError;
use crate::state::{ArciumConfig, VaultConfig};

#[derive(Accounts)]
pub struct SetArciumStatus<'info> {
    pub governance: Signer<'info>,

    #[account(
        constraint = vault_config.governance == governance.key() @ VaultError::Unauthorized,
    )]
    pub vault_config: Account<'info, VaultConfig>,

    #[account(
        mut,
        seeds = [b"arcium_config", vault_config.key().as_ref()],
        bump = arcium_config.bump,
        constraint = arcium_config.vault_config == vault_config.key() @ VaultError::InvalidArciumConfig,
    )]
    pub arcium_config: Account<'info, ArciumConfig>,
}

fn validate_arcium_status_transition(
    current_status: u8,
    target_status: u8,
    deployment_configured: bool,
) -> Result<()> {
    require!(
        matches!(
            target_status,
            ARCIUM_STATUS_DISABLED
                | ARCIUM_STATUS_MIRROR
                | ARCIUM_STATUS_ENFORCED
                | ARCIUM_STATUS_PAUSED
        ),
        VaultError::InvalidArciumStatus
    );

    if ArciumConfig::status_requires_deployment(target_status) {
        require!(deployment_configured, VaultError::InvalidArciumConfig);
    }

    if current_status == target_status {
        return Ok(());
    }

    if target_status == ARCIUM_STATUS_ENFORCED {
        require!(
            current_status == ARCIUM_STATUS_MIRROR,
            VaultError::InvalidArciumStatus
        );
    }

    Ok(())
}

pub fn handler(ctx: Context<SetArciumStatus>, status: u8) -> Result<()> {
    validate_arcium_status_transition(
        ctx.accounts.arcium_config.status,
        status,
        ctx.accounts.arcium_config.deployment_configured(),
    )?;

    ctx.accounts.arcium_config.status = status;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validates_status_transition_rules() {
        assert!(validate_arcium_status_transition(
            ARCIUM_STATUS_DISABLED,
            ARCIUM_STATUS_DISABLED,
            false
        )
        .is_ok());
        assert!(validate_arcium_status_transition(
            ARCIUM_STATUS_DISABLED,
            ARCIUM_STATUS_PAUSED,
            false
        )
        .is_ok());
        assert!(validate_arcium_status_transition(
            ARCIUM_STATUS_DISABLED,
            ARCIUM_STATUS_MIRROR,
            false
        )
        .is_err());
        assert!(validate_arcium_status_transition(
            ARCIUM_STATUS_DISABLED,
            ARCIUM_STATUS_MIRROR,
            true
        )
        .is_ok());
        assert!(validate_arcium_status_transition(
            ARCIUM_STATUS_DISABLED,
            ARCIUM_STATUS_ENFORCED,
            true
        )
        .is_err());
        assert!(validate_arcium_status_transition(
            ARCIUM_STATUS_MIRROR,
            ARCIUM_STATUS_ENFORCED,
            false
        )
        .is_err());
        assert!(validate_arcium_status_transition(
            ARCIUM_STATUS_MIRROR,
            ARCIUM_STATUS_ENFORCED,
            true
        )
        .is_ok());
        assert!(validate_arcium_status_transition(
            ARCIUM_STATUS_ENFORCED,
            ARCIUM_STATUS_ENFORCED,
            true
        )
        .is_ok());
        assert!(validate_arcium_status_transition(
            ARCIUM_STATUS_ENFORCED,
            ARCIUM_STATUS_ENFORCED,
            false
        )
        .is_err());
        assert!(validate_arcium_status_transition(ARCIUM_STATUS_MIRROR, 99, true).is_err());
    }
}
