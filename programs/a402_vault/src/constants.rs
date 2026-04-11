pub const MAX_SETTLEMENTS_PER_TX: usize = 20;
pub const DISPUTE_WINDOW_SEC: i64 = 86400; // 24 hours

pub const VAULT_STATUS_ACTIVE: u8 = 0;
pub const VAULT_STATUS_PAUSED: u8 = 1;
pub const VAULT_STATUS_MIGRATING: u8 = 2;
pub const VAULT_STATUS_RETIRED: u8 = 3;
