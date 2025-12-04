use serde::{Deserialize, Serialize};
use chrono::{DateTime, Utc};

use crate::sensors::process::ProcessInfo;

/// A snapshot of one host at a point in time.
/// For now it only includes processes; later we can add net/registry/drivers.
#[derive(Debug, Serialize, Deserialize)]
pub struct SystemSnapshot {
    pub host_id: String,
    pub collected_at: DateTime<Utc>,
    pub processes: Vec<ProcessInfo>,
}
