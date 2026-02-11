use chrono::{DateTime, Local, NaiveDate};
use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};

/// A seconds-granularity Unix timestamp, represented as an integer.
#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
#[serde(transparent)]
pub struct Timestamp(pub u64);

impl Timestamp {
    pub fn now() -> Self {
        let duration = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system time is before unix epoch");
        Self(duration.as_secs())
    }
}

/// A nanoseconds-granularity Unix timestamp, represented as an integer.
#[derive(
    Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Default, Hash,
)]
#[serde(transparent)]
pub struct NanoTimestamp(pub u64);

impl NanoTimestamp {
    pub fn now() -> Self {
        let duration = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system time is before unix epoch");
        Self(duration.as_nanos() as u64)
    }

    pub fn naive_date(self) -> Option<NaiveDate> {
        let secs = i64::try_from(self.0 / 1_000_000_000).ok()?;
        let nsec = u32::try_from(self.0 % 1_000_000_000).ok()?;
        let dt = DateTime::from_timestamp(secs, nsec)?;
        Some(dt.with_timezone(&Local).date_naive())
    }
}
