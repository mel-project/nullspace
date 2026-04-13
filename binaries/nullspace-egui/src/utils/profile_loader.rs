use std::collections::HashMap;
use std::collections::hash_map::Entry;
use std::path::PathBuf;
use std::time::{Duration, SystemTime};

use nullspace_client::UserDetails;
use nullspace_structs::username::UserName;
use smol::channel::TryRecvError;

use crate::rpc::{flatten_rpc, get_rpc};
use crate::utils::profile_cache::{self, CachedProfile};

const PROFILE_INITIAL_RETRY_BACKOFF: Duration = Duration::from_secs(60);
const PROFILE_MAX_RETRY_BACKOFF: Duration = Duration::from_secs(60 * 60);
const PROFILE_CACHE_TTL: Duration = Duration::from_secs(60 * 60);

pub struct ProfileLoader {
    entries: HashMap<UserName, ProfileEntry>,
    label_counts: HashMap<String, usize>,
    label_index_dirty: bool,
    cache_dir: PathBuf,
}

#[derive(Default)]
struct ProfileEntry {
    last_good: Option<CachedProfile>,
    inflight: Option<smol::channel::Receiver<Result<UserDetails, String>>>,
    last_error: Option<String>,
    retry_after: Option<SystemTime>,
    retry_failures: u32,
    missing: bool,
    force_refresh: bool,
}

impl ProfileLoader {
    pub fn new(cache_dir: PathBuf) -> Self {
        Self {
            entries: HashMap::new(),
            label_counts: HashMap::new(),
            label_index_dirty: true,
            cache_dir,
        }
    }

    pub fn view(&mut self, username: &UserName) -> Option<UserDetails> {
        let entry = match self.entries.entry(username.clone()) {
            Entry::Occupied(entry) => entry.into_mut(),
            Entry::Vacant(entry) => {
                self.label_index_dirty = true;
                let cached = profile_cache::load_entry(&self.cache_dir, username);
                entry.insert(ProfileEntry {
                    last_good: cached,
                    ..ProfileEntry::default()
                })
            }
        };

        if let Some(rx) = &entry.inflight {
            let previous_display = entry
                .last_good
                .as_ref()
                .and_then(|profile| profile.details.display_name.clone());
            match rx.try_recv() {
                Ok(result) => {
                    entry.inflight = None;
                    match result {
                        Ok(profile) => {
                            entry.missing = false;
                            entry.last_good = Some(profile_cache::fresh_entry(profile));
                            entry.last_error = None;
                            entry.retry_after = None;
                            entry.retry_failures = 0;
                            if let Some(details) = entry.last_good.as_ref() {
                                profile_cache::write_entry(&self.cache_dir, details);
                            }
                            let next_display = entry
                                .last_good
                                .as_ref()
                                .and_then(|profile| profile.details.display_name.clone());
                            if previous_display != next_display {
                                self.label_index_dirty = true;
                            }
                        }
                        Err(err) => {
                            record_refresh_failure(entry, err);
                        }
                    }
                }
                Err(TryRecvError::Empty) => {
                    // still pending
                }
                Err(TryRecvError::Closed) => {
                    entry.inflight = None;
                    record_refresh_failure(entry, "profile refresh task dropped".to_string());
                }
            }
        }

        let retry_ready = entry
            .retry_after
            .map(|when| when <= SystemTime::now())
            .unwrap_or(true);
        let cache_stale = entry
            .last_good
            .as_ref()
            .map(|entry| is_stale(entry.cached_at_unix_secs))
            .unwrap_or(true);
        let should_fetch =
            entry.inflight.is_none() && !entry.missing && retry_ready && (entry.force_refresh || cache_stale);

        if should_fetch {
            entry.force_refresh = false;
            let username = username.clone();
            let (tx, rx) = smol::channel::bounded(1);
            smol::spawn(async move {
                let result = flatten_rpc(get_rpc().user_details(username).await);
                let _ = tx.send(result).await;
            })
            .detach();
            entry.inflight = Some(rx);
        }

        entry.last_good.as_ref().map(|entry| entry.details.clone())
    }

    fn refresh_label_index(&mut self) {
        if !self.label_index_dirty {
            return;
        }

        self.label_counts.clear();
        for (entry_username, entry) in &self.entries {
            let base = entry
                .last_good
                .as_ref()
                .and_then(|profile| profile.details.display_name.clone())
                .unwrap_or_else(|| entry_username.as_str().to_string());
            self.label_counts
                .entry(base)
                .and_modify(|count| *count += 1)
                .or_insert(1);
        }

        self.label_index_dirty = false;
    }

    pub fn label_for(&mut self, username: &UserName) -> String {
        let view = self.view(username);
        self.refresh_label_index();

        let (base, has_display) = match view.as_ref() {
            Some(details) => {
                let display_name = details.display_name.clone();
                let base = display_name
                    .clone()
                    .unwrap_or_else(|| username.as_str().to_string());
                let has_display = display_name.is_some();
                (base, has_display)
            }
            None => (username.as_str().to_string(), false),
        };

        if has_display && self.label_counts.get(&base).copied().unwrap_or(0) > 1 {
            format!("{base} ({})", username.as_str())
        } else {
            base
        }
    }

    pub fn invalidate(&mut self, username: &UserName) {
        let entry = self.entries.entry(username.clone()).or_default();
        entry.missing = false;
        entry.last_error = None;
        entry.retry_after = None;
        entry.retry_failures = 0;
        entry.force_refresh = true;
    }
}

fn record_refresh_failure(entry: &mut ProfileEntry, err: String) {
    entry.retry_failures = entry.retry_failures.saturating_add(1);
    entry.last_error = Some(err);
    entry.retry_after = Some(SystemTime::now() + retry_backoff(entry.retry_failures));
}

fn retry_backoff(consecutive_failures: u32) -> Duration {
    let shift = consecutive_failures.saturating_sub(1).min(16);
    let multiplier = 1u64 << shift;
    Duration::from_secs(
        PROFILE_INITIAL_RETRY_BACKOFF
            .as_secs()
            .saturating_mul(multiplier)
            .min(PROFILE_MAX_RETRY_BACKOFF.as_secs()),
    )
}

fn is_stale(cached_at_unix_secs: u64) -> bool {
    let now = profile_cache::current_unix_secs();
    cached_at_unix_secs == 0
        || now.saturating_sub(cached_at_unix_secs) >= PROFILE_CACHE_TTL.as_secs()
}

#[cfg(test)]
mod tests {
    use super::{PROFILE_MAX_RETRY_BACKOFF, is_stale, retry_backoff};

    #[test]
    fn zero_timestamp_is_stale() {
        assert!(is_stale(0));
    }

    #[test]
    fn fresh_timestamp_is_not_stale() {
        let now = crate::utils::profile_cache::current_unix_secs();
        assert!(!is_stale(now));
    }

    #[test]
    fn retry_backoff_grows_exponentially() {
        assert_eq!(retry_backoff(1).as_secs(), 60);
        assert_eq!(retry_backoff(2).as_secs(), 120);
        assert_eq!(retry_backoff(3).as_secs(), 240);
    }

    #[test]
    fn retry_backoff_is_capped() {
        assert_eq!(retry_backoff(32), PROFILE_MAX_RETRY_BACKOFF);
    }
}
