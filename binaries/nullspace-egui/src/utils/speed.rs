use std::sync::LazyLock;
use std::time::Instant;

use dashmap::DashMap;

use crate::utils::units::unit_for_bytes;

static SPEEDS: LazyLock<DashMap<String, SpeedState>> = LazyLock::new(DashMap::new);

struct SpeedState {
    last_at: Instant,
    last_val: f32,
    smoothed: f32, // this is smoothed rate (units/sec)
}

pub fn speed(var: &str, val: f32) -> f32 {
    const TAU_SECONDS: f32 = 3.0;
    let now = Instant::now();

    match SPEEDS.entry(var.to_owned()) {
        dashmap::mapref::entry::Entry::Occupied(mut entry) => {
            let s = entry.get_mut();
            let dt = (now - s.last_at).as_secs_f32();
            if dt > 0.0 {
                let inst = (val - s.last_val) / dt; // <-- the missing piece
                let alpha = 1.0 - (-dt / TAU_SECONDS).exp();
                s.smoothed += alpha * (inst - s.smoothed);
            }
            s.last_at = now;
            s.last_val = val;
            s.smoothed
        }
        dashmap::mapref::entry::Entry::Vacant(entry) => {
            entry.insert(SpeedState {
                last_at: now,
                last_val: val,
                smoothed: 0.0,
            });
            0.0
        }
    }
}

/// Formats a speed string, like "1.0 MB / 3.0 MB, 1.2 MB/s, 3:14"
pub fn speed_fmt(var: &str, current_bytes: u64, max_bytes: u64) -> (String, String, String) {
    fn fmt_amount(x: f32) -> String {
        // keep it stable / readable; tweak if you want more/less precision
        format!("{:.1}", x)
    }

    fn fmt_eta(mut secs: f32) -> String {
        if !secs.is_finite() || secs <= 0.0 {
            secs = 0.0;
        }
        let total = secs.round() as u64;

        let h = total / 3600;
        let m = (total % 3600) / 60;
        let s = total % 60;

        if h > 0 {
            format!("{h}:{m:02}:{s:02}")
        } else {
            format!("{m}:{s:02}")
        }
    }

    let (unit_scale, unit_suffix) = unit_for_bytes(current_bytes.max(max_bytes));
    let current = current_bytes as f32 / unit_scale as f32;
    let max = max_bytes as f32 / unit_scale as f32;

    // Left side: "1.0 MB / 3.0 MB"
    let left = if max > 0.0 {
        format!(
            "{} {} / {} {}",
            fmt_amount(current),
            unit_suffix,
            fmt_amount(max),
            unit_suffix
        )
    } else {
        format!("{} {}", fmt_amount(current), unit_suffix)
    };

    let remaining_bytes = max_bytes.saturating_sub(current_bytes) as f32;
    let rate = speed(var, current_bytes as f32);

    // Middle: speed with unit (e.g. "1.2 MB/s")
    let speed_text = if rate.is_finite() && rate > 0.0 {
        let (rate_scale, rate_suffix) = unit_for_bytes(rate.max(1.0) as u64);
        let rate_amount = rate / rate_scale as f32;
        format!("{} {}/s", fmt_amount(rate_amount), rate_suffix)
    } else {
        String::new()
    };

    let right = if max_bytes > 0 && remaining_bytes > 0.0 && rate.is_finite() && rate > 0.0 {
        let eta = remaining_bytes / rate;

        fmt_eta(eta)
    } else if max_bytes > 0 && remaining_bytes <= 0.0 {
        // done (or over)
        String::new()
    } else {
        // not enough info yet (first sample, zero max, etc.)
        String::new()
    };

    (left, speed_text, right)
}
