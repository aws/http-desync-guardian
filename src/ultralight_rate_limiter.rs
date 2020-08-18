///
/// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
///
/// Licensed under the Apache License, Version 2.0 (the "License").
/// You may not use this file except in compliance with the License.
/// A copy of the License is located at
///
///  http://aws.amazon.com/apache2.0
///
/// or in the "license" file accompanying this file. This file is distributed
/// on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
/// express or implied. See the License for the specific language governing
/// permissions and limitations under the License.
///
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

/// An ultra light rate limiter.
/// It allows exactly limit queries per slot of time (without handling bursts),
/// which makes it much simpler to test, and it's good enough (to limit logging).
pub struct UltraLightRateLimiter {
    counter: AtomicU64,
    limit: u32,
    time_slot_size: u32,
    ticker_ms: fn() -> u64,
}

impl UltraLightRateLimiter {
    /// Creates a new rate limiter based on the desired limit per second,
    /// and a clock function.
    /// # Arguments
    /// `limit_per_second` how many permits it issues per second. If greater than 1, then it's truncated
    /// `ticker_ms` a clock function with `ms` precision. E.g. a `MONOTONIC_CLOCK`
    pub fn new(limit_per_second: f64, ticker_ms: fn() -> u64) -> Self {
        assert!(
            limit_per_second > 0.,
            "limit_per_second must be greater than zero."
        );

        let time_slot_size;
        let limit;
        if limit_per_second >= 1. {
            limit = limit_per_second as u32;
            time_slot_size = Duration::from_secs(1).as_millis() as u32;
        } else {
            limit = 1;
            time_slot_size = (Duration::from_secs(1).as_millis() as f64 / limit_per_second) as u32;
        }

        Self {
            counter: AtomicU64::new(0),
            limit,
            time_slot_size,
            ticker_ms,
        }
    }

    #[cfg_attr(feature = "coverage", inline(never))]
    #[cfg_attr(not(feature = "coverage"), inline(always))]
    pub fn try_acquire_value<T>(&self, value: T) -> Option<T> {
        if self.try_acquire() {
            Some(value)
        } else {
            None
        }
    }

    pub fn try_acquire(&self) -> bool {
        let time = (self.ticker_ms)();
        let current_time_slot: u32 = (time / self.time_slot_size as u64) as u32;

        let current = self.counter.load(Ordering::Relaxed);
        let new_value = self.update_time_slot(current_time_slot, current);
        // Update only when the limit is not exhausted.
        // Otherwise do not update the value and reject.
        new_value != current
            && self
                .counter
                .compare_exchange(current, new_value, Ordering::Relaxed, Ordering::Relaxed)
                .is_ok()
    }

    fn update_time_slot(&self, current_time_slot: u32, v: u64) -> u64 {
        const U32_BITS: u64 = 32;

        let mut time_slot = (v >> U32_BITS) as u32;
        let mut count = v as u32;
        if time_slot < current_time_slot {
            count = 1;
            time_slot = current_time_slot;
        } else if count < self.limit {
            count += 1;
        } else {
            // it's already above the limit in this time-slot.
            // do not change anything
            return v;
        }
        ((time_slot as u64) << U32_BITS) | count as u64
    }
}

#[cfg(test)]
mod tests {
    use crate::ultralight_rate_limiter::UltraLightRateLimiter;
    use std::cell::RefCell;

    #[test]
    fn test_once_per_second() {
        let rate_limiter = UltraLightRateLimiter::new(1., get_ticker(vec![0, 500, 1000]));

        assert!(rate_limiter.try_acquire(), "Must grant a permit");
        assert!(!rate_limiter.try_acquire(), "Must not grant a permit");
        assert!(rate_limiter.try_acquire(), "Must grant a permit");
    }

    #[test]
    fn test_twice_per_second() {
        let rate_limiter = UltraLightRateLimiter::new(2., get_ticker(vec![0, 500, 600, 1000]));

        assert!(rate_limiter.try_acquire(), "Must grant a permit");
        assert!(rate_limiter.try_acquire(), "Must grant a permit");
        assert!(!rate_limiter.try_acquire(), "Must not grant a permit");
        assert!(rate_limiter.try_acquire(), "Must grant a permit");
    }

    #[test]
    fn test_100_per_second() {
        let time_ticks = (0..2000).collect();
        let rate_limiter = UltraLightRateLimiter::new(100., get_ticker(time_ticks));

        // trying to get 1000 permits a second. only 100 should be granted
        for _ in 0..100 {
            assert!(rate_limiter.try_acquire(), "Must grant a permit");
        }
        for _ in 100..1000 {
            assert!(!rate_limiter.try_acquire(), "Must not grant a permit");
        }
        // the second second
        assert!(rate_limiter.try_acquire(), "Must grant a permit");
    }

    #[test]
    fn test_round_down() {
        let rate_limiter = UltraLightRateLimiter::new(2.99, get_ticker(vec![0, 500, 600, 1000]));

        assert!(rate_limiter.try_acquire(), "Must grant a permit");
        assert!(rate_limiter.try_acquire(), "Must grant a permit");
        assert!(!rate_limiter.try_acquire(), "Must not grant a permit");
        assert!(rate_limiter.try_acquire(), "Must grant a permit");
    }

    #[test]
    fn test_once_per_minute() {
        let rate_limiter =
            UltraLightRateLimiter::new(1. / 60 as f64, get_ticker(vec![0, 30_000, 50_000, 60_000]));

        assert!(rate_limiter.try_acquire(), "Must grant a permit");
        assert!(!rate_limiter.try_acquire(), "Must not grant a permit");
        assert!(!rate_limiter.try_acquire(), "Must not grant a permit");
        assert!(rate_limiter.try_acquire(), "Must grant a permit");
    }

    #[test]
    fn test_twice_per_minute() {
        let rate_limiter =
            UltraLightRateLimiter::new(2. / 60 as f64, get_ticker(vec![0, 30_000, 50_000, 60_000]));

        assert!(rate_limiter.try_acquire(), "Must grant a permit");
        assert!(rate_limiter.try_acquire(), "Must grant a permit");
        assert!(!rate_limiter.try_acquire(), "Must not grant a permit");
        assert!(rate_limiter.try_acquire(), "Must grant a permit");
    }

    #[test]
    fn test_time_stamp_overflow() {
        let time = 10_000 * 0xffff_ffff;
        let rate_limiter = UltraLightRateLimiter::new(
            2.,
            get_ticker(vec![time, time + 100, time + 500, time + 1000]),
        );

        assert!(rate_limiter.try_acquire(), "Must grant a permit");
        assert!(rate_limiter.try_acquire(), "Must grant a permit");
        assert!(!rate_limiter.try_acquire(), "Must not grant a permit");
        assert!(rate_limiter.try_acquire(), "Must grant a permit");
    }

    #[test]
    fn test_try_acquire_value() {
        let rate_limiter = UltraLightRateLimiter::new(1., get_ticker(vec![0, 500, 1000]));

        assert_eq!(
            rate_limiter.try_acquire_value(1),
            Some(1),
            "Must grant a permit"
        );
        assert!(
            rate_limiter.try_acquire_value(2).is_none(),
            "Must not grant a permit"
        );
        assert_eq!(
            rate_limiter.try_acquire_value(3),
            Some(3),
            "Must grant a permit"
        );
    }

    // to enable parallel execution of tests
    thread_local! {
        static VALUES: RefCell<Option<Vec<u64>>> = RefCell::new(None);
        static INDEX: RefCell<usize> = RefCell::new(0);
    }

    fn get_ticker(time_points: Vec<u64>) -> fn() -> u64 {
        INDEX.with(|idx| {
            *idx.borrow_mut() = 0;
        });
        VALUES.with(|vec| {
            *vec.borrow_mut() = Some(time_points);
        });
        get_time
    }

    fn get_time() -> u64 {
        let index = INDEX.with(|idx| {
            let current_index = *idx.borrow();
            *idx.borrow_mut() += 1;
            current_index
        });
        let value = VALUES.with(|vec| {
            let values = vec.borrow();
            values.as_ref().unwrap()[index]
        });
        value
    }
}
