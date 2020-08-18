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
use crate::http_token_utils::{http_token, HttpToken};
use crate::request_analyzer::{HttpRequestData, RequestAnalysisResult};
use crate::ultralight_rate_limiter::UltraLightRateLimiter;
use crate::{
    ClassificationReason, ExtClassificationMetricsSettings, ExtLoggingSettings,
    ExtRequestAnalysisMetricsUnit, ExtString, ExtTierMetricsSettings, RequestSafetyTier,
    MESSAGE_MAX_SIZE,
};
use core::hash::Hash;
use lazy_static::lazy_static;
use smallvec::SmallVec;
use std::collections::HashMap;
use std::sync::atomic::AtomicPtr;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::time::Instant;

const LOG_MESSAGE_RATE_LIMIT: f64 = 100. / 1.;
/// How many entries we keep on stack before spilling over to the heap.
const METRICS_VECTOR_SIZE: usize = 128;
pub const MONITORED_METHODS: &[&str] = &[
    "GET", "PUT", "POST", "PATCH", "DELETE", "HEAD", "OPTIONS", "OTHER",
];

/// Static logging settings (initialized once by an external caller).
static LOGGER_SETTINGS: AtomicSettings<LoggingSettings> = AtomicSettings::empty();
static TIER_METRICS_SETTINGS: AtomicSettings<TierMetricsSettings> = AtomicSettings::empty();
static CLASSIFICATION_METRICS_SETTINGS: AtomicSettings<ClassificationMetricsSettings> =
    AtomicSettings::empty();

pub struct AtomicSettings<T> {
    settings: AtomicPtr<T>,
}

impl<T> AtomicSettings<T> {
    pub const fn empty() -> Self {
        Self {
            settings: AtomicPtr::new(std::ptr::null_mut()),
        }
    }

    #[inline(always)]
    pub fn get(&self) -> Option<&'static T> {
        let ptr = self.settings.load(Ordering::Relaxed);
        if ptr.is_null() {
            None
        } else {
            // a pointer is set only once, that's why it's safe to dereference it
            unsafe { Some(&(*ptr)) }
        }
    }

    /// A test version of the `store` method that always sets the value
    #[cfg(test)]
    pub fn store(&self, new_value: T) -> Result<(), &str> {
        // in tests we allow to re-write the value
        self.settings
            .store(Box::into_raw(Box::new(new_value)), Ordering::Relaxed);
        Ok(())
    }

    /// Sets the value if it was not set before.
    #[cfg(not(test))]
    // cov: begin-ignore-line
    pub fn store(&self, new_value: T) -> Result<(), &str> {
        // we allow the value to be set only once in production
        // to avoid dealing with race conditions during swaps
        // or overhead to ensure there are no race conditions
        // a simple model - write once, read-only afterwards
        // value is set only if settings were originally null.
        if self
            .settings
            .compare_and_swap(
                std::ptr::null_mut(),
                Box::into_raw(Box::new(new_value)),
                Ordering::Relaxed,
            )
            .is_null()
        {
            Ok(())
        } else {
            Err("Can be set only once.")
        }
    }
    // cov: end-ignore-line
}

lazy_static! {
    pub static ref TIER_STATS: RequestAnalysisStatisticsStore<RequestSafetyTier> =
        RequestAnalysisStatisticsStore::<RequestSafetyTier>::new();
}

lazy_static! {
    pub static ref CLASSIFICATION_STATS: RequestAnalysisStatisticsStore<ClassificationReason> =
        RequestAnalysisStatisticsStore::<ClassificationReason>::new();
}

lazy_static! {
    pub static ref START_TIME: Instant = Instant::now();
}

/// Logging settings
pub struct LoggingSettings {
    rate_limiter: UltraLightRateLimiter,
    callback: extern "C" fn(RequestSafetyTier, u32, *const u8),
}

/// Request Safety Tier metrics settings
pub struct TierMetricsSettings {
    rate_limiter: UltraLightRateLimiter,
    callback: extern "C" fn(u32, *const ExtRequestAnalysisMetricsUnit<RequestSafetyTier>),
}

/// Classification Reason metrics settings
pub struct ClassificationMetricsSettings {
    rate_limiter: UltraLightRateLimiter,
    callback: extern "C" fn(u32, *const ExtRequestAnalysisMetricsUnit<ClassificationReason>),
}

pub struct RequestAnalysisCounterPerMethod<T>
where
    T: Hash + Eq + strum::IntoEnumIterator,
{
    method: HttpToken<'static>,
    counters_map: HashMap<T, AtomicU32>,
}

/// Unit structure for emitting Metrics.
pub struct RequestAnalysisMetricsUnit<T>
where
    T: Hash + Eq,
{
    /// Method name
    pub method: HttpToken<'static>,
    /// Request safety tier.
    pub counter_type: T,
    /// Count for the request safety tier.
    pub count: u32,
}

/// Contains aggregated statistics for processing requests metrics in a HashMap.
/// Such as counter per category, rejection reasons, etc.
/// Mapped to the corresponding RequestSafetyTier.
pub struct RequestAnalysisStatisticsStore<T>
where
    T: Hash + Eq + strum::IntoEnumIterator,
{
    stats: Vec<RequestAnalysisCounterPerMethod<T>>,
}

pub trait CounterType {
    fn get_counter_type(result: &RequestAnalysisResult) -> Self;
}

impl CounterType for RequestSafetyTier {
    #[cfg_attr(feature = "coverage", inline(never))]
    #[cfg_attr(not(feature = "coverage"), inline(always))]
    fn get_counter_type(result: &RequestAnalysisResult) -> Self {
        result.tier
    }
}

impl CounterType for ClassificationReason {
    #[cfg_attr(feature = "coverage", inline(never))]
    #[cfg_attr(not(feature = "coverage"), inline(always))]
    fn get_counter_type(result: &RequestAnalysisResult) -> Self {
        result.reason
    }
}

pub trait MetricsCallback<T>
where
    T: Hash + Eq,
{
    fn is_enabled() -> bool;
    fn get_metrics_callback() -> Option<extern "C" fn(u32, *const ExtRequestAnalysisMetricsUnit<T>)>;
}

impl MetricsCallback<RequestSafetyTier> for RequestSafetyTier {
    #[inline(always)]
    fn is_enabled() -> bool {
        TierMetricsSettings::get().is_some()
    }

    #[inline(always)]
    fn get_metrics_callback(
    ) -> Option<extern "C" fn(u32, *const ExtRequestAnalysisMetricsUnit<RequestSafetyTier>)> {
        if let Some(settings) = TierMetricsSettings::get() {
            settings.rate_limiter.try_acquire_value(settings.callback)
        } else {
            None
        }
    }
}

impl MetricsCallback<ClassificationReason> for ClassificationReason {
    #[inline(always)]
    fn is_enabled() -> bool {
        ClassificationMetricsSettings::get().is_some()
    }

    #[inline(always)]
    fn get_metrics_callback(
    ) -> Option<extern "C" fn(u32, *const ExtRequestAnalysisMetricsUnit<ClassificationReason>)>
    {
        if let Some(settings) = ClassificationMetricsSettings::get() {
            settings.rate_limiter.try_acquire_value(settings.callback)
        } else {
            None
        }
    }
}

impl LoggingSettings {
    /// Initializes the logging settings.
    /// The function is expected to be called once, any subsequent calls don't change the settings.
    ///
    /// # Parameters
    /// `settings` - a settings struct
    /// The `callback` must be non-null.
    pub fn set(settings: &ExtLoggingSettings) -> Result<(), &str> {
        let callback = settings
            .callback
            .expect("Callback to send logs is required");
        let settings = LoggingSettings {
            rate_limiter: UltraLightRateLimiter::new(
                LOG_MESSAGE_RATE_LIMIT,
                get_current_time_millis,
            ),
            callback,
        };
        LOGGER_SETTINGS.store(settings)
    }

    #[inline(always)]
    pub fn log_message(tier: RequestSafetyTier, msg: &str) {
        if let Some(s) = LOGGER_SETTINGS.get() {
            s.try_log_message(tier, msg);
        }
    }

    #[inline(always)]
    fn try_log_message(&self, tier: RequestSafetyTier, msg: &str) {
        if self.rate_limiter.try_acquire() {
            (self.callback)(tier, msg.len().min(MESSAGE_MAX_SIZE) as u32, msg.as_ptr());
        }
    }
}

impl TierMetricsSettings {
    /// Initializes Request Safety Tier Metrics settings.
    /// The function is expected to be called once, any subsequent calls don't change the settings.
    ///
    /// # Parameters
    /// `settings` - a settings struct
    /// This method will copy the values (so the original pointers may be freed).
    /// The `callback` must be non-null.
    pub fn set(settings: &ExtTierMetricsSettings) -> Result<(), &str> {
        let period_seconds = settings.period_seconds;
        let callback = settings
            .callback
            .expect("Callback to send tier metrics is required");

        let settings = TierMetricsSettings {
            rate_limiter: UltraLightRateLimiter::new(
                1. / period_seconds as f64,
                get_current_time_millis,
            ),
            callback,
        };
        TIER_METRICS_SETTINGS.store(settings)
    }

    #[inline(always)]
    fn get() -> Option<&'static Self> {
        TIER_METRICS_SETTINGS.get()
    }
}

impl ClassificationMetricsSettings {
    /// Initializes Classification Reason Metrics settings.
    /// The function is expected to be called once, any subsequent calls don't change the settings.
    ///
    /// # Parameters
    /// `settings` - a settings struct
    /// This method will copy the values (so the original pointers may be freed).
    /// The `callback` must be non-null.
    pub fn set(settings: &ExtClassificationMetricsSettings) -> Result<(), &str> {
        let period_seconds = settings.period_seconds;
        let callback = settings
            .callback
            .expect("Callback to send classification metrics is required");

        let settings = ClassificationMetricsSettings {
            rate_limiter: UltraLightRateLimiter::new(
                1. / period_seconds as f64,
                get_current_time_millis,
            ),
            callback,
        };
        CLASSIFICATION_METRICS_SETTINGS.store(settings)
    }

    #[inline(always)]
    fn get() -> Option<&'static Self> {
        CLASSIFICATION_METRICS_SETTINGS.get()
    }
}

impl<T: strum::IntoEnumIterator> RequestAnalysisCounterPerMethod<T>
where
    T: Hash + Eq,
{
    fn new(method: HttpToken<'static>) -> Self {
        let counters_map = T::iter().map(|tier| (tier, Default::default())).collect();

        Self {
            method,
            counters_map,
        }
    }
}

impl<T> RequestAnalysisStatisticsStore<T>
where
    T: Hash + Eq + CounterType + MetricsCallback<T> + strum::IntoEnumIterator + std::fmt::Debug,
{
    fn new() -> Self {
        let stats = MONITORED_METHODS
            .iter()
            .map(|method| RequestAnalysisCounterPerMethod::<T>::new(http_token(method)))
            .collect();

        Self { stats }
    }

    pub fn update_counters(&self, request: &HttpRequestData, result: &RequestAnalysisResult) {
        if !<T as self::MetricsCallback<T>>::is_enabled() {
            // if metrics were not initialized, do nothing
            // as the app is supposed to handle logs/metrics itself
            return;
        }
        // This lookup is 5x-20x faster than HashMap
        // for a small set of methods.
        let counters = self
            .stats
            .iter()
            .find(|m| m.method == request.method)
            .unwrap_or(&self.stats[self.stats.len() - 1]);

        let counter_type = &counters.counters_map[&self::CounterType::get_counter_type(result)];
        counter_type.fetch_add(1, Ordering::Relaxed);

        self.emit_granular_metrics_event();
    }

    pub fn get_and_reset_metrics_snapshot(
        &self,
    ) -> SmallVec<[RequestAnalysisMetricsUnit<T>; METRICS_VECTOR_SIZE]> {
        let mut metrics_collection = SmallVec::new();

        // Iterate through the stats vector and extract relevant tier counts
        // for all the methods to aggregate them
        self.stats.iter().for_each(|counter_aggregate| {
            for counter_type in T::iter() {
                let count =
                    counter_aggregate.counters_map[&counter_type].fetch_and(0, Ordering::Relaxed);
                if count > 0 {
                    metrics_collection.push(RequestAnalysisMetricsUnit {
                        method: counter_aggregate.method,
                        counter_type,
                        count,
                    })
                }
            }
        });

        metrics_collection
    }

    fn emit_granular_metrics_event(&self) {
        if let Some(metrics_callback) = <T as self::MetricsCallback<T>>::get_metrics_callback() {
            let snapshot: SmallVec<[ExtRequestAnalysisMetricsUnit<T>; METRICS_VECTOR_SIZE]> = self
                .get_and_reset_metrics_snapshot()
                .into_iter()
                .map(|item| {
                    ExtRequestAnalysisMetricsUnit::<T>::new(
                        ExtString::from_http_token(item.method),
                        item.counter_type,
                        item.count,
                    )
                })
                .collect();

            if !snapshot.is_empty() {
                (metrics_callback)(snapshot.len() as u32, snapshot.as_ptr());
            }
        }
    }
}

impl<T> ExtRequestAnalysisMetricsUnit<T>
where
    T: Hash + Eq,
{
    fn new(method: ExtString, counter_type: T, count: u32) -> Self {
        Self {
            method,
            counter_type,
            count,
        }
    }
}

/// Monotonic clock function, returning `ms` since startup.
/// Makes a system call only in 1/16 of cases (coarse-grained time, good enough)
static LAST_TIME: AtomicU64 = AtomicU64::new(0);
#[cfg(not(test))]
static SKIPS: AtomicU64 = AtomicU64::new(0);

#[cfg(not(test))]
// cov: begin-ignore-line
fn get_current_time_millis() -> u64 {
    let start_time = *START_TIME;
    let x = SKIPS.fetch_add(1, Ordering::Relaxed);
    if x > LOG_MESSAGE_RATE_LIMIT as u64 >> 4 {
        SKIPS.fetch_and(0, Ordering::Relaxed);
    }
    if x == 1 {
        let current = Instant::now()
            .saturating_duration_since(start_time)
            .as_millis() as u64;
        LAST_TIME.store(current, Ordering::Relaxed);
        current
    } else {
        LAST_TIME.load(Ordering::Relaxed)
    }
}
// cov: end-ignore-line

#[cfg(test)]
fn get_current_time_millis() -> u64 {
    let current = LAST_TIME.load(Ordering::Relaxed);
    // move by 10 seconds in tests on each call
    LAST_TIME.store(current + 10_000, Ordering::Relaxed);
    current
}
