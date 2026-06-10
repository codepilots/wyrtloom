/// Behavioural baseline interface — the anomaly authority consumed by
/// CG-20 (design-defect signals) and CG-25 (novelty interest signals).
/// The anomaly rule is coded and deterministic (CG-4): rolling per-metric
/// statistics with a k-sigma threshold, never an LLM judgement.
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::sync::Mutex;

/// One observed behaviour sample, e.g. ("parser", "p95_latency_ms", 41.0).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Observation {
    pub component: String,
    pub metric: String,
    pub value: f64,
}

impl Observation {
    pub fn new(component: impl Into<String>, metric: impl Into<String>, value: f64) -> Self {
        Self { component: component.into(), metric: metric.into(), value }
    }

    /// Deterministic one-line rendering for signals and audit details.
    pub fn describe(&self) -> String {
        format!("{}/{} = {}", self.component, self.metric, self.value)
    }
}

pub trait BehaviouralBaseline: Send + Sync {
    /// Is this observation anomalous against the learned baseline?
    /// Must be deterministic for a given baseline state (CG-4).
    fn is_anomalous(&self, observation: &Observation) -> bool;
}

/// Below this many samples the baseline refuses to call anything anomalous
/// — an unlearned baseline must not generate false alarms.
pub const MIN_SAMPLES: usize = 5;

/// An observation further than this many standard deviations from the mean
/// is anomalous.
pub const SIGMA_THRESHOLD: f64 = 3.0;

/// Rolling baseline: per (component, metric) sample history with a k-sigma
/// anomaly rule.
#[derive(Default)]
pub struct RollingBaseline {
    samples: Mutex<BTreeMap<(String, String), Vec<f64>>>,
}

impl RollingBaseline {
    pub fn new() -> Self {
        Self::default()
    }

    /// Feed the baseline. Recording and checking are separate on purpose:
    /// an anomalous observation can be checked first and recorded after,
    /// so a burst of anomalies does not silently become the new normal
    /// before anyone has looked at it.
    pub fn record(&self, observation: &Observation) {
        self.samples
            .lock()
            .unwrap()
            .entry((observation.component.clone(), observation.metric.clone()))
            .or_default()
            .push(observation.value);
    }

    pub fn sample_count(&self, component: &str, metric: &str) -> usize {
        self.samples
            .lock()
            .unwrap()
            .get(&(component.to_string(), metric.to_string()))
            .map(|v| v.len())
            .unwrap_or(0)
    }

    fn mean_and_stddev(values: &[f64]) -> (f64, f64) {
        let n = values.len() as f64;
        let mean = values.iter().sum::<f64>() / n;
        let variance = values.iter().map(|v| (v - mean).powi(2)).sum::<f64>() / n;
        (mean, variance.sqrt())
    }
}

impl BehaviouralBaseline for RollingBaseline {
    fn is_anomalous(&self, observation: &Observation) -> bool {
        let samples = self.samples.lock().unwrap();
        let Some(values) =
            samples.get(&(observation.component.clone(), observation.metric.clone()))
        else {
            return false;
        };
        if values.len() < MIN_SAMPLES {
            return false;
        }
        let (mean, stddev) = Self::mean_and_stddev(values);
        if stddev == 0.0 {
            // A perfectly flat history: any departure at all is anomalous.
            (observation.value - mean).abs() > f64::EPSILON
        } else {
            (observation.value - mean).abs() > SIGMA_THRESHOLD * stddev
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn trained_baseline() -> RollingBaseline {
        let b = RollingBaseline::new();
        for value in [10.0, 11.0, 9.0, 10.5, 9.5, 10.0] {
            b.record(&Observation::new("parser", "latency_ms", value));
        }
        b
    }

    #[test]
    fn unlearned_baseline_calls_nothing_anomalous() {
        let b = RollingBaseline::new();
        assert!(!b.is_anomalous(&Observation::new("parser", "latency_ms", 1_000_000.0)));
        for value in [10.0, 10.0, 10.0] {
            b.record(&Observation::new("parser", "latency_ms", value));
        }
        // Still under MIN_SAMPLES.
        assert!(!b.is_anomalous(&Observation::new("parser", "latency_ms", 1_000_000.0)));
    }

    #[test]
    fn far_outliers_are_anomalous_in_band_values_are_not() {
        let b = trained_baseline();
        assert!(b.is_anomalous(&Observation::new("parser", "latency_ms", 50.0)));
        assert!(!b.is_anomalous(&Observation::new("parser", "latency_ms", 10.2)));
    }

    #[test]
    fn flat_history_flags_any_departure() {
        let b = RollingBaseline::new();
        for _ in 0..6 {
            b.record(&Observation::new("bus", "queue_depth", 0.0));
        }
        assert!(b.is_anomalous(&Observation::new("bus", "queue_depth", 1.0)));
        assert!(!b.is_anomalous(&Observation::new("bus", "queue_depth", 0.0)));
    }

    #[test]
    fn metrics_are_isolated_from_each_other() {
        let b = trained_baseline();
        // A different metric on the same component has no history.
        assert!(!b.is_anomalous(&Observation::new("parser", "error_rate", 99.0)));
    }

    #[test]
    fn cg4_anomaly_check_is_deterministic() {
        let b = trained_baseline();
        let obs = Observation::new("parser", "latency_ms", 50.0);
        assert_eq!(b.is_anomalous(&obs), b.is_anomalous(&obs));
    }
}
