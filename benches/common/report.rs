//! Benchmark reporting utilities.
//!
//! Produces structured summaries of benchmark results for CI/CD integration
//! and human-readable terminal output.

use std::collections::BTreeMap;
use std::time::Duration;

/// A single benchmark measurement for custom reporting.
#[derive(Debug, Clone, serde::Serialize)]
pub struct Measurement {
    pub name: String,
    pub group: String,
    pub iterations: u64,
    pub total_time_ns: u64,
    pub mean_ns: f64,
    pub throughput_ops_sec: f64,
    pub notes: Option<String>,
}

impl Measurement {
    pub fn new(name: &str, group: &str, iterations: u64, total: Duration) -> Self {
        let total_ns = total.as_nanos() as u64;
        let mean_ns = total_ns as f64 / iterations as f64;
        let throughput = if total.as_secs_f64() > 0.0 {
            iterations as f64 / total.as_secs_f64()
        } else {
            0.0
        };
        Self {
            name: name.to_string(),
            group: group.to_string(),
            iterations,
            total_time_ns: total_ns,
            mean_ns,
            throughput_ops_sec: throughput,
            notes: None,
        }
    }

    pub fn with_note(mut self, note: &str) -> Self {
        self.notes = Some(note.to_string());
        self
    }
}

/// Accumulates measurements and produces reports.
#[derive(Debug, Default, serde::Serialize)]
pub struct BenchReport {
    pub suite_name: String,
    pub timestamp: String,
    pub measurements: Vec<Measurement>,
}

impl BenchReport {
    pub fn new(suite_name: &str) -> Self {
        Self {
            suite_name: suite_name.to_string(),
            timestamp: chrono::Utc::now().to_rfc3339(),
            measurements: Vec::new(),
        }
    }

    pub fn add(&mut self, m: Measurement) {
        self.measurements.push(m);
    }

    /// Produce a grouped summary table as a string.
    pub fn summary(&self) -> String {
        let mut groups: BTreeMap<&str, Vec<&Measurement>> = BTreeMap::new();
        for m in &self.measurements {
            groups.entry(&m.group).or_default().push(m);
        }

        let mut out = String::new();
        out.push_str(&format!(
            "\n╔══════════════════════════════════════════════════════════════╗\n"
        ));
        out.push_str(&format!(
            "║  R0N-Ingress Benchmark Report: {:<30}║\n",
            self.suite_name
        ));
        out.push_str(&format!("║  Timestamp: {:<48}║\n", self.timestamp));
        out.push_str(&format!(
            "╚══════════════════════════════════════════════════════════════╝\n\n"
        ));

        for (group, measurements) in &groups {
            out.push_str(&format!("── {} ──\n", group));
            out.push_str(&format!(
                "  {:<40} {:>12} {:>14}\n",
                "Benchmark", "Mean (ns)", "Throughput"
            ));
            out.push_str(&format!("  {}\n", "─".repeat(68)));
            for m in measurements {
                let tp = if m.throughput_ops_sec > 1_000_000.0 {
                    format!("{:.2}M ops/s", m.throughput_ops_sec / 1_000_000.0)
                } else if m.throughput_ops_sec > 1_000.0 {
                    format!("{:.2}K ops/s", m.throughput_ops_sec / 1_000.0)
                } else {
                    format!("{:.2} ops/s", m.throughput_ops_sec)
                };
                out.push_str(&format!(
                    "  {:<40} {:>12.1} {:>14}\n",
                    m.name, m.mean_ns, tp
                ));
            }
            out.push('\n');
        }
        out
    }

    /// Serialize the report to JSON for CI integration.
    pub fn to_json(&self) -> String {
        serde_json::to_string_pretty(self).unwrap_or_default()
    }
}
