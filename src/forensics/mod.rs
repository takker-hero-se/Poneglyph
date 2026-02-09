pub mod tombstone;
pub mod anomaly;

use anyhow::Result;
use serde::{Serialize, Deserialize};
use std::collections::HashMap;
use std::path::Path;

use crate::ese::NtdsDatabase;
use crate::objects::user::AdUser;
use crate::objects::computer::AdComputer;
use crate::objects::group::AdGroup;
use crate::acl::AceEntry;

#[derive(Debug, Serialize, Deserialize)]
pub struct ForensicsReport {
    pub metadata: ReportMetadata,
    pub deleted_objects: tombstone::DeletedObjects,
    pub findings: Vec<anomaly::Finding>,
    pub summary: ReportSummary,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ReportMetadata {
    pub tool: String,
    pub version: String,
    pub timestamp: String,
    pub ntds_path: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ReportSummary {
    pub total_findings: usize,
    pub critical_count: usize,
    pub high_count: usize,
    pub medium_count: usize,
    pub low_count: usize,
    pub info_count: usize,
    pub deleted_users: usize,
    pub deleted_computers: usize,
    pub deleted_groups: usize,
}

/// Run the full forensics analysis pipeline.
pub fn run_forensics(
    db: &NtdsDatabase,
    users: &[AdUser],
    computers: &[AdComputer],
    groups: &[AdGroup],
    aces_by_sid: &HashMap<String, Vec<AceEntry>>,
    ntds_path: &Path,
) -> Result<ForensicsReport> {
    // Phase A: Tombstone recovery
    let deleted_objects = tombstone::extract_deleted_objects(db)?;

    // Phase B: Anomaly detection
    let findings = anomaly::run_all_rules(users, computers, groups, aces_by_sid)?;

    let summary = ReportSummary {
        total_findings: findings.len(),
        critical_count: findings.iter().filter(|f| f.severity == anomaly::Severity::Critical).count(),
        high_count: findings.iter().filter(|f| f.severity == anomaly::Severity::High).count(),
        medium_count: findings.iter().filter(|f| f.severity == anomaly::Severity::Medium).count(),
        low_count: findings.iter().filter(|f| f.severity == anomaly::Severity::Low).count(),
        info_count: findings.iter().filter(|f| f.severity == anomaly::Severity::Info).count(),
        deleted_users: deleted_objects.users.len(),
        deleted_computers: deleted_objects.computers.len(),
        deleted_groups: deleted_objects.groups.len(),
    };

    Ok(ForensicsReport {
        metadata: ReportMetadata {
            tool: "poneglyph".to_string(),
            version: env!("CARGO_PKG_VERSION").to_string(),
            timestamp: chrono::Utc::now().to_rfc3339(),
            ntds_path: ntds_path.display().to_string(),
        },
        deleted_objects,
        findings,
        summary,
    })
}

/// Print the summary table to stdout.
pub fn print_summary(report: &ForensicsReport) {
    println!("\n=== Forensics Report Summary ===\n");

    println!("Deleted Objects Recovered:");
    println!("  Users:     {}", report.deleted_objects.users.len());
    println!("  Computers: {}", report.deleted_objects.computers.len());
    println!("  Groups:    {}", report.deleted_objects.groups.len());

    println!("\nSecurity Findings:");
    println!("  {:>10}  {:>5}", "Severity", "Count");
    println!("  {}", "-".repeat(18));
    if report.summary.critical_count > 0 {
        println!("  {:>10}  {:>5}", "CRITICAL", report.summary.critical_count);
    }
    if report.summary.high_count > 0 {
        println!("  {:>10}  {:>5}", "HIGH", report.summary.high_count);
    }
    if report.summary.medium_count > 0 {
        println!("  {:>10}  {:>5}", "MEDIUM", report.summary.medium_count);
    }
    if report.summary.low_count > 0 {
        println!("  {:>10}  {:>5}", "LOW", report.summary.low_count);
    }
    if report.summary.info_count > 0 {
        println!("  {:>10}  {:>5}", "INFO", report.summary.info_count);
    }
    println!("  {}", "-".repeat(18));
    println!("  {:>10}  {:>5}", "TOTAL", report.summary.total_findings);

    println!("\nFindings Detail:");
    for (i, f) in report.findings.iter().enumerate() {
        println!("  {}. [{}] {}: {}",
            i + 1,
            f.severity.as_str(),
            f.rule_id,
            f.title,
        );
        if !f.affected_objects.is_empty() {
            let preview: Vec<&str> = f.affected_objects.iter()
                .take(5)
                .map(|o| o.name.as_str())
                .collect();
            let more = if f.affected_objects.len() > 5 {
                format!(" (+{} more)", f.affected_objects.len() - 5)
            } else {
                String::new()
            };
            println!("     Affected: {}{}", preview.join(", "), more);
        }
    }
}

/// Write the forensics report to a JSON file.
pub fn write_report(report: &ForensicsReport, output_path: &Path) -> Result<()> {
    let content = serde_json::to_string_pretty(report)?;
    std::fs::write(output_path, &content)?;
    log::info!("Forensics report written to {}", output_path.display());
    Ok(())
}
