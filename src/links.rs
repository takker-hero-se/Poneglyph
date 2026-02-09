use anyhow::{Context, Result};
use indicatif::{ProgressBar, ProgressStyle};
use std::collections::HashMap;

use crate::ese::NtdsDatabase;
use crate::objects::{get_i32_value};

/// Resolve group memberships from the link_table.
///
/// Returns a map: group_DNT → Vec<member_DNT>
///
/// link_table columns:
///   - link_DNT: the group's DNT
///   - backlink_DNT: the member's DNT
///   - link_base: attribute ID (1 = member/memberOf)
pub fn resolve_group_memberships(db: &NtdsDatabase) -> Result<HashMap<i32, Vec<i32>>> {
    let table = db.link_table()
        .context("Failed to open link_table")?;

    let record_count = table.count_records()
        .context("Failed to count link_table records")?;

    log::info!("Scanning {} link_table records for group memberships...", record_count);

    // Find column indices by name
    let col_count = table.count_columns().unwrap_or(0);
    let mut link_dnt_col: Option<i32> = None;
    let mut backlink_dnt_col: Option<i32> = None;
    let mut link_base_col: Option<i32> = None;

    for i in 0..col_count {
        if let Ok(col) = table.column(i) {
            if let Ok(name) = col.name() {
                match name.as_str() {
                    "link_DNT" => link_dnt_col = Some(i),
                    "backlink_DNT" => backlink_dnt_col = Some(i),
                    "link_base" => link_base_col = Some(i),
                    _ => {}
                }
            }
        }
    }

    if link_dnt_col.is_none() || backlink_dnt_col.is_none() {
        log::warn!("link_table columns not found. Columns available:");
        for i in 0..col_count {
            if let Ok(col) = table.column(i) {
                if let Ok(name) = col.name() {
                    log::warn!("  col {}: {}", i, name);
                }
            }
        }
        anyhow::bail!("Cannot find link_DNT/backlink_DNT columns in link_table");
    }

    let pb = ProgressBar::new(record_count as u64);
    pb.set_style(
        ProgressStyle::default_bar()
            .template("[{elapsed_precise}] {bar:40.magenta/dark_gray} {pos}/{len} links ({per_sec})")
            .unwrap()
            .progress_chars("=> "),
    );

    let mut memberships: HashMap<i32, Vec<i32>> = HashMap::new();

    for i in 0..record_count {
        pb.inc(1);

        let record = match table.record(i) {
            Ok(r) => r,
            Err(_) => continue,
        };

        // link_base = 1 means member/memberOf relationship
        if let Some(base) = get_i32_value(&record, link_base_col) {
            if base != 1 {
                continue;
            }
        }

        let group_dnt = match get_i32_value(&record, link_dnt_col) {
            Some(d) => d,
            None => continue,
        };

        let member_dnt = match get_i32_value(&record, backlink_dnt_col) {
            Some(d) => d,
            None => continue,
        };

        memberships.entry(group_dnt).or_default().push(member_dnt);
    }

    pb.finish_with_message(format!(
        "Resolved {} groups with {} total membership links",
        memberships.len(),
        memberships.values().map(|v| v.len()).sum::<usize>()
    ));

    Ok(memberships)
}
