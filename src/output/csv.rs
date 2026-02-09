use anyhow::Result;
use std::io::Write;
use std::path::Path;

use crate::objects::user::AdUser;
use crate::objects::computer::AdComputer;
use crate::objects::group::AdGroup;
use crate::forensics::tombstone::DeletedObjects;

/// A timeline event entry.
struct TimelineEntry {
    datetime: String,
    timestamp_desc: String,
    source: String,
    message: String,
    extra: String,
}

/// Write a forensic timeline CSV from all AD objects.
/// Format is compatible with plaso / GolDRoger CSV ingestion.
pub fn write_timeline(
    output_path: &Path,
    users: &[AdUser],
    computers: &[AdComputer],
    groups: &[AdGroup],
) -> Result<()> {
    let mut entries = Vec::new();

    // User timeline events
    for u in users {
        let base_extra = format!("sam={} sid={} enabled={}",
            u.sam_account_name,
            u.sid.as_deref().unwrap_or("-"),
            u.enabled,
        );

        if let Some(ref ts) = u.when_created {
            entries.push(TimelineEntry {
                datetime: ts.clone(),
                timestamp_desc: "Creation Time".to_string(),
                source: "NTDS-User".to_string(),
                message: format!("User '{}' created", u.sam_account_name),
                extra: base_extra.clone(),
            });
        }
        if let Some(ref ts) = u.when_changed {
            entries.push(TimelineEntry {
                datetime: ts.clone(),
                timestamp_desc: "Modification Time".to_string(),
                source: "NTDS-User".to_string(),
                message: format!("User '{}' modified", u.sam_account_name),
                extra: base_extra.clone(),
            });
        }
        if let Some(ref ts) = u.pwd_last_set {
            entries.push(TimelineEntry {
                datetime: ts.clone(),
                timestamp_desc: "Password Change".to_string(),
                source: "NTDS-User".to_string(),
                message: format!("User '{}' password changed", u.sam_account_name),
                extra: base_extra.clone(),
            });
        }
        if let Some(ref ts) = u.last_logon_timestamp {
            entries.push(TimelineEntry {
                datetime: ts.clone(),
                timestamp_desc: "Last Logon".to_string(),
                source: "NTDS-User".to_string(),
                message: format!("User '{}' last logon (replicated)", u.sam_account_name),
                extra: base_extra.clone(),
            });
        }
    }

    // Computer timeline events
    for c in computers {
        let base_extra = format!("sam={} sid={} os={}",
            c.sam_account_name,
            c.sid.as_deref().unwrap_or("-"),
            c.operating_system.as_deref().unwrap_or("-"),
        );

        if let Some(ref ts) = c.when_created {
            entries.push(TimelineEntry {
                datetime: ts.clone(),
                timestamp_desc: "Creation Time".to_string(),
                source: "NTDS-Computer".to_string(),
                message: format!("Computer '{}' joined domain",
                    c.dns_hostname.as_deref().unwrap_or(&c.sam_account_name)),
                extra: base_extra.clone(),
            });
        }
        if let Some(ref ts) = c.last_logon_timestamp {
            entries.push(TimelineEntry {
                datetime: ts.clone(),
                timestamp_desc: "Last Logon".to_string(),
                source: "NTDS-Computer".to_string(),
                message: format!("Computer '{}' last logon",
                    c.dns_hostname.as_deref().unwrap_or(&c.sam_account_name)),
                extra: base_extra.clone(),
            });
        }
    }

    // Group timeline events
    for g in groups {
        if let Some(ref ts) = g.when_created {
            entries.push(TimelineEntry {
                datetime: ts.clone(),
                timestamp_desc: "Creation Time".to_string(),
                source: "NTDS-Group".to_string(),
                message: format!("Group '{}' created", g.sam_account_name),
                extra: format!("sid={} type={}",
                    g.sid.as_deref().unwrap_or("-"),
                    g.group_type_flags.join(",")),
            });
        }
    }

    // Sort by datetime
    entries.sort_by(|a, b| a.datetime.cmp(&b.datetime));

    // Write CSV
    let mut file = std::fs::File::create(output_path)?;
    writeln!(file, "datetime,timestamp_desc,source,source_long,message,filename,inode,format,extra")?;
    for e in &entries {
        writeln!(file, "{},{},{},Active Directory,{},ntds.dit,-,ntds,{}",
            csv_escape(&e.datetime),
            csv_escape(&e.timestamp_desc),
            csv_escape(&e.source),
            csv_escape(&e.message),
            csv_escape(&e.extra),
        )?;
    }

    log::info!("Written {} timeline events to {}", entries.len(), output_path.display());
    Ok(())
}

/// Write a forensic timeline CSV that includes deleted/tombstone objects.
pub fn write_forensics_timeline(
    output_path: &Path,
    users: &[AdUser],
    computers: &[AdComputer],
    groups: &[AdGroup],
    deleted: Option<&DeletedObjects>,
) -> Result<()> {
    let mut entries = Vec::new();

    // Live user events
    for u in users {
        let base_extra = format!("sam={} sid={} enabled={}",
            u.sam_account_name,
            u.sid.as_deref().unwrap_or("-"),
            u.enabled,
        );
        if let Some(ref ts) = u.when_created {
            entries.push(TimelineEntry {
                datetime: ts.clone(),
                timestamp_desc: "Creation Time".to_string(),
                source: "NTDS-User".to_string(),
                message: format!("User '{}' created", u.sam_account_name),
                extra: base_extra.clone(),
            });
        }
        if let Some(ref ts) = u.pwd_last_set {
            entries.push(TimelineEntry {
                datetime: ts.clone(),
                timestamp_desc: "Password Change".to_string(),
                source: "NTDS-User".to_string(),
                message: format!("User '{}' password changed", u.sam_account_name),
                extra: base_extra.clone(),
            });
        }
        if let Some(ref ts) = u.last_logon_timestamp {
            entries.push(TimelineEntry {
                datetime: ts.clone(),
                timestamp_desc: "Last Logon".to_string(),
                source: "NTDS-User".to_string(),
                message: format!("User '{}' last logon", u.sam_account_name),
                extra: base_extra.clone(),
            });
        }
    }

    // Live computer events
    for c in computers {
        let base_extra = format!("sam={} sid={}",
            c.sam_account_name,
            c.sid.as_deref().unwrap_or("-"),
        );
        if let Some(ref ts) = c.when_created {
            entries.push(TimelineEntry {
                datetime: ts.clone(),
                timestamp_desc: "Creation Time".to_string(),
                source: "NTDS-Computer".to_string(),
                message: format!("Computer '{}' joined domain",
                    c.dns_hostname.as_deref().unwrap_or(&c.sam_account_name)),
                extra: base_extra.clone(),
            });
        }
    }

    // Live group events
    for g in groups {
        if let Some(ref ts) = g.when_created {
            entries.push(TimelineEntry {
                datetime: ts.clone(),
                timestamp_desc: "Creation Time".to_string(),
                source: "NTDS-Group".to_string(),
                message: format!("Group '{}' created", g.sam_account_name),
                extra: format!("sid={}", g.sid.as_deref().unwrap_or("-")),
            });
        }
    }

    // Deleted object events
    if let Some(del) = deleted {
        let all_deleted = del.users.iter()
            .chain(del.computers.iter())
            .chain(del.groups.iter())
            .chain(del.other.iter());

        for d in all_deleted {
            let obj_name = d.sam_account_name.as_deref()
                .or(d.name.as_deref())
                .unwrap_or("unknown");
            let obj_type = format!("{:?}", d.object_type);
            let base_extra = format!("sid={} dnt={} type={}",
                d.sid.as_deref().unwrap_or("-"),
                d.dnt.map(|v| v.to_string()).unwrap_or_else(|| "-".to_string()),
                obj_type,
            );

            if let Some(ref ts) = d.when_created {
                entries.push(TimelineEntry {
                    datetime: ts.clone(),
                    timestamp_desc: "Creation Time".to_string(),
                    source: format!("NTDS-Deleted-{}", obj_type),
                    message: format!("Deleted {} '{}' originally created", obj_type, obj_name),
                    extra: base_extra.clone(),
                });
            }
            if let Some(ref ts) = d.when_changed {
                entries.push(TimelineEntry {
                    datetime: ts.clone(),
                    timestamp_desc: "Deletion Time (approx)".to_string(),
                    source: format!("NTDS-Deleted-{}", obj_type),
                    message: format!("{} '{}' deleted (approx)", obj_type, obj_name),
                    extra: base_extra.clone(),
                });
            }
        }
    }

    // Sort by datetime
    entries.sort_by(|a, b| a.datetime.cmp(&b.datetime));

    // Write CSV
    let mut file = std::fs::File::create(output_path)?;
    writeln!(file, "datetime,timestamp_desc,source,source_long,message,filename,inode,format,extra")?;
    for e in &entries {
        writeln!(file, "{},{},{},Active Directory,{},ntds.dit,-,ntds,{}",
            csv_escape(&e.datetime),
            csv_escape(&e.timestamp_desc),
            csv_escape(&e.source),
            csv_escape(&e.message),
            csv_escape(&e.extra),
        )?;
    }

    log::info!("Written {} forensic timeline events to {}", entries.len(), output_path.display());
    Ok(())
}

fn csv_escape(s: &str) -> String {
    if s.contains(',') || s.contains('"') || s.contains('\n') {
        format!("\"{}\"", s.replace('"', "\"\""))
    } else {
        s.to_string()
    }
}
