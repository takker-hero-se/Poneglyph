use anyhow::Result;
use serde_json::json;
use std::io::Write;
use std::path::Path;

use crate::objects::user::AdUser;
use crate::objects::computer::AdComputer;
use crate::objects::group::AdGroup;
use crate::objects::trust::AdTrust;

/// Write a D3.js force-directed graph JSON file.
///
/// Output format:
/// ```json
/// {
///   "nodes": [{ "id": "SID", "name": "...", "type": "user|computer|group|trust", ... }],
///   "links": [{ "source": "SID", "target": "SID", "type": "MemberOf|TrustBy|..." }]
/// }
/// ```
pub fn write_graph(
    output_path: &Path,
    users: &[AdUser],
    computers: &[AdComputer],
    groups: &[AdGroup],
    trusts: &[AdTrust],
) -> Result<()> {
    let mut nodes = Vec::new();
    let mut links = Vec::new();

    // User nodes
    for u in users {
        let sid = match &u.sid {
            Some(s) => s.clone(),
            None => continue,
        };
        nodes.push(json!({
            "id": sid,
            "name": u.sam_account_name,
            "type": "user",
            "enabled": u.enabled,
            "adminCount": u.admin_count.unwrap_or(0) != 0,
        }));
    }

    // Computer nodes
    for c in computers {
        let sid = match &c.sid {
            Some(s) => s.clone(),
            None => continue,
        };
        nodes.push(json!({
            "id": sid,
            "name": c.dns_hostname.as_deref().unwrap_or(&c.sam_account_name),
            "type": if c.is_dc { "dc" } else { "computer" },
            "os": c.operating_system,
        }));
    }

    // Group nodes + membership links
    for g in groups {
        let sid = match &g.sid {
            Some(s) => s.clone(),
            None => continue,
        };
        nodes.push(json!({
            "id": sid,
            "name": g.sam_account_name,
            "type": "group",
            "highValue": g.high_value,
        }));

        // Member → Group links
        for member_sid in &g.members {
            links.push(json!({
                "source": member_sid,
                "target": sid,
                "type": "MemberOf",
            }));
        }
    }

    // Trust links
    for t in trusts {
        if let Some(ref target_sid) = t.sid {
            nodes.push(json!({
                "id": target_sid,
                "name": t.trust_partner,
                "type": "domain",
            }));
            links.push(json!({
                "source": target_sid,
                "target": "domain",
                "type": format!("Trust({})", t.trust_direction_str),
            }));
        }
    }

    let graph = json!({
        "nodes": nodes,
        "links": links,
    });

    let content = serde_json::to_string_pretty(&graph)?;
    let mut file = std::fs::File::create(output_path)?;
    file.write_all(content.as_bytes())?;
    file.write_all(b"\n")?;

    log::info!("Written graph JSON with {} nodes, {} links to {}",
        nodes.len(), links.len(), output_path.display());
    Ok(())
}
