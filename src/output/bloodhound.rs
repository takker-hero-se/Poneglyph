use anyhow::Result;
use serde_json::{json, Value};
use std::io::Write;
use std::path::Path;

use crate::objects::user::AdUser;
use crate::objects::computer::AdComputer;
use crate::objects::group::AdGroup;
use crate::objects::trust::AdTrust;
use crate::objects::domain_sid;

/// Write BloodHound CE v5 compatible JSON files.
pub fn write_bloodhound(
    output_dir: &Path,
    domain: &str,
    users: &[AdUser],
    computers: &[AdComputer],
    groups: &[AdGroup],
    trusts: &[AdTrust],
) -> Result<()> {
    std::fs::create_dir_all(output_dir)?;

    let domain_upper = domain.to_uppercase();

    write_users_json(output_dir, &domain_upper, users)?;
    write_groups_json(output_dir, &domain_upper, groups)?;
    write_computers_json(output_dir, &domain_upper, computers)?;
    write_domains_json(output_dir, &domain_upper, users, trusts)?;

    log::info!("BloodHound JSON written to {}", output_dir.display());
    Ok(())
}

fn write_users_json(dir: &Path, domain: &str, users: &[AdUser]) -> Result<()> {
    let data: Vec<Value> = users.iter().map(|u| {
        let name = format!("{}@{}", u.sam_account_name.to_uppercase(), domain);
        let object_id = u.sid.as_deref().unwrap_or("");
        let domain_sid_str = u.sid.as_deref().and_then(domain_sid).unwrap_or_default();

        let primary_group_sid = u.primary_group_id.map(|pgid| {
            format!("{}-{}", domain_sid_str, pgid)
        });

        json!({
            "Properties": {
                "domain": domain,
                "name": name,
                "objectid": object_id,
                "samaccountname": u.sam_account_name,
                "displayname": u.display_name,
                "description": u.description,
                "domainsid": domain_sid_str,
                "enabled": u.enabled,
                "admincount": u.admin_count.unwrap_or(0) != 0,
                "dontreqpreauth": u.uac_flags.iter().any(|f| f == "DONT_REQ_PREAUTH"),
                "passwordnotreqd": u.uac_flags.iter().any(|f| f == "PASSWD_NOT_REQUIRED"),
                "pwdneverexpires": u.uac_flags.iter().any(|f| f == "DONT_EXPIRE_PASSWORD"),
                "trustedtoauth": u.uac_flags.iter().any(|f| f == "TRUSTED_TO_AUTH_FOR_DELEG"),
                "sensitive": false,
                "unconstraineddelegation": u.uac_flags.iter().any(|f| f == "TRUSTED_FOR_DELEGATION"),
                "hasspn": !u.spns.is_empty(),
                "highvalue": u.admin_count.unwrap_or(0) != 0,
                "whencreated": u.when_created,
                "pwdlastset": u.pwd_last_set,
                "lastlogon": u.last_logon,
                "lastlogontimestamp": u.last_logon_timestamp,
                "serviceprincipalnames": u.spns,
            },
            "PrimaryGroupSID": primary_group_sid,
            "MemberOf": [],
            "Aces": [],
        })
    }).collect();

    let output = json!({
        "meta": { "type": "users", "count": data.len(), "version": 5, "methods": 0 },
        "data": data,
    });

    write_json_file(&dir.join("users.json"), &output)?;
    log::info!("Written {} users to BloodHound JSON", data.len());
    Ok(())
}

fn write_groups_json(dir: &Path, domain: &str, groups: &[AdGroup]) -> Result<()> {
    let data: Vec<Value> = groups.iter().map(|g| {
        let name = format!("{}@{}", g.sam_account_name.to_uppercase(), domain);
        let object_id = g.sid.as_deref().unwrap_or("");

        json!({
            "Properties": {
                "domain": domain,
                "name": name,
                "objectid": object_id,
                "samaccountname": g.sam_account_name,
                "description": g.description,
                "admincount": g.admin_count.unwrap_or(0) != 0,
                "highvalue": g.high_value,
                "whencreated": g.when_created,
            },
            "Members": g.members.iter().map(|sid| json!({"ObjectIdentifier": sid, "ObjectType": "Base"})).collect::<Vec<_>>(),
            "MemberOf": [],
            "Aces": [],
        })
    }).collect();

    let output = json!({
        "meta": { "type": "groups", "count": data.len(), "version": 5, "methods": 0 },
        "data": data,
    });

    write_json_file(&dir.join("groups.json"), &output)?;
    log::info!("Written {} groups to BloodHound JSON", data.len());
    Ok(())
}

fn write_computers_json(dir: &Path, domain: &str, computers: &[AdComputer]) -> Result<()> {
    let data: Vec<Value> = computers.iter().map(|c| {
        let name = c.dns_hostname.as_deref()
            .map(|h| h.to_uppercase())
            .unwrap_or_else(|| format!("{}@{}", c.sam_account_name.to_uppercase(), domain));
        let object_id = c.sid.as_deref().unwrap_or("");
        let domain_sid_str = c.sid.as_deref().and_then(domain_sid).unwrap_or_default();

        let primary_group_sid = c.primary_group_id.map(|pgid| {
            format!("{}-{}", domain_sid_str, pgid)
        });

        json!({
            "Properties": {
                "domain": domain,
                "name": name,
                "objectid": object_id,
                "samaccountname": c.sam_account_name,
                "description": c.description,
                "enabled": c.enabled,
                "operatingsystem": c.operating_system,
                "whencreated": c.when_created,
                "lastlogon": c.last_logon,
                "lastlogontimestamp": c.last_logon_timestamp,
                "unconstraineddelegation": c.uac_flags.iter().any(|f| f == "TRUSTED_FOR_DELEGATION"),
                "highvalue": c.is_dc,
            },
            "PrimaryGroupSID": primary_group_sid,
            "MemberOf": [],
            "Aces": [],
        })
    }).collect();

    let output = json!({
        "meta": { "type": "computers", "count": data.len(), "version": 5, "methods": 0 },
        "data": data,
    });

    write_json_file(&dir.join("computers.json"), &output)?;
    log::info!("Written {} computers to BloodHound JSON", data.len());
    Ok(())
}

fn write_domains_json(
    dir: &Path,
    domain: &str,
    users: &[AdUser],
    trusts: &[AdTrust],
) -> Result<()> {
    // Try to extract domain SID from the first user's SID
    let domain_sid_str = users.iter()
        .find_map(|u| u.sid.as_deref().and_then(domain_sid))
        .unwrap_or_default();

    let trust_data: Vec<Value> = trusts.iter().map(|t| {
        json!({
            "TargetDomainName": t.trust_partner.to_uppercase(),
            "TargetDomainSid": t.sid,
            "TrustDirection": t.trust_direction_str,
            "TrustType": t.trust_type_str,
            "IsTransitive": t.trust_attributes & 1 != 0,
        })
    }).collect();

    let data = vec![json!({
        "Properties": {
            "domain": domain,
            "name": domain,
            "objectid": &domain_sid_str,
            "highvalue": true,
        },
        "Trusts": trust_data,
        "ChildDomains": [],
        "Links": [],
        "Aces": [],
    })];

    let output = json!({
        "meta": { "type": "domains", "count": data.len(), "version": 5, "methods": 0 },
        "data": data,
    });

    write_json_file(&dir.join("domains.json"), &output)?;
    log::info!("Written domain info to BloodHound JSON");
    Ok(())
}

fn write_json_file(path: &Path, value: &Value) -> Result<()> {
    let content = serde_json::to_string_pretty(value)?;
    let mut file = std::fs::File::create(path)?;
    file.write_all(content.as_bytes())?;
    file.write_all(b"\n")?;
    Ok(())
}
