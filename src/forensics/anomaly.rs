use serde::{Serialize, Deserialize};
use std::collections::HashMap;
use anyhow::Result;

use crate::objects::user::AdUser;
use crate::objects::computer::AdComputer;
use crate::objects::group::AdGroup;
use crate::acl::AceEntry;
use crate::schema::uac;

// ==================== Data Model ====================

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub enum Severity {
    Critical,
    High,
    Medium,
    Low,
    Info,
}

impl Severity {
    pub fn as_str(&self) -> &'static str {
        match self {
            Severity::Critical => "CRITICAL",
            Severity::High => "HIGH",
            Severity::Medium => "MEDIUM",
            Severity::Low => "LOW",
            Severity::Info => "INFO",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AffectedObject {
    pub name: String,
    pub sid: Option<String>,
    pub object_type: String,
    pub detail: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    pub rule_id: String,
    pub title: String,
    pub description: String,
    pub severity: Severity,
    pub mitre_attack: Option<String>,
    pub affected_objects: Vec<AffectedObject>,
}

// ==================== Rule Trait ====================

trait AnomalyRule {
    fn id(&self) -> &'static str;
    fn title(&self) -> &'static str;
    fn description(&self) -> &'static str;
    fn severity(&self) -> Severity;
    fn mitre_attack(&self) -> Option<&'static str> { None }

    fn evaluate(
        &self,
        users: &[AdUser],
        computers: &[AdComputer],
        groups: &[AdGroup],
        aces_by_sid: &HashMap<String, Vec<AceEntry>>,
    ) -> Vec<AffectedObject>;

    fn to_finding(&self, affected: Vec<AffectedObject>) -> Option<Finding> {
        if affected.is_empty() {
            return None;
        }
        Some(Finding {
            rule_id: self.id().to_string(),
            title: self.title().to_string(),
            description: self.description().to_string(),
            severity: self.severity(),
            mitre_attack: self.mitre_attack().map(|s| s.to_string()),
            affected_objects: affected,
        })
    }
}

// ==================== Rule Implementations ====================

// ANOM-001: AS-REP Roastable
struct AsRepRoastable;
impl AnomalyRule for AsRepRoastable {
    fn id(&self) -> &'static str { "ANOM-001" }
    fn title(&self) -> &'static str { "AS-REP Roastable Accounts" }
    fn description(&self) -> &'static str {
        "Accounts with DONT_REQ_PREAUTH flag allow offline password cracking without credentials."
    }
    fn severity(&self) -> Severity { Severity::High }
    fn mitre_attack(&self) -> Option<&'static str> { Some("T1558.004") }

    fn evaluate(&self, users: &[AdUser], _: &[AdComputer], _: &[AdGroup],
                _: &HashMap<String, Vec<AceEntry>>) -> Vec<AffectedObject> {
        users.iter()
            .filter(|u| u.enabled && u.user_account_control & uac::DONT_REQ_PREAUTH != 0)
            .map(|u| AffectedObject {
                name: u.sam_account_name.clone(),
                sid: u.sid.clone(),
                object_type: "User".to_string(),
                detail: None,
            })
            .collect()
    }
}

// ANOM-002: PASSWD_NOTREQD
struct PasswordNotRequired;
impl AnomalyRule for PasswordNotRequired {
    fn id(&self) -> &'static str { "ANOM-002" }
    fn title(&self) -> &'static str { "Password Not Required Accounts" }
    fn description(&self) -> &'static str {
        "Accounts with PASSWD_NOTREQD flag can have empty passwords."
    }
    fn severity(&self) -> Severity { Severity::High }
    fn mitre_attack(&self) -> Option<&'static str> { Some("T1078") }

    fn evaluate(&self, users: &[AdUser], _: &[AdComputer], _: &[AdGroup],
                _: &HashMap<String, Vec<AceEntry>>) -> Vec<AffectedObject> {
        users.iter()
            .filter(|u| u.enabled && u.user_account_control & uac::PASSWD_NOTREQD != 0)
            .map(|u| AffectedObject {
                name: u.sam_account_name.clone(),
                sid: u.sid.clone(),
                object_type: "User".to_string(),
                detail: None,
            })
            .collect()
    }
}

// ANOM-003: Non-Expiring Passwords on Privileged Accounts
struct NonExpiringPrivileged;
impl AnomalyRule for NonExpiringPrivileged {
    fn id(&self) -> &'static str { "ANOM-003" }
    fn title(&self) -> &'static str { "Non-Expiring Passwords on Privileged Accounts" }
    fn description(&self) -> &'static str {
        "Privileged accounts (adminCount=1) with DONT_EXPIRE_PASSWORD flag."
    }
    fn severity(&self) -> Severity { Severity::Medium }
    fn mitre_attack(&self) -> Option<&'static str> { Some("T1078.002") }

    fn evaluate(&self, users: &[AdUser], _: &[AdComputer], _: &[AdGroup],
                _: &HashMap<String, Vec<AceEntry>>) -> Vec<AffectedObject> {
        users.iter()
            .filter(|u| u.enabled
                && u.admin_count == Some(1)
                && u.user_account_control & uac::DONT_EXPIRE_PASSWORD != 0)
            .map(|u| AffectedObject {
                name: u.sam_account_name.clone(),
                sid: u.sid.clone(),
                object_type: "User".to_string(),
                detail: None,
            })
            .collect()
    }
}

// ANOM-004: Stale Accounts (no logon in >90 days but enabled)
struct StaleAccounts;
impl AnomalyRule for StaleAccounts {
    fn id(&self) -> &'static str { "ANOM-004" }
    fn title(&self) -> &'static str { "Stale Enabled Accounts" }
    fn description(&self) -> &'static str {
        "Enabled accounts with no logon in over 90 days represent unnecessary attack surface."
    }
    fn severity(&self) -> Severity { Severity::Low }
    fn mitre_attack(&self) -> Option<&'static str> { Some("T1078") }

    fn evaluate(&self, users: &[AdUser], _: &[AdComputer], _: &[AdGroup],
                _: &HashMap<String, Vec<AceEntry>>) -> Vec<AffectedObject> {
        let threshold = (chrono::Utc::now() - chrono::Duration::days(90))
            .format("%Y-%m-%d %H:%M:%S UTC")
            .to_string();

        users.iter()
            .filter(|u| {
                if !u.enabled { return false; }
                match &u.last_logon_timestamp {
                    Some(ts) => ts.as_str() < threshold.as_str(),
                    None => {
                        u.when_created.as_ref()
                            .map(|c| c.as_str() < threshold.as_str())
                            .unwrap_or(false)
                    }
                }
            })
            .map(|u| AffectedObject {
                name: u.sam_account_name.clone(),
                sid: u.sid.clone(),
                object_type: "User".to_string(),
                detail: Some(format!("Last logon: {}",
                    u.last_logon_timestamp.as_deref().unwrap_or("Never"))),
            })
            .collect()
    }
}

// ANOM-005: Never-Logged-In Enabled Accounts
struct NeverLoggedIn;
impl AnomalyRule for NeverLoggedIn {
    fn id(&self) -> &'static str { "ANOM-005" }
    fn title(&self) -> &'static str { "Never-Logged-In Enabled Accounts" }
    fn description(&self) -> &'static str {
        "Enabled accounts that have never logged in may be dormant or backdoor accounts."
    }
    fn severity(&self) -> Severity { Severity::Low }

    fn evaluate(&self, users: &[AdUser], _: &[AdComputer], _: &[AdGroup],
                _: &HashMap<String, Vec<AceEntry>>) -> Vec<AffectedObject> {
        users.iter()
            .filter(|u| u.enabled
                && u.last_logon_timestamp.is_none()
                && u.last_logon.is_none()
                && u.logon_count.unwrap_or(0) == 0)
            .map(|u| AffectedObject {
                name: u.sam_account_name.clone(),
                sid: u.sid.clone(),
                object_type: "User".to_string(),
                detail: u.when_created.as_ref().map(|c| format!("Created: {}", c)),
            })
            .collect()
    }
}

// ANOM-006: Unconstrained Delegation
struct UnconstrainedDelegation;
impl AnomalyRule for UnconstrainedDelegation {
    fn id(&self) -> &'static str { "ANOM-006" }
    fn title(&self) -> &'static str { "Unconstrained Delegation" }
    fn description(&self) -> &'static str {
        "Accounts with TRUSTED_FOR_DELEGATION can impersonate any user to any service."
    }
    fn severity(&self) -> Severity { Severity::Critical }
    fn mitre_attack(&self) -> Option<&'static str> { Some("T1550.003") }

    fn evaluate(&self, users: &[AdUser], computers: &[AdComputer], _: &[AdGroup],
                _: &HashMap<String, Vec<AceEntry>>) -> Vec<AffectedObject> {
        let mut affected = Vec::new();

        // Non-DC computers with unconstrained delegation
        for c in computers {
            if c.enabled && !c.is_dc
                && c.user_account_control & uac::TRUSTED_FOR_DELEGATION != 0
            {
                affected.push(AffectedObject {
                    name: c.sam_account_name.clone(),
                    sid: c.sid.clone(),
                    object_type: "Computer".to_string(),
                    detail: c.operating_system.clone(),
                });
            }
        }

        // User accounts with unconstrained delegation
        for u in users {
            if u.enabled && u.user_account_control & uac::TRUSTED_FOR_DELEGATION != 0 {
                affected.push(AffectedObject {
                    name: u.sam_account_name.clone(),
                    sid: u.sid.clone(),
                    object_type: "User".to_string(),
                    detail: Some("User account with unconstrained delegation".to_string()),
                });
            }
        }

        affected
    }
}

// ANOM-007: Constrained Delegation with Protocol Transition
struct ConstrainedDelegationProtocolTransition;
impl AnomalyRule for ConstrainedDelegationProtocolTransition {
    fn id(&self) -> &'static str { "ANOM-007" }
    fn title(&self) -> &'static str { "Constrained Delegation with Protocol Transition" }
    fn description(&self) -> &'static str {
        "Accounts with TRUSTED_TO_AUTH_FOR_DELEGATION (S4U2Self + S4U2Proxy) \
         can request service tickets on behalf of any user."
    }
    fn severity(&self) -> Severity { Severity::High }
    fn mitre_attack(&self) -> Option<&'static str> { Some("T1550.003") }

    fn evaluate(&self, users: &[AdUser], computers: &[AdComputer], _: &[AdGroup],
                _: &HashMap<String, Vec<AceEntry>>) -> Vec<AffectedObject> {
        let mut affected = Vec::new();

        for u in users {
            if u.enabled && u.user_account_control & uac::TRUSTED_TO_AUTH_FOR_DELEGATION != 0 {
                affected.push(AffectedObject {
                    name: u.sam_account_name.clone(),
                    sid: u.sid.clone(),
                    object_type: "User".to_string(),
                    detail: None,
                });
            }
        }

        for c in computers {
            if c.enabled && c.user_account_control & uac::TRUSTED_TO_AUTH_FOR_DELEGATION != 0 {
                affected.push(AffectedObject {
                    name: c.sam_account_name.clone(),
                    sid: c.sid.clone(),
                    object_type: "Computer".to_string(),
                    detail: None,
                });
            }
        }

        affected
    }
}

// ANOM-008: AdminCount=1
struct AdminCountSet;
impl AnomalyRule for AdminCountSet {
    fn id(&self) -> &'static str { "ANOM-008" }
    fn title(&self) -> &'static str { "Accounts with adminCount=1" }
    fn description(&self) -> &'static str {
        "Accounts with adminCount=1 are (or were) members of protected groups. \
         Orphaned adminCount may indicate SDProp residue."
    }
    fn severity(&self) -> Severity { Severity::Info }

    fn evaluate(&self, users: &[AdUser], _: &[AdComputer], _: &[AdGroup],
                _: &HashMap<String, Vec<AceEntry>>) -> Vec<AffectedObject> {
        users.iter()
            .filter(|u| u.enabled && u.admin_count == Some(1))
            .map(|u| AffectedObject {
                name: u.sam_account_name.clone(),
                sid: u.sid.clone(),
                object_type: "User".to_string(),
                detail: None,
            })
            .collect()
    }
}

// ANOM-009: High Bad Password Count
struct HighBadPasswordCount;
impl AnomalyRule for HighBadPasswordCount {
    fn id(&self) -> &'static str { "ANOM-009" }
    fn title(&self) -> &'static str { "Accounts with High Bad Password Count" }
    fn description(&self) -> &'static str {
        "Accounts with high bad password counts may indicate brute-force or password spraying attacks."
    }
    fn severity(&self) -> Severity { Severity::Medium }
    fn mitre_attack(&self) -> Option<&'static str> { Some("T1110") }

    fn evaluate(&self, users: &[AdUser], _: &[AdComputer], _: &[AdGroup],
                _: &HashMap<String, Vec<AceEntry>>) -> Vec<AffectedObject> {
        const BAD_PWD_THRESHOLD: i32 = 5;
        users.iter()
            .filter(|u| u.bad_pwd_count.unwrap_or(0) >= BAD_PWD_THRESHOLD)
            .map(|u| AffectedObject {
                name: u.sam_account_name.clone(),
                sid: u.sid.clone(),
                object_type: "User".to_string(),
                detail: Some(format!("Bad password count: {}", u.bad_pwd_count.unwrap_or(0))),
            })
            .collect()
    }
}

// ANOM-010: Recently Created Accounts
struct RecentlyCreatedAccounts;
impl AnomalyRule for RecentlyCreatedAccounts {
    fn id(&self) -> &'static str { "ANOM-010" }
    fn title(&self) -> &'static str { "Recently Created Accounts" }
    fn description(&self) -> &'static str {
        "Accounts created within the last 30 days. During incident response, \
         these may represent attacker-created persistence."
    }
    fn severity(&self) -> Severity { Severity::Info }
    fn mitre_attack(&self) -> Option<&'static str> { Some("T1136.002") }

    fn evaluate(&self, users: &[AdUser], _: &[AdComputer], _: &[AdGroup],
                _: &HashMap<String, Vec<AceEntry>>) -> Vec<AffectedObject> {
        let threshold = (chrono::Utc::now() - chrono::Duration::days(30))
            .format("%Y-%m-%d %H:%M:%S UTC")
            .to_string();

        users.iter()
            .filter(|u| {
                u.when_created.as_ref()
                    .map(|c| c.as_str() > threshold.as_str())
                    .unwrap_or(false)
            })
            .map(|u| AffectedObject {
                name: u.sam_account_name.clone(),
                sid: u.sid.clone(),
                object_type: "User".to_string(),
                detail: u.when_created.as_ref().map(|c| format!("Created: {}", c)),
            })
            .collect()
    }
}

// ANOM-011: DCSync-Capable Non-Admin Accounts
struct DCSyncCapable;
impl AnomalyRule for DCSyncCapable {
    fn id(&self) -> &'static str { "ANOM-011" }
    fn title(&self) -> &'static str { "DCSync-Capable Non-Admin Accounts" }
    fn description(&self) -> &'static str {
        "Non-default accounts with both GetChanges and GetChangesAll rights \
         can perform DCSync attacks to extract all password hashes."
    }
    fn severity(&self) -> Severity { Severity::Critical }
    fn mitre_attack(&self) -> Option<&'static str> { Some("T1003.006") }

    fn evaluate(&self, _: &[AdUser], _: &[AdComputer], _: &[AdGroup],
                aces_by_sid: &HashMap<String, Vec<AceEntry>>) -> Vec<AffectedObject> {
        let mut affected = Vec::new();

        for (sid, aces) in aces_by_sid {
            // Skip well-known admin SIDs
            let rid_part = sid.rsplit('-').next().unwrap_or("");
            if matches!(rid_part, "516" | "498" | "512" | "519" | "500") {
                continue;
            }

            let has_get_changes = aces.iter().any(|a| a.right_name == "GetChanges");
            let has_get_changes_all = aces.iter().any(|a| a.right_name == "GetChangesAll");

            if has_get_changes && has_get_changes_all {
                affected.push(AffectedObject {
                    name: sid.clone(),
                    sid: Some(sid.clone()),
                    object_type: "Principal".to_string(),
                    detail: Some("Has both GetChanges + GetChangesAll".to_string()),
                });
            }
        }

        affected
    }
}

// ANOM-012: SID History Present
struct SidHistoryPresent;
impl AnomalyRule for SidHistoryPresent {
    fn id(&self) -> &'static str { "ANOM-012" }
    fn title(&self) -> &'static str { "SID History Present" }
    fn description(&self) -> &'static str {
        "Accounts with sIDHistory can be abused for lateral movement and \
         privilege escalation across domain boundaries."
    }
    fn severity(&self) -> Severity { Severity::High }
    fn mitre_attack(&self) -> Option<&'static str> { Some("T1134.005") }

    fn evaluate(&self, users: &[AdUser], _: &[AdComputer], _: &[AdGroup],
                _: &HashMap<String, Vec<AceEntry>>) -> Vec<AffectedObject> {
        users.iter()
            .filter(|u| u.has_sid_history)
            .map(|u| AffectedObject {
                name: u.sam_account_name.clone(),
                sid: u.sid.clone(),
                object_type: "User".to_string(),
                detail: Some("sIDHistory attribute present".to_string()),
            })
            .collect()
    }
}

// ANOM-013: Shadow Credentials
struct ShadowCredentials;
impl AnomalyRule for ShadowCredentials {
    fn id(&self) -> &'static str { "ANOM-013" }
    fn title(&self) -> &'static str { "Shadow Credentials Detected" }
    fn description(&self) -> &'static str {
        "Accounts with msDS-KeyCredentialLink may indicate an attacker has written \
         their own certificate for persistence via PKINIT."
    }
    fn severity(&self) -> Severity { Severity::High }
    fn mitre_attack(&self) -> Option<&'static str> { Some("T1098.004") }

    fn evaluate(&self, users: &[AdUser], _: &[AdComputer], _: &[AdGroup],
                _: &HashMap<String, Vec<AceEntry>>) -> Vec<AffectedObject> {
        users.iter()
            .filter(|u| u.has_key_credential_link)
            .map(|u| AffectedObject {
                name: u.sam_account_name.clone(),
                sid: u.sid.clone(),
                object_type: "User".to_string(),
                detail: Some("msDS-KeyCredentialLink attribute present".to_string()),
            })
            .collect()
    }
}

// ANOM-014: Kerberoastable Accounts
struct Kerberoastable;
impl AnomalyRule for Kerberoastable {
    fn id(&self) -> &'static str { "ANOM-014" }
    fn title(&self) -> &'static str { "Kerberoastable User Accounts" }
    fn description(&self) -> &'static str {
        "User accounts with SPNs set. Any authenticated user can request a service ticket \
         and attempt offline password cracking."
    }
    fn severity(&self) -> Severity { Severity::High }
    fn mitre_attack(&self) -> Option<&'static str> { Some("T1558.003") }

    fn evaluate(&self, users: &[AdUser], _: &[AdComputer], _: &[AdGroup],
                _: &HashMap<String, Vec<AceEntry>>) -> Vec<AffectedObject> {
        users.iter()
            .filter(|u| u.enabled && !u.spns.is_empty())
            .map(|u| AffectedObject {
                name: u.sam_account_name.clone(),
                sid: u.sid.clone(),
                object_type: "User".to_string(),
                detail: Some(format!("SPNs: {}", u.spns.join(", "))),
            })
            .collect()
    }
}

// ==================== Rule Registry & Runner ====================

fn all_rules() -> Vec<Box<dyn AnomalyRule>> {
    vec![
        Box::new(AsRepRoastable),
        Box::new(PasswordNotRequired),
        Box::new(NonExpiringPrivileged),
        Box::new(StaleAccounts),
        Box::new(NeverLoggedIn),
        Box::new(UnconstrainedDelegation),
        Box::new(ConstrainedDelegationProtocolTransition),
        Box::new(AdminCountSet),
        Box::new(HighBadPasswordCount),
        Box::new(RecentlyCreatedAccounts),
        Box::new(DCSyncCapable),
        Box::new(SidHistoryPresent),
        Box::new(ShadowCredentials),
        Box::new(Kerberoastable),
    ]
}

/// Run all anomaly detection rules and collect findings.
pub fn run_all_rules(
    users: &[AdUser],
    computers: &[AdComputer],
    groups: &[AdGroup],
    aces_by_sid: &HashMap<String, Vec<AceEntry>>,
) -> Result<Vec<Finding>> {
    let rules = all_rules();
    let mut findings = Vec::new();

    for rule in &rules {
        log::debug!("Running rule: {} - {}", rule.id(), rule.title());
        let affected = rule.evaluate(users, computers, groups, aces_by_sid);
        if let Some(finding) = rule.to_finding(affected) {
            log::info!("Rule {} found {} affected objects",
                finding.rule_id, finding.affected_objects.len());
            findings.push(finding);
        }
    }

    findings.sort_by(|a, b| a.severity.cmp(&b.severity));

    Ok(findings)
}
