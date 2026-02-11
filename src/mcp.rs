//! MCP (Model Context Protocol) server for Poneglyph NTDS.dit analysis.
//!
//! Exposes Poneglyph's forensic analysis capabilities as MCP tools
//! that can be invoked by Claude Desktop, MCP Inspector, or any MCP client.
//!
//! Usage: `poneglyph mcp` (communicates via stdin/stdout JSON-RPC)

use anyhow::Result;
use rmcp::handler::server::router::tool::ToolRouter;
use rmcp::handler::server::wrapper::Parameters;
use rmcp::model::{Implementation, ServerCapabilities, ServerInfo};
use rmcp::{tool, tool_handler, tool_router, ErrorData, ServerHandler, ServiceExt};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;

use crate::{acl, bootkey, crypto, ese, forensics, links, objects};

// ==================== Request Types ====================

#[derive(Debug, Deserialize, JsonSchema)]
pub struct NtdsPathRequest {
    #[schemars(description = "Absolute path to the NTDS.dit file")]
    pub ntds_path: String,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct UsersRequest {
    #[schemars(description = "Absolute path to the NTDS.dit file")]
    pub ntds_path: String,
    #[schemars(description = "Include disabled accounts (default: false)")]
    pub include_disabled: Option<bool>,
    #[schemars(description = "Filter by sAMAccountName substring (case-insensitive)")]
    pub search: Option<String>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct HashesRequest {
    #[schemars(description = "Absolute path to the NTDS.dit file")]
    pub ntds_path: String,
    #[schemars(description = "Absolute path to the SYSTEM registry hive")]
    pub system_path: String,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct ForensicsRequest {
    #[schemars(description = "Absolute path to the NTDS.dit file")]
    pub ntds_path: String,
    #[schemars(description = "Include ACL analysis for DCSync detection (slower)")]
    pub include_acls: Option<bool>,
}

// ==================== Response Types ====================

#[derive(Debug, Serialize)]
struct HashEntry {
    sam_account_name: String,
    rid: u32,
    nt_hash: Option<String>,
    lm_hash: Option<String>,
}

#[derive(Debug, Serialize)]
struct ObjectsSummary {
    user_count: usize,
    computer_count: usize,
    group_count: usize,
    gpo_count: usize,
    trust_count: usize,
    users: Vec<objects::user::AdUser>,
    computers: Vec<objects::computer::AdComputer>,
    groups: Vec<objects::group::AdGroup>,
    gpos: Vec<objects::gpo::AdGpo>,
    trusts: Vec<objects::trust::AdTrust>,
}

// ==================== MCP Server ====================

#[derive(Debug, Clone)]
pub struct PoneglyphMcp {
    tool_router: ToolRouter<Self>,
}

impl PoneglyphMcp {
    pub fn new() -> Self {
        Self {
            tool_router: Self::tool_router(),
        }
    }
}

fn err(msg: String) -> ErrorData {
    ErrorData::internal_error(msg, None)
}

#[tool_router]
impl PoneglyphMcp {
    #[tool(
        name = "ntds_info",
        description = "Get NTDS.dit database metadata: table names, record counts. Use this first to verify the database is valid."
    )]
    async fn ntds_info(
        &self,
        Parameters(req): Parameters<NtdsPathRequest>,
    ) -> Result<String, ErrorData> {
        tokio::task::spawn_blocking(move || {
            let db = ese::NtdsDatabase::open(&PathBuf::from(&req.ntds_path))
                .map_err(|e| err(format!("Failed to open NTDS.dit: {e}")))?;
            let info = db.info()
                .map_err(|e| err(format!("Failed to read database info: {e}")))?;
            serde_json::to_string_pretty(&info)
                .map_err(|e| err(format!("Serialization error: {e}")))
        })
        .await
        .map_err(|e| err(format!("Task error: {e}")))?
    }

    #[tool(
        name = "ntds_users",
        description = "Extract Active Directory user accounts from NTDS.dit. Returns user details including SID, UAC flags, timestamps, SPN list, and privilege indicators. Optionally filter by sAMAccountName substring."
    )]
    async fn ntds_users(
        &self,
        Parameters(req): Parameters<UsersRequest>,
    ) -> Result<String, ErrorData> {
        let include_disabled = req.include_disabled.unwrap_or(false);
        let search = req.search;
        tokio::task::spawn_blocking(move || {
            let db = ese::NtdsDatabase::open(&PathBuf::from(&req.ntds_path))
                .map_err(|e| err(format!("Failed to open NTDS.dit: {e}")))?;
            let mut users = objects::user::extract_users(&db, include_disabled)
                .map_err(|e| err(format!("Failed to extract users: {e}")))?;
            if let Some(ref term) = search {
                let lower = term.to_lowercase();
                users.retain(|u| u.sam_account_name.to_lowercase().contains(&lower));
            }
            serde_json::to_string_pretty(&users)
                .map_err(|e| err(format!("Serialization error: {e}")))
        })
        .await
        .map_err(|e| err(format!("Task error: {e}")))?
    }

    #[tool(
        name = "ntds_hashes",
        description = "Extract and decrypt password hashes from NTDS.dit. Requires both NTDS.dit and SYSTEM registry hive (for BootKey). Returns NT/LM hashes in hex format."
    )]
    async fn ntds_hashes(
        &self,
        Parameters(req): Parameters<HashesRequest>,
    ) -> Result<String, ErrorData> {
        tokio::task::spawn_blocking(move || {
            let boot_key = bootkey::extract_bootkey(&PathBuf::from(&req.system_path))
                .map_err(|e| err(format!("Failed to extract BootKey: {e}")))?;
            let db = ese::NtdsDatabase::open(&PathBuf::from(&req.ntds_path))
                .map_err(|e| err(format!("Failed to open NTDS.dit: {e}")))?;
            let encrypted_pek = crypto::extract_pek_list(&db)
                .map_err(|e| err(format!("Failed to extract PEK: {e}")))?;
            let pek = crypto::decrypt_pek(&encrypted_pek, &boot_key)
                .map_err(|e| err(format!("Failed to decrypt PEK: {e}")))?;
            let raw_hashes = objects::user::extract_user_hashes(&db)
                .map_err(|e| err(format!("Failed to extract hashes: {e}")))?;

            let entries: Vec<HashEntry> = raw_hashes
                .iter()
                .map(|raw| {
                    let nt = raw.encrypted_nt_hash.as_ref()
                        .and_then(|enc| crypto::decrypt_hash(enc, &pek, raw.rid))
                        .map(hex::encode);
                    let lm = raw.encrypted_lm_hash.as_ref()
                        .and_then(|enc| crypto::decrypt_hash(enc, &pek, raw.rid))
                        .map(hex::encode);
                    HashEntry {
                        sam_account_name: raw.sam_account_name.clone(),
                        rid: raw.rid,
                        nt_hash: nt,
                        lm_hash: lm,
                    }
                })
                .collect();

            serde_json::to_string_pretty(&entries)
                .map_err(|e| err(format!("Serialization error: {e}")))
        })
        .await
        .map_err(|e| err(format!("Task error: {e}")))?
    }

    #[tool(
        name = "ntds_objects",
        description = "Extract all AD object types from NTDS.dit: users, computers, groups, GPOs, and domain trusts with group membership resolution."
    )]
    async fn ntds_objects(
        &self,
        Parameters(req): Parameters<NtdsPathRequest>,
    ) -> Result<String, ErrorData> {
        tokio::task::spawn_blocking(move || {
            let db = ese::NtdsDatabase::open(&PathBuf::from(&req.ntds_path))
                .map_err(|e| err(format!("Failed to open NTDS.dit: {e}")))?;

            let dnt_sid_map = objects::build_dnt_sid_map(&db)
                .map_err(|e| err(format!("Failed to build DNT-SID map: {e}")))?;
            let users = objects::user::extract_users(&db, true)
                .map_err(|e| err(format!("Failed to extract users: {e}")))?;
            let computers = objects::computer::extract_computers(&db)
                .map_err(|e| err(format!("Failed to extract computers: {e}")))?;
            let mut groups = objects::group::extract_groups(&db)
                .map_err(|e| err(format!("Failed to extract groups: {e}")))?;
            let gpos = objects::gpo::extract_gpos(&db)
                .map_err(|e| err(format!("Failed to extract GPOs: {e}")))?;
            let trusts = objects::trust::extract_trusts(&db)
                .map_err(|e| err(format!("Failed to extract trusts: {e}")))?;

            if let Ok(memberships) = links::resolve_group_memberships(&db) {
                for group in &mut groups {
                    if let Some(dnt) = group.dnt {
                        if let Some(member_dnts) = memberships.get(&dnt) {
                            for &member_dnt in member_dnts {
                                if let Some(sid) = dnt_sid_map.get(&member_dnt) {
                                    group.members.push(sid.clone());
                                }
                            }
                        }
                    }
                }
            }

            let summary = ObjectsSummary {
                user_count: users.len(),
                computer_count: computers.len(),
                group_count: groups.len(),
                gpo_count: gpos.len(),
                trust_count: trusts.len(),
                users, computers, groups, gpos, trusts,
            };
            serde_json::to_string_pretty(&summary)
                .map_err(|e| err(format!("Serialization error: {e}")))
        })
        .await
        .map_err(|e| err(format!("Task error: {e}")))?
    }

    #[tool(
        name = "ntds_forensics",
        description = "Run forensic analysis on NTDS.dit: recover deleted (tombstoned) objects and detect 14 security anomalies including AS-REP roasting, Kerberoasting, unconstrained delegation, DCSync-capable accounts, and shadow credentials. Use include_acls=true for DCSync detection (slower)."
    )]
    async fn ntds_forensics(
        &self,
        Parameters(req): Parameters<ForensicsRequest>,
    ) -> Result<String, ErrorData> {
        let include_acls = req.include_acls.unwrap_or(false);
        tokio::task::spawn_blocking(move || {
            let path = PathBuf::from(&req.ntds_path);
            let db = ese::NtdsDatabase::open(&path)
                .map_err(|e| err(format!("Failed to open NTDS.dit: {e}")))?;
            let users = objects::user::extract_users(&db, true)
                .map_err(|e| err(format!("Failed to extract users: {e}")))?;
            let computers = objects::computer::extract_computers(&db)
                .map_err(|e| err(format!("Failed to extract computers: {e}")))?;
            let groups = objects::group::extract_groups(&db)
                .map_err(|e| err(format!("Failed to extract groups: {e}")))?;

            let aces_by_sid: HashMap<String, Vec<acl::AceEntry>> = if include_acls {
                acl::build_domain_aces(&db)
                    .map_err(|e| err(format!("ACL analysis failed: {e}")))?
            } else {
                HashMap::new()
            };

            let report = forensics::run_forensics(
                &db, &users, &computers, &groups, &aces_by_sid, &path,
            )
            .map_err(|e| err(format!("Forensics failed: {e}")))?;

            serde_json::to_string_pretty(&report)
                .map_err(|e| err(format!("Serialization error: {e}")))
        })
        .await
        .map_err(|e| err(format!("Task error: {e}")))?
    }
}

#[tool_handler]
impl ServerHandler for PoneglyphMcp {
    fn get_info(&self) -> ServerInfo {
        ServerInfo {
            instructions: Some(
                "Poneglyph analyzes NTDS.dit (Active Directory database) files offline. \
                 All tools require an absolute path to an NTDS.dit file. \
                 Hash extraction also requires a SYSTEM registry hive. \
                 Typical workflow: ntds_info -> ntds_users/ntds_objects -> ntds_forensics -> ntds_hashes."
                    .to_string(),
            ),
            capabilities: ServerCapabilities::builder().enable_tools().build(),
            server_info: Implementation {
                name: "poneglyph".to_string(),
                version: env!("CARGO_PKG_VERSION").to_string(),
                title: Some("Poneglyph NTDS.dit Forensic Analysis".to_string()),
                description: Some(
                    "Offline Active Directory forensics: user extraction, hash decryption, \
                     anomaly detection, tombstone recovery".to_string(),
                ),
                icons: None,
                website_url: None,
            },
            ..Default::default()
        }
    }
}

/// Run the MCP server over stdio.
pub async fn run_mcp_server() -> Result<()> {
    let server = PoneglyphMcp::new()
        .serve(rmcp::transport::io::stdio())
        .await
        .map_err(|e| anyhow::anyhow!("MCP server initialization failed: {e}"))?;
    server
        .waiting()
        .await
        .map_err(|e| anyhow::anyhow!("MCP server error: {e}"))?;
    Ok(())
}
