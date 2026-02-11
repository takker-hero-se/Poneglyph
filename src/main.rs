use anyhow::Result;
use clap::{Parser, Subcommand};
use std::path::PathBuf;

mod ese;
mod schema;
mod objects;
mod bootkey;
mod crypto;
mod collect;
mod output;
mod links;
mod acl;
mod forensics;

#[derive(Parser)]
#[command(name = "poneglyph")]
#[command(version = "0.2.0")]
#[command(about = "NTDS.dit forensic analysis tool - part of GolDRoger suite")]
#[command(long_about = "Poneglyph decodes the secrets hidden within Active Directory's NTDS.dit database.\nLike the ancient stones that reveal hidden history, this tool reads the binary\nstructure of ESE databases to extract users, groups, relationships, and attack paths.")]
struct Cli {
    /// Enable verbose output
    #[arg(short, long, global = true)]
    verbose: bool,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Display database information (tables, record counts, page size)
    Info {
        /// Path to NTDS.dit file
        #[arg(short, long)]
        ntds: PathBuf,
    },

    /// Extract user accounts from NTDS.dit
    Users {
        /// Path to NTDS.dit file
        #[arg(short, long)]
        ntds: PathBuf,

        /// Output format: json, csv, table
        #[arg(short, long, default_value = "table")]
        format: String,

        /// Output file path (stdout if not specified)
        #[arg(short, long)]
        output: Option<PathBuf>,

        /// Include disabled accounts
        #[arg(long)]
        include_disabled: bool,
    },

    /// Extract password hashes (requires SYSTEM hive)
    Hashes {
        /// Path to NTDS.dit file
        #[arg(short, long)]
        ntds: PathBuf,

        /// Path to SYSTEM registry hive
        #[arg(short, long)]
        system: PathBuf,

        /// Output file path (stdout if not specified)
        #[arg(short, long)]
        output: Option<PathBuf>,

        /// Output format: hashcat, john, pwdump
        #[arg(long, default_value = "hashcat")]
        format: String,
    },

    /// Collect NTDS.dit and SYSTEM hive from a live domain controller (requires admin)
    Collect {
        /// Output directory for collected files
        #[arg(short, long, default_value = "poneglyph-collect")]
        output_dir: PathBuf,

        /// Custom NTDS.dit path (auto-detect if not specified)
        #[arg(long)]
        ntds_path: Option<PathBuf>,

        /// Don't delete the shadow copy after collection
        #[arg(long)]
        no_cleanup: bool,

        /// Create a zip archive of collected files
        #[arg(long)]
        zip: bool,
    },

    /// Run forensic analysis: tombstone recovery + anomaly detection
    Forensics {
        /// Path to NTDS.dit file
        #[arg(short, long)]
        ntds: PathBuf,

        /// Output directory for forensics report
        #[arg(short, long, default_value = "poneglyph-forensics")]
        output_dir: PathBuf,

        /// Include ACL analysis for DCSync detection (slower)
        #[arg(long)]
        acls: bool,
    },

    /// Full dump: extract all objects, relationships, and generate output files
    Dump {
        /// Path to NTDS.dit file
        #[arg(short, long)]
        ntds: PathBuf,

        /// Path to SYSTEM registry hive (optional, needed for hash extraction)
        #[arg(long)]
        system: Option<PathBuf>,

        /// Output directory
        #[arg(short, long, default_value = "poneglyph-output")]
        output_dir: PathBuf,

        /// Domain name (auto-detected if not specified)
        #[arg(long)]
        domain: Option<String>,

        /// Generate BloodHound-compatible JSON
        #[arg(long)]
        bloodhound: bool,

        /// Generate hashcat-format hash file
        #[arg(long)]
        hashcat: bool,

        /// Generate D3.js graph JSON for GolDRoger web UI
        #[arg(long)]
        graph: bool,

        /// Generate forensic timeline CSV
        #[arg(long)]
        timeline: bool,

        /// Generate all output formats
        #[arg(long)]
        all: bool,
    },
}

fn print_banner() {
    let ver = env!("CARGO_PKG_VERSION");
    eprintln!(r"
    ┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
    ┃                                              ┃
    ┃    ░▒▓█  P O N E G L Y P H  █▓▒░            ┃
    ┃    ◆━━━━━━━━━━━━━━━━━━━━━━━━━━━━◆            ┃
    ┃                                              ┃
    ┃     NTDS.dit Forensic Analysis Tool          ┃
    ┃     Decode the secrets within AD             ┃
    ┃                                              ┃
    ┃     BootKey ─► PEK ─► Hash ─► Decode         ┃
    ┃                                              ┃
    ┃    ◆━━━━━━━━━━━━━━━━━━━━━━━━━━━━◆            ┃");
    eprintln!("    ┃                                 v{:<6}      ┃", ver);
    eprintln!(r"    ┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛");
    eprintln!();
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    if cli.verbose {
        env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("debug")).init();
    } else {
        env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();
    }

    print_banner();

    match cli.command {
        Commands::Info { ntds } => cmd_info(&ntds),
        Commands::Users { ntds, format, output, include_disabled } => {
            cmd_users(&ntds, &format, output.as_deref(), include_disabled)
        }
        Commands::Hashes { ntds, system, output, format } => {
            cmd_hashes(&ntds, &system, output.as_deref(), &format)
        }
        Commands::Collect { output_dir, ntds_path, no_cleanup, zip } => {
            cmd_collect(&output_dir, ntds_path.as_deref(), no_cleanup, zip)
        }
        Commands::Forensics { ntds, output_dir, acls } => {
            cmd_forensics(&ntds, &output_dir, acls)
        }
        Commands::Dump { ntds, system, output_dir, domain, bloodhound, hashcat, graph, timeline, all } => {
            cmd_dump(&ntds, system.as_deref(), &output_dir, domain.as_deref(), bloodhound, hashcat, graph, timeline, all)
        }
    }
}

fn cmd_info(ntds_path: &std::path::Path) -> Result<()> {
    println!("Poneglyph - NTDS.dit Analysis Tool");
    println!("===================================\n");

    let db = ese::NtdsDatabase::open(ntds_path)?;
    let info = db.info()?;

    println!("Database: {}", ntds_path.display());
    println!("Tables:   {}", info.table_count);
    println!();

    println!("Table Details:");
    println!("{:<30} {:>10}", "Name", "Records");
    println!("{}", "-".repeat(42));
    for table_info in &info.tables {
        if table_info.record_count >= 0 {
            println!("{:<30} {:>10}", table_info.name, table_info.record_count);
        } else {
            println!("{:<30} {:>10}", table_info.name, "N/A");
        }
    }

    Ok(())
}

fn cmd_users(
    ntds_path: &std::path::Path,
    format: &str,
    output: Option<&std::path::Path>,
    include_disabled: bool,
) -> Result<()> {
    let db = ese::NtdsDatabase::open(ntds_path)?;
    let users = objects::user::extract_users(&db, include_disabled)?;

    println!("Extracted {} user accounts", users.len());

    let content = match format {
        "json" => serde_json::to_string_pretty(&users)?,
        "csv" => {
            let mut out = String::from("sAMAccountName,SID,Enabled,PwdLastSet,LastLogon,Description\n");
            for u in &users {
                out.push_str(&format!(
                    "{},{},{},{},{},{}\n",
                    u.sam_account_name,
                    u.sid.as_deref().unwrap_or("-"),
                    u.enabled,
                    u.pwd_last_set.as_deref().unwrap_or("-"),
                    u.last_logon_timestamp.as_deref().unwrap_or("-"),
                    u.description.as_deref().unwrap_or(""),
                ));
            }
            out
        }
        _ => {
            // Table format
            println!();
            println!("{:<25} {:<50} {:<8} {:<22} {}", "Account", "SID", "Enabled", "PwdLastSet", "Description");
            println!("{}", "-".repeat(120));
            for u in &users {
                println!(
                    "{:<25} {:<50} {:<8} {:<22} {}",
                    u.sam_account_name,
                    u.sid.as_deref().unwrap_or("-"),
                    if u.enabled { "Yes" } else { "No" },
                    u.pwd_last_set.as_deref().unwrap_or("-"),
                    u.description.as_deref().unwrap_or(""),
                );
            }
            return Ok(());
        }
    };

    if let Some(path) = output {
        std::fs::write(path, &content)?;
        println!("Written to {}", path.display());
    } else {
        println!("{}", content);
    }

    Ok(())
}

fn cmd_hashes(
    ntds_path: &std::path::Path,
    system_path: &std::path::Path,
    output: Option<&std::path::Path>,
    _format: &str,
) -> Result<()> {
    // Step 1: Extract BootKey from SYSTEM hive
    println!("[1/4] Extracting BootKey from SYSTEM hive...");
    let bootkey = bootkey::extract_bootkey(system_path)?;
    println!("  BootKey: {}", hex::encode(bootkey));

    // Step 2: Open NTDS.dit and extract encrypted PEK
    println!("[2/4] Extracting encrypted PEK from NTDS.dit...");
    let db = ese::NtdsDatabase::open(ntds_path)?;
    let encrypted_pek = crypto::extract_pek_list(&db)?;

    // Step 3: Decrypt PEK using BootKey
    println!("[3/4] Decrypting PEK...");
    let pek = crypto::decrypt_pek(&encrypted_pek, &bootkey)?;
    println!("  PEK: {}", hex::encode(pek));

    // Step 4: Extract and decrypt user hashes
    println!("[4/4] Extracting and decrypting password hashes...");
    let raw_hashes = objects::user::extract_user_hashes(&db)?;
    println!("  Found {} accounts with encrypted hashes", raw_hashes.len());

    let mut user_hashes = Vec::new();
    let mut success_count = 0u32;

    for raw in &raw_hashes {
        let nt_hash = raw.encrypted_nt_hash.as_ref()
            .and_then(|enc| crypto::decrypt_hash(enc, &pek, raw.rid));
        let lm_hash = raw.encrypted_lm_hash.as_ref()
            .and_then(|enc| crypto::decrypt_hash(enc, &pek, raw.rid));

        if nt_hash.is_some() || lm_hash.is_some() {
            success_count += 1;
        }

        user_hashes.push(crypto::UserHash {
            sam_account_name: raw.sam_account_name.clone(),
            rid: raw.rid,
            nt_hash,
            lm_hash,
        });
    }

    println!("  Decrypted {} hashes successfully", success_count);

    // Output in hashcat format
    output::hashcat::write_hashes(&user_hashes, output)?;

    Ok(())
}

fn cmd_collect(
    output_dir: &std::path::Path,
    ntds_path: Option<&std::path::Path>,
    no_cleanup: bool,
    zip: bool,
) -> Result<()> {
    println!("Poneglyph - AD Evidence Collection");
    println!("===================================\n");

    let result = collect::collect_ad_files(output_dir, ntds_path, no_cleanup)?;

    println!();
    println!("Collection complete!");
    println!("  NTDS.dit:  {} ({:.1} MB)", result.ntds_path.display(), result.ntds_size as f64 / 1_048_576.0);
    println!("  SYSTEM:    {} ({:.1} MB)", result.system_path.display(), result.system_size as f64 / 1_048_576.0);
    println!("  EDB logs:  {} file(s)", result.log_files.len());
    println!("  DB state:  {}", result.db_state);

    if zip {
        println!();
        println!("Creating zip archive...");
        let zip_path = collect::zip_collected_files(output_dir)?;
        let zip_size = std::fs::metadata(&zip_path)?.len();
        println!("  Archive: {} ({:.1} MB)", zip_path.display(), zip_size as f64 / 1_048_576.0);
    }

    println!();
    println!("Next steps:");
    println!("  poneglyph info   --ntds {}", result.ntds_path.display());
    println!("  poneglyph users  --ntds {}", result.ntds_path.display());
    println!("  poneglyph hashes --ntds {} --system {}", result.ntds_path.display(), result.system_path.display());

    Ok(())
}

fn cmd_dump(
    ntds_path: &std::path::Path,
    system_path: Option<&std::path::Path>,
    output_dir: &std::path::Path,
    domain: Option<&str>,
    bloodhound: bool,
    hashcat: bool,
    graph: bool,
    timeline: bool,
    all: bool,
) -> Result<()> {
    let do_bloodhound = all || bloodhound;
    let do_hashcat = all || hashcat;
    let do_graph = all || graph;
    let do_timeline = all || timeline;

    // If nothing specified, default to all
    let none_selected = !do_bloodhound && !do_hashcat && !do_graph && !do_timeline;
    let do_bloodhound = do_bloodhound || none_selected;
    let do_graph = do_graph || none_selected;
    let do_timeline = do_timeline || none_selected;
    let do_hashcat = do_hashcat || (none_selected && system_path.is_some());

    std::fs::create_dir_all(output_dir)?;

    println!("Poneglyph - Full AD Dump");
    println!("========================\n");

    // Step 1: Open database
    println!("[1/7] Opening NTDS.dit...");
    let db = ese::NtdsDatabase::open(ntds_path)?;

    // Step 2: Build DNT→SID map
    println!("[2/7] Building DNT→SID mapping...");
    let dnt_sid_map = objects::build_dnt_sid_map(&db)?;
    println!("  {} objects with SIDs", dnt_sid_map.len());

    // Step 3: Extract all objects
    println!("[3/7] Extracting AD objects...");

    let users = objects::user::extract_users(&db, true)?;
    println!("  Users:     {}", users.len());

    let computers = objects::computer::extract_computers(&db)?;
    println!("  Computers: {}", computers.len());

    let mut groups = objects::group::extract_groups(&db)?;
    println!("  Groups:    {}", groups.len());

    let gpos = objects::gpo::extract_gpos(&db)?;
    println!("  GPOs:      {}", gpos.len());

    let trusts = objects::trust::extract_trusts(&db)?;
    println!("  Trusts:    {}", trusts.len());

    // Step 4: Resolve group memberships via link_table
    println!("[4/7] Resolving group memberships from link_table...");
    match links::resolve_group_memberships(&db) {
        Ok(memberships) => {
            let mut total_members = 0usize;
            for group in &mut groups {
                if let Some(dnt) = group.dnt {
                    if let Some(member_dnts) = memberships.get(&dnt) {
                        for &member_dnt in member_dnts {
                            if let Some(sid) = dnt_sid_map.get(&member_dnt) {
                                group.members.push(sid.clone());
                                total_members += 1;
                            }
                        }
                    }
                }
            }
            println!("  Resolved {} membership links", total_members);
        }
        Err(e) => {
            log::warn!("Failed to resolve link_table: {}. Group memberships will be empty.", e);
            println!("  Warning: Could not parse link_table ({})", e);
        }
    }

    // Step 5: Auto-detect domain name
    let domain_name = domain
        .map(|s| s.to_string())
        .or_else(|| {
            // Try to detect from user UPN suffix
            users.iter()
                .find_map(|u| u.user_principal_name.as_deref())
                .and_then(|upn| upn.split('@').nth(1))
                .map(|d| d.to_uppercase())
        })
        .unwrap_or_else(|| "UNKNOWN.LOCAL".to_string());
    println!("\n  Domain: {}", domain_name);

    // Step 6: Hash extraction (if SYSTEM hive provided)
    let mut user_hashes = Vec::new();
    if let Some(sys_path) = system_path {
        println!("[5/7] Extracting password hashes...");
        let bootkey = bootkey::extract_bootkey(sys_path)?;
        let encrypted_pek = crypto::extract_pek_list(&db)?;
        let pek = crypto::decrypt_pek(&encrypted_pek, &bootkey)?;
        let raw_hashes = objects::user::extract_user_hashes(&db)?;

        for raw in &raw_hashes {
            let nt_hash = raw.encrypted_nt_hash.as_ref()
                .and_then(|enc| crypto::decrypt_hash(enc, &pek, raw.rid));
            let lm_hash = raw.encrypted_lm_hash.as_ref()
                .and_then(|enc| crypto::decrypt_hash(enc, &pek, raw.rid));

            user_hashes.push(crypto::UserHash {
                sam_account_name: raw.sam_account_name.clone(),
                rid: raw.rid,
                nt_hash,
                lm_hash,
            });
        }
        println!("  Decrypted {} hashes", user_hashes.len());
    } else {
        println!("[5/7] Skipping hash extraction (no SYSTEM hive provided)");
    }

    // Step 7: Generate outputs
    println!("[6/7] Generating output files...");

    if do_bloodhound {
        let bh_dir = output_dir.join("bloodhound");
        output::bloodhound::write_bloodhound(&bh_dir, &domain_name, &users, &computers, &groups, &trusts)?;
        println!("  BloodHound JSON -> {}", bh_dir.display());
    }

    if do_graph {
        let graph_path = output_dir.join("graph.json");
        output::graph::write_graph(&graph_path, &users, &computers, &groups, &trusts)?;
        println!("  D3.js Graph     -> {}", graph_path.display());
    }

    if do_timeline {
        let csv_path = output_dir.join("timeline.csv");
        output::csv::write_timeline(&csv_path, &users, &computers, &groups)?;
        println!("  Timeline CSV    -> {}", csv_path.display());
    }

    if do_hashcat && !user_hashes.is_empty() {
        let hash_path = output_dir.join("hashes.txt");
        output::hashcat::write_hashes(&user_hashes, Some(&hash_path))?;
        println!("  Hashcat hashes  -> {}", hash_path.display());
    }

    // Summary
    println!("\n[7/7] Done!");
    println!("========================================");
    println!("  Users:     {}", users.len());
    println!("  Computers: {}", computers.len());
    println!("  Groups:    {}", groups.len());
    println!("  GPOs:      {}", gpos.len());
    println!("  Trusts:    {}", trusts.len());
    if !user_hashes.is_empty() {
        println!("  Hashes:    {}", user_hashes.len());
    }
    println!("  Output:    {}", output_dir.display());

    Ok(())
}

fn cmd_forensics(
    ntds_path: &std::path::Path,
    output_dir: &std::path::Path,
    include_acls: bool,
) -> Result<()> {
    println!("Poneglyph - Forensics Analysis");
    println!("===============================\n");

    std::fs::create_dir_all(output_dir)?;

    // Step 1: Open database
    println!("[1/5] Opening NTDS.dit...");
    let db = ese::NtdsDatabase::open(ntds_path)?;

    // Step 2: Extract objects (include disabled for forensics)
    println!("[2/5] Extracting AD objects...");
    let users = objects::user::extract_users(&db, true)?;
    println!("  Users:     {}", users.len());
    let computers = objects::computer::extract_computers(&db)?;
    println!("  Computers: {}", computers.len());
    let groups = objects::group::extract_groups(&db)?;
    println!("  Groups:    {}", groups.len());

    // Step 3: ACL analysis (optional)
    println!("[3/5] ACL analysis...");
    let aces_by_sid = if include_acls {
        build_domain_aces(&db)?
    } else {
        println!("  Skipped (use --acls to enable DCSync detection)");
        std::collections::HashMap::new()
    };

    // Step 4: Run forensics
    println!("[4/5] Running forensics analysis...");
    let report = forensics::run_forensics(
        &db, &users, &computers, &groups, &aces_by_sid, ntds_path,
    )?;

    // Step 5: Output
    println!("[5/5] Generating output...");
    let report_path = output_dir.join("forensics-report.json");
    forensics::write_report(&report, &report_path)?;
    println!("  Report: {}", report_path.display());

    // Write deleted objects timeline
    let timeline_path = output_dir.join("deleted-timeline.csv");
    output::csv::write_forensics_timeline(
        &timeline_path,
        &users,
        &computers,
        &groups,
        Some(&report.deleted_objects),
    )?;
    println!("  Timeline: {}", timeline_path.display());

    // Print summary to stdout
    forensics::print_summary(&report);

    Ok(())
}

fn build_domain_aces(
    db: &ese::NtdsDatabase,
) -> Result<std::collections::HashMap<String, Vec<acl::AceEntry>>> {
    let sd_table = db.sd_table()?;
    let record_count = sd_table.count_records()?;

    let mut aces_by_sid: std::collections::HashMap<String, Vec<acl::AceEntry>> =
        std::collections::HashMap::new();

    // Find sd_value column in sd_table
    let col_count = sd_table.count_columns()?;
    let mut sd_value_col: Option<i32> = None;
    for i in 0..col_count {
        if let Ok(col) = sd_table.column(i) {
            if let Ok(name) = col.name() {
                if name == "sd_value" {
                    sd_value_col = Some(i);
                }
            }
        }
    }

    let sd_col = match sd_value_col {
        Some(c) => c,
        None => {
            log::warn!("sd_value column not found in sd_table");
            return Ok(aces_by_sid);
        }
    };

    println!("  Parsing {} security descriptors...", record_count);

    for i in 0..record_count {
        let record = match sd_table.record(i) {
            Ok(r) => r,
            Err(_) => continue,
        };

        if let Some(sd_data) = objects::get_binary_value(&record, Some(sd_col)) {
            if let Ok(aces) = acl::parse_security_descriptor(&sd_data) {
                for ace in aces {
                    aces_by_sid.entry(ace.principal_sid.clone())
                        .or_default()
                        .push(ace);
                }
            }
        }
    }

    println!("  Parsed {} principals with ACEs", aces_by_sid.len());
    Ok(aces_by_sid)
}
