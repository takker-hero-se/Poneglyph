use anyhow::{Context, Result, bail};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::Command;

/// Result of a successful collection operation.
pub struct CollectResult {
    pub ntds_path: PathBuf,
    pub system_path: PathBuf,
    pub ntds_size: u64,
    pub system_size: u64,
    pub log_files: Vec<PathBuf>,
    pub db_state: DbState,
}

/// ESE database shutdown state.
#[derive(Debug, Clone, PartialEq)]
pub enum DbState {
    Clean,
    Dirty,
    Unknown(String),
}

impl std::fmt::Display for DbState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DbState::Clean => write!(f, "Clean Shutdown"),
            DbState::Dirty => write!(f, "Dirty Shutdown"),
            DbState::Unknown(s) => write!(f, "{}", s),
        }
    }
}

/// Collect NTDS.dit and SYSTEM hive from a live domain controller.
///
/// Uses Volume Shadow Copy to safely copy the locked NTDS.dit and
/// its EDB transaction logs, and `reg save` to export the SYSTEM registry hive.
/// After collection, verifies database integrity with `esentutl /mh`.
pub fn collect_ad_files(
    output_dir: &Path,
    custom_ntds: Option<&Path>,
    no_cleanup: bool,
) -> Result<CollectResult> {
    // Step 1: Check admin privileges
    if !is_admin() {
        bail!(
            "Administrator privileges required.\n\
             Please run this command from an elevated (Administrator) command prompt."
        );
    }
    log::info!("Running with administrator privileges");

    // Step 2: Determine NTDS.dit path
    let ntds_source = match custom_ntds {
        Some(p) => p.to_path_buf(),
        None => find_ntds_path()?,
    };
    log::info!("NTDS.dit source: {}", ntds_source.display());

    // Determine the NTDS directory (contains log files)
    let ntds_dir = ntds_source.parent()
        .ok_or_else(|| anyhow::anyhow!("Cannot determine NTDS directory from path"))?;

    // Determine drive letter from NTDS.dit path
    let drive = ntds_source
        .to_str()
        .and_then(|s| s.chars().next())
        .ok_or_else(|| anyhow::anyhow!("Cannot determine drive letter from NTDS.dit path"))?;

    // Get the relative path within the drive (e.g., "Windows\NTDS\ntds.dit")
    let ntds_relative = ntds_source
        .to_str()
        .and_then(|s| s.get(3..)) // Skip "C:\"
        .ok_or_else(|| anyhow::anyhow!("Invalid NTDS.dit path format"))?;

    // Get the relative path for the NTDS directory
    let ntds_dir_relative = ntds_dir
        .to_str()
        .and_then(|s| s.get(3..)) // Skip "C:\"
        .ok_or_else(|| anyhow::anyhow!("Invalid NTDS directory path format"))?;

    // Create output directory
    std::fs::create_dir_all(output_dir)
        .context(format!("Failed to create output directory: {}", output_dir.display()))?;

    // Step 3: Create Volume Shadow Copy
    println!("[1/4] Creating Volume Shadow Copy for {}:\\", drive);
    let (shadow_device, shadow_id) = create_shadow_copy(drive)?;
    log::info!("Shadow Copy device: {}", shadow_device);
    log::info!("Shadow Copy ID: {}", shadow_id);

    // Step 4: Copy NTDS.dit from shadow copy
    println!("[2/4] Copying NTDS.dit from shadow copy...");
    let shadow_ntds_path = format!("{}\\{}", shadow_device, ntds_relative);
    let dest_ntds = output_dir.join("ntds.dit");

    let copy_result = std::fs::copy(&shadow_ntds_path, &dest_ntds)
        .context(format!("Failed to copy NTDS.dit from {}", shadow_ntds_path));

    // Step 5: Copy EDB log files from shadow copy
    println!("[3/4] Copying EDB transaction logs...");
    let shadow_ntds_dir = format!("{}\\{}", shadow_device, ntds_dir_relative);
    let log_files = copy_edb_logs(&shadow_ntds_dir, output_dir);

    // Clean up shadow copy regardless of copy result
    if !no_cleanup {
        println!("  Cleaning up shadow copy...");
        if let Err(e) = delete_shadow_copy(&shadow_id) {
            log::warn!("Failed to delete shadow copy: {}. Manual cleanup may be needed.", e);
            eprintln!("  Warning: Could not delete shadow copy {}. Run: vssadmin delete shadows /shadow={} /quiet", shadow_id, shadow_id);
        }
    } else {
        println!("  Shadow copy retained (--no-cleanup): {}", shadow_id);
    }

    let ntds_size = copy_result?;
    println!("  NTDS.dit copied ({:.1} MB)", ntds_size as f64 / 1_048_576.0);

    let log_files = match log_files {
        Ok(files) => {
            if files.is_empty() {
                println!("  No EDB log files found");
            } else {
                let total: u64 = files.iter()
                    .filter_map(|p| std::fs::metadata(p).ok())
                    .map(|m| m.len())
                    .sum();
                println!("  {} EDB log file(s) copied ({:.1} MB)", files.len(), total as f64 / 1_048_576.0);
            }
            files
        }
        Err(e) => {
            eprintln!("  Warning: Failed to copy EDB logs: {}", e);
            vec![]
        }
    };

    // Step 6: Save SYSTEM hive
    println!("[4/4] Saving SYSTEM registry hive...");
    let dest_system = output_dir.join("SYSTEM");
    save_system_hive(&dest_system)?;
    let system_size = std::fs::metadata(&dest_system)
        .context("Failed to read SYSTEM hive metadata")?
        .len();
    println!("  SYSTEM hive saved ({:.1} MB)", system_size as f64 / 1_048_576.0);

    // Step 7: Verify database state with esentutl
    println!();
    let db_state = verify_db_state(&dest_ntds);
    match &db_state {
        DbState::Clean => {
            println!("  Database state: Clean Shutdown (OK)");
        }
        DbState::Dirty => {
            eprintln!("  WARNING: Database state: Dirty Shutdown");
            eprintln!("  The database may contain uncommitted transactions.");
            if log_files.is_empty() {
                eprintln!("  No EDB log files were found - recovery may not be possible.");
                eprintln!("  Consider using 'ntdsutil \"activate instance ntds\" ifm \"create full <dir>\"' instead.");
            } else {
                eprintln!("  EDB log files have been collected for potential recovery.");
                eprintln!("  You can attempt recovery with: esentutl /r edb /d /l <log_dir>");
            }
        }
        DbState::Unknown(msg) => {
            eprintln!("  Database state: {} (esentutl check failed)", msg);
            eprintln!("  The database may still be usable - try opening it with Poneglyph.");
        }
    }

    Ok(CollectResult {
        ntds_path: dest_ntds,
        system_path: dest_system,
        ntds_size,
        system_size,
        log_files,
        db_state,
    })
}

/// Copy EDB transaction log files from the shadow copy NTDS directory.
///
/// Copies: edb.log, edb*.log, edbres*.jrs, edb.chk, temp.edb
fn copy_edb_logs(shadow_ntds_dir: &str, output_dir: &Path) -> Result<Vec<PathBuf>> {
    let mut copied = Vec::new();

    // List files in the shadow NTDS directory
    let entries = std::fs::read_dir(shadow_ntds_dir)
        .context(format!("Failed to read NTDS directory: {}", shadow_ntds_dir))?;

    for entry in entries {
        let entry = entry?;
        let path = entry.path();

        if !path.is_file() {
            continue;
        }

        let file_name = match path.file_name().and_then(|n| n.to_str()) {
            Some(n) => n.to_lowercase(),
            None => continue,
        };

        // Match EDB log files: edb*.log, edb*.jrs, edb.chk, temp.edb
        let should_copy = file_name.starts_with("edb") && (
            file_name.ends_with(".log") ||
            file_name.ends_with(".jrs") ||
            file_name.ends_with(".chk")
        ) || file_name == "temp.edb";

        if should_copy {
            let original_name = path.file_name().unwrap().to_str().unwrap();
            let dest = output_dir.join(original_name);
            match std::fs::copy(&path, &dest) {
                Ok(size) => {
                    log::debug!("Copied {} ({} bytes)", original_name, size);
                    copied.push(dest);
                }
                Err(e) => {
                    log::warn!("Failed to copy {}: {}", original_name, e);
                }
            }
        }
    }

    Ok(copied)
}

/// Verify the ESE database state using `esentutl /mh`.
///
/// Returns Clean, Dirty, or Unknown.
fn verify_db_state(ntds_path: &Path) -> DbState {
    let ntds_str = match ntds_path.to_str() {
        Some(s) => s,
        None => return DbState::Unknown("Invalid path".to_string()),
    };

    let output = match Command::new("esentutl")
        .args(["/mh", ntds_str])
        .output()
    {
        Ok(o) => o,
        Err(e) => return DbState::Unknown(format!("esentutl not found: {}", e)),
    };

    let stdout = String::from_utf8_lossy(&output.stdout);
    log::debug!("esentutl /mh output:\n{}", stdout);

    // Parse "State:" line from esentutl output
    for line in stdout.lines() {
        let line = line.trim();
        if line.starts_with("State:") {
            let state = line.strip_prefix("State:").unwrap().trim();
            if state.contains("Clean Shutdown") {
                return DbState::Clean;
            } else if state.contains("Dirty Shutdown") {
                return DbState::Dirty;
            } else {
                return DbState::Unknown(state.to_string());
            }
        }
    }

    DbState::Unknown("Could not determine state".to_string())
}

/// Check if the current process has administrator privileges.
fn is_admin() -> bool {
    let output = Command::new("net")
        .args(["session"])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status();

    matches!(output, Ok(status) if status.success())
}

/// Find the NTDS.dit path from the registry, falling back to the default location.
fn find_ntds_path() -> Result<PathBuf> {
    // Try to read from registry: HKLM\SYSTEM\CurrentControlSet\Services\NTDS\Parameters
    let output = Command::new("reg")
        .args([
            "query",
            r"HKLM\SYSTEM\CurrentControlSet\Services\NTDS\Parameters",
            "/v",
            "DSA Database File",
        ])
        .output()
        .context("Failed to query registry for NTDS.dit path")?;

    if output.status.success() {
        let stdout = String::from_utf8_lossy(&output.stdout);
        // Parse the REG_SZ value from output like:
        //     DSA Database File    REG_SZ    C:\Windows\NTDS\ntds.dit
        for line in stdout.lines() {
            let line = line.trim();
            if line.contains("DSA Database File") {
                if let Some(path_str) = line.split("REG_SZ").nth(1) {
                    let path = PathBuf::from(path_str.trim());
                    if !path.as_os_str().is_empty() {
                        log::info!("NTDS.dit path from registry: {}", path.display());
                        return Ok(path);
                    }
                }
            }
        }
    }

    // Default path
    let system_root = std::env::var("SystemRoot").unwrap_or_else(|_| r"C:\Windows".to_string());
    let default_path = PathBuf::from(format!(r"{}\NTDS\ntds.dit", system_root));
    log::info!("Using default NTDS.dit path: {}", default_path.display());
    Ok(default_path)
}

/// Create a Volume Shadow Copy and return (device_path, shadow_id).
fn create_shadow_copy(drive: char) -> Result<(String, String)> {
    let output = Command::new("vssadmin")
        .args(["create", "shadow", &format!("/for={}:", drive)])
        .output()
        .context("Failed to execute vssadmin. Is the Volume Shadow Copy service running?")?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        let stdout = String::from_utf8_lossy(&output.stdout);
        bail!(
            "vssadmin create shadow failed.\n\
             stdout: {}\n\
             stderr: {}\n\
             Ensure the Volume Shadow Copy service is running and there is sufficient disk space.",
            stdout.trim(),
            stderr.trim()
        );
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    log::debug!("vssadmin output:\n{}", stdout);

    let device = parse_shadow_field(&stdout, "Shadow Copy Volume Name")
        .ok_or_else(|| anyhow::anyhow!(
            "Could not parse Shadow Copy Volume Name from vssadmin output:\n{}",
            stdout
        ))?;

    let shadow_id = parse_shadow_field(&stdout, "Shadow Copy ID")
        .ok_or_else(|| anyhow::anyhow!(
            "Could not parse Shadow Copy ID from vssadmin output:\n{}",
            stdout
        ))?;

    Ok((device, shadow_id))
}

/// Parse a field value from vssadmin output.
/// Looks for lines like: "   Shadow Copy Volume Name: \\?\GLOBALROOT\Device\..."
fn parse_shadow_field(output: &str, field_name: &str) -> Option<String> {
    for line in output.lines() {
        let line = line.trim();
        if let Some(rest) = line.strip_prefix(field_name) {
            if let Some(value) = rest.strip_prefix(':') {
                return Some(value.trim().to_string());
            }
        }
    }
    None
}

/// Save the SYSTEM registry hive to a file using `reg save`.
fn save_system_hive(dest: &Path) -> Result<()> {
    let dest_str = dest.to_str()
        .ok_or_else(|| anyhow::anyhow!("Invalid output path for SYSTEM hive"))?;

    let output = Command::new("reg")
        .args(["save", r"HKLM\SYSTEM", dest_str, "/y"])
        .output()
        .context("Failed to execute reg save")?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        bail!("reg save HKLM\\SYSTEM failed: {}", stderr.trim());
    }

    Ok(())
}

/// Delete a shadow copy by its ID.
fn delete_shadow_copy(shadow_id: &str) -> Result<()> {
    let output = Command::new("vssadmin")
        .args([
            "delete",
            "shadows",
            &format!("/shadow={}", shadow_id),
            "/quiet",
        ])
        .output()
        .context("Failed to execute vssadmin delete")?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        bail!("vssadmin delete shadows failed: {}", stderr.trim());
    }

    Ok(())
}

/// Zip all files in the output directory into a single archive.
///
/// Returns the path to the created zip file.
pub fn zip_collected_files(output_dir: &Path) -> Result<PathBuf> {
    let now = chrono::Local::now();
    let zip_name = format!("poneglyph-collect-{}.zip", now.format("%Y%m%d-%H%M%S"));
    let zip_path = output_dir.join(&zip_name);

    let zip_file = std::fs::File::create(&zip_path)
        .context(format!("Failed to create zip file: {}", zip_path.display()))?;
    let mut zip = zip::ZipWriter::new(zip_file);
    let options = zip::write::SimpleFileOptions::default()
        .compression_method(zip::CompressionMethod::Deflated);

    let mut count = 0u32;
    for entry in std::fs::read_dir(output_dir)
        .context(format!("Failed to read directory: {}", output_dir.display()))?
    {
        let entry = entry?;
        let path = entry.path();

        // Skip the zip file itself and directories
        if path == zip_path || !path.is_file() {
            continue;
        }

        let file_name = match path.file_name().and_then(|n| n.to_str()) {
            Some(n) => n.to_string(),
            None => continue,
        };

        zip.start_file(&file_name, options)
            .context(format!("Failed to add {} to zip", file_name))?;

        let mut f = std::fs::File::open(&path)
            .context(format!("Failed to open {}", path.display()))?;
        let mut buf = Vec::new();
        f.read_to_end(&mut buf)?;
        zip.write_all(&buf)?;

        count += 1;
        log::debug!("Added to zip: {}", file_name);
    }

    zip.finish()?;

    let zip_size = std::fs::metadata(&zip_path)?.len();
    log::info!("Created zip archive: {} ({} files, {:.1} MB)",
        zip_path.display(), count, zip_size as f64 / 1_048_576.0);

    Ok(zip_path)
}
