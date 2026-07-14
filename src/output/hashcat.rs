use crate::crypto::UserHash;
use anyhow::Result;
use std::io::Write;
use std::path::Path;

const EMPTY_NT_HASH: &str = "31d6cfe0d16ae931b73c59d7e0c089c0";
const EMPTY_LM_HASH: &str = "aad3b435b51404eeaad3b435b51404ee";

/// Format a single hash entry in secretsdump-compatible format:
/// `username:RID:LM_HASH:NT_HASH:::`
///
/// Caveat: a `None` hash is rendered as the well-known empty-password value for
/// hashcat/secretsdump compatibility. A genuinely blank password decrypts to
/// that same value via the crypto path (so it arrives as `Some`), so `None` here
/// generally means the attribute was absent. Present-but-undecryptable hashes are
/// logged as a warning at the decryption site so a failure is never silently
/// presented as a blank password.
pub fn format_entry(entry: &UserHash) -> String {
    let nt = entry.nt_hash
        .map(|h| hex::encode(h))
        .unwrap_or_else(|| EMPTY_NT_HASH.to_string());

    let lm = entry.lm_hash
        .map(|h| hex::encode(h))
        .unwrap_or_else(|| EMPTY_LM_HASH.to_string());

    format!("{}:{}:{}:{}:::", entry.sam_account_name, entry.rid, lm, nt)
}

/// Write all hash entries to a file or stdout.
pub fn write_hashes(entries: &[UserHash], output: Option<&Path>) -> Result<()> {
    let mut lines: Vec<String> = entries.iter().map(format_entry).collect();
    lines.sort();

    let content = lines.join("\n");

    if let Some(path) = output {
        // The output holds decrypted domain credentials — create it non-world-readable.
        let mut file = create_private_file(path)?;
        file.write_all(content.as_bytes())?;
        file.write_all(b"\n")?;
        log::info!("Written {} hashes to {}", entries.len(), path.display());
    } else {
        println!("{}", content);
    }

    Ok(())
}

/// Create a file restricted to the owner (mode 0o600) on Unix. On Windows the
/// file inherits the directory ACL; document that the output directory must be
/// access-controlled when handling extracted credentials.
fn create_private_file(path: &Path) -> std::io::Result<std::fs::File> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(path)
    }
    #[cfg(not(unix))]
    {
        std::fs::File::create(path)
    }
}
