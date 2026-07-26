use anyhow::{Context, Result, bail};
use libesedb::EseDb;
use serde::Serialize;
use std::path::Path;

/// Convert a filesystem path to the string form libesedb's file layer expects.
/// On Windows, libbfio rejects forward-slash separators, so a Unix-style path
/// (e.g. "C:/dev/ntds.dit" passed from Git-Bash/WSL/scripts) is normalized to
/// backslashes; otherwise libesedb fails with an opaque "unable to open file".
pub fn libesedb_path(path: &Path) -> Result<String> {
    let s = path.to_str()
        .with_context(|| format!("Path is not valid UTF-8: {}", path.display()))?;
    #[cfg(windows)]
    { Ok(s.replace('/', "\\")) }
    #[cfg(not(windows))]
    { Ok(s.to_string()) }
}

/// Information about a single table in the database.
#[derive(Debug, Serialize)]
pub struct TableInfo {
    pub name: String,
    pub record_count: i64,
}

/// Summary information about the NTDS.dit database.
#[derive(Debug, Serialize)]
pub struct DatabaseInfo {
    pub table_count: i32,
    pub tables: Vec<TableInfo>,
}

/// Wrapper around libesedb for NTDS.dit access.
pub struct NtdsDatabase {
    db: EseDb,
}

impl NtdsDatabase {
    /// Open an NTDS.dit file for reading.
    pub fn open(path: &Path) -> Result<Self> {
        // Clear error for a missing/unreadable file rather than libesedb's opaque
        // open failure. (Path::exists handles either separator on Windows.)
        if !path.exists() {
            bail!("ESE database not found: {}", path.display());
        }

        let path_str = libesedb_path(path)?;

        let db = EseDb::open(&path_str)
            .with_context(|| format!(
                "Failed to open ESE database: {path_str} \
                 (if it is a valid ESE/NTDS.dit, it may be a Dirty-Shutdown capture \
                 needing `esentutl /r` soft-recovery on a working copy first)"
            ))?;

        Ok(Self { db })
    }

    /// Get database summary information.
    pub fn info(&self) -> Result<DatabaseInfo> {
        let table_count = self.db.count_tables()
            .context("Failed to count tables")?;

        let mut tables = Vec::new();

        for i in 0..table_count {
            let table = self.db.table(i)
                .context(format!("Failed to open table index {}", i))?;

            let name = table.name()
                .context("Failed to get table name")?;

            let record_count = match table.count_records() {
                Ok(n) => n as i64,
                Err(e) => {
                    log::warn!("Could not count records for table '{}': {}", name, e);
                    -1
                }
            };

            tables.push(TableInfo {
                name,
                record_count,
            });
        }

        Ok(DatabaseInfo {
            table_count,
            tables,
        })
    }

    /// Get a reference to the underlying EseDb. (Reserved public API for library
    /// consumers needing raw ESE access; not used internally.)
    #[allow(dead_code)]
    pub fn db(&self) -> &EseDb {
        &self.db
    }

    /// Open the datatable (main AD object table).
    pub fn datatable(&self) -> Result<libesedb::Table<'_>> {
        let table_count = self.db.count_tables()?;
        for i in 0..table_count {
            let table = self.db.table(i)?;
            if table.name()? == "datatable" {
                return Ok(table);
            }
        }
        anyhow::bail!("datatable not found in NTDS.dit")
    }

    /// Open the link_table (relationships between AD objects).
    pub fn link_table(&self) -> Result<libesedb::Table<'_>> {
        let table_count = self.db.count_tables()?;
        for i in 0..table_count {
            let table = self.db.table(i)?;
            if table.name()? == "link_table" {
                return Ok(table);
            }
        }
        anyhow::bail!("link_table not found in NTDS.dit")
    }

    /// Open the sd_table (security descriptors).
    pub fn sd_table(&self) -> Result<libesedb::Table<'_>> {
        let table_count = self.db.count_tables()?;
        for i in 0..table_count {
            let table = self.db.table(i)?;
            if table.name()? == "sd_table" {
                return Ok(table);
            }
        }
        anyhow::bail!("sd_table not found in NTDS.dit")
    }
}
