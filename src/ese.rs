use anyhow::{Context, Result};
use libesedb::EseDb;
use std::path::Path;

/// Information about a single table in the database.
#[derive(Debug)]
pub struct TableInfo {
    pub name: String,
    pub record_count: i64,
}

/// Summary information about the NTDS.dit database.
#[derive(Debug)]
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
        let path_str = path.to_str()
            .context("Invalid path encoding")?;

        let db = EseDb::open(path_str)
            .context(format!("Failed to open ESE database: {}", path.display()))?;

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

    /// Get a reference to the underlying EseDb.
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
