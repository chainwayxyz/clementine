//! # Text Database
//!
//! Raw text file as the database. This is a simple solution to the database
//! problem. It might not be a suitable solution. Therefore, it might be better
//! to use a DBMS in production.
//!
//! ## File Format
//!
//! Data is serialized using serde, before writing to the file. So, it's a JSON
//! file.

use super::common::DatabaseContent;
use serde::{Deserialize, Serialize};
use std::io::prelude::*;
use std::{
    fs::{self, File},
    path::PathBuf,
};

/// Configuration for the text database.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct TextDatabase {
    /// File to save database.
    file: PathBuf,
}
impl TextDatabase {
    pub fn new(file: PathBuf) -> Self {
        Self { file }
    }

    /// Reads data from a text file and returns deserialized `DatabaseContent`.
    pub fn read(&self) -> Result<DatabaseContent, std::io::Error> {
        let contents = match fs::read_to_string(&self.file) {
            Ok(c) => c,
            Err(e) => return Err(e),
        };

        let deserialized: DatabaseContent = match serde_json::from_str(&contents) {
            Ok(c) => c,
            Err(e) => return Err(e.into()),
        };

        Ok(deserialized)
    }

    /// Serializes data and writes to a text file.
    pub fn write(&self, content: DatabaseContent) -> Result<(), std::io::Error> {
        let serialized = match serde_json::to_string(&content) {
            Ok(c) => c,
            Err(e) => return Err(e.into()),
        };

        let mut file = match File::create(&self.file) {
            Ok(c) => c,
            Err(e) => return Err(e.into()),
        };

        return file.write_all(serialized.as_bytes());
    }
}

#[cfg(test)]
mod tests {
    use std::fs;

    use crate::{
        constants::TEXT_DATABASE,
        db::{
            common::DatabaseContent,
            text::TextDatabase,
        },
    };

    #[test]
    fn new() {
        assert_eq!(
            TextDatabase::new(TEXT_DATABASE.into()),
            TextDatabase {
                file: TEXT_DATABASE.into()
            }
        )
    }

    /// Writes mock database to file, then reads it. Compares if input equals
    /// output.
    #[test]
    fn write_read() {
        let expected = DatabaseContent::new();
        let dbms = TextDatabase::new(TEXT_DATABASE.into());

        // Check if file is writable.
        match dbms.write(expected.clone()) {
            Ok(_) => assert!(true),
            Err(_) => assert!(false),
        };

        // Check if read operation is successful.
        match dbms.read() {
            Ok(c) => assert_eq!(expected, c),
            Err(_) => assert!(false),
        }

        // Clean things up.
        match fs::remove_file(TEXT_DATABASE) {
            Ok(_) => assert!(true),
            Err(_) => assert!(false),
        }
    }
}
