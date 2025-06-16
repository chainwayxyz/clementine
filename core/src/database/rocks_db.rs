use anyhow::{anyhow, Context, Result};
use borsh::{BorshDeserialize, BorshSerialize};
use rocksdb::{
    ColumnFamily, ColumnFamilyDescriptor, IteratorMode, Options, ReadOptions, WriteBatch, DB,
};
use std::collections::HashSet;
use std::path::Path;
use tracing::info;

use jmt::{
    storage::{
        HasPreimage, LeafNode, Node, NodeBatch, NodeKey, TreeReader, TreeUpdateBatch, TreeWriter,
    },
    KeyHash, OwnedValue, RootHash, Sha256Jmt, Version,
};

/// RocksDB storage implementation for the Jellyfish Merkle Tree
pub struct RocksDbStorage {
    /// The underlying RocksDB instance
    db: DB,
}

// Column family names
const NODES_CF: &str = "nodes";
const VALUES_CF: &str = "values";
const PREIMAGES_CF: &str = "preimages";
const METADATA_CF: &str = "metadata";
const VERSION_METADATA_CF: &str = "version_metadata";
const VALUE_VERSION_INDEX_CF: &str = "value_version_index";

// Special keys for metadata
const LATEST_ROOT_KEY: &[u8] = b"LATEST_ROOT";
const LATEST_VERSION_KEY: &[u8] = b"LATEST_VERSION";
const RIGHTMOST_LEAF_KEY: &[u8] = b"RIGHTMOST_LEAF";

/// Version-specific metadata structure
#[derive(Debug, Clone, BorshSerialize, BorshDeserialize, PartialEq)] // Added PartialEq for tests
pub struct VersionMetadata {
    pub root_hash: RootHash, // Made fields public for direct access in tests if needed
    pub rightmost_leaf: Option<(NodeKey, LeafNode)>,
}

/// Storage statistics
#[derive(Debug, PartialEq)] // Added PartialEq for tests
pub struct StorageStats {
    pub nodes_size: u64,
    pub values_size: u64,
    pub version_metadata_size: u64,
    pub value_version_index_size: u64,
    pub total_versions: usize,
}

impl RocksDbStorage {
    /// Creates a new `RocksDbStorage` instance or opens an existing one at the given path.
    pub fn connect<P: AsRef<Path>>(path: P) -> Result<Self> {
        let path_ref = path.as_ref();
        let db_exists =
            path_ref.exists() && path_ref.is_dir() && path_ref.read_dir()?.next().is_some();

        let mut opts = Options::default();
        opts.create_if_missing(true);
        opts.create_missing_column_families(true);

        // Recommended RocksDB options for general use cases
        opts.set_write_buffer_size(16 * 1024 * 1024); // Increased write buffer size
        opts.set_max_write_buffer_number(4); // Increased max write buffers
        opts.set_target_file_size_base(64 * 1024 * 1024);
        // opts.set_max_background_jobs(std::cmp::max(2, num_cpus::get() as i32 / 2)); // Dynamic background jobs
        opts.set_enable_write_thread_adaptive_yield(true);
        // opts.increase_parallelism(num_cpus::get() as i32); // Increase parallelism

        // Column family options
        let mut cf_opts = Options::default();
        // For production, consider enabling compression like LZ4 or ZSTD.
        // cf_opts.set_compression_type(rocksdb::DBCompressionType::Lz4);
        cf_opts.set_compression_type(rocksdb::DBCompressionType::None); // Kept as original for now

        let cf_descriptors = [
            NODES_CF,
            VALUES_CF,
            PREIMAGES_CF,
            METADATA_CF,
            VERSION_METADATA_CF,
            VALUE_VERSION_INDEX_CF,
        ]
        .iter()
        .map(|cf_name| ColumnFamilyDescriptor::new(*cf_name, cf_opts.clone()))
        .collect::<Vec<_>>();

        let db = DB::open_cf_descriptors(&opts, path_ref, cf_descriptors)
            .with_context(|| format!("Failed to open RocksDB database at {:?}", path_ref))?;

        if db_exists {
            println!("Connected to existing RocksDB database at {:?}", path_ref);
        } else {
            println!("Created new RocksDB database at {:?}", path_ref);
        }

        Ok(Self { db })
    }

    /// Helper to get a column family handle.
    fn cf_handle(&self, cf_name: &str) -> Result<&ColumnFamily> {
        // Corrected return type
        self.db
            .cf_handle(cf_name)
            .ok_or_else(|| anyhow!("Column family '{}' not found", cf_name))
    }

    /// Retrieves metadata for a specific version.
    pub fn get_version_metadata(&self, version: Version) -> Result<Option<VersionMetadata>> {
        let cf = self.cf_handle(VERSION_METADATA_CF)?;
        let key = version.to_be_bytes();
        self.db.get_cf(cf, key)?.map_or(Ok(None), |bytes| {
            VersionMetadata::try_from_slice(&bytes)
                .map(Some)
                .with_context(|| {
                    format!(
                        "Failed to deserialize version metadata for version {}",
                        version
                    )
                })
        })
    }

    /// Stores metadata for a specific version.
    fn store_version_metadata(&self, version: Version, metadata: &VersionMetadata) -> Result<()> {
        let cf = self.cf_handle(VERSION_METADATA_CF)?;
        let key = version.to_be_bytes();
        let value = borsh::to_vec(metadata).context("Failed to serialize version metadata")?;
        self.db
            .put_cf(cf, key, value)
            .context("Failed to store version metadata")
    }

    /// Retrieves the root hash for a specific version.
    pub fn get_root_at_version(&self, version: Version) -> Result<Option<RootHash>> {
        Ok(self.get_version_metadata(version)?.map(|m| m.root_hash))
    }

    /// Retrieves the rightmost leaf node for a specific version.
    pub fn get_rightmost_leaf_at_version(
        &self,
        version: Version,
    ) -> Result<Option<(NodeKey, LeafNode)>> {
        Ok(self
            .get_version_metadata(version)?
            .and_then(|m| m.rightmost_leaf))
    }

    /// Prunes the database, removing data for versions more recent than `target_version_inclusive`.
    /// The `target_version_inclusive` itself will become the new latest version.
    pub fn prune(&self, target_version_inclusive: Version) -> Result<()> {
        let latest_version = self.get_latest_version()?;

        if target_version_inclusive > latest_version {
            return Err(anyhow!(
                "Cannot prune to future version {} when latest is {}",
                target_version_inclusive,
                latest_version
            ));
        }

        // If already at the target version, and it's not a special case for ensuring v0 exists
        if target_version_inclusive == latest_version {
            // Special handling: if target is 0 and it's already the latest,
            // ensure its metadata exists. This can happen if `prune(0)` is called multiple times
            // on an already "fresh" DB.
            if target_version_inclusive == 0 && self.get_version_metadata(0)?.is_none() {
                info!(
                    "Pruning to version 0, which is current latest, but metadata missing. Ensuring default metadata for version 0."
                );
                // This path will be covered by the main logic below,
                // so no direct return here, let it flow to the metadata creation.
            } else {
                info!(
                    "Prune target version {} is the same as latest version {}. No significant pruning needed.",
                    target_version_inclusive, latest_version
                );
                // If not version 0, or if version 0 metadata already exists, then it's truly a no-op.
                if target_version_inclusive != 0 || self.get_version_metadata(0)?.is_some() {
                    return Ok(());
                }
            }
        }

        let mut batch = WriteBatch::default();

        let version_metadata_cf = self.cf_handle(VERSION_METADATA_CF)?;
        let values_cf = self.cf_handle(VALUES_CF)?;
        let value_version_index_cf = self.cf_handle(VALUE_VERSION_INDEX_CF)?;

        // Prune versions from (target_version_inclusive + 1) up to latest_version
        // This loop will not run if target_version_inclusive == latest_version
        for version_to_prune in (target_version_inclusive + 1)..=latest_version {
            let version_key_bytes = version_to_prune.to_be_bytes();

            batch.delete_cf(version_metadata_cf, version_key_bytes);

            if let Some(key_hash_list_bytes) =
                self.db.get_cf(value_version_index_cf, version_key_bytes)?
            {
                match <Vec<KeyHash>>::try_from_slice(&key_hash_list_bytes) {
                    Ok(key_hashes) => {
                        for key_hash in key_hashes {
                            let mut value_key = key_hash.0.to_vec();
                            value_key.extend_from_slice(&version_key_bytes);
                            batch.delete_cf(values_cf, value_key);
                        }
                    }
                    Err(e) => {
                        eprintln!(
                            "Warning: Failed to deserialize KeyHash list for version {}: {}. \
                             Some values for this version might not be pruned via index.",
                            version_to_prune, e
                        );
                    }
                }
            }
            batch.delete_cf(value_version_index_cf, version_key_bytes);
        }

        let metadata_cf = self.cf_handle(METADATA_CF)?;

        // Retrieve or create metadata for the target_version_inclusive.
        let target_metadata = match self.get_version_metadata(target_version_inclusive)? {
            Some(meta) => meta,
            None => {
                if target_version_inclusive == 0 {
                    // This is the "fresh start" case where version 0 metadata doesn't exist.
                    // Create it using the default empty JMT root.
                    println!( // Consider using tracing::info! if integrated
                        "No metadata found for target version 0 during prune. Creating default metadata for fresh start."
                    );

                    let fresh_v0_metadata = VersionMetadata {
                        root_hash: DEFAULT_EMPTY_JMT_ROOT,
                        rightmost_leaf: None, // An empty tree at version 0 has no rightmost leaf
                    };

                    // Store this newly created metadata for version 0.
                    // It's important to do this before it's used to update LATEST_ROOT_KEY.
                    // Storing it outside the main batch is okay here as it's a setup step.
                    self.store_version_metadata(0, &fresh_v0_metadata).context(
                        "Failed to store fresh metadata for version 0 during prune operation",
                    )?;

                    fresh_v0_metadata // Use this newly created metadata
                } else {
                    // If metadata is missing for any other version (> 0), it's an error.
                    return Err(anyhow!(
                        "No metadata found for target version {} (and it's not version 0, so this is an error)",
                        target_version_inclusive
                    ));
                }
            }
        };

        // Update the main metadata table (METADATA_CF) to reflect the new latest state.
        batch.put_cf(
            metadata_cf,
            LATEST_VERSION_KEY,
            target_version_inclusive.to_be_bytes(),
        );
        batch.put_cf(
            metadata_cf,
            LATEST_ROOT_KEY,
            target_metadata.root_hash.0.to_vec(), // Uses the (potentially newly created) root hash for v0
        );

        if let Some((ref node_key, ref leaf_node)) = target_metadata.rightmost_leaf {
            let combined_bytes = borsh::to_vec(&(node_key, leaf_node))
                .context("Failed to serialize target rightmost leaf tuple for prune")?;
            batch.put_cf(metadata_cf, RIGHTMOST_LEAF_KEY, combined_bytes);
        } else {
            // If target_metadata (especially for a fresh v0) has no rightmost_leaf
            batch.delete_cf(metadata_cf, RIGHTMOST_LEAF_KEY);
        }

        self.db
            .write(batch)
            .context("Failed to write prune batch to RocksDB")?;

        println!(
            "Pruned database. New latest version is {}. Previous latest was {}.",
            target_version_inclusive, latest_version
        );
        Ok(())
    }

    /// Inspects all column families and prints their contents.
    /// Useful for debugging.
    pub fn inspect_all(&self) -> Result<()> {
        for cf_name in [
            NODES_CF,
            VALUES_CF,
            PREIMAGES_CF,
            METADATA_CF,
            VERSION_METADATA_CF,
            VALUE_VERSION_INDEX_CF,
        ] {
            let cf = self.cf_handle(cf_name)?;
            println!("--- Column Family: {} ---", cf_name);
            let iter = self.db.iterator_cf(cf, IteratorMode::Start);
            for result in iter {
                let (key, value) = result.context("Failed to read entry during inspection")?;
                match cf_name {
                    NODES_CF => {
                        let parsed_key = NodeKey::try_from_slice(&key)
                            .map_or_else(|_| format!("{:?}", key), |nk| format!("{:?}", nk));
                        let parsed_value = Node::try_from_slice(&value).map_or_else(
                            |_| format!("Raw: {:?}", value),
                            |n| format!("Node: {:?}", n),
                        );
                        println!("{} => {}", parsed_key, parsed_value);
                    }
                    VALUES_CF => {
                        let key_repr = if key.len() >= 40 {
                            // Assuming KeyHash (32 bytes) + Version (8 bytes)
                            let key_hash_bytes: [u8; 32] = key[..32].try_into().unwrap_or_default();
                            let version_bytes: [u8; 8] = key[32..40].try_into().unwrap_or_default();
                            let version = u64::from_be_bytes(version_bytes);
                            format!("KeyHash: {:x?}, Version: {}", key_hash_bytes, version)
                        } else {
                            format!("{:?}", key)
                        };
                        println!("{} => Value: {:?}", key_repr, value);
                    }
                    PREIMAGES_CF => {
                        println!(
                            "{:x?} => Preimage: {}", // Changed to lossy string for better display
                            key,
                            String::from_utf8_lossy(&value)
                        );
                    }
                    METADATA_CF => {
                        let name = match key.as_ref() {
                            LATEST_ROOT_KEY => "LATEST_ROOT",
                            LATEST_VERSION_KEY => "LATEST_VERSION",
                            RIGHTMOST_LEAF_KEY => "RIGHTMOST_LEAF",
                            _ => "UNKNOWN_METADATA_KEY",
                        };
                        // Handle deserialization for known types
                        let val_repr = if key == LATEST_VERSION_KEY.into() && value.len() == 8 {
                            format!(
                                "{}",
                                u64::from_be_bytes(value.as_ref().try_into().unwrap_or_default())
                            )
                        } else if key == LATEST_ROOT_KEY.into() && value.len() == 32 {
                            format!("{:x?}", value)
                        } else if key == RIGHTMOST_LEAF_KEY.into() {
                            <(NodeKey, LeafNode)>::try_from_slice(&value).map_or_else(
                                |_| format!("Raw: {:?}", value),
                                |rl| format!("{:?}", rl),
                            )
                        } else {
                            format!("{:?}", value)
                        };
                        println!("{} => {}", name, val_repr);
                    }
                    VERSION_METADATA_CF => {
                        let key_repr = if key.len() == 8 {
                            format!(
                                "Version: {}",
                                u64::from_be_bytes(key.as_ref().try_into().unwrap_or_default())
                            )
                        } else {
                            format!("{:?}", key)
                        };
                        let parsed_value = VersionMetadata::try_from_slice(&value).map_or_else(
                            |_| format!("Raw: {:?}", value),
                            |meta| format!("Metadata: {:?}", meta),
                        );
                        println!("{} => {}", key_repr, parsed_value);
                    }
                    VALUE_VERSION_INDEX_CF => {
                        let key_repr = if key.len() == 8 {
                            format!(
                                "Version: {}",
                                u64::from_be_bytes(key.as_ref().try_into().unwrap_or_default())
                            )
                        } else {
                            format!("{:?}", key)
                        };
                        let parsed_value = <Vec<KeyHash>>::try_from_slice(&value).map_or_else(
                            |_| format!("Raw KeyHash List: {:?}", value),
                            |kh| format!("KeyHashes: {:?}", kh),
                        );
                        println!("{} => {}", key_repr, parsed_value);
                    }
                    _ => println!("{:?} => {:?}", key, value), // Should not happen
                }
            }
        }
        Ok(())
    }

    /// Get a JMT instance that uses this storage
    pub fn get_jmt(&self) -> Sha256Jmt<Self> {
        Sha256Jmt::new(self)
    }

    /// Retrieves metadata for a range of versions.
    pub fn get_version_metadata_range(
        &self,
        start_version: Version,
        end_version: Version,
    ) -> Result<Vec<(Version, VersionMetadata)>> {
        if start_version > end_version {
            return Ok(Vec::new());
        }
        (start_version..=end_version)
            .filter_map(|version| {
                self.get_version_metadata(version)
                    .map(|opt_meta| opt_meta.map(|meta| (version, meta)))
                    .transpose()
            })
            .collect::<Result<Vec<_>>>()
    }

    /// Retrieves a sorted list of all existing versions.
    pub fn get_all_versions(&self) -> Result<Vec<Version>> {
        let cf = self.cf_handle(VERSION_METADATA_CF)?;
        let mut versions = Vec::new();
        let iter = self.db.iterator_cf(cf, IteratorMode::Start);
        for result in iter {
            let (key, _) = result.context("Failed to read version key")?;
            if key.len() == 8 {
                // Version keys are u64 (8 bytes)
                if let Ok(version_arr) = key.as_ref().try_into() {
                    versions.push(u64::from_be_bytes(version_arr));
                } else {
                    eprintln!(
                        "Warning: Found key in {} with unexpected length: {:?}",
                        VERSION_METADATA_CF, key
                    );
                }
            }
        }
        versions.sort_unstable(); // Use unstable sort, as order of equal elements doesn't matter
        Ok(versions)
    }

    /// Retrieves storage statistics.
    pub fn get_storage_stats(&self) -> Result<StorageStats> {
        let estimate_live_data_size = |cf_name: &str| -> Result<u64> {
            let cf_handle = self.cf_handle(cf_name)?;
            // If RocksDB returns None for the estimate (e.g., for empty or very small CFs),
            // treat it as 0. This matches common practice and original behavior.
            Ok(self
                .db
                .property_int_value_cf(cf_handle, "rocksdb.estimate-live-data-size")?
                .unwrap_or(0))
        };

        Ok(StorageStats {
            nodes_size: estimate_live_data_size(NODES_CF)?,
            values_size: estimate_live_data_size(VALUES_CF)?,
            version_metadata_size: estimate_live_data_size(VERSION_METADATA_CF)?,
            value_version_index_size: estimate_live_data_size(VALUE_VERSION_INDEX_CF)?,
            total_versions: self.get_all_versions()?.len(),
        })
    }

    /// Compacts all column families in the database.
    pub fn compact(&self) -> Result<()> {
        for cf_name in [
            NODES_CF,
            VALUES_CF,
            PREIMAGES_CF,
            METADATA_CF,
            VERSION_METADATA_CF,
            VALUE_VERSION_INDEX_CF,
        ] {
            let cf = self.cf_handle(cf_name)?;
            self.db.compact_range_cf(cf, None::<&[u8]>, None::<&[u8]>);
            println!("Compaction triggered for CF: {}", cf_name);
        }
        Ok(())
    }

    /// Stores the preimage of a key hash.
    pub fn store_key_preimage(&self, key_hash: KeyHash, preimage: &[u8]) -> Result<()> {
        let cf = self.cf_handle(PREIMAGES_CF)?;
        self.db
            .put_cf(cf, key_hash.0.as_slice(), preimage)
            .with_context(|| format!("Failed to store key preimage for hash: {:?}", key_hash))
    }

    /// Retrieves the latest root hash of the tree.
    pub fn get_latest_root(&self) -> Result<Option<RootHash>> {
        let cf = self.cf_handle(METADATA_CF)?;
        self.db
            .get_cf(cf, LATEST_ROOT_KEY)?
            .map_or(Ok(None), |bytes| {
                bytes
                    .as_slice()
                    .try_into()
                    .map(RootHash)
                    .map(Some)
                    .map_err(|_| {
                        anyhow!(
                            "Invalid root hash format in metadata (expected 32 bytes, got {})",
                            bytes.len()
                        )
                    })
            })
    }

    /// Stores the latest root hash.
    fn store_latest_root(&self, root_hash: RootHash) -> Result<()> {
        let cf = self.cf_handle(METADATA_CF)?;
        self.db
            .put_cf(cf, LATEST_ROOT_KEY, root_hash.0.as_slice())
            .context("Failed to store latest root hash")
    }

    /// Updates the tree with a batch of changes for a given version.
    pub fn update_with_batch(
        &self,
        root_hash: RootHash,
        tree_update_batch: TreeUpdateBatch,
        version: Version,
    ) -> Result<()> {
        // First, write all node and value changes from the batch to their respective column families.
        // This also updates the VALUE_VERSION_INDEX_CF.
        self.write_node_batch(&tree_update_batch.node_batch)?;

        // Determine the rightmost leaf for this new version.
        // Start with the rightmost leaf from the previous version, if one exists.
        let mut new_version_rightmost_leaf: Option<(NodeKey, LeafNode)> = if version > 0 {
            self.get_version_metadata(version - 1)?
                .and_then(|prev_meta| prev_meta.rightmost_leaf)
        } else {
            None // No previous version for version 0
        };

        // Now, iterate through all leaf nodes *in the current batch*.
        // Nodes in the batch can be new leaves or updates to existing nodes (that might now be leaves).
        // If any of these are further to the right than our current candidate (or if no candidate yet),
        // it becomes the new candidate for the rightmost leaf.
        for (batch_node_key, batch_node) in tree_update_batch.node_batch.nodes() {
            if let Node::Leaf(batch_leaf_node) = batch_node {
                if new_version_rightmost_leaf.as_ref().map_or(
                    true,
                    |(_candidate_nk, candidate_leaf)| {
                        batch_leaf_node.key_hash() > candidate_leaf.key_hash()
                    },
                ) {
                    new_version_rightmost_leaf =
                        Some((batch_node_key.clone(), batch_leaf_node.clone()));
                }
            }
        }
        // At this point, new_version_rightmost_leaf holds the best candidate for the rightmost leaf
        // considering both the previous version's RML and any leaves processed in the current batch.
        // Note: This logic correctly handles new insertions and updates. If the previous RML was deleted
        // and the new RML is an older, untouched leaf not present in the current batch, this simplistic
        // deduction might be insufficient. However, for many common update patterns (including new righter leaves),
        // this is an improvement. A fully robust solution for all deletion scenarios might require more info from JMT.

        // Store the metadata for this new version.
        let version_metadata = VersionMetadata {
            root_hash,
            rightmost_leaf: new_version_rightmost_leaf.clone(), // Store the determined rightmost leaf
        };
        self.store_version_metadata(version, &version_metadata)?;

        // Update the global "latest" pointers.
        self.store_latest_root(root_hash)?;
        self.store_latest_version(version)?;

        // Update the global rightmost leaf in METADATA_CF.
        // This is an optimization for quickly getting the latest tree's rightmost leaf.
        let metadata_cf = self.cf_handle(METADATA_CF)?;
        if let Some((ref node_key, ref leaf_node)) = new_version_rightmost_leaf {
            let combined_bytes = borsh::to_vec(&(node_key, leaf_node))
                .context("Failed to serialize rightmost leaf tuple for global metadata")?;
            self.db
                .put_cf(metadata_cf, RIGHTMOST_LEAF_KEY, combined_bytes)
                .context("Failed to store global rightmost leaf in metadata")?;
        } else {
            // If there's no rightmost leaf (e.g., tree is empty after this update), delete the global key.
            self.db
                .delete_cf(metadata_cf, RIGHTMOST_LEAF_KEY)
                .context("Failed to delete global rightmost leaf from metadata")?;
        }
        Ok(())
    }

    /// Retrieves the latest version number.
    pub fn get_latest_version(&self) -> Result<Version> {
        let cf = self.cf_handle(METADATA_CF)?;
        self.db
            .get_cf(cf, LATEST_VERSION_KEY)?
            .map_or(Ok(0), |bytes| {
                // Default to version 0 if not found (e.g., new DB)
                bytes
                    .as_slice()
                    .try_into()
                    .map(u64::from_be_bytes)
                    .map_err(|_| {
                        anyhow!(
                            "Invalid version format in metadata (expected 8 bytes, got {})",
                            bytes.len()
                        )
                    })
            })
    }

    /// Stores the latest version number.
    pub fn store_latest_version(&self, version: Version) -> Result<()> {
        let cf = self.cf_handle(METADATA_CF)?;
        self.db
            .put_cf(cf, LATEST_VERSION_KEY, version.to_be_bytes())
            .context("Failed to store latest version")
    }
}

impl TreeReader for RocksDbStorage {
    fn get_node_option(&self, node_key: &NodeKey) -> Result<Option<Node>> {
        let cf = self.cf_handle(NODES_CF)?;
        let key_bytes =
            borsh::to_vec(node_key).context("Failed to serialize node key for get_node_option")?;
        self.db.get_cf(cf, key_bytes)?.map_or(Ok(None), |bytes| {
            Node::try_from_slice(&bytes)
                .map(Some)
                .with_context(|| format!("Failed to deserialize node for key: {:?}", node_key))
        })
    }

    fn get_rightmost_leaf(&self) -> Result<Option<(NodeKey, LeafNode)>> {
        let metadata_cf = self.cf_handle(METADATA_CF)?;
        if let Some(bytes) = self.db.get_cf(metadata_cf, RIGHTMOST_LEAF_KEY)? {
            match <(NodeKey, LeafNode)>::try_from_slice(&bytes) {
                Ok(tuple) => return Ok(Some(tuple)),
                Err(e) => {
                    // This could happen if data is corrupted or from an older incompatible version.
                    // Fallback to version-specific metadata.
                    eprintln!(
                        "Warning: Failed to deserialize rightmost leaf from METADATA_CF: {}. \
                         Falling back to latest version metadata.",
                        e
                    );
                }
            }
        }

        // Fallback: Get from the latest version's specific metadata.
        let latest_version = self.get_latest_version()?;
        // If latest_version is 0 and no metadata exists for it (e.g., an empty tree after init or pruned to 0),
        // then there's no rightmost leaf.
        if latest_version == 0 && self.get_version_metadata(0)?.is_none() {
            return Ok(None);
        }
        self.get_rightmost_leaf_at_version(latest_version)
    }

    fn get_value_option(
        &self,
        max_version: Version,
        key_hash: KeyHash,
    ) -> Result<Option<OwnedValue>> {
        let cf = self.cf_handle(VALUES_CF)?;
        let prefix = key_hash.0.to_vec();

        let mut read_opts = ReadOptions::default();
        read_opts.set_iterate_upper_bound(
            // Create an upper bound for the iteration: key_hash + (max_version + 1)
            // This helps RocksDB optimize by not scanning beyond relevant versions.
            {
                let mut upper_bound = prefix.clone();
                upper_bound.extend_from_slice(&(max_version + 1).to_be_bytes());
                upper_bound
            },
        );
        // Iterate in reverse from key_hash + max_version towards key_hash + 0
        // The first valid entry found will be the correct one.
        let mut iter_key = prefix.clone();
        iter_key.extend_from_slice(&max_version.to_be_bytes());

        let iter = self.db.iterator_cf_opt(
            cf,
            read_opts,
            IteratorMode::From(&iter_key, rocksdb::Direction::Reverse),
        );

        for result in iter {
            let (key, value) = result.context("Failed to read value entry during scan")?;

            // Ensure we are still within the prefix for the given key_hash
            if !key.starts_with(&prefix) {
                break; // Moved past relevant keys for this key_hash
            }

            if key.len() == prefix.len() + 8 {
                // KeyHash + Version (8 bytes)
                // The version is already implicitly <= max_version due to iteration start and direction.
                // The first item found in reverse iteration is the latest eligible version.
                return Ok(Some(value.to_vec()));
            } else {
                eprintln!(
                    "Warning: Encountered malformed key in VALUES_CF during get_value_option: {:x?}",
                    key
                );
            }
        }
        Ok(None) // No value found up to max_version
    }
}

impl HasPreimage for RocksDbStorage {
    fn preimage(&self, key_hash: KeyHash) -> Result<Option<Vec<u8>>> {
        let cf = self.cf_handle(PREIMAGES_CF)?;
        let opt_db_vector = self
            .db
            .get_cf(cf, key_hash.0.as_slice())
            .with_context(|| format!("RocksDB failed to get preimage for hash: {:?}", key_hash))?;

        Ok(opt_db_vector.map(|db_vec| db_vec.to_vec()))
    }
}

impl TreeWriter for RocksDbStorage {
    fn write_node_batch(&self, node_batch: &NodeBatch) -> Result<()> {
        let nodes_cf = self.cf_handle(NODES_CF)?;
        let values_cf = self.cf_handle(VALUES_CF)?;
        let value_version_index_cf = self.cf_handle(VALUE_VERSION_INDEX_CF)?;

        let mut batch = WriteBatch::default();
        let mut key_hashes_for_current_version = HashSet::new();
        let mut current_batch_version: Option<Version> = None;

        // Process values first to determine the batch version and validate consistency.
        for ((val_version, key_hash), value_opt) in node_batch.values() {
            if let Some(existing_version) = current_batch_version {
                if *val_version != existing_version {
                    return Err(anyhow!(
                        "NodeBatch contains mixed versions ({} and {}) for values. Expected all to be consistent.",
                        existing_version, *val_version
                    ));
                }
            } else {
                current_batch_version = Some(*val_version);
            }
            key_hashes_for_current_version.insert(*key_hash);

            let mut value_key = key_hash.0.to_vec();
            value_key.extend_from_slice(&val_version.to_be_bytes());

            if let Some(value) = value_opt {
                batch.put_cf(values_cf, &value_key, value.as_slice());
            } else {
                batch.delete_cf(values_cf, &value_key);
            }
        }

        // Write nodes
        for (key, node) in node_batch.nodes() {
            let key_bytes = borsh::to_vec(key)
                .with_context(|| format!("Failed to serialize node key: {:?}", key))?;
            let node_bytes = borsh::to_vec(node)
                .with_context(|| format!("Failed to serialize node: {:?}", node))?;
            batch.put_cf(nodes_cf, key_bytes, node_bytes);
        }

        // Update VALUE_VERSION_INDEX_CF if a version was determined and keys were affected
        if let Some(determined_version) = current_batch_version {
            if !key_hashes_for_current_version.is_empty() {
                let key_hash_vec: Vec<KeyHash> =
                    key_hashes_for_current_version.into_iter().collect();
                let serialized_key_hashes = borsh::to_vec(&key_hash_vec)
                    .context("Failed to serialize KeyHash list for version index")?;
                batch.put_cf(
                    value_version_index_cf,
                    determined_version.to_be_bytes(),
                    serialized_key_hashes,
                );
            }
        }

        self.db
            .write(batch)
            .context("Failed to write node batch to RocksDB")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin_consensus_core::utxo_set::{KeyOutPoint, OutPointBytes, UTXOBytes, UTXO};
    use jmt::ValueHash;
    use std::{fs, thread, time::Duration};
    use tempfile::{tempdir, TempDir};

    // Helper to create a RocksDbStorage instance in a temporary directory for tests.
    fn create_test_storage() -> Result<(RocksDbStorage, TempDir)> {
        let temp_dir = tempdir().context("Failed to create temp dir for test DB")?;
        let storage = RocksDbStorage::connect(temp_dir.path())?;
        Ok((storage, temp_dir))
    }

    // Helper to simplify tree updates in tests for readability
    fn update_tree_for_test(
        storage: &RocksDbStorage,
        tree: &Sha256Jmt<RocksDbStorage>, // Explicit lifetime
        version: Version,
        updates: Vec<(KeyHash, Option<Vec<u8>>)>,
    ) -> Result<RootHash> {
        let jmt_updates: Vec<(KeyHash, Option<OwnedValue>)> = updates
            .into_iter()
            .map(|(kh, val_opt)| (kh, val_opt.map(Into::into)))
            .collect();
        let (root, batch) = tree.put_value_set(jmt_updates, version)?;
        storage.update_with_batch(root, batch, version)?;
        Ok(root)
    }

    // Helper to generate KeyHash for tests
    fn kh(s: &[u8]) -> KeyHash {
        KeyHash::with::<sha2::Sha256>(s)
    }

    #[test]
    fn test_pruning_with_value_version_index() -> Result<()> {
        let (storage, _temp_dir) = create_test_storage()?;
        let tree = storage.get_jmt();

        let key_a = kh(b"key_a");
        let key_b = kh(b"key_b");
        let key_c = kh(b"key_c");

        storage.store_key_preimage(key_a, b"key_a")?;
        storage.store_key_preimage(key_b, b"key_b")?;
        storage.store_key_preimage(key_c, b"key_c")?;

        // Version 0: A=a_v0, B=b_v0
        update_tree_for_test(
            &storage,
            &tree,
            0,
            vec![
                (key_a, Some(b"a_v0".to_vec())),
                (key_b, Some(b"b_v0".to_vec())),
            ],
        )?;

        // Version 1: A=a_v1 (update), C=c_v1 (new)
        update_tree_for_test(
            &storage,
            &tree,
            1,
            vec![
                (key_a, Some(b"a_v1".to_vec())),
                (key_c, Some(b"c_v1".to_vec())),
            ],
        )?;

        // Version 2: B=b_v2 (update), C=c_v2 (update)
        update_tree_for_test(
            &storage,
            &tree,
            2,
            vec![
                (key_b, Some(b"b_v2".to_vec())),
                (key_c, Some(b"c_v2".to_vec())),
            ],
        )?;

        // Version 3: A=null (delete), B=b_v3 (update)
        update_tree_for_test(
            &storage,
            &tree,
            3,
            vec![
                (key_a, None), // Deletion of A
                (key_b, Some(b"b_v3".to_vec())),
            ],
        )?;

        assert_eq!(
            storage.get_latest_version()?,
            3,
            "Latest version before prune"
        );

        // Check value_version_index_cf for version 2
        let index_cf_handle = storage.cf_handle(VALUE_VERSION_INDEX_CF)?;
        let v2_key_hashes_bytes = storage
            .db
            .get_cf(index_cf_handle, 2u64.to_be_bytes())?
            .expect("Index for v2 should exist");
        let v2_key_hashes = <Vec<KeyHash>>::try_from_slice(&v2_key_hashes_bytes)?;
        assert_eq!(
            v2_key_hashes.len(),
            2,
            "Version 2 should have touched 2 keys (B and C)"
        );
        assert!(v2_key_hashes.contains(&key_b));
        assert!(v2_key_hashes.contains(&key_c));

        // Prune to version 1 (versions 2 and 3 should be removed)
        storage.prune(1)?;
        assert_eq!(
            storage.get_latest_version()?,
            1,
            "Latest version after prune"
        );

        // Verify states at version 1 (which is now the latest)
        assert_eq!(
            tree.get(key_a, 1)?, // Querying at current latest
            Some(b"a_v1".to_vec().into()),
            "key_a at v1"
        );
        assert_eq!(
            tree.get(key_b, 1)?,
            Some(b"b_v0".to_vec().into()),
            "key_b at v1 should be from v0"
        );
        assert_eq!(
            tree.get(key_c, 1)?,
            Some(b"c_v1".to_vec().into()),
            "key_c at v1"
        );

        // Check that the specific versioned value for (key_b, v2) is gone from VALUES_CF
        let values_cf_handle = storage.cf_handle(VALUES_CF)?;
        let mut v2_value_key_for_b = key_b.0.to_vec();
        v2_value_key_for_b.extend_from_slice(&2u64.to_be_bytes());
        assert!(
            storage
                .db
                .get_cf(values_cf_handle, v2_value_key_for_b)?
                .is_none(),
            "Value for (key_b, v2) should be pruned from VALUES_CF"
        );

        let mut v3_value_key_for_b = key_b.0.to_vec();
        v3_value_key_for_b.extend_from_slice(&3u64.to_be_bytes());
        assert!(
            storage
                .db
                .get_cf(values_cf_handle, v3_value_key_for_b)?
                .is_none(),
            "Value for (key_b, v3) should be pruned"
        );

        // Check that index entries for V2 and V3 are gone
        assert!(
            storage
                .db
                .get_cf(index_cf_handle, 2u64.to_be_bytes())?
                .is_none(),
            "Index for v2 should be pruned"
        );
        assert!(
            storage
                .db
                .get_cf(index_cf_handle, 3u64.to_be_bytes())?
                .is_none(),
            "Index for v3 should be pruned"
        );

        // Check Version Metadata
        assert!(
            storage.get_version_metadata(2)?.is_none(),
            "Version metadata for v2 should be pruned"
        );
        assert!(
            storage.get_version_metadata(3)?.is_none(),
            "Version metadata for v3 should be pruned"
        );
        assert!(
            storage.get_version_metadata(1)?.is_some(),
            "Version metadata for v1 should exist"
        );

        Ok(())
    }

    #[test]
    fn test_versioned_metadata_storage_and_retrieval() -> Result<()> {
        let (storage, _temp_dir) = create_test_storage()?;
        let tree = storage.get_jmt();

        let mut roots = vec![];
        let mut all_rightmost_leaves = vec![];

        for version in 0..3 {
            let key_val = format!("key_{}", version);
            let key_hash = kh(key_val.as_bytes());
            let value = format!("value_{}", version).into_bytes();

            storage.store_key_preimage(key_hash, key_val.as_bytes())?;

            let (root, batch) = tree.put_value_set([(key_hash, Some(value))], version)?;
            storage.update_with_batch(root, batch, version)?;
            roots.push(root);

            let current_rightmost = storage.get_rightmost_leaf_at_version(version)?.unwrap();
            all_rightmost_leaves.push(current_rightmost);
        }

        for version_idx in 0..3 {
            let version = version_idx as u64;
            let metadata = storage
                .get_version_metadata(version)?
                .expect("Should have metadata for this version");

            assert_eq!(metadata.root_hash, roots[version_idx]);
            assert_eq!(
                metadata.rightmost_leaf.as_ref(),
                Some(&all_rightmost_leaves[version_idx])
            );

            let root_from_direct_method = storage
                .get_root_at_version(version)?
                .expect("Should have root from direct method");
            assert_eq!(root_from_direct_method, roots[version_idx]);

            let rightmost_from_direct_method = storage
                .get_rightmost_leaf_at_version(version)?
                .expect("Should have rightmost leaf from direct method");
            assert_eq!(
                rightmost_from_direct_method,
                all_rightmost_leaves[version_idx]
            );
        }
        Ok(())
    }

    #[test]
    fn test_basic_pruning() -> Result<()> {
        let (storage, _temp_dir) = create_test_storage()?;
        let tree = storage.get_jmt();

        let mut key_value_pairs = vec![];
        for version in 0..5 {
            let key_s = format!("key_{}", version);
            let key_hash = kh(key_s.as_bytes());
            let value = format!("value_{}", version).into_bytes();

            storage.store_key_preimage(key_hash, key_s.as_bytes())?;
            key_value_pairs.push((key_hash, value.clone()));

            let (root, batch) = tree.put_value_set([(key_hash, Some(value))], version)?;
            storage.update_with_batch(root, batch, version)?;
        }

        assert_eq!(
            storage.get_latest_version()?,
            4,
            "Latest version before prune"
        );

        storage.prune(2)?; // Prune, making version 2 the latest

        assert_eq!(
            storage.get_latest_version()?,
            2,
            "Latest version after prune"
        );

        // Verify metadata for kept versions (0, 1, 2)
        for version in 0..=2 {
            assert!(
                storage.get_version_metadata(version)?.is_some(),
                "Metadata for version {} should exist",
                version
            );
        }

        // Verify metadata for pruned versions (3, 4) is gone
        for version in 3..=4 {
            assert!(
                storage.get_version_metadata(version)?.is_none(),
                "Metadata for version {} should be pruned",
                version
            );
        }

        // Verify values for kept versions
        // tree.get(key, version) will get the value as of 'version'
        for (idx, (key_hash, original_value)) in key_value_pairs.iter().enumerate() {
            let version = idx as u64;
            if version <= 2 {
                // Versions 0, 1, 2
                assert_eq!(
                    tree.get(*key_hash, version)?,
                    Some(original_value.clone().into()),
                    "Value for key in version {} should exist",
                    version
                );
            } else {
                // Versions 3, 4
                // For pruned versions, tree.get(key, pruned_version) should reflect state at new latest (version 2)
                // This means if a key was last updated at version 0, it will still be value_v0.
                // A direct lookup of the specific (key, pruned_version_value) should fail if that value itself was pruned.
                let value_at_new_latest = tree.get(*key_hash, 2)?; // Query at the new latest version
                assert_eq!(
                    tree.get(*key_hash, version)?,
                    value_at_new_latest,
                    "Value for key at pruned version {} should reflect state at new latest (v2)",
                    version
                );
            }
        }
        Ok(())
    }

    #[test]
    fn test_rightmost_leaf_tracking_and_persistence() -> Result<()> {
        let (storage, _temp_dir) = create_test_storage()?;
        let tree = storage.get_jmt();

        let keys = [b"utxo_c", b"utxo_a", b"utxo_b"]; // Intentionally not sorted by key for robust test
        let mut expected_rightmost_key_hash_at_version: Vec<(KeyHash, KeyHash)> = Vec::new();

        for (version_idx, key_bytes) in keys.iter().enumerate() {
            let version = version_idx as u64;
            let key_hash = kh(*key_bytes);
            let value = format!("data_{}", String::from_utf8_lossy(*key_bytes)).into_bytes(); // Corrected: dereference key_bytes
            storage.store_key_preimage(key_hash, *key_bytes)?;

            let (root, batch) = tree.put_value_set([(key_hash, Some(value))], version)?;
            storage.update_with_batch(root, batch, version)?;

            // Determine the actual rightmost leaf up to this version
            let mut current_max_kh = KeyHash([0u8; 32]);
            if version_idx == 0
                || key_hash > expected_rightmost_key_hash_at_version.last().unwrap().0
            {
                current_max_kh = key_hash;
            } else {
                current_max_kh = expected_rightmost_key_hash_at_version.last().unwrap().0;
            }
            // This finds the actual rightmost key hash among all inserted so far.
            let mut all_keys_so_far = Vec::new();
            for i in 0..=version_idx {
                all_keys_so_far.push(kh(keys[i]));
            }
            all_keys_so_far.sort(); // JMT key hashes determine leaf order
            let actual_rightmost_kh_in_tree = *all_keys_so_far.last().unwrap();

            expected_rightmost_key_hash_at_version.push((actual_rightmost_kh_in_tree, key_hash)); // Store (actual_in_tree, current_inserted)

            let version_meta = storage
                .get_version_metadata(version)?
                .expect("Metadata should exist");
            let (rm_node_key, rm_leaf_node) = version_meta
                .rightmost_leaf
                .expect("Rightmost leaf should be set in version metadata");
            assert_eq!(
                rm_leaf_node.key_hash(),
                actual_rightmost_kh_in_tree,
                "Rightmost leaf in version {} metadata mismatch",
                version
            );

            let global_rightmost = storage
                .get_rightmost_leaf()?
                .expect("Global rightmost leaf should be set");
            assert_eq!(
                global_rightmost.1.key_hash(),
                actual_rightmost_kh_in_tree,
                "Global rightmost leaf mismatch at version {}",
                version
            );
        }
        Ok(())
    }

    #[test]
    fn test_historical_root_access_after_pruning() -> Result<()> {
        let (storage, _temp_dir) = create_test_storage()?;
        let tree = storage.get_jmt();

        let key = b"evolving_utxo";
        let key_hash = kh(key);
        storage.store_key_preimage(key_hash, key)?;

        let mut historical_roots = vec![];
        for version in 0..5 {
            let value = format!("value_at_version_{}", version).into_bytes();
            let (root, batch) = tree.put_value_set([(key_hash, Some(value))], version)?;
            storage.update_with_batch(root, batch, version)?;
            historical_roots.push(root);
        }

        storage.prune(2)?; // Prune to version 2 (versions 0, 1, 2 remain)

        // Verify accessible roots
        for version_idx in 0..=2 {
            let version = version_idx as u64;
            let root = storage
                .get_root_at_version(version)?
                .expect("Root should exist for kept version");
            assert_eq!(root, historical_roots[version_idx]);
        }

        // Verify pruned roots are gone
        for version_idx in 3..5 {
            let version = version_idx as u64;
            assert!(
                storage.get_root_at_version(version)?.is_none(),
                "Root for pruned version {} should be None",
                version
            );
        }
        Ok(())
    }

    #[test]
    fn test_complex_pruning_and_value_retrieval() -> Result<()> {
        let (storage, _temp_dir) = create_test_storage()?;
        let tree = storage.get_jmt();

        let key_a_bytes = b"utxo_a";
        let key_b_bytes = b"utxo_b";
        let key_c_bytes = b"utxo_c";

        let key_a = kh(key_a_bytes);
        let key_b = kh(key_b_bytes);
        let key_c = kh(key_c_bytes);

        storage.store_key_preimage(key_a, key_a_bytes)?;
        storage.store_key_preimage(key_b, key_b_bytes)?;
        storage.store_key_preimage(key_c, key_c_bytes)?;

        // Version 0: Insert all three
        update_tree_for_test(
            &storage,
            &tree,
            0,
            vec![
                (key_a, Some(b"a_v0".to_vec())),
                (key_b, Some(b"b_v0".to_vec())),
                (key_c, Some(b"c_v0".to_vec())),
            ],
        )?;

        // Version 1: Update A
        update_tree_for_test(&storage, &tree, 1, vec![(key_a, Some(b"a_v1".to_vec()))])?;

        // Version 2: Delete B
        update_tree_for_test(&storage, &tree, 2, vec![(key_b, None)])?;

        // Version 3: Update C
        update_tree_for_test(&storage, &tree, 3, vec![(key_c, Some(b"c_v3".to_vec()))])?;

        assert_eq!(storage.get_latest_version()?, 3);
        storage.prune(1)?; // Prune to version 1 (0 and 1 remain)
        assert_eq!(storage.get_latest_version()?, 1);

        // Verify values at version 1 (the new latest)
        assert_eq!(
            tree.get(key_a, 1)?,
            Some(b"a_v1".to_vec().into()),
            "key_a at v1"
        );
        assert_eq!(
            tree.get(key_b, 1)?,
            Some(b"b_v0".to_vec().into()),
            "key_b at v1 (from v0)"
        );
        assert_eq!(
            tree.get(key_c, 1)?,
            Some(b"c_v0".to_vec().into()),
            "key_c at v1 (from v0)"
        );

        // Verify values at version 0
        assert_eq!(
            tree.get(key_a, 0)?,
            Some(b"a_v0".to_vec().into()),
            "key_a at v0"
        );
        assert_eq!(
            tree.get(key_b, 0)?,
            Some(b"b_v0".to_vec().into()),
            "key_b at v0"
        );
        assert_eq!(
            tree.get(key_c, 0)?,
            Some(b"c_v0".to_vec().into()),
            "key_c at v0"
        );

        // Attempting to get values at pruned versions (e.g., 2 or 3) should reflect the state at the new latest (v1)
        assert_eq!(
            tree.get(key_a, 2)?,
            tree.get(key_a, 1)?,
            "key_a at v2 (pruned) should fallback to v1"
        );
        assert_eq!(
            tree.get(key_b, 2)?,
            tree.get(key_b, 1)?,
            "key_b at v2 (pruned) where it was deleted, should fallback to v1 (b_v0)"
        );
        assert_eq!(
            tree.get(key_c, 3)?,
            tree.get(key_c, 1)?,
            "key_c at v3 (pruned) should fallback to v1"
        );

        Ok(())
    }

    #[test]
    fn test_version_gap_handling_and_retrieval() -> Result<()> {
        let (storage, _temp_dir) = create_test_storage()?;
        let tree = storage.get_jmt();

        let versions_to_create = vec![0, 2, 5];
        let key_hash = kh(b"test_key");
        storage.store_key_preimage(key_hash, b"test_key")?;

        for &version in &versions_to_create {
            let value = format!("value_at_{}", version).into_bytes();
            update_tree_for_test(&storage, &tree, version, vec![(key_hash, Some(value))])?;
        }

        assert_eq!(storage.get_latest_version()?, 5);

        for &version in &versions_to_create {
            assert!(
                storage.get_version_metadata(version)?.is_some(),
                "Metadata for created version {} should exist",
                version
            );
            let expected_value = format!("value_at_{}", version).into_bytes();
            assert_eq!(tree.get(key_hash, version)?, Some(expected_value.into()));
        }

        let gap_versions = vec![1, 3, 4];
        for version in gap_versions {
            assert!(
                storage.get_version_metadata(version)?.is_none(),
                "Metadata for gap version {} should not exist",
                version
            );
            // Querying a value at a gap version should retrieve the value from the closest prior existing version.
            let expected_prior_version = versions_to_create
                .iter()
                .filter(|&&v| v < version)
                .last()
                .copied();
            if let Some(prior_v) = expected_prior_version {
                let expected_value = format!("value_at_{}", prior_v).into_bytes();
                assert_eq!(
                    tree.get(key_hash, version)?,
                    Some(expected_value.into()),
                    "Value at gap version {} should be from version {}",
                    version,
                    prior_v
                );
            } else {
                // Gap version is before the first created version (e.g. if first version was > 0)
                assert_eq!(
                    tree.get(key_hash, version)?,
                    None,
                    "Value at gap version {} before any data should be None",
                    version
                );
            }
        }
        Ok(())
    }

    #[test]
    fn test_prune_error_cases() -> Result<()> {
        let (storage, _temp_dir) = create_test_storage()?;
        let tree = storage.get_jmt();

        for version in 0..3 {
            // versions 0, 1, 2
            update_tree_for_test(
                &storage,
                &tree,
                version,
                vec![(kh(&[version as u8]), Some(vec![version as u8]))],
            )?;
        }
        assert_eq!(storage.get_latest_version()?, 2);

        // Try to prune to a version > latest version (should fail)
        assert!(
            storage.prune(3).is_err(),
            "Pruning to version greater than latest should fail"
        );
        // Try to prune to a version == latest version (should be a no-op, not error)
        assert!(
            storage.prune(2).is_ok(),
            "Pruning to current latest version should be Ok (no-op)"
        );
        assert_eq!(
            storage.get_latest_version()?,
            2,
            "Version should remain unchanged after pruning to latest"
        );

        // Verify successful prune
        storage.prune(0)?;
        assert_eq!(
            storage.get_latest_version()?,
            0,
            "Latest version should be 0 after pruning to 0"
        );
        assert!(storage.get_version_metadata(0)?.is_some());
        assert!(storage.get_version_metadata(1)?.is_none());
        assert!(storage.get_version_metadata(2)?.is_none());

        Ok(())
    }

    #[test]
    fn test_version_metadata_persistence_across_reconnections() -> Result<()> {
        let temp_dir = tempdir().context("Failed to create temp dir for persistence test")?;
        let db_path = temp_dir.path().to_path_buf(); // Keep path for reuse

        let mut roots_v1 = vec![];
        // Create and populate database (first connection)
        {
            let storage = RocksDbStorage::connect(&db_path)?;
            let tree = storage.get_jmt();
            for version in 0..3 {
                let key_val = format!("key_initial_{}", version);
                let key_hash = kh(key_val.as_bytes());
                let value = format!("value_initial_{}", version).into_bytes();
                storage.store_key_preimage(key_hash, key_val.as_bytes())?;
                let (root, batch) = tree.put_value_set([(key_hash, Some(value))], version)?;
                storage.update_with_batch(root, batch, version)?;
                roots_v1.push(root);
            }
            storage
                .db
                .flush_wal(true)
                .context("Failed to flush WAL in first connection")?; // Ensure data hits disk
                                                                      // Storage (and DB) is dropped here, closing the connection
        }

        thread::sleep(Duration::from_millis(200)); // Give some time for file system operations

        // Reconnect and verify (second connection)
        {
            let storage = RocksDbStorage::connect(&db_path)?;
            assert_eq!(
                storage.get_latest_version()?,
                2,
                "Latest version mismatch after reconnect"
            );
            for version_idx in 0..3 {
                let version = version_idx as u64;
                let metadata = storage
                    .get_version_metadata(version)?
                    .expect("Metadata missing after reconnect");
                assert_eq!(
                    metadata.root_hash, roots_v1[version_idx],
                    "Root hash mismatch for version {} after reconnect",
                    version
                );
                assert!(
                    metadata.rightmost_leaf.is_some(),
                    "Rightmost leaf missing for version {} after reconnect",
                    version
                );
            }
            println!("All version metadata successfully persisted and retrieved after first reconnection.");
            storage
                .db
                .flush_wal(true)
                .context("Failed to flush WAL in second connection")?;
        }
        Ok(())
    }

    #[test]
    fn test_get_all_versions_and_range() -> Result<()> {
        let (storage, _temp_dir) = create_test_storage()?;
        let tree = storage.get_jmt();

        let versions_created = vec![0, 2, 5, 7, 10];
        for &version in &versions_created {
            update_tree_for_test(
                &storage,
                &tree,
                version,
                vec![(kh(&[version as u8]), Some(vec![0]))],
            )?;
        }

        let all_versions_retrieved = storage.get_all_versions()?;
        assert_eq!(
            all_versions_retrieved, versions_created,
            "Mismatch in all retrieved versions"
        );

        let range_metadata = storage.get_version_metadata_range(2, 7)?;
        assert_eq!(
            range_metadata.len(),
            3,
            "Incorrect number of versions in range 2-7"
        ); // Should include 2, 5, 7
        let versions_in_range: Vec<Version> = range_metadata.iter().map(|(v, _)| *v).collect();
        assert_eq!(versions_in_range, vec![2, 5, 7]);

        for (version, metadata) in range_metadata {
            assert!(metadata.rightmost_leaf.is_some());
        }

        let empty_range = storage.get_version_metadata_range(100, 101)?;
        assert!(
            empty_range.is_empty(),
            "Range query for non-existent versions should be empty"
        );

        let single_version_range = storage.get_version_metadata_range(5, 5)?;
        assert_eq!(single_version_range.len(), 1);
        assert_eq!(single_version_range[0].0, 5);

        Ok(())
    }

    #[test]
    fn test_storage_stats_estimation() -> Result<()> {
        let (storage, _temp_dir) = create_test_storage()?;
        let tree = storage.get_jmt();

        let initial_stats = storage.get_storage_stats()?;
        assert_eq!(
            initial_stats.total_versions, 0,
            "Initial total versions should be 0"
        );

        for version in 0..5 {
            let key_s = format!("key_stats_{}", version);
            let key_hash = kh(key_s.as_bytes());
            let value = vec![version as u8; 1024]; // 1KB per value
            storage.store_key_preimage(key_hash, key_s.as_bytes())?;
            update_tree_for_test(&storage, &tree, version, vec![(key_hash, Some(value))])?;
        }

        // Flush WAL to ensure data is written from memtables to L0 SSTs
        storage.db.flush_wal(true).context("Failed to flush WAL")?;

        // Compact relevant Column Families to further encourage estimates to update.
        // `estimate-live-data-size` is more accurate after compactions.
        let values_cf_handle = storage.cf_handle(VALUES_CF)?;
        storage
            .db
            .compact_range_cf(values_cf_handle, None::<&[u8]>, None::<&[u8]>);
        println!("Compaction triggered for VALUES_CF");

        let nodes_cf_handle = storage.cf_handle(NODES_CF)?;
        storage
            .db
            .compact_range_cf(nodes_cf_handle, None::<&[u8]>, None::<&[u8]>);
        println!("Compaction triggered for NODES_CF");

        // Compaction can be asynchronous. Give it some time to complete and for stats to reflect.
        thread::sleep(Duration::from_millis(300)); // Increased sleep

        let stats_after_data = storage.get_storage_stats()?;
        println!(
            "Storage stats after data, flush, and targeted compaction: {:?}",
            stats_after_data
        );
        assert_eq!(stats_after_data.total_versions, 5);

        assert!(
            stats_after_data.nodes_size >= initial_stats.nodes_size,
            "Nodes size should not decrease. Initial: {}, After data: {}",
            initial_stats.nodes_size,
            stats_after_data.nodes_size
        );
        // This is the critical assertion. If it's still 0 > 0, the data amount / test setup
        // may not be enough for RocksDB to estimate a non-zero size consistently.
        assert!(
            stats_after_data.values_size > initial_stats.values_size,
            "Values size should increase. Initial: {}, After data: {}",
            initial_stats.values_size,
            stats_after_data.values_size
        );
        assert!(
            stats_after_data.version_metadata_size >= initial_stats.version_metadata_size,
            "Version metadata size should not decrease. Initial: {}, After data: {}",
            initial_stats.version_metadata_size,
            stats_after_data.version_metadata_size
        );
        assert!(
            stats_after_data.value_version_index_size >= initial_stats.value_version_index_size,
            "Value version index size should not decrease. Initial: {}, After data: {}",
            initial_stats.value_version_index_size,
            stats_after_data.value_version_index_size
        );

        // A full DB compaction can also be done, which is what the test originally had later.
        storage
            .compact()
            .context("Failed to perform full DB compaction")?;
        thread::sleep(Duration::from_millis(200)); // Give time for full compaction and stats update

        let stats_after_full_compact = storage.get_storage_stats()?;
        println!(
            "Storage stats after full compaction: {:?}",
            stats_after_full_compact
        );
        assert_eq!(stats_after_full_compact.total_versions, 5);
        // Even after full compaction, check if values_size is greater than its initial state.
        assert!(
            stats_after_full_compact.values_size > initial_stats.values_size,
            "Values size after full compaction should still be > initial. Initial: {}, Compacted: {}",
            initial_stats.values_size, stats_after_full_compact.values_size
        );

        Ok(())
    }

    // Helper for UTXO tests
    fn generate_utxo(
        txid_byte: u8,
        vout: u32,
        value: u64,
    ) -> (KeyOutPoint, UTXO, KeyHash, OutPointBytes, UTXOBytes) {
        let key = KeyOutPoint {
            txid: [txid_byte; 32],
            vout,
        };
        let utxo = UTXO {
            value,
            block_height: 500_000,
            block_time: 1_500_000_000,
            is_coinbase: false,
            script_pubkey: vec![txid_byte; 34],
        };
        let key_bytes = OutPointBytes::from(key);
        let utxo_bytes = UTXOBytes::from(utxo.clone());
        let key_hash = kh(key_bytes.as_ref());
        (key, utxo, key_hash, key_bytes, utxo_bytes)
    }

    fn generate_dummy_utxos_for_test(count: usize) -> Vec<(KeyOutPoint, UTXO)> {
        (0..count)
            .map(|i| {
                let mut txid = [0u8; 32];
                txid[0] = 100 + i as u8; // Ensure unique txid
                (
                    KeyOutPoint {
                        txid,
                        vout: i as u32,
                    },
                    UTXO {
                        value: 10_000_000 + i as u64,
                        block_height: 400_000 + i as u32,
                        block_time: 1_400_000_000 + i as u32,
                        is_coinbase: false,
                        script_pubkey: vec![i as u8; 20],
                    },
                )
            })
            .collect()
    }

    #[test]
    fn test_utxo_lifecycle_insertion_deletion_proofs() -> Result<()> {
        let (storage, _temp_dir) = create_test_storage()?;
        let tree = storage.get_jmt();

        let (_key, _utxo, key_hash, key_bytes, utxo_bytes) = generate_utxo(1, 0, 1000);
        storage.store_key_preimage(key_hash, key_bytes.as_ref())?;

        // Insert UTXO at version 0
        let (root_v0, batch_v0) =
            tree.put_value_set([(key_hash, Some(utxo_bytes.0.clone()))], 0)?;
        storage.update_with_batch(root_v0, batch_v0, 0)?;

        let (val_opt_v0, proof_v0) = tree.get_with_proof(key_hash, 0)?;
        assert_eq!(
            val_opt_v0,
            Some(utxo_bytes.0.clone()),
            "UTXO should exist at v0"
        );
        proof_v0.verify_existence(root_v0, key_hash, &utxo_bytes.0)?;
        println!("UTXO insertion at v0 verified.");

        // Spend (delete) UTXO at version 1
        let (root_v1, update_proof_v1, batch_v1) =
            tree.put_value_set_with_proof([(key_hash, None)], 1)?;
        storage.update_with_batch(root_v1, batch_v1, 1)?;

        let (val_opt_v1, proof_v1_nonexist) = tree.get_with_proof(key_hash, 1)?;
        assert_eq!(val_opt_v1, None, "UTXO should be deleted at v1");
        proof_v1_nonexist.verify_nonexistence(root_v1, key_hash)?;

        // Verify the update proof for deletion
        update_proof_v1.verify_update(root_v0, root_v1, &[(key_hash, None::<Vec<u8>>)])?;
        println!("UTXO deletion at v1 and its proof verified.");

        assert_eq!(storage.get_latest_root()?, Some(root_v1));
        Ok(())
    }

    #[test]
    fn test_transaction_simulation_spend_create() -> Result<()> {
        let (storage, _temp_dir) = create_test_storage()?;
        let tree = storage.get_jmt();
        let mut current_version = 0;

        // 0. Populate with some initial dummy UTXOs
        let dummy_utxos = generate_dummy_utxos_for_test(3);
        let mut dummy_updates = Vec::new();
        for (key, utxo) in dummy_utxos {
            let key_bytes = OutPointBytes::from(key);
            let utxo_bytes = UTXOBytes::from(utxo);
            let kh = kh(key_bytes.as_ref());
            storage.store_key_preimage(kh, key_bytes.as_ref())?;
            dummy_updates.push((kh, Some(utxo_bytes.0)));
        }
        let (root_after_dummies, batch_dummies) =
            tree.put_value_set(dummy_updates, current_version)?;
        storage.update_with_batch(root_after_dummies, batch_dummies, current_version)?;
        let mut prev_root = root_after_dummies;
        current_version += 1;

        // 1. Create and insert a UTXO to be spent (utxo_spent)
        let (_key_spent, _utxo_spent_obj, kh_spent, kb_spent, ub_spent) =
            generate_utxo(10, 1, 5000);
        storage.store_key_preimage(kh_spent, kb_spent.as_ref())?;
        let (root_after_insert_spent, batch_insert_spent) =
            tree.put_value_set([(kh_spent, Some(ub_spent.0.clone()))], current_version)?;
        storage.update_with_batch(root_after_insert_spent, batch_insert_spent, current_version)?;

        let (val_check, proof_check_exist) = tree.get_with_proof(kh_spent, current_version)?;
        assert_eq!(val_check, Some(ub_spent.0.clone()));
        proof_check_exist.verify_existence(root_after_insert_spent, kh_spent, &ub_spent.0)?;
        prev_root = root_after_insert_spent;
        current_version += 1;

        // 2. Spend utxo_spent (delete it)
        let (root_after_delete_spent, proof_delete_spent, batch_delete_spent) =
            tree.put_value_set_with_proof([(kh_spent, None)], current_version)?;
        storage.update_with_batch(root_after_delete_spent, batch_delete_spent, current_version)?;
        proof_delete_spent.verify_update(
            prev_root,
            root_after_delete_spent,
            &[(kh_spent, None::<Vec<u8>>)],
        )?;
        prev_root = root_after_delete_spent;
        current_version += 1;

        // 3. Create a new UTXO (utxo_created)
        let (_key_created, _utxo_created_obj, kh_created, kb_created, ub_created) =
            generate_utxo(11, 0, 3000);
        storage.store_key_preimage(kh_created, kb_created.as_ref())?;
        let (root_after_insert_created, proof_insert_created, batch_insert_created) = tree
            .put_value_set_with_proof(
                [(kh_created, Some(ub_created.0.clone()))],
                current_version,
            )?;
        storage.update_with_batch(
            root_after_insert_created,
            batch_insert_created,
            current_version,
        )?;
        proof_insert_created.verify_update(
            prev_root,
            root_after_insert_created,
            &[(kh_created, Some(ub_created.0.clone()))],
        )?;

        assert_eq!(storage.get_latest_root()?, Some(root_after_insert_created));
        assert_eq!(storage.get_latest_version()?, current_version);
        Ok(())
    }

    #[test]
    fn test_utxo_update_same_key_different_value() -> Result<()> {
        let (storage, _temp_dir) = create_test_storage()?;
        let tree = storage.get_jmt();
        let mut current_version = 0;

        // 1. Insert initial UTXO (utxo_v1)
        let (_key, _utxo_v1_obj, key_hash, key_bytes, utxo_v1_bytes) = generate_utxo(20, 0, 1000);
        storage.store_key_preimage(key_hash, key_bytes.as_ref())?;
        let (root_v0, batch_v0) =
            tree.put_value_set([(key_hash, Some(utxo_v1_bytes.0.clone()))], current_version)?;
        storage.update_with_batch(root_v0, batch_v0, current_version)?;
        let mut prev_root = root_v0;
        current_version += 1;

        // 2. Update the UTXO (utxo_v2 - same key, new value)
        let utxo_v2 = UTXO {
            value: 800,
            block_height: 500_001,
            .._utxo_v1_obj.clone()
        };
        let utxo_v2_bytes = UTXOBytes::from(utxo_v2);
        let (root_v1, proof_update, batch_v1) = tree.put_value_set_with_proof(
            [(key_hash, Some(utxo_v2_bytes.0.clone()))],
            current_version,
        )?;
        storage.update_with_batch(root_v1, batch_v1, current_version)?;

        // Verify update proof
        proof_update.verify_update(
            prev_root,
            root_v1,
            &[(key_hash, Some(utxo_v2_bytes.0.clone()))],
        )?;

        // Verify current state
        let (val_current, proof_current) = tree.get_with_proof(key_hash, current_version)?;
        assert_eq!(val_current, Some(utxo_v2_bytes.0.clone()));
        proof_current.verify_existence(root_v1, key_hash, &utxo_v2_bytes.0)?;

        // Verify previous state is still accessible by version
        let (val_prev_version, _) = tree.get_with_proof(key_hash, current_version - 1)?;
        assert_eq!(val_prev_version, Some(utxo_v1_bytes.0));
        Ok(())
    }

    #[test]
    fn test_first_utxo_insertion_into_empty_tree() -> Result<()> {
        let (storage, _temp_dir) = create_test_storage()?;
        let tree = storage.get_jmt();

        assert_eq!(
            storage.get_latest_version()?,
            0,
            "Initial version should be 0 for new DB"
        );
        assert!(
            storage.get_latest_root()?.is_none(),
            "Initial root should be None for new DB"
        );

        let (_key, _utxo_obj, key_hash, key_bytes, utxo_bytes) = generate_utxo(30, 0, 500);
        storage.store_key_preimage(key_hash, key_bytes.as_ref())?;

        // JMT's initial "empty" root is a specific placeholder, not None.
        // The `put_value_set_with_proof` will use this initial root.
        let initial_tree_root = RootHash::from([
            83, 80, 65, 82, 83, 69, 95, 77, 69, 82, 75, 76, 69, 95, 80, 76, 65, 67, 69, 72, 79, 76,
            68, 69, 82, 95, 72, 65, 83, 72, 95, 95,
        ]); // Empty Merkle tree root

        let (root_after_insert, update_proof, batch) = tree.put_value_set_with_proof(
            [(key_hash, Some(utxo_bytes.0.clone()))],
            0, // First version
        )?;
        storage.update_with_batch(root_after_insert, batch, 0)?;

        let (val_opt, proof_exist) = tree.get_with_proof(key_hash, 0)?;
        assert_eq!(val_opt, Some(utxo_bytes.0.clone()));
        proof_exist.verify_existence(root_after_insert, key_hash, &utxo_bytes.0)?;

        // The `prev_root_hash` for the update proof should be what the JMT considered its root before this update.
        // If the DB was truly empty (no METADATA_CF LATEST_ROOT), JMT starts from its theoretical empty root.
        let jmt_internal_empty_root = RootHash::from([
            83, 80, 65, 82, 83, 69, 95, 77, 69, 82, 75, 76, 69, 95, 80, 76, 65, 67, 69, 72, 79, 76,
            68, 69, 82, 95, 72, 65, 83, 72, 95, 95,
        ]); // Empty Merkle tree root

        update_proof.verify_update(
            jmt_internal_empty_root,
            root_after_insert,
            &[(key_hash, Some(utxo_bytes.0.clone()))],
        )?;

        assert_eq!(storage.get_latest_root()?, Some(root_after_insert));
        assert_eq!(storage.get_latest_version()?, 0);
        Ok(())
    }

    #[test]
    fn test_reconnection_to_existing_db_and_data_integrity() -> Result<()> {
        let temp_dir_obj = tempdir().context("Failed to create temp_dir for reconnection test")?;
        let db_path = temp_dir_obj.path().to_path_buf(); // Ensure path lives long enough

        let key1_bytes = b"key_conn_1";
        let val1_bytes = b"val_conn_1";
        let meta_key_bytes = b"meta_conn_key";
        let meta_val_bytes = b"meta_conn_val";

        // First connection: Create DB, write some data directly (not via JMT)
        {
            let storage1 = RocksDbStorage::connect(&db_path)?;
            let preimages_cf1 = storage1.cf_handle(PREIMAGES_CF)?;
            let metadata_cf1 = storage1.cf_handle(METADATA_CF)?;

            storage1.db.put_cf(preimages_cf1, key1_bytes, val1_bytes)?;
            storage1
                .db
                .put_cf(metadata_cf1, meta_key_bytes, meta_val_bytes)?;
            storage1.db.flush_wal(true)?; // Ensure data is on disk
                                          // storage1 is dropped, DB closed
        }

        thread::sleep(Duration::from_millis(100));

        // Second connection: Reconnect, verify old data, write new data
        let key2_bytes = b"key_conn_2";
        let val2_bytes = b"val_conn_2";
        {
            let storage2 = RocksDbStorage::connect(&db_path)?;
            let preimages_cf2 = storage2.cf_handle(PREIMAGES_CF)?;
            let metadata_cf2 = storage2.cf_handle(METADATA_CF)?;

            assert_eq!(
                storage2.db.get_cf(preimages_cf2, key1_bytes)?,
                Some(val1_bytes.to_vec()),
                "Data from conn1 (key1) mismatch in conn2"
            );
            assert_eq!(
                storage2.db.get_cf(metadata_cf2, meta_key_bytes)?,
                Some(meta_val_bytes.to_vec()),
                "Data from conn1 (meta_key) mismatch in conn2"
            );

            storage2.db.put_cf(preimages_cf2, key2_bytes, val2_bytes)?;
            storage2.db.flush_wal(true)?;
            // storage2 is dropped
        }

        thread::sleep(Duration::from_millis(100));

        // Third connection: Verify all data
        {
            let storage3 = RocksDbStorage::connect(&db_path)?;
            let preimages_cf3 = storage3.cf_handle(PREIMAGES_CF)?;
            let metadata_cf3 = storage3.cf_handle(METADATA_CF)?;

            assert_eq!(
                storage3.db.get_cf(preimages_cf3, key1_bytes)?,
                Some(val1_bytes.to_vec()),
                "Data from conn1 (key1) mismatch in conn3"
            );
            assert_eq!(
                storage3.db.get_cf(metadata_cf3, meta_key_bytes)?,
                Some(meta_val_bytes.to_vec()),
                "Data from conn1 (meta_key) mismatch in conn3"
            );
            assert_eq!(
                storage3.db.get_cf(preimages_cf3, key2_bytes)?,
                Some(val2_bytes.to_vec()),
                "Data from conn2 (key2) mismatch in conn3"
            );
            println!("All data verified across reconnections.");
        }
        Ok(())
    }
}