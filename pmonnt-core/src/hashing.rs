//! SHA-256 hashing utility with caching

use anyhow::{anyhow, Context, Result};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::fs::{self, File};
use std::io::{BufReader, Read};
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::SystemTime;

#[derive(Debug, Clone, Copy)]
struct FileMeta {
    modified: SystemTime,
    len: u64,
}

trait FileOps: Send + Sync {
    fn canonicalize(&self, path: &Path) -> std::path::PathBuf;
    fn metadata(&self, path: &str) -> Result<FileMeta>;
    fn open(&self, path: &str) -> Result<Box<dyn Read + Send>>;
}

#[derive(Debug, Default)]
struct StdFileOps;

impl FileOps for StdFileOps {
    fn canonicalize(&self, path: &Path) -> std::path::PathBuf {
        std::fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf())
    }

    fn metadata(&self, path: &str) -> Result<FileMeta> {
        let metadata = fs::metadata(path)
            .with_context(|| format!("Cannot read file metadata for '{}'", path))?;
        let modified = metadata
            .modified()
            .map_err(|e| anyhow!("Cannot get file modification time: {}", e))?;
        Ok(FileMeta {
            modified,
            len: metadata.len(),
        })
    }

    fn open(&self, path: &str) -> Result<Box<dyn Read + Send>> {
        let file = File::open(path).with_context(|| format!("Cannot open file '{}'", path))?;
        Ok(Box::new(file))
    }
}

/// Cache entry for a computed hash
#[derive(Debug, Clone)]
struct HashCacheEntry {
    sha256: String,
    modified_time: SystemTime,
    file_size: u64,
}

/// Hash computer with caching based on file path and modification time
#[derive(Clone)]
pub struct HashComputer {
    cache: Arc<Mutex<HashMap<String, HashCacheEntry>>>,
    ops: Arc<dyn FileOps>,
}

impl HashComputer {
    pub fn new() -> Self {
        Self {
            cache: Arc::new(Mutex::new(HashMap::new())),
            ops: Arc::new(StdFileOps::default()),
        }
    }

    #[cfg(test)]
    fn new_with_ops(ops: Arc<dyn FileOps>) -> Self {
        Self {
            cache: Arc::new(Mutex::new(HashMap::new())),
            ops,
        }
    }

    /// Compute SHA-256 hash of a file, using cache if file hasn't changed
    /// Uses streaming reads to avoid loading entire file into memory
    /// Cache key: (path, mtime, size) for robustness
    pub fn compute_sha256(&self, path: &str) -> Result<String> {
        let meta = self.ops.metadata(path)?;
        let modified_time = meta.modified;
        let file_size = meta.len;

        // Preserve existing normalization semantics, but route canonicalization through ops.
        let cache_key = {
            let p = Path::new(path);
            let p = self.ops.canonicalize(p);
            let s = p.to_string_lossy().to_string();

            #[cfg(windows)]
            {
                s.replace('\\', "/").to_ascii_lowercase()
            }

            #[cfg(not(windows))]
            {
                s
            }
        };

        // Check cache first
        {
            let cache = self.cache.lock().unwrap_or_else(|p| p.into_inner());
            if let Some(entry) = cache.get(&cache_key) {
                if entry.modified_time == modified_time && entry.file_size == file_size {
                    return Ok(entry.sha256.clone());
                }
            }
        }

        // Compute hash using streaming reads
        let file = self.ops.open(path)?;
        let mut reader = BufReader::new(file);
        let mut hasher = Sha256::new();
        let mut buffer = [0u8; 8192]; // 8KB chunks

        loop {
            let bytes_read = reader
                .read(&mut buffer)
                .map_err(|e| anyhow!("Cannot read file: {}", e))?;

            if bytes_read == 0 {
                break;
            }

            hasher.update(&buffer[..bytes_read]);
        }

        let result = hasher.finalize();
        let sha256 = format!("{:x}", result);

        // Update cache
        {
            let mut cache = self.cache.lock().unwrap_or_else(|p| p.into_inner());
            cache.insert(
                cache_key,
                HashCacheEntry {
                    sha256: sha256.clone(),
                    modified_time,
                    file_size,
                },
            );
        }

        Ok(sha256)
    }
}

impl Default for HashComputer {
    fn default() -> Self {
        Self::new()
    }
}

/// Standalone function to compute SHA-256 without caching
/// Uses streaming reads to avoid loading entire file into memory
pub fn compute_sha256_simple<P: AsRef<Path>>(path: P) -> Result<String> {
    let path_ref = path.as_ref();
    let file = File::open(path_ref)
        .with_context(|| format!("Cannot open file '{}'", path_ref.display()))?;

    let mut reader = BufReader::new(file);
    let mut hasher = Sha256::new();
    let mut buffer = [0u8; 8192]; // 8KB chunks

    loop {
        let bytes_read = reader
            .read(&mut buffer)
            .map_err(|e| anyhow!("Cannot read file: {}", e))?;

        if bytes_read == 0 {
            break;
        }

        hasher.update(&buffer[..bytes_read]);
    }

    let result = hasher.finalize();
    Ok(format!("{:x}", result))
}

/// Returns true if `s` is exactly 64 ASCII hex characters.
pub fn is_valid_sha256(s: &str) -> bool {
    s.len() == 64 && s.chars().all(|c| c.is_ascii_hexdigit())
}

#[cfg(test)]
mod tests {
    use super::{is_valid_sha256, FileMeta, FileOps, HashComputer};
    use std::collections::HashMap;
    use std::io::{Cursor, Read};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};
    use std::time::{Duration, SystemTime};

    #[test]
    fn valid_sha256_lower_hex() {
        assert!(is_valid_sha256(
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        ));
    }

    #[test]
    fn valid_sha256_upper_hex() {
        assert!(is_valid_sha256(
            "E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855"
        ));
    }

    #[test]
    fn invalid_sha256_wrong_len() {
        assert!(!is_valid_sha256("deadbeef"));
    }

    #[test]
    fn invalid_sha256_non_hex() {
        let mut s = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855".to_string();
        s.replace_range(0..1, "z");
        assert!(!is_valid_sha256(&s));
    }

    // Regression tests: HashComputer cache behavior must remain deterministic.

    #[derive(Clone)]
    struct MockFileOps {
        files: Arc<Mutex<HashMap<String, (Vec<u8>, FileMeta)>>>,
        opens: Arc<AtomicUsize>,
    }

    impl MockFileOps {
        fn new() -> Self {
            Self {
                files: Arc::new(Mutex::new(HashMap::new())),
                opens: Arc::new(AtomicUsize::new(0)),
            }
        }

        fn put(&self, path: &str, bytes: Vec<u8>, modified: SystemTime) {
            let meta = FileMeta {
                modified,
                len: bytes.len() as u64,
            };
            self.files
                .lock()
                .unwrap()
                .insert(path.to_string(), (bytes, meta));
        }

        fn set_modified(&self, path: &str, modified: SystemTime) {
            let mut guard = self.files.lock().unwrap();
            let Some((_bytes, meta)) = guard.get_mut(path) else {
                return;
            };
            meta.modified = modified;
        }

        fn opens(&self) -> usize {
            self.opens.load(Ordering::Relaxed)
        }
    }

    impl FileOps for MockFileOps {
        fn canonicalize(&self, path: &std::path::Path) -> std::path::PathBuf {
            // Identity: keep tests OS-independent.
            path.to_path_buf()
        }

        fn metadata(&self, path: &str) -> anyhow::Result<FileMeta> {
            let guard = self.files.lock().unwrap();
            let (_, meta) = guard
                .get(path)
                .cloned()
                .ok_or_else(|| anyhow::anyhow!("missing mock file"))?;
            Ok(meta)
        }

        fn open(&self, path: &str) -> anyhow::Result<Box<dyn Read + Send>> {
            self.opens.fetch_add(1, Ordering::Relaxed);
            let guard = self.files.lock().unwrap();
            let (bytes, _) = guard
                .get(path)
                .cloned()
                .ok_or_else(|| anyhow::anyhow!("missing mock file"))?;
            Ok(Box::new(Cursor::new(bytes)))
        }
    }

    #[test]
    fn hash_cache_hit_does_not_reopen_file() {
        let ops = MockFileOps::new();
        let t0 = SystemTime::UNIX_EPOCH + Duration::from_secs(1);
        ops.put("file.bin", b"hello".to_vec(), t0);

        let hc = HashComputer::new_with_ops(Arc::new(ops.clone()));
        let h1 = hc.compute_sha256("file.bin").unwrap();
        let h2 = hc.compute_sha256("file.bin").unwrap();

        assert_eq!(h1, h2);
        assert_eq!(ops.opens(), 1, "expected second call to hit cache");
    }

    #[test]
    fn hash_cache_invalidation_on_size_change_rehashes() {
        let ops = MockFileOps::new();
        let t0 = SystemTime::UNIX_EPOCH + Duration::from_secs(1);
        ops.put("file.bin", b"hello".to_vec(), t0);

        let hc = HashComputer::new_with_ops(Arc::new(ops.clone()));
        let h1 = hc.compute_sha256("file.bin").unwrap();

        // Append bytes -> size changes -> must recompute.
        let t1 = SystemTime::UNIX_EPOCH + Duration::from_secs(2);
        ops.put("file.bin", b"hello!!".to_vec(), t1);

        let h2 = hc.compute_sha256("file.bin").unwrap();
        assert_ne!(h1, h2);
        assert_eq!(ops.opens(), 2);
    }

    #[test]
    fn hash_cache_invalidation_on_mtime_change_rehashes_even_if_bytes_same() {
        let ops = MockFileOps::new();
        let t0 = SystemTime::UNIX_EPOCH + Duration::from_secs(1);
        ops.put("file.bin", b"hello".to_vec(), t0);

        let hc = HashComputer::new_with_ops(Arc::new(ops.clone()));
        let h1 = hc.compute_sha256("file.bin").unwrap();

        let t1 = SystemTime::UNIX_EPOCH + Duration::from_secs(99);
        ops.set_modified("file.bin", t1);

        let h2 = hc.compute_sha256("file.bin").unwrap();
        assert_eq!(h1, h2, "bytes unchanged, hash must match");
        assert_eq!(ops.opens(), 2, "mtime change must invalidate cache");
    }
}
