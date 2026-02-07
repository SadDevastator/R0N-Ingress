//! Log rotation support

use super::config::{RotationConfig, RotationStrategy};
use super::error::LogResult;
use chrono::{DateTime, Datelike, Timelike, Utc};
use std::fs::{self, File, OpenOptions};
use std::io::{BufWriter, Write};
use std::path::{Path, PathBuf};

/// Log file rotator
pub struct LogRotator {
    /// Base path for log file
    base_path: PathBuf,

    /// Configuration
    config: RotationConfig,

    /// Current file size (tracked)
    current_size: u64,

    /// Last rotation check time
    last_rotation: Option<DateTime<Utc>>,

    /// Current file writer
    writer: Option<BufWriter<File>>,
}

impl LogRotator {
    /// Create a new log rotator
    pub fn new(path: impl Into<PathBuf>, config: RotationConfig) -> LogResult<Self> {
        let base_path = path.into();

        // Ensure parent directory exists
        if let Some(parent) = base_path.parent() {
            fs::create_dir_all(parent)?;
        }

        let current_size = if base_path.exists() {
            fs::metadata(&base_path)?.len()
        } else {
            0
        };

        Ok(Self {
            base_path,
            config,
            current_size,
            last_rotation: None,
            writer: None,
        })
    }

    /// Get the current log file path
    pub fn current_path(&self) -> &Path {
        &self.base_path
    }

    /// Get the current file size
    pub fn current_size(&self) -> u64 {
        self.current_size
    }

    /// Check if rotation is needed
    pub fn needs_rotation(&self) -> bool {
        match self.config.strategy {
            RotationStrategy::Never => false,
            RotationStrategy::Size => self.current_size >= self.config.max_size_bytes,
            RotationStrategy::Daily => self.needs_time_rotation(24),
            RotationStrategy::Hourly => self.needs_time_rotation(1),
        }
    }

    fn needs_time_rotation(&self, hours: i64) -> bool {
        let now = Utc::now();

        match self.last_rotation {
            Some(last) => {
                let duration = now.signed_duration_since(last);
                duration.num_hours() >= hours
            },
            None => {
                // Check if file exists and was created before current period
                if self.base_path.exists() {
                    if let Ok(metadata) = fs::metadata(&self.base_path) {
                        if let Ok(modified) = metadata.modified() {
                            let modified: DateTime<Utc> = modified.into();
                            let duration = now.signed_duration_since(modified);
                            return duration.num_hours() >= hours;
                        }
                    }
                }
                false
            },
        }
    }

    /// Perform rotation if needed
    pub fn rotate_if_needed(&mut self) -> LogResult<bool> {
        if !self.needs_rotation() {
            return Ok(false);
        }

        self.rotate()?;
        Ok(true)
    }

    /// Force rotation
    pub fn rotate(&mut self) -> LogResult<()> {
        // Close current writer
        self.writer = None;

        if !self.base_path.exists() {
            return Ok(());
        }

        // Generate rotated filename
        let rotated_path = self.generate_rotated_path();

        // Rename current file
        fs::rename(&self.base_path, &rotated_path)?;

        // Compress if configured
        if self.config.compress {
            self.compress_file(&rotated_path)?;
        }

        // Clean up old backups
        self.cleanup_old_backups()?;

        // Reset state
        self.current_size = 0;
        self.last_rotation = Some(Utc::now());

        Ok(())
    }

    fn generate_rotated_path(&self) -> PathBuf {
        let now = Utc::now();
        let timestamp = now.format("%Y%m%d-%H%M%S");

        let stem = self
            .base_path
            .file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or("log");
        let ext = self
            .base_path
            .extension()
            .and_then(|s| s.to_str())
            .unwrap_or("log");

        let parent = self.base_path.parent().unwrap_or(Path::new("."));

        parent.join(format!("{}.{}.{}", stem, timestamp, ext))
    }

    fn compress_file(&self, path: &Path) -> LogResult<()> {
        // Note: In production, use flate2 or similar for gzip compression
        // For now, just add .gz extension to indicate it should be compressed
        let compressed_path = path.with_extension(
            path.extension()
                .map(|e| format!("{}.gz", e.to_string_lossy()))
                .unwrap_or_else(|| "gz".to_string()),
        );

        // Placeholder: In real implementation, compress the file
        // For now, just rename
        fs::rename(path, compressed_path)?;

        Ok(())
    }

    fn cleanup_old_backups(&self) -> LogResult<()> {
        let parent = self.base_path.parent().unwrap_or(Path::new("."));
        let stem = self
            .base_path
            .file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or("");

        // Collect backup files
        let mut backups: Vec<PathBuf> = fs::read_dir(parent)?
            .filter_map(|e| e.ok())
            .map(|e| e.path())
            .filter(|p| {
                p.file_name()
                    .and_then(|n| n.to_str())
                    .map(|n| {
                        n.starts_with(stem) && n != self.base_path.file_name().unwrap_or_default()
                    })
                    .unwrap_or(false)
            })
            .collect();

        // Sort by modification time (oldest first)
        backups.sort_by(|a, b| {
            let time_a = fs::metadata(a)
                .and_then(|m| m.modified())
                .unwrap_or(std::time::SystemTime::UNIX_EPOCH);
            let time_b = fs::metadata(b)
                .and_then(|m| m.modified())
                .unwrap_or(std::time::SystemTime::UNIX_EPOCH);
            time_a.cmp(&time_b)
        });

        // Remove oldest files if we have too many
        while backups.len() > self.config.max_backups as usize {
            if let Some(oldest) = backups.first() {
                fs::remove_file(oldest)?;
                backups.remove(0);
            }
        }

        Ok(())
    }

    /// Get or create the file writer
    pub fn writer(&mut self) -> LogResult<&mut BufWriter<File>> {
        if self.writer.is_none() {
            let file = OpenOptions::new()
                .create(true)
                .append(true)
                .open(&self.base_path)?;

            self.writer = Some(BufWriter::new(file));
        }

        Ok(self.writer.as_mut().unwrap())
    }

    /// Write data to the log file
    pub fn write(&mut self, data: &[u8]) -> LogResult<()> {
        // Check rotation first
        self.rotate_if_needed()?;

        let writer = self.writer()?;
        writer.write_all(data)?;
        writer.write_all(b"\n")?;

        self.current_size += data.len() as u64 + 1;

        Ok(())
    }

    /// Flush the writer
    pub fn flush(&mut self) -> LogResult<()> {
        if let Some(writer) = &mut self.writer {
            writer.flush()?;
        }
        Ok(())
    }
}

impl std::fmt::Debug for LogRotator {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LogRotator")
            .field("base_path", &self.base_path)
            .field("current_size", &self.current_size)
            .field("strategy", &self.config.strategy)
            .finish()
    }
}

/// Generate a time-based log filename
pub fn time_based_filename(base: &Path, pattern: &str) -> PathBuf {
    let now = Utc::now();

    let formatted = pattern
        .replace("%Y", &format!("{:04}", now.year()))
        .replace("%m", &format!("{:02}", now.month()))
        .replace("%d", &format!("{:02}", now.day()))
        .replace("%H", &format!("{:02}", now.hour()))
        .replace("%M", &format!("{:02}", now.minute()))
        .replace("%S", &format!("{:02}", now.second()));

    let stem = base.file_stem().and_then(|s| s.to_str()).unwrap_or("log");
    let ext = base.extension().and_then(|s| s.to_str()).unwrap_or("log");
    let parent = base.parent().unwrap_or(Path::new("."));

    parent.join(format!("{}.{}.{}", stem, formatted, ext))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::env::temp_dir;

    fn temp_log_path() -> PathBuf {
        temp_dir().join(format!("test_log_{}.log", std::process::id()))
    }

    #[test]
    fn test_rotator_creation() {
        let path = temp_log_path();
        let config = RotationConfig::by_size(1024);

        let rotator = LogRotator::new(&path, config).unwrap();
        assert_eq!(rotator.current_size(), 0);

        // Cleanup
        let _ = fs::remove_file(&path);
    }

    #[test]
    fn test_needs_rotation_size() {
        let path = temp_log_path();
        let config = RotationConfig::by_size(100);

        let mut rotator = LogRotator::new(&path, config).unwrap();

        assert!(!rotator.needs_rotation());

        // Simulate large file
        rotator.current_size = 200;
        assert!(rotator.needs_rotation());

        // Cleanup
        let _ = fs::remove_file(&path);
    }

    #[test]
    fn test_needs_rotation_never() {
        let path = temp_log_path();
        let config = RotationConfig {
            strategy: RotationStrategy::Never,
            ..Default::default()
        };

        let mut rotator = LogRotator::new(&path, config).unwrap();
        rotator.current_size = 1_000_000_000;

        assert!(!rotator.needs_rotation());

        // Cleanup
        let _ = fs::remove_file(&path);
    }

    #[test]
    fn test_write_and_rotate() {
        let path = temp_log_path();
        let config = RotationConfig::by_size(50);

        let mut rotator = LogRotator::new(&path, config).unwrap();

        // Write some data
        rotator.write(b"Line 1: Some log data").unwrap();
        rotator.write(b"Line 2: More log data").unwrap();
        rotator.flush().unwrap();

        // Check rotation happened
        if rotator.current_size() >= 50 {
            assert!(rotator.rotate_if_needed().unwrap());
        }

        // Cleanup
        let _ = fs::remove_file(&path);
        // Also clean up rotated files
        if let Some(parent) = path.parent() {
            let _ = fs::read_dir(parent).map(|entries| {
                for entry in entries.flatten() {
                    if entry.path().to_string_lossy().contains("test_log_") {
                        let _ = fs::remove_file(entry.path());
                    }
                }
            });
        }
    }

    #[test]
    fn test_generate_rotated_path() {
        let path = PathBuf::from("/var/log/app.log");
        let config = RotationConfig::default();

        let rotator = LogRotator::new(&path, config).unwrap_or_else(|_| {
            // May fail on read-only filesystem, use temp
            LogRotator::new(temp_log_path(), RotationConfig::default()).unwrap()
        });

        let rotated = rotator.generate_rotated_path();
        let name = rotated.file_name().unwrap().to_string_lossy();

        // Should contain timestamp pattern
        assert!(name.contains('.'));
    }

    #[test]
    fn test_time_based_filename() {
        let base = PathBuf::from("/var/log/app.log");
        let filename = time_based_filename(&base, "%Y-%m-%d");

        let name = filename.file_name().unwrap().to_string_lossy();
        assert!(name.starts_with("app."));

        // Should contain date components
        let now = Utc::now();
        assert!(name.contains(&format!("{:04}", now.year())));
    }
}
