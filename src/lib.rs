//! WordPress Audit - Real-time WordPress security scanner
//!
//! Scans WordPress websites to detect versions, plugins, and themes.
//!
//! # Example
//!
//! ```no_run
//! use wordpress_audit::{Scanner, Analyzer};
//!
//! #[tokio::main]
//! async fn main() -> wordpress_audit::Result<()> {
//!     let scanner = Scanner::new("https://example.com")?;
//!     let scan = scanner.scan().await?;
//!     let analysis = Analyzer::new(scan).analyze();
//!     println!("WordPress: {}", analysis.wordpress.version);
//!     Ok(())
//! }
//! ```

pub mod analyze;
pub mod error;
pub mod output;
pub mod scanner;

pub use analyze::{Analysis, Analyzer, ComponentAnalysis, ComponentStatus};
pub use error::{Error, Result};
pub use output::{OutputConfig, OutputFormat, OutputSort, output_analysis};
pub use scanner::{PluginInfo, ScanResult, Scanner, ScannerBuilder, ThemeInfo};
