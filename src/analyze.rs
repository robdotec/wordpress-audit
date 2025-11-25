//! Analysis logic for WordPress scan results

use crate::scanner::ScanResult;
use serde::Serialize;
use std::cmp::Ordering;
use std::collections::HashMap;

/// Placeholder for unknown/missing version information
const UNKNOWN_VERSION: &str = "-";

/// Compare two version strings semantically
/// Returns Ordering::Greater if current > latest (ahead/dev version)
/// Returns Ordering::Less if current < latest (outdated)
/// Returns Ordering::Equal if they match
fn compare_versions(current: &str, latest: &str) -> Ordering {
    // Parse version parts, handling alpha/beta/rc suffixes
    fn parse_version(v: &str) -> (Vec<u64>, bool) {
        // Split off any suffix like -alpha, -beta, -rc
        let pos = v.find(|c: char| c == '-' || c.is_ascii_alphabetic());
        let version_part = match pos {
            Some(p) => &v[..p],
            None => v,
        };
        let has_suffix = pos.is_some();

        let parts: Vec<u64> = version_part
            .split('.')
            .filter_map(|p| p.parse().ok())
            .collect();

        (parts, has_suffix)
    }

    let (current_parts, current_has_suffix) = parse_version(current);
    let (latest_parts, latest_has_suffix) = parse_version(latest);

    // Compare numeric parts
    let max_len = current_parts.len().max(latest_parts.len());
    for i in 0..max_len {
        let c = current_parts.get(i).copied().unwrap_or(0);
        let l = latest_parts.get(i).copied().unwrap_or(0);
        match c.cmp(&l) {
            Ordering::Equal => continue,
            other => return other,
        }
    }

    // If numeric parts are equal, check suffixes
    // A version without suffix is considered newer than one with suffix
    // (e.g., 7.0 > 7.0-alpha)
    match (current_has_suffix, latest_has_suffix) {
        (false, true) => Ordering::Greater,
        (true, false) => Ordering::Less,
        _ => Ordering::Equal,
    }
}

/// Component type
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum ComponentType {
    /// WordPress core
    Core,
    /// Theme
    Theme,
    /// Plugin
    Plugin,
}

impl std::fmt::Display for ComponentType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Core => write!(f, "Core"),
            Self::Theme => write!(f, "Theme"),
            Self::Plugin => write!(f, "Plugin"),
        }
    }
}

/// Analysis result for a single component
#[derive(Debug, Clone, Serialize)]
pub struct ComponentAnalysis {
    /// Component type
    pub component_type: ComponentType,

    /// Component name/slug
    pub name: String,

    /// Detected version (or "-" if unknown)
    pub version: String,

    /// Latest available version (or "-" if unknown)
    pub latest_version: String,

    /// Component status
    pub status: ComponentStatus,
}

impl ComponentAnalysis {
    fn new(
        component_type: ComponentType,
        name: impl Into<String>,
        version: Option<String>,
        latest_version: Option<String>,
    ) -> Self {
        let version_str = version.unwrap_or_else(|| UNKNOWN_VERSION.to_string());
        let latest_str = latest_version.unwrap_or_else(|| UNKNOWN_VERSION.to_string());

        let status = if version_str == UNKNOWN_VERSION {
            ComponentStatus::Unknown
        } else if latest_str == UNKNOWN_VERSION {
            // Can't compare without latest version
            ComponentStatus::Ok
        } else {
            match compare_versions(&version_str, &latest_str) {
                Ordering::Less => ComponentStatus::Outdated,
                Ordering::Equal | Ordering::Greater => ComponentStatus::Ok,
            }
        };

        Self {
            component_type,
            name: name.into(),
            version: version_str,
            latest_version: latest_str,
            status,
        }
    }

    fn not_detected(component_type: ComponentType, name: impl Into<String>) -> Self {
        Self {
            component_type,
            name: name.into(),
            version: UNKNOWN_VERSION.to_string(),
            latest_version: UNKNOWN_VERSION.to_string(),
            status: ComponentStatus::NotDetected,
        }
    }
}

/// Component status
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum ComponentStatus {
    /// Component is up to date
    Ok,
    /// Component detected but version unknown
    Unknown,
    /// Component is outdated
    Outdated,
    /// Component not detected
    NotDetected,
}

/// Complete analysis results
#[derive(Debug, Clone, Serialize)]
pub struct Analysis {
    /// Target URL
    pub url: String,

    /// WordPress core analysis
    pub wordpress: ComponentAnalysis,

    /// Main theme analysis
    pub theme: ComponentAnalysis,

    /// Plugin analyses
    pub plugins: HashMap<String, ComponentAnalysis>,
}

impl Analysis {
    /// Check if WordPress was detected
    pub fn is_wordpress(&self) -> bool {
        self.wordpress.status != ComponentStatus::NotDetected
    }

    /// Get count of detected plugins
    pub fn plugin_count(&self) -> usize {
        self.plugins.len()
    }

    /// Get count of outdated components
    pub fn outdated_count(&self) -> usize {
        let core_outdated = (self.wordpress.status == ComponentStatus::Outdated) as usize;
        let theme_outdated = (self.theme.status == ComponentStatus::Outdated) as usize;
        let plugins_outdated = self
            .plugins
            .values()
            .filter(|p| p.status == ComponentStatus::Outdated)
            .count();

        core_outdated + theme_outdated + plugins_outdated
    }
}

/// Analyzer for scan results
pub struct Analyzer {
    scan: ScanResult,
}

impl Analyzer {
    /// Create a new analyzer for the given scan result
    pub fn new(scan: ScanResult) -> Self {
        Self { scan }
    }

    /// Perform the analysis
    pub fn analyze(self) -> Analysis {
        Analysis {
            url: self.scan.url.to_string(),
            wordpress: self.analyze_wordpress(),
            theme: self.analyze_theme(),
            plugins: self.analyze_plugins(),
        }
    }

    fn analyze_wordpress(&self) -> ComponentAnalysis {
        match &self.scan.wordpress_version {
            Some(version) => ComponentAnalysis::new(
                ComponentType::Core,
                "WordPress",
                Some(version.clone()),
                self.scan.wordpress_latest.clone(),
            ),
            None if self.scan.wordpress_detected => {
                // WordPress detected via REST API or cookies, but version unknown
                ComponentAnalysis::new(
                    ComponentType::Core,
                    "WordPress",
                    None,
                    self.scan.wordpress_latest.clone(),
                )
            }
            None => ComponentAnalysis::not_detected(ComponentType::Core, "WordPress"),
        }
    }

    fn analyze_theme(&self) -> ComponentAnalysis {
        match &self.scan.theme {
            Some(theme) => ComponentAnalysis::new(
                ComponentType::Theme,
                &theme.slug,
                theme.version.clone(),
                theme.latest_version.clone(),
            ),
            None => ComponentAnalysis::not_detected(ComponentType::Theme, "-"),
        }
    }

    fn analyze_plugins(&self) -> HashMap<String, ComponentAnalysis> {
        self.scan
            .plugins
            .iter()
            .map(|plugin| {
                let analysis = ComponentAnalysis::new(
                    ComponentType::Plugin,
                    &plugin.slug,
                    plugin.version.clone(),
                    plugin.latest_version.clone(),
                );
                (plugin.slug.clone(), analysis)
            })
            .collect()
    }
}
