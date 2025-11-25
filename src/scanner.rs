//! WordPress website scanner
//!
//! Detects WordPress version, plugins, and themes by analyzing the website.

use crate::error::{Error, Result};
use regex::Regex;
use reqwest::Client;
use scraper::{Html, Selector};
use serde::Deserialize;
use std::collections::HashSet;
use std::net::{IpAddr, ToSocketAddrs};
use std::time::Duration;
use url::Url;

/// User agent for requests (standard Chrome on Windows)
const USER_AGENT: &str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36";

/// Request timeout in seconds
const TIMEOUT_SECS: u64 = 30;

/// WordPress.org API base URL
const WP_API_BASE: &str = "https://api.wordpress.org";

/// WordPress detection paths
const WP_JSON_PATH: &str = "/wp-json/";
const WP_FEED_PATH: &str = "/feed/";
const WP_README_PATH: &str = "/readme.html";

/// WordPress cookie prefixes
const WP_COOKIE_PREFIXES: &[&str] = &["wordpress_", "wp-"];
const WP_LANG_COOKIE: &str = "wp_lang";

/// Paths to skip when detecting plugins
const SKIP_PLUGIN_SLUGS: &[&str] = &["index", "cache"];

/// Allowed URL schemes
const ALLOWED_SCHEMES: &[&str] = &["http", "https"];

/// Scan results from analyzing a WordPress site
#[derive(Debug, Clone)]
pub struct ScanResult {
    /// Target URL
    pub url: Url,
    /// Whether WordPress was detected (even without version)
    pub wordpress_detected: bool,
    /// WordPress version if detected
    pub wordpress_version: Option<String>,
    /// Latest WordPress version
    pub wordpress_latest: Option<String>,
    /// Main theme if detected
    pub theme: Option<ThemeInfo>,
    /// Detected plugins
    pub plugins: Vec<PluginInfo>,
}

/// Theme information
#[derive(Debug, Clone)]
pub struct ThemeInfo {
    /// Theme slug
    pub slug: String,
    /// Theme version if detected
    pub version: Option<String>,
    /// Latest version from WordPress.org
    pub latest_version: Option<String>,
}

/// Plugin information
#[derive(Debug, Clone)]
pub struct PluginInfo {
    /// Plugin slug
    pub slug: String,
    /// Plugin version if detected
    pub version: Option<String>,
    /// Latest version from WordPress.org
    pub latest_version: Option<String>,
}

/// WordPress.org plugin API response
#[derive(Debug, Deserialize)]
struct PluginApiResponse {
    version: Option<String>,
}

/// WordPress.org theme API response
#[derive(Debug, Deserialize)]
struct ThemeApiResponse {
    version: Option<String>,
}

/// WordPress version check API response
#[derive(Debug, Deserialize)]
struct WpVersionResponse {
    offers: Vec<WpVersionOffer>,
}

#[derive(Debug, Deserialize)]
struct WpVersionOffer {
    version: String,
}

/// WordPress REST API root response
#[derive(Debug, Deserialize)]
struct WpJsonResponse {
    /// Site name
    name: Option<String>,
    /// Site URL
    url: Option<String>,
    /// Available namespaces (e.g., ["wp/v2", "oembed/1.0"])
    namespaces: Option<Vec<String>>,
}

/// WordPress scanner
#[derive(Debug)]
pub struct Scanner {
    client: Client,
    base_url: Url,
}

/// Builder for configuring a Scanner with options
#[derive(Debug)]
pub struct ScannerBuilder {
    url: String,
    allow_private: bool,
}

impl ScannerBuilder {
    /// Create a new builder for the given URL or domain
    pub fn new(url: &str) -> Self {
        Self {
            url: url.to_string(),
            allow_private: false,
        }
    }

    /// Allow scanning private/internal IP addresses (localhost, 192.168.x.x, etc.)
    ///
    /// By default, SSRF protection blocks requests to internal networks.
    /// Enable this to scan local WordPress installations.
    pub fn allow_private(mut self, allow: bool) -> Self {
        self.allow_private = allow;
        self
    }

    /// Build the Scanner with the configured options
    pub fn build(self) -> Result<Scanner> {
        Scanner::build_internal(&self.url, self.allow_private)
    }
}

impl Scanner {
    /// Create a new scanner for the given URL or domain
    ///
    /// Uses default settings with SSRF protection enabled.
    /// For more options, use [`Scanner::builder()`].
    pub fn new(url: &str) -> Result<Self> {
        Self::build_internal(url, false)
    }

    /// Create a builder for configuring scanner options
    ///
    /// # Example
    ///
    /// ```no_run
    /// use wordpress_audit::Scanner;
    ///
    /// let scanner = Scanner::builder("localhost:8080")
    ///     .allow_private(true)
    ///     .build()?;
    /// # Ok::<(), wordpress_audit::Error>(())
    /// ```
    pub fn builder(url: &str) -> ScannerBuilder {
        ScannerBuilder::new(url)
    }

    /// Internal builder function
    fn build_internal(url: &str, allow_private: bool) -> Result<Self> {
        // Auto-add https:// if no scheme provided
        let url_with_scheme = if !url.contains("://") {
            format!("https://{}", url)
        } else {
            url.to_string()
        };

        let base_url =
            Url::parse(&url_with_scheme).map_err(|e| Error::InvalidUrl(e.to_string()))?;

        // Validate URL scheme (SSRF protection)
        if !ALLOWED_SCHEMES.contains(&base_url.scheme()) {
            return Err(Error::InvalidUrl(format!(
                "scheme '{}' not allowed (use http or https)",
                base_url.scheme()
            )));
        }

        // Validate host is not internal/private (SSRF protection)
        if !allow_private {
            Self::validate_host(&base_url)?;
        }

        let client = Client::builder()
            .user_agent(USER_AGENT)
            .timeout(Duration::from_secs(TIMEOUT_SECS))
            .danger_accept_invalid_certs(false)
            .build()
            .map_err(|e| Error::HttpClient(e.to_string()))?;

        Ok(Self { client, base_url })
    }

    /// Validate that the host is not an internal/private address (SSRF protection)
    fn validate_host(url: &Url) -> Result<()> {
        let host = url
            .host_str()
            .ok_or_else(|| Error::InvalidUrl("missing host".to_string()))?;

        // Block localhost variants
        if host == "localhost" || host.ends_with(".localhost") {
            return Err(Error::InvalidUrl("localhost not allowed".to_string()));
        }

        // Resolve hostname to IP and check if it's internal
        let port = url
            .port()
            .unwrap_or(if url.scheme() == "https" { 443 } else { 80 });
        let socket_addr = format!("{}:{}", host, port);

        if let Ok(addrs) = socket_addr.to_socket_addrs() {
            for addr in addrs {
                if Self::is_internal_ip(addr.ip()) {
                    return Err(Error::InvalidUrl(format!(
                        "internal/private IP address not allowed: {}",
                        addr.ip()
                    )));
                }
            }
        }

        Ok(())
    }

    /// Check if an IP address is internal/private (RFC 1918, link-local, loopback, etc.)
    fn is_internal_ip(ip: IpAddr) -> bool {
        match ip {
            IpAddr::V4(ipv4) => {
                ipv4.is_loopback()                      // 127.0.0.0/8
                    || ipv4.is_private()                // 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16
                    || ipv4.is_link_local()             // 169.254.0.0/16
                    || ipv4.is_broadcast()              // 255.255.255.255
                    || ipv4.is_unspecified()            // 0.0.0.0
                    || ipv4.octets()[0] == 100          // Shared address space 100.64.0.0/10
                        && ipv4.octets()[1] >= 64
                        && ipv4.octets()[1] <= 127
                    || ipv4.octets() == [169, 254, 169, 254]  // AWS metadata
                    || ipv4.octets()[..2] == [192, 0] // Documentation/test ranges
            }
            IpAddr::V6(ipv6) => {
                ipv6.is_loopback()                      // ::1
                    || ipv6.is_unspecified()            // ::
                    // Unique local addresses (fc00::/7)
                    || (ipv6.segments()[0] & 0xfe00) == 0xfc00
                    // Link-local (fe80::/10)
                    || (ipv6.segments()[0] & 0xffc0) == 0xfe80
            }
        }
    }

    /// Scan the WordPress site
    pub async fn scan(&self) -> Result<ScanResult> {
        // Fetch homepage
        let homepage_html = self.fetch_page(&self.base_url).await?;
        let document = Html::parse_document(&homepage_html);

        // Detect WordPress version
        let wordpress_version = self.detect_wp_version(&document).await;

        // If version not found, try alternative detection methods
        let wordpress_detected = wordpress_version.is_some()
            || self.detect_wp_from_rest_api().await.is_some()
            || self.detect_wp_from_cookies().await.is_some();

        // Fetch latest WordPress version
        let wordpress_latest = self.fetch_wp_latest_version().await;

        // Detect theme and fetch latest version
        let theme = self.detect_theme(&document).await;

        // Detect plugins and fetch latest versions
        let plugins = self.detect_plugins(&document).await;

        Ok(ScanResult {
            url: self.base_url.clone(),
            wordpress_detected,
            wordpress_version,
            wordpress_latest,
            theme,
            plugins,
        })
    }

    /// Fetch latest WordPress version from API
    async fn fetch_wp_latest_version(&self) -> Option<String> {
        let url = format!("{}/core/version-check/1.7/", WP_API_BASE);
        let response: WpVersionResponse =
            self.client.get(&url).send().await.ok()?.json().await.ok()?;
        response.offers.first().map(|o| o.version.clone())
    }

    /// Fetch latest plugin version from WordPress.org API
    async fn fetch_plugin_latest_version(&self, slug: &str) -> Option<String> {
        let url = format!(
            "{}/plugins/info/1.2/?action=plugin_information&slug={}",
            WP_API_BASE, slug
        );
        let response: PluginApiResponse =
            self.client.get(&url).send().await.ok()?.json().await.ok()?;
        response.version
    }

    /// Fetch latest theme version from WordPress.org API
    async fn fetch_theme_latest_version(&self, slug: &str) -> Option<String> {
        let url = format!(
            "{}/themes/info/1.2/?action=theme_information&slug={}",
            WP_API_BASE, slug
        );
        let response: ThemeApiResponse =
            self.client.get(&url).send().await.ok()?.json().await.ok()?;
        response.version
    }

    /// Fetch a page and return its HTML
    async fn fetch_page(&self, url: &Url) -> Result<String> {
        let response = self
            .client
            .get(url.as_str())
            .send()
            .await
            .map_err(|e| Error::HttpRequest(e.to_string()))?;

        if !response.status().is_success() {
            return Err(Error::HttpStatus(response.status().as_u16()));
        }

        response
            .text()
            .await
            .map_err(|e| Error::HttpRequest(e.to_string()))
    }

    /// Detect WordPress version from various sources
    async fn detect_wp_version(&self, document: &Html) -> Option<String> {
        // Try meta generator tag first
        if let Some(version) = self.detect_version_from_meta(document) {
            return Some(version);
        }

        // Try RSS feed
        if let Some(version) = self.detect_version_from_feed().await {
            return Some(version);
        }

        // Try readme.html
        self.detect_version_from_readme().await
    }

    /// Detect version from meta generator tag
    fn detect_version_from_meta(&self, document: &Html) -> Option<String> {
        let selector = Selector::parse("meta[name='generator']").ok()?;

        for element in document.select(&selector) {
            if let Some(content) = element.value().attr("content")
                && content.starts_with("WordPress")
            {
                // Extract version from "WordPress X.Y.Z"
                let version = content.strip_prefix("WordPress ")?.trim();
                if !version.is_empty() {
                    return Some(version.to_string());
                }
            }
        }
        None
    }

    /// Detect version from RSS feed
    async fn detect_version_from_feed(&self) -> Option<String> {
        let feed_url = self.base_url.join(WP_FEED_PATH).ok()?;
        let html = self.fetch_page(&feed_url).await.ok()?;

        // Look for <generator>https://wordpress.org/?v=X.Y.Z</generator>
        let re = Regex::new(r"wordpress\.org/\?v=([0-9.]+)").ok()?;
        re.captures(&html)?.get(1).map(|m| m.as_str().to_string())
    }

    /// Detect version from readme.html
    async fn detect_version_from_readme(&self) -> Option<String> {
        let readme_url = self.base_url.join(WP_README_PATH).ok()?;
        let html = self.fetch_page(&readme_url).await.ok()?;

        // Look for "Version X.Y.Z" in readme
        let re = Regex::new(r"Version\s+([0-9.]+)").ok()?;
        re.captures(&html)?.get(1).map(|m| m.as_str().to_string())
    }

    /// Detect WordPress via wp-json REST API endpoint
    async fn detect_wp_from_rest_api(&self) -> Option<()> {
        let api_url = self.base_url.join(WP_JSON_PATH).ok()?;

        let response = self.client.get(api_url.as_str()).send().await.ok()?;

        if !response.status().is_success() {
            return None;
        }

        // Try to parse as WordPress REST API response
        let api_response: WpJsonResponse = response.json().await.ok()?;

        // Check for WordPress-specific namespaces
        if let Some(namespaces) = &api_response.namespaces
            && namespaces.iter().any(|ns| ns.starts_with("wp/"))
        {
            return Some(());
        }

        // If we got a valid response with expected fields, it's likely WordPress
        if api_response.name.is_some() || api_response.url.is_some() {
            return Some(());
        }

        None
    }

    /// Check for WordPress cookies in response headers
    async fn detect_wp_from_cookies(&self) -> Option<()> {
        let response = self.client.get(self.base_url.as_str()).send().await.ok()?;

        // Check for WordPress-specific cookies
        for cookie in response.cookies() {
            let name = cookie.name();
            let is_wp_cookie =
                WP_COOKIE_PREFIXES.iter().any(|p| name.starts_with(p)) || name == WP_LANG_COOKIE;
            if is_wp_cookie {
                return Some(());
            }
        }

        // Also check Set-Cookie headers for WordPress patterns
        if let Some(set_cookie) = response.headers().get("set-cookie")
            && let Ok(cookie_str) = set_cookie.to_str()
            && WP_COOKIE_PREFIXES.iter().any(|p| cookie_str.contains(p))
        {
            return Some(());
        }

        None
    }

    /// Detect the main theme
    async fn detect_theme(&self, document: &Html) -> Option<ThemeInfo> {
        // Look for theme in stylesheet URLs
        let link_selector = Selector::parse("link[rel='stylesheet']").ok()?;

        for element in document.select(&link_selector) {
            if let Some(href) = element.value().attr("href")
                && let Some(mut theme) = self.extract_theme_from_url(href)
            {
                // Fetch latest version from WordPress.org
                theme.latest_version = self.fetch_theme_latest_version(&theme.slug).await;
                return Some(theme);
            }
        }

        // Also check style tags and other sources
        let style_re = Regex::new(r"/wp-content/themes/([^/]+)/").ok()?;

        let html = document.html();
        if let Some(caps) = style_re.captures(&html) {
            let slug = caps.get(1)?.as_str().to_string();
            let latest_version = self.fetch_theme_latest_version(&slug).await;
            return Some(ThemeInfo {
                slug,
                version: None,
                latest_version,
            });
        }

        None
    }

    /// Extract theme info from a URL
    fn extract_theme_from_url(&self, url: &str) -> Option<ThemeInfo> {
        // Match /wp-content/themes/theme-name/
        let re = Regex::new(r"/wp-content/themes/([^/]+)/").ok()?;
        let caps = re.captures(url)?;
        let slug = caps.get(1)?.as_str().to_string();

        // Try to extract version from URL query params
        let version = if let Some(v_pos) = url.find("ver=") {
            let v_start = v_pos + 4;
            let v_end = url[v_start..]
                .find(|c: char| !c.is_ascii_alphanumeric() && c != '.' && c != '-' && c != '_')
                .map(|i| v_start + i)
                .unwrap_or(url.len());
            let raw_version = url[v_start..v_end].to_string();
            Some(Self::normalize_version(&raw_version))
        } else {
            None
        };

        Some(ThemeInfo {
            slug,
            version,
            latest_version: None,
        })
    }

    /// Detect plugins from the page (includes mu-plugins)
    async fn detect_plugins(&self, document: &Html) -> Vec<PluginInfo> {
        let mut plugin_slugs = HashSet::new();
        let html = document.html();

        // Regex to find plugin paths - includes both plugins and mu-plugins
        let plugin_re = Regex::new(r"/wp-content/(?:mu-)?plugins/([a-zA-Z0-9_-]+)/").unwrap();

        for caps in plugin_re.captures_iter(&html) {
            if let Some(slug) = caps.get(1) {
                let slug_str = slug.as_str().to_string();
                if !SKIP_PLUGIN_SLUGS.contains(&slug_str.as_str()) {
                    plugin_slugs.insert(slug_str);
                }
            }
        }

        // Convert to PluginInfo, fetching latest versions
        let mut plugins = Vec::new();
        for slug in plugin_slugs {
            let version = self.find_plugin_version(&html, &slug);
            let latest_version = self.fetch_plugin_latest_version(&slug).await;
            plugins.push(PluginInfo {
                slug,
                version,
                latest_version,
            });
        }
        plugins
    }

    /// Find plugin version from HTML
    fn find_plugin_version(&self, html: &str, slug: &str) -> Option<String> {
        // Look for ver= parameter in plugin URLs (supports both plugins and mu-plugins)
        let pattern = format!(
            r#"/wp-content/(?:mu-)?plugins/{}/[^'"]*\?[^'"]*ver=([0-9a-zA-Z._-]+)"#,
            regex::escape(slug)
        );
        let re = Regex::new(&pattern).ok()?;
        let caps = re.captures(html)?;
        let version = caps.get(1)?.as_str().to_string();

        // Filter out Unix timestamps (10-digit numbers) and hash-like versions
        Some(Self::normalize_version(&version))
    }

    /// Normalize version string - detect timestamps and hashes
    fn normalize_version(version: &str) -> String {
        // Unix timestamp detection (10 digits, starts with 1 or 2, reasonable range)
        if version.len() == 10
            && version.chars().all(|c| c.is_ascii_digit())
            && version.starts_with(['1', '2'])
        {
            return format!("(timestamp:{})", version);
        }

        // Git commit hash detection (40 hex chars or 7+ hex abbreviation)
        if (version.len() == 40 || version.len() >= 7)
            && version.chars().all(|c| c.is_ascii_hexdigit())
            && !version.chars().all(|c| c.is_ascii_digit())
        {
            let short = if version.len() > 7 {
                &version[..7]
            } else {
                version
            };
            return format!("(hash:{})", short);
        }

        version.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_valid_url() {
        // Note: This may fail if example.com resolves to an internal IP in test environment
        let scanner = Scanner::new("https://example.com");
        assert!(scanner.is_ok());
    }

    #[test]
    fn parse_invalid_url() {
        let scanner = Scanner::new("not a url");
        assert!(scanner.is_err());
    }

    #[test]
    fn reject_localhost() {
        let result = Scanner::new("http://localhost");
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("localhost"));
    }

    #[test]
    fn reject_localhost_subdomain() {
        let result = Scanner::new("http://foo.localhost");
        assert!(result.is_err());
    }

    #[test]
    fn reject_file_scheme() {
        let result = Scanner::new("file:///etc/passwd");
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("scheme"));
    }

    #[test]
    fn reject_ftp_scheme() {
        let result = Scanner::new("ftp://example.com");
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("scheme"));
    }

    #[test]
    fn internal_ip_detection() {
        use std::net::Ipv4Addr;

        // Private ranges
        assert!(Scanner::is_internal_ip(IpAddr::V4(Ipv4Addr::new(
            10, 0, 0, 1
        ))));
        assert!(Scanner::is_internal_ip(IpAddr::V4(Ipv4Addr::new(
            172, 16, 0, 1
        ))));
        assert!(Scanner::is_internal_ip(IpAddr::V4(Ipv4Addr::new(
            192, 168, 1, 1
        ))));

        // Loopback
        assert!(Scanner::is_internal_ip(IpAddr::V4(Ipv4Addr::new(
            127, 0, 0, 1
        ))));

        // Link-local
        assert!(Scanner::is_internal_ip(IpAddr::V4(Ipv4Addr::new(
            169, 254, 1, 1
        ))));

        // Public IP should pass
        assert!(!Scanner::is_internal_ip(IpAddr::V4(Ipv4Addr::new(
            8, 8, 8, 8
        ))));
        assert!(!Scanner::is_internal_ip(IpAddr::V4(Ipv4Addr::new(
            93, 184, 216, 34
        ))));
    }

    #[test]
    fn normalize_semantic_version() {
        assert_eq!(Scanner::normalize_version("1.2.3"), "1.2.3");
        assert_eq!(Scanner::normalize_version("22.0.0"), "22.0.0");
        assert_eq!(Scanner::normalize_version("7.0-alpha"), "7.0-alpha");
    }

    #[test]
    fn normalize_timestamp_version() {
        // Unix timestamps should be marked
        assert_eq!(
            Scanner::normalize_version("1748271784"),
            "(timestamp:1748271784)"
        );
        assert_eq!(
            Scanner::normalize_version("1748268723"),
            "(timestamp:1748268723)"
        );
    }

    #[test]
    fn normalize_hash_version() {
        // Git hashes should be shortened and marked
        assert_eq!(
            Scanner::normalize_version("569ab5664387d06c16a234c9771d3d57fb15720a"),
            "(hash:569ab56)"
        );
        assert_eq!(Scanner::normalize_version("abcdef1"), "(hash:abcdef1)");
    }

    #[test]
    fn normalize_date_version() {
        // Date-like versions (8 digits) should pass through
        assert_eq!(Scanner::normalize_version("20200121"), "20200121");
    }
}
