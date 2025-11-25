# wordpress-audit

A fast, safe Rust CLI tool for auditing WordPress websites. Detects WordPress core version, themes, and plugins, then checks them against the latest versions from WordPress.org.

[![Crates.io](https://img.shields.io/crates/v/wordpress-audit.svg)](https://crates.io/crates/wordpress-audit)
[![Documentation](https://docs.rs/wordpress-audit/badge.svg)](https://docs.rs/wordpress-audit)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

## Features

- **WordPress detection** via meta tags, RSS feed, REST API, and cookies
- **Version detection** for core, themes, and plugins
- **Outdated component detection** comparing against WordPress.org API
- **mu-plugins support** detects must-use plugins
- **SSRF protection** blocks requests to private/internal IPs
- **Multiple output formats** human-readable tables or JSON

## Installation

### Pre-built binaries

Download from [GitHub Releases](https://github.com/robdotec/wordpress-audit/releases):

| Platform | Architecture | File |
|----------|--------------|------|
| Linux | x86_64 | `wordpress-audit-linux-x86_64.tar.gz` |
| Linux | x86_64 (static) | `wordpress-audit-linux-x86_64-musl.tar.gz` |
| Linux | ARM64 | `wordpress-audit-linux-aarch64.tar.gz` |
| macOS | Intel | `wordpress-audit-macos-x86_64.tar.gz` |
| macOS | Apple Silicon | `wordpress-audit-macos-aarch64.tar.gz` |
| Windows | x86_64 | `wordpress-audit-windows-x86_64.zip` |

### Cargo

```bash
cargo install wordpress-audit
```

### Build from source

```bash
git clone https://github.com/robdotec/wordpress-audit
cd wordpress-audit
cargo build --release
```

## Usage

```bash
# Basic scan
wordpress-audit example.com

# JSON output
wordpress-audit example.com -o json

# Sort by status (outdated first)
wordpress-audit example.com --sort status

# Scan local WordPress installation
wordpress-audit localhost:8080 --allow-private
```

## Example Output

```
WordPress Audit v1.0.0
by Robert F. Ecker <robert@robdotec.com>

┌────────┬──────────────────────┬─────────────────┬────────┬──────────┐
│ Type   ┆ Name                 ┆ Version         ┆ Latest ┆ Status   │
╞════════╪══════════════════════╪═════════════════╪════════╪══════════╡
│ Core   ┆ WordPress            ┆ 6.8.1           ┆ 6.8.3  ┆ Outdated │
├╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌┤
│ Theme  ┆ flavor-flavor        ┆ 1.2.0           ┆ 1.2.0  ┆    Ok    │
├╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌┤
│ Plugin ┆ contact-form-7       ┆ 5.8.1           ┆ 6.0.5  ┆ Outdated │
├╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌┤
│ Plugin ┆ woocommerce          ┆ 9.0.0           ┆ 9.0.0  ┆    Ok    │
└────────┴──────────────────────┴─────────────────┴────────┴──────────┘
```

## CLI Options

| Option | Description |
|--------|-------------|
| `-o, --output <FORMAT>` | Output format: `human` (default), `json`, `none` |
| `--sort <ORDER>` | Sort order: `type` (default), `name`, `status` |
| `--allow-private` | Allow scanning localhost and private IPs |
| `-h, --help` | Print help |
| `-V, --version` | Print version |

## Detection Methods

### WordPress Core

1. `<meta name="generator" content="WordPress X.Y.Z">`
2. RSS feed: `/feed/` containing `wordpress.org/?v=X.Y.Z`
3. README: `/readme.html` containing version
4. REST API: `/wp-json/` with WordPress namespaces
5. Cookies: `wordpress_*` or `wp-*` prefixes

### Themes

- Detected from `/wp-content/themes/{slug}/` URLs in stylesheets
- Version extracted from `?ver=` query parameters

### Plugins

- Detected from `/wp-content/plugins/{slug}/` URLs
- Also detects `/wp-content/mu-plugins/{slug}/` (must-use plugins)
- Version extracted from `?ver=` query parameters

## Version Normalization

The tool identifies non-semantic versions:

| Version Type | Display |
|--------------|---------|
| Semantic | `1.2.3` |
| Unix timestamp | `(timestamp:1748271784)` |
| Git hash | `(hash:569ab56)` |
| Date-based | `20200121` |

## Security

### SSRF Protection

By default, requests to internal/private addresses are blocked:

- Localhost (`127.0.0.1`, `::1`, `localhost`)
- Private networks (RFC 1918: `10.x`, `172.16-31.x`, `192.168.x`)
- Link-local (`169.254.x` including cloud metadata `169.254.169.254`)
- IPv6 unique local (`fc00::/7`) and link-local (`fe80::/10`)

Use `--allow-private` to scan local WordPress installations:

```bash
wordpress-audit localhost:8080 --allow-private
wordpress-audit 192.168.1.100 --allow-private
```

### Scheme Validation

Only `http` and `https` schemes are allowed. File, FTP, and other schemes are rejected.

## Library Usage

```rust
use wordpress_audit::{Scanner, Analyzer};

#[tokio::main]
async fn main() -> wordpress_audit::Result<()> {
    let scanner = Scanner::new("https://example.com")?;
    let scan = scanner.scan().await?;
    let analysis = Analyzer::new(scan).analyze();

    println!("WordPress: {}", analysis.wordpress.version);
    println!("Outdated: {}", analysis.outdated_count());

    Ok(())
}
```

### Scanning Local Sites

```rust
use wordpress_audit::Scanner;

let scanner = Scanner::builder("localhost:8080")
    .allow_private(true)
    .build()?;
```

## License

MIT License - see [LICENSE](LICENSE) for details.
