//! WordPress Audit CLI - Scan WordPress websites for security information

use clap::{Parser, ValueEnum};
use std::process::ExitCode;

use wordpress_audit::{
    Analyzer, Scanner,
    output::{OutputConfig, OutputFormat, OutputSort, output_analysis},
};

/// WordPress security scanner - detects versions, plugins, and themes
#[derive(Parser, Debug)]
#[command(name = "wordpress-audit")]
#[command(version, about, long_about = None)]
struct Args {
    /// URL of the WordPress site to scan
    url: String,

    /// Output format
    #[arg(short = 'o', long = "output", default_value = "human", value_enum)]
    output_format: OutputFormatArg,

    /// Sort order for output
    #[arg(long = "sort", default_value = "type", value_enum)]
    sort: OutputSortArg,

    /// Allow scanning private/internal IP addresses (localhost, 192.168.x.x, etc.)
    #[arg(long = "allow-private")]
    allow_private: bool,
}

/// Output format argument
#[derive(Clone, Copy, Debug, ValueEnum)]
enum OutputFormatArg {
    Human,
    Json,
    None,
}

impl From<OutputFormatArg> for OutputFormat {
    fn from(arg: OutputFormatArg) -> Self {
        match arg {
            OutputFormatArg::Human => OutputFormat::Human,
            OutputFormatArg::Json => OutputFormat::Json,
            OutputFormatArg::None => OutputFormat::None,
        }
    }
}

/// Output sort argument
#[derive(Clone, Copy, Debug, ValueEnum)]
enum OutputSortArg {
    /// Sort by type (Core, Theme, Plugin), then by name (default)
    Type,
    /// Sort alphabetically by name only
    Name,
    /// Sort by status, then by type, then by name
    Status,
}

impl From<OutputSortArg> for OutputSort {
    fn from(arg: OutputSortArg) -> Self {
        match arg {
            OutputSortArg::Type => OutputSort::Type,
            OutputSortArg::Name => OutputSort::Name,
            OutputSortArg::Status => OutputSort::Status,
        }
    }
}

#[tokio::main]
async fn main() -> ExitCode {
    let args = Args::parse();

    // Print banner for human output
    if matches!(args.output_format, OutputFormatArg::Human) {
        print_banner();
    }

    let output_config = OutputConfig::new(args.output_format.into(), args.sort.into());

    match run_scan(&args.url, args.allow_private, &output_config).await {
        Ok(_) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("Error: {}", e);
            ExitCode::FAILURE
        }
    }
}

async fn run_scan(
    url: &str,
    allow_private: bool,
    output_config: &OutputConfig,
) -> wordpress_audit::Result<()> {
    let scanner = Scanner::builder(url).allow_private(allow_private).build()?;
    let scan_result = scanner.scan().await?;
    let analysis = Analyzer::new(scan_result).analyze();

    let stdout = std::io::stdout();
    let mut writer = stdout.lock();
    output_analysis(&analysis, output_config, &mut writer)?;

    Ok(())
}

fn print_banner() {
    const VERSION: &str = env!("CARGO_PKG_VERSION");
    println!("WordPress Audit v{}", VERSION);
    println!("by Robert F. Ecker <robert@robdotec.com>");
    println!();
}
