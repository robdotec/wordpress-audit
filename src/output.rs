//! Output formatting for WordPress scan results

use crate::analyze::{Analysis, ComponentAnalysis, ComponentStatus, ComponentType};
use crate::error::{Error, Result};
use comfy_table::{
    Attribute, Cell, CellAlignment, Color, ContentArrangement, Table, presets::UTF8_FULL,
};
use std::io::Write;
use std::str::FromStr;

/// Output format for results
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum OutputFormat {
    /// Human-readable table output
    #[default]
    Human,
    /// JSON output
    Json,
    /// No output (silent mode)
    None,
}

impl FromStr for OutputFormat {
    type Err = Error;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "human" => Ok(Self::Human),
            "json" => Ok(Self::Json),
            "none" => Ok(Self::None),
            _ => Err(Error::InvalidOutputFormat(s.to_string())),
        }
    }
}

/// Sort order for output
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum OutputSort {
    /// Sort by type (Core, Theme, Plugin), then by name (default)
    #[default]
    Type,
    /// Sort alphabetically by name only
    Name,
    /// Sort by status, then by type, then by name
    Status,
}

impl FromStr for OutputSort {
    type Err = Error;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "type" => Ok(Self::Type),
            "name" => Ok(Self::Name),
            "status" => Ok(Self::Status),
            _ => Err(Error::InvalidOutputSort(s.to_string())),
        }
    }
}

/// Configuration for output formatting
#[derive(Debug, Clone, Default)]
pub struct OutputConfig {
    /// Output format
    pub format: OutputFormat,
    /// Sort order
    pub sort: OutputSort,
}

impl OutputConfig {
    /// Create a new output config
    pub fn new(format: OutputFormat, sort: OutputSort) -> Self {
        Self { format, sort }
    }
}

/// Output the analysis results
pub fn output_analysis<W: Write>(
    analysis: &Analysis,
    config: &OutputConfig,
    writer: &mut W,
) -> Result<()> {
    match config.format {
        OutputFormat::Human => output_human(analysis, config, writer),
        OutputFormat::Json => output_json(analysis, writer),
        OutputFormat::None => Ok(()),
    }
}

/// Output JSON format
fn output_json<W: Write>(analysis: &Analysis, writer: &mut W) -> Result<()> {
    serde_json::to_writer_pretty(&mut *writer, analysis)?;
    writeln!(writer).map_err(Error::OutputFailed)?;
    Ok(())
}

/// Output human-readable table format
fn output_human<W: Write>(
    analysis: &Analysis,
    config: &OutputConfig,
    writer: &mut W,
) -> Result<()> {
    let mut table = Table::new();
    table
        .load_preset(UTF8_FULL)
        .set_content_arrangement(ContentArrangement::Dynamic)
        .set_header(vec![
            Cell::new("Type").add_attribute(Attribute::Bold),
            Cell::new("Name").add_attribute(Attribute::Bold),
            Cell::new("Version").add_attribute(Attribute::Bold),
            Cell::new("Latest").add_attribute(Attribute::Bold),
            Cell::new("Status").add_attribute(Attribute::Bold),
        ]);

    // Placeholder for when no plugins detected
    let no_plugins = ComponentAnalysis {
        component_type: ComponentType::Plugin,
        name: "-".to_string(),
        version: "-".to_string(),
        latest_version: "-".to_string(),
        status: ComponentStatus::NotDetected,
    };

    // Collect all components
    let mut components: Vec<&ComponentAnalysis> = Vec::new();
    components.push(&analysis.wordpress);
    components.push(&analysis.theme);
    if analysis.plugins.is_empty() {
        components.push(&no_plugins);
    } else {
        for component in analysis.plugins.values() {
            components.push(component);
        }
    }

    // Helper to get sort priority by type (Core=0, Theme=1, Plugin=2)
    let type_order = |t: ComponentType| -> u8 {
        match t {
            ComponentType::Core => 0,
            ComponentType::Theme => 1,
            ComponentType::Plugin => 2,
        }
    };

    // Sort based on config
    match config.sort {
        // Default: by type (Core, Theme, Plugin), then by name
        OutputSort::Type => {
            components.sort_by(|a, b| {
                type_order(a.component_type)
                    .cmp(&type_order(b.component_type))
                    .then_with(|| a.name.cmp(&b.name))
            });
        }
        // By name only (alphabetically)
        OutputSort::Name => {
            components.sort_by(|a, b| a.name.cmp(&b.name));
        }
        // By status first, then type, then name
        OutputSort::Status => {
            components.sort_by(|a, b| {
                b.status
                    .cmp(&a.status)
                    .then_with(|| type_order(a.component_type).cmp(&type_order(b.component_type)))
                    .then_with(|| a.name.cmp(&b.name))
            });
        }
    }

    // Add rows
    for component in components {
        add_component_row(&mut table, component);
    }

    writeln!(writer, "{}", table).map_err(Error::OutputFailed)
}

/// Add a row for a component to the table
fn add_component_row(table: &mut Table, component: &ComponentAnalysis) {
    let status_cell = match component.status {
        ComponentStatus::Ok => Cell::new("Ok")
            .fg(Color::Green)
            .set_alignment(CellAlignment::Center),
        ComponentStatus::Outdated => Cell::new("Outdated")
            .fg(Color::Yellow)
            .set_alignment(CellAlignment::Center),
        ComponentStatus::Unknown => Cell::new("Unknown")
            .fg(Color::DarkGrey)
            .set_alignment(CellAlignment::Center),
        ComponentStatus::NotDetected => Cell::new("Not Found")
            .fg(Color::DarkGrey)
            .set_alignment(CellAlignment::Center),
    };

    table.add_row(vec![
        Cell::new(component.component_type.to_string()),
        Cell::new(&component.name),
        Cell::new(&component.version),
        Cell::new(&component.latest_version),
        status_cell,
    ]);
}
