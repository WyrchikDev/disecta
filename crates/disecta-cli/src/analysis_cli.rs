use std::io::{self, Write};

use clap::{Args, ValueEnum};
use disecta_core::{Address, Analysis, AnalysisLimits, Binary, Evidence, Function, Reference};

use crate::{CliError, write_json};

#[derive(Args)]
pub(crate) struct Options {
    /// Maximum candidate functions to analyze.
    #[arg(long, global = true, default_value_t = 4096, value_parser = clap::value_parser!(u32).range(1..=100_000))]
    max_functions: u32,

    /// Maximum decoded instructions per function.
    #[arg(long, global = true, default_value_t = 4096, value_parser = clap::value_parser!(u32).range(1..=100_000))]
    max_function_instructions: u32,
}

impl From<&Options> for AnalysisLimits {
    fn from(options: &Options) -> Self {
        Self {
            functions: options.max_functions as usize,
            per_function: options.max_function_instructions as usize,
        }
    }
}

#[derive(Clone, Copy, Default, ValueEnum)]
pub(crate) enum GraphFormat {
    #[default]
    Text,
    Dot,
}

#[derive(Clone, Copy)]
pub(crate) enum Report {
    Functions,
    Cfg {
        address: Address,
        format: GraphFormat,
    },
    References(Address),
    Calls(Option<Address>),
    Analyze,
}

pub(crate) fn write(
    out: &mut impl Write,
    image: &Binary<'_>,
    report: Report,
    limits: AnalysisLimits,
    json: bool,
) -> Result<(), CliError> {
    if let Report::Cfg { address, format } = report {
        let graph = image.cfg(address, limits)?;
        match (json, format) {
            (true, GraphFormat::Text) => write_json(out, &graph)?,
            (_, GraphFormat::Dot) => graph.write_dot(out)?,
            (false, GraphFormat::Text) => {
                function(out, &graph.function)?;
                if let Some(reason) = graph.entry_status {
                    writeln!(out, "Entry status: {}", reason.label())?;
                }
                let mut edges = graph.edges.iter().peekable();
                for block in &graph.blocks {
                    writeln!(out, "\n{}–{}", block.start, block.end)?;
                    for instruction in &block.instructions {
                        writeln!(
                            out,
                            "  {:<18} {}",
                            instruction.address.to_string(),
                            instruction.text
                        )?;
                    }
                    while let Some(edge) = edges.next_if(|edge| edge.from == block.start) {
                        writeln!(
                            out,
                            "  {} → {} ({})",
                            edge.kind.label(),
                            address_text(edge.target),
                            edge.resolution.label()
                        )?;
                    }
                }
                for range in &graph.unrecovered_ranges {
                    writeln!(out, "Unrecovered {}–{}", range.start, range.end)?;
                }
            }
        }
        return Ok(());
    }

    let analysis = image.analyze(limits)?;
    match (json, report) {
        (true, Report::Analyze) => write_json(out, &analysis)?,
        (true, Report::Functions) => write_json(
            out,
            &serde_json::json!({
                "schema": analysis.schema, "functions": analysis.functions, "limited": analysis.limited
            }),
        )?,
        (true, Report::References(address)) => {
            let references = analysis.references_at(address);
            write_json(
                out,
                &serde_json::json!({
                    "schema": analysis.schema, "references": references,
                    "import_slot": analysis.import_slots.get(&address)
                }),
            )?;
        }
        (true, Report::Calls(entry)) => write_json(
            out,
            &serde_json::json!({
                "schema": analysis.schema, "function": entry,
                "calls": analysis.calls(entry).collect::<Vec<_>>(), "limited": analysis.limited
            }),
        )?,
        (false, Report::Analyze | Report::Functions) => {
            for entry in &analysis.functions {
                function(out, entry)?;
            }
            writeln!(
                out,
                "{} candidate(s), {} reference(s)",
                analysis.functions.len(),
                analysis.references.len()
            )?;
        }
        (false, Report::References(address)) => {
            let references = analysis.references_at(address);
            for (heading, items) in [
                ("Incoming", references.incoming),
                ("Outgoing", references.outgoing),
            ] {
                writeln!(out, "{heading} references at {address} ({})", items.len())?;
                for item in items {
                    reference(out, &analysis, item)?;
                }
            }
        }
        (false, Report::Calls(entry)) => {
            for call in analysis.calls(entry) {
                reference(out, &analysis, call)?;
            }
        }
        (_, Report::Cfg { .. }) => unreachable!("CFG handled separately"),
    }
    if !json && analysis.limited {
        writeln!(out, "Analysis is partial: a resource limit was reached.")?;
    }
    Ok(())
}

fn function(out: &mut impl Write, entry: &Function) -> io::Result<()> {
    let names = entry
        .names
        .iter()
        .map(|name| name.escape_default().to_string())
        .collect::<Vec<_>>();
    writeln!(
        out,
        "{}  {:?}  {} instruction(s)  {}",
        entry.address,
        entry.confidence,
        entry.instructions,
        names.join(", ")
    )?;
    for item in &entry.evidence {
        match item {
            Evidence::EntryPoint => writeln!(out, "  executable entry point")?,
            Evidence::Symbol { name, size } => writeln!(
                out,
                "  code symbol {} ({size} bytes)",
                name.escape_default()
            )?,
            Evidence::Export { name } => {
                writeln!(out, "  executable export {}", name.escape_default())?
            }
            Evidence::RuntimeRange { end } => {
                writeln!(out, "  PE runtime extent through {end} (exclusive)")?
            }
            Evidence::DirectCall { site } => writeln!(out, "  direct call at {site}")?,
            Evidence::Requested => writeln!(out, "  requested entry address")?,
        }
    }
    if entry.overlaps || entry.conflicting_extent || entry.limited {
        writeln!(
            out,
            "  overlap: {}, conflicting bounds: {}, limited: {}",
            entry.overlaps, entry.conflicting_extent, entry.limited
        )?;
    }
    Ok(())
}

fn reference(out: &mut impl Write, analysis: &Analysis, item: &Reference) -> io::Result<()> {
    let label = item
        .target
        .and_then(|address| analysis.import_slots.get(&address))
        .map_or_else(String::new, |import| {
            let name = import.name.escape_default();
            if import.library.is_empty() {
                format!(" {name}")
            } else {
                format!(" {}!{name}", import.library.escape_default())
            }
        });
    writeln!(
        out,
        "  {}  {:?} → {}{}  (function {})",
        item.source,
        item.kind,
        address_text(item.target),
        label,
        item.function
    )
}

fn address_text(address: Option<Address>) -> String {
    address.map_or_else(|| "—".into(), |address| address.to_string())
}
