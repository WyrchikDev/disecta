#![forbid(unsafe_code)]

mod analysis_cli;
mod web;

use std::fs::File;
use std::io::{self, Read, Write};
use std::path::PathBuf;
use std::process::ExitCode;
use std::time::Duration;

use clap::{Parser, Subcommand};
use disecta_core::{Address, Binary, ErrorKind, Limits, Metadata};
use serde::Serialize;

#[derive(Parser)]
#[command(version, about)]
struct Cli {
    /// Emit JSON results and error details.
    #[arg(long, global = true)]
    json: bool,

    /// Reject input files larger than this number of MiB (1–1024).
    #[arg(long, global = true, default_value_t = 64, value_parser = clap::value_parser!(u32).range(1..=1024))]
    max_file_mib: u32,

    /// Maximum analysis time per operation, in milliseconds.
    #[arg(long, global = true, default_value_t = 5000, value_parser = clap::value_parser!(u64).range(1..))]
    time_ms: u64,

    /// Maximum number of metadata records read per image.
    #[arg(long, global = true, default_value_t = 100_000, value_parser = clap::value_parser!(u32).range(1..=1_000_000))]
    max_metadata: u32,

    /// Include analysis diagnostics on stderr.
    #[arg(long, short, global = true)]
    verbose: bool,

    #[command(flatten)]
    analysis: analysis_cli::Options,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Print executable headers, sections, symbols, imports and exports.
    Inspect { path: PathBuf },
    /// Linearly decode file-backed machine code.
    Disasm {
        path: PathBuf,
        /// Select a zero-based section index from inspect.
        #[arg(long)]
        section: Option<usize>,
        /// Start decoding at this virtual address (0x-prefixed hexadecimal or decimal).
        #[arg(long, value_parser = parse_address)]
        start: Option<Address>,
        /// Maximum instructions to decode in this request.
        #[arg(long, default_value_t = 256)]
        count: usize,
    },
    /// Discover function candidates and report their evidence.
    Functions { path: PathBuf },
    /// Recover a function's reachable control-flow graph.
    Cfg {
        path: PathBuf,
        /// Root virtual address.
        #[arg(long, value_parser = parse_address)]
        function: Address,
        /// Use Graphviz DOT or a human-readable listing.
        #[arg(long, value_enum, conflicts_with = "json")]
        format: Option<analysis_cli::GraphFormat>,
    },
    /// List references to and from an exact virtual address.
    Xrefs {
        path: PathBuf,
        #[arg(long, value_parser = parse_address)]
        address: Address,
    },
    /// List direct and unresolved indirect call sites.
    Calls {
        path: PathBuf,
        /// Restrict to incoming or outgoing calls at a function entry.
        #[arg(long, value_parser = parse_address)]
        function: Option<Address>,
    },
    /// Report discovered functions, static references, and mapped import slots.
    Analyze { path: PathBuf },
    /// Serve the local graphical workbench on 127.0.0.1.
    Gui {
        /// Loopback port. Use 0 for an automatically assigned port.
        #[arg(long, default_value_t = 0)]
        port: u16,
    },
}

#[derive(Debug, Serialize)]
struct CliError {
    kind: &'static str,
    message: String,
    #[serde(skip)]
    code: u8,
}

impl From<disecta_core::Error> for CliError {
    fn from(error: disecta_core::Error) -> Self {
        let (kind, code) = match error.kind {
            ErrorKind::Malformed => ("malformed", 3),
            ErrorKind::Unsupported => ("unsupported", 3),
            ErrorKind::Address => ("address", 3),
            ErrorKind::Limit => ("limit", 4),
        };
        Self {
            kind,
            code,
            message: error.message,
        }
    }
}

impl From<io::Error> for CliError {
    fn from(error: io::Error) -> Self {
        Self {
            kind: "io",
            message: error.to_string(),
            code: 1,
        }
    }
}

impl From<serde_json::Error> for CliError {
    fn from(error: serde_json::Error) -> Self {
        Self {
            kind: "output",
            message: error.to_string(),
            code: 1,
        }
    }
}

fn main() -> ExitCode {
    let args = Cli::parse();
    match run(&args) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            if args.json {
                eprintln!("{}", serde_json::json!(error));
            } else {
                eprintln!("disecta: {}", error.message);
            }
            ExitCode::from(error.code)
        }
    }
}

fn run(args: &Cli) -> Result<(), CliError> {
    let limits = Limits {
        file_bytes: args.max_file_mib as usize * 1024 * 1024,
        metadata_entries: args.max_metadata as usize,
        time: Duration::from_millis(args.time_ms),
        ..Limits::default()
    };
    let path = match &args.command {
        Command::Inspect { path }
        | Command::Disasm { path, .. }
        | Command::Functions { path }
        | Command::Cfg { path, .. }
        | Command::Xrefs { path, .. }
        | Command::Calls { path, .. }
        | Command::Analyze { path } => path,
        Command::Gui { port } => {
            return web::serve(*port, limits, (&args.analysis).into(), args.verbose);
        }
    };
    let file = File::open(path)
        .map_err(|error| io::Error::new(error.kind(), format!("{}: {error}", path.display())))?;
    if !file.metadata()?.is_file() {
        return Err(CliError {
            kind: "io",
            message: "expected a regular file".into(),
            code: 1,
        });
    }
    let mut bytes = Vec::new();
    file.take(limits.file_bytes as u64 + 1)
        .read_to_end(&mut bytes)?;
    let image = Binary::parse(&bytes, limits)?;
    if args.verbose {
        eprintln!("Read {} bytes from {}", bytes.len(), path.display());
    }
    let mut out = io::BufWriter::new(io::stdout().lock());
    match &args.command {
        Command::Inspect { .. } if args.json => write_json(&mut out, image.metadata())?,
        Command::Inspect { .. } => inspect(&mut out, image.metadata())?,
        Command::Disasm {
            section,
            start,
            count,
            ..
        } => {
            let section = match *section {
                Some(index) => index,
                None => find_section(image.metadata(), *start)?,
            };
            let page = image.disassemble(section, *start, *count)?;
            if args.json {
                write_json(&mut out, &page)?;
            } else {
                for instruction in page.instructions {
                    writeln!(
                        out,
                        "{:<18}  {:<44}  {}",
                        instruction.address.to_string(),
                        instruction.bytes,
                        instruction.text
                    )?;
                }
                if let Some(next) = page.next_address {
                    writeln!(out, "Continue at {next}")?;
                }
            }
        }
        command => {
            use analysis_cli::Report;
            let report = match command {
                Command::Functions { .. } => Report::Functions,
                Command::Cfg {
                    function, format, ..
                } => Report::Cfg {
                    address: *function,
                    format: format.unwrap_or_default(),
                },
                Command::Xrefs { address, .. } => Report::References(*address),
                Command::Calls { function, .. } => Report::Calls(*function),
                Command::Analyze { .. } => Report::Analyze,
                _ => unreachable!("handled before writing analysis"),
            };
            analysis_cli::write(&mut out, &image, report, (&args.analysis).into(), args.json)?;
        }
    }
    out.flush()?;
    Ok(())
}

fn inspect(out: &mut impl Write, meta: &Metadata) -> io::Result<()> {
    writeln!(
        out,
        "{} {} image, {} bytes",
        format_label(meta),
        meta.architecture,
        meta.file_size
    )?;
    writeln!(out, "Image base  {}", meta.image_base)?;
    if let Some(entry) = meta.entry {
        writeln!(out, "Entry       {entry}")?;
    }
    writeln!(
        out,
        "\nIndex  Section              Address             Size        File offset  Perm"
    )?;
    for (index, section) in meta.sections.iter().enumerate() {
        let flags = [
            section.read.map_or('?', |r| if r { 'r' } else { '-' }),
            if section.write { 'w' } else { '-' },
            if section.execute { 'x' } else { '-' },
        ];
        let offset = section
            .file_offset
            .map_or_else(|| "-".into(), |offset| format!("0x{offset:X}"));
        writeln!(
            out,
            "{index:>5}  {:<18}   {:<18}  {:>10}  {:>11}  {}",
            section.name.escape_default().to_string(),
            section.address.to_string(),
            section.size,
            offset,
            flags.iter().collect::<String>()
        )?;
    }
    for symbol in &meta.symbols {
        writeln!(
            out,
            "Symbol  {}  {}",
            symbol.address,
            symbol.name.escape_default()
        )?;
    }
    for import in &meta.imports {
        writeln!(
            out,
            "Import  {:<20} {}",
            import.library.escape_default().to_string(),
            import.name.escape_default()
        )?;
    }
    for export in &meta.exports {
        let address = export
            .address
            .map_or_else(|| "-".into(), |address| address.to_string());
        let detail = export.target_detail.as_deref().unwrap_or_default();
        writeln!(
            out,
            "Export  {}  {}  {}",
            address,
            export.name.escape_default(),
            detail.escape_default()
        )?;
    }
    Ok(())
}

fn format_label(meta: &Metadata) -> &'static str {
    match meta.format {
        disecta_core::Format::Pe => "PE32+",
        disecta_core::Format::Elf => "ELF64",
    }
}

fn write_json(out: &mut impl Write, data: &impl Serialize) -> Result<(), CliError> {
    serde_json::to_writer_pretty(&mut *out, data)?;
    writeln!(out)?;
    Ok(())
}

fn parse_address(text: &str) -> Result<Address, String> {
    let value = match text.strip_prefix("0x").or_else(|| text.strip_prefix("0X")) {
        Some(hex) => u64::from_str_radix(hex, 16),
        None => text.parse(),
    };
    value
        .map(Address)
        .map_err(|_| "expected a 64-bit virtual address".into())
}

fn find_section(metadata: &Metadata, address: Option<Address>) -> Result<usize, CliError> {
    let mut candidates = metadata.sections.iter().enumerate().filter(|(_, section)| {
        section.execute
            && section.file_size > 0
            && address.is_none_or(|address| {
                address
                    .0
                    .checked_sub(section.address.0)
                    .is_some_and(|delta| delta < section.file_size.min(section.size))
            })
    });
    let error = |message: &str| CliError {
        kind: "address",
        message: message.into(),
        code: 3,
    };
    let (index, _) = candidates
        .next()
        .ok_or_else(|| error("no file-backed executable section for that address"))?;
    if address.is_some() && candidates.next().is_some() {
        return Err(error(
            "multiple executable sections cover the address; specify --section",
        ));
    }
    Ok(index)
}
