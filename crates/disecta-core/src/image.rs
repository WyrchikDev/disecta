use std::fmt;
use std::time::{Duration, Instant};

use object::{
    ExportTarget, FileKind, NameOrOrdinal, Object, ObjectSection, ObjectSegment, ObjectSymbol,
    SectionFlags, SegmentFlags, elf, pe,
};
use serde::Serialize;

/// Recoverable failure category, also emitted as a JSON error code.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ErrorKind {
    /// Invalid, inconsistent or truncated file data.
    Malformed,
    /// Format, architecture or file type outside the supported executable model.
    Unsupported,
    /// A configured byte, entry, instruction or time limit was reached.
    Limit,
    /// An address cannot be mapped unambiguously to file-backed code.
    Address,
}

/// Structured analysis error.
#[derive(Debug, Serialize)]
pub struct Error {
    /// Machine-readable error code.
    pub kind: ErrorKind,
    /// Human-readable detail.
    pub message: String,
}

impl Error {
    pub(crate) fn new(kind: ErrorKind, message: impl Into<String>) -> Self {
        Self {
            kind,
            message: message.into(),
        }
    }

    fn malformed(error: impl fmt::Display) -> Self {
        Self::new(ErrorKind::Malformed, error.to_string())
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for Error {}

/// Bounds applied independently to each input and decoding request.
#[derive(Clone, Copy, Debug)]
pub struct Limits {
    /// Maximum input bytes.
    pub file_bytes: usize,
    /// Maximum total sections, mappings, symbol records, imports and exports.
    pub metadata_entries: usize,
    /// Maximum total bytes of decoded names.
    pub name_bytes: usize,
    /// Maximum number of instructions in one disassembly.
    pub instructions: usize,
    /// Cooperative per-operation time budget.
    pub time: Duration,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            file_bytes: 64 * 1024 * 1024,
            metadata_entries: 100_000,
            name_bytes: 4 * 1024 * 1024,
            instructions: 100_000,
            time: Duration::from_secs(5),
        }
    }
}

/// An address in the image's preferred (PE) or link-time (ELF) virtual address space.
/// Serializes as a hexadecimal string to preserve all 64 bits in JSON clients.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Address(pub u64);

impl fmt::Display for Address {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "0x{:X}", self.0)
    }
}

impl Serialize for Address {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.collect_str(self)
    }
}

/// Supported executable containers.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub enum Format {
    /// Windows PE32+ image.
    #[serde(rename = "PE32+")]
    Pe,
    /// ELF64 executable or shared object.
    #[serde(rename = "ELF64")]
    Elf,
}

/// A section, or a load segment used when executable section headers are absent.
#[derive(Clone, Debug, Serialize)]
pub struct Section {
    /// Name recorded in the image, or a PT_LOAD index.
    pub name: String,
    /// Start in the original virtual address space.
    pub address: Address,
    /// In-memory extent, including zero-fill.
    pub size: u64,
    /// File offset for the section's backed bytes.
    pub file_offset: Option<u64>,
    /// Number of bytes mapped from the file.
    pub file_size: u64,
    /// Read permission, or null if ELF provides no single covering segment.
    pub read: Option<bool>,
    /// Write flag.
    pub write: bool,
    /// Execute flag.
    pub execute: bool,
}

/// A defined symbol read from an embedded symbol table.
#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub struct Symbol {
    /// Link-time symbol address.
    pub address: Address,
    /// Name from the symbol table.
    pub name: String,
    /// Recorded extent, or zero when absent.
    pub size: u64,
    /// Symbol table kind.
    pub kind: String,
}

/// A referenced external symbol.
#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub struct Import {
    /// Library name when the file associates one with the import.
    pub library: String,
    /// Imported name, or ordinal as reported by the loader backend.
    pub name: String,
}

/// A symbol exported by the image.
#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub struct Export {
    /// Target address for a direct export, or the resolver for an indirect function.
    pub address: Option<Address>,
    /// Exported name.
    pub name: String,
    /// Forwarder, resolver, TLS offset, or absolute value when present.
    pub target_detail: Option<String>,
}

/// Original image metadata used by both the CLI and graphical workbench.
#[derive(Debug, Serialize)]
pub struct Metadata {
    /// Container format.
    pub format: Format,
    /// Instruction-set architecture.
    pub architecture: &'static str,
    /// Optional entry point.
    pub entry: Option<Address>,
    /// Preferred load base (PE) or lowest file load address (ELF).
    pub image_base: Address,
    /// Original file size in bytes.
    pub file_size: usize,
    /// Image sections in file header order.
    pub sections: Vec<Section>,
    /// Defined embedded symbols.
    pub symbols: Vec<Symbol>,
    /// Imported symbols.
    pub imports: Vec<Import>,
    /// Exported symbols.
    pub exports: Vec<Export>,
}

#[derive(Debug)]
struct Mapping {
    address: u64,
    size: u64,
    offset: u64,
    file_size: u64,
    flags: elf::ProgramFlags,
}

impl Mapping {
    fn file_offset(&self, address: u64) -> Option<u64> {
        let delta = address.checked_sub(self.address)?;
        (delta < self.file_size).then(|| self.offset + delta)
    }
}

pub(crate) struct Budget {
    started: Instant,
    limits: Limits,
    entries_left: usize,
    names_left: usize,
}

impl Budget {
    pub(crate) fn new(limits: Limits) -> Self {
        Self {
            started: Instant::now(),
            limits,
            entries_left: limits.metadata_entries,
            names_left: limits.name_bytes,
        }
    }

    pub(crate) fn check(&self) -> Result<(), Error> {
        if self.started.elapsed() >= self.limits.time {
            return Err(Error::new(ErrorKind::Limit, "analysis time limit exceeded"));
        }
        Ok(())
    }

    fn record(&mut self) -> Result<(), Error> {
        self.check()?;
        self.entries_left = self
            .entries_left
            .checked_sub(1)
            .ok_or_else(|| Error::new(ErrorKind::Limit, "metadata entry limit exceeded"))?;
        Ok(())
    }

    fn name(&mut self, name: &[u8]) -> Result<String, Error> {
        // Invalid UTF-8 can grow by up to 3x after replacement.
        let bound = name.len().saturating_mul(3);
        self.names_left = self
            .names_left
            .checked_sub(bound)
            .ok_or_else(|| Error::new(ErrorKind::Limit, "metadata name budget exceeded"))?;
        Ok(String::from_utf8_lossy(name).into_owned())
    }

    fn symbol_name(&mut self, name: NameOrOrdinal<&[u8]>) -> Result<String, Error> {
        match name {
            NameOrOrdinal::Name(name) => self.name(name),
            NameOrOrdinal::Ordinal(ordinal) => Ok(format!("#{ordinal}")),
        }
    }
}

/// A validated static view of an executable. The input stays borrowed and is never executed.
#[derive(Debug)]
pub struct Binary<'data> {
    bytes: &'data [u8],
    metadata: Metadata,
    mappings: Vec<Mapping>,
    pub(crate) limits: Limits,
}

impl<'data> Binary<'data> {
    /// Parse a little-endian x86-64 PE32+ or ELF64 image within the supplied limits.
    pub fn parse(bytes: &'data [u8], limits: Limits) -> Result<Self, Error> {
        if bytes.len() > limits.file_bytes {
            return Err(Error::new(
                ErrorKind::Limit,
                "input exceeds the file size limit",
            ));
        }
        let mut budget = Budget::new(limits);
        budget.check()?;
        let kind = FileKind::parse(bytes).map_err(Error::malformed)?;
        let format = match kind {
            FileKind::Pe64 => Format::Pe,
            FileKind::Elf64 => Format::Elf,
            _ => {
                return Err(Error::new(
                    ErrorKind::Unsupported,
                    "expected a PE32+ or ELF64 image",
                ));
            }
        };
        let file = object::File::parse(bytes).map_err(Error::malformed)?;
        if file.architecture() != object::Architecture::X86_64 || !file.is_little_endian() {
            return Err(Error::new(
                ErrorKind::Unsupported,
                "expected little-endian x86-64",
            ));
        }
        if !matches!(
            file.kind(),
            object::ObjectKind::Executable | object::ObjectKind::Dynamic
        ) {
            return Err(Error::new(
                ErrorKind::Unsupported,
                "expected an executable or shared library",
            ));
        }

        let mut mappings = Vec::new();
        if format == Format::Elf {
            for segment in file.segments() {
                budget.record()?;
                let SegmentFlags::Elf { p_flags, .. } = segment.flags() else {
                    continue;
                };
                let (offset, size) = segment.file_range();
                if size > segment.size() {
                    return Err(Error::malformed(
                        "ELF load segment has filesz greater than memsz",
                    ));
                }
                validate_range(bytes, segment.address(), segment.size(), offset, size)?;
                mappings.push(Mapping {
                    address: segment.address(),
                    size: segment.size(),
                    offset,
                    file_size: size,
                    flags: p_flags,
                });
            }
        }

        let mut sections = Vec::new();
        for section in file.sections() {
            budget.record()?;
            let address = section.address();
            let size = section.size();
            if format == Format::Pe && address < file.relative_address_base() {
                return Err(Error::malformed("PE section virtual address overflow"));
            }
            let (file_offset, file_size) = match section.file_range() {
                Some((offset, len)) => (Some(offset), len),
                None => (None, 0),
            };
            validate_range(
                bytes,
                address,
                size,
                file_offset.unwrap_or_default(),
                file_size,
            )?;
            let (read, write, execute) = match section.flags() {
                SectionFlags::Coff { characteristics } => (
                    Some(characteristics.contains(pe::IMAGE_SCN_MEM_READ)),
                    characteristics.contains(pe::IMAGE_SCN_MEM_WRITE),
                    characteristics.contains(pe::IMAGE_SCN_MEM_EXECUTE),
                ),
                SectionFlags::Elf { sh_flags, .. } => {
                    let read = if sh_flags.contains(elf::SHF_ALLOC) {
                        mappings
                            .iter()
                            .find(|map| {
                                address.checked_sub(map.address).is_some_and(|delta| {
                                    delta < map.size && size <= map.size - delta
                                })
                            })
                            .map(|map| map.flags.contains(elf::PF_R))
                    } else {
                        None
                    };
                    (
                        read,
                        sh_flags.contains(elf::SHF_WRITE),
                        sh_flags.contains(elf::SHF_ALLOC | elf::SHF_EXECINSTR),
                    )
                }
                _ => return Err(Error::malformed("unexpected section flags")),
            };

            let name = budget.name(section.name_bytes().map_err(Error::malformed)?)?;
            sections.push(Section {
                name,
                address: Address(address),
                size,
                file_offset,
                file_size,
                read,
                write,
                execute,
            });
            if format == Format::Pe {
                mappings.push(Mapping {
                    address,
                    size,
                    offset: file_offset.unwrap_or_default(),
                    file_size: file_size.min(size),
                    flags: elf::ProgramFlags(0),
                });
            }
        }
        if format == Format::Elf
            && !sections
                .iter()
                .any(|section| section.execute && section.file_size > 0)
        {
            for (index, map) in mappings.iter().enumerate() {
                budget.record()?;
                sections.push(Section {
                    name: format!("PT_LOAD[{index}]"),
                    address: Address(map.address),
                    size: map.size,
                    file_offset: Some(map.offset),
                    file_size: map.file_size,
                    read: Some(map.flags.contains(elf::PF_R)),
                    write: map.flags.contains(elf::PF_W),
                    execute: map.flags.contains(elf::PF_X),
                });
            }
        }
        if let object::File::Pe64(pe) = &file {
            use object::read::pe::{ImageNtHeaders, ImageOptionalHeader};
            let size = u64::from(pe.nt_headers().optional_header().size_of_headers());
            let address = file.relative_address_base();
            validate_range(bytes, address, size, 0, size)?;
            mappings.push(Mapping {
                address,
                size,
                offset: 0,
                file_size: size,
                flags: elf::ProgramFlags(0),
            });
        }
        let image_base = match format {
            Format::Pe => file.relative_address_base(),
            Format::Elf => mappings.iter().map(|m| m.address).min().unwrap_or_default(),
        };

        let mut symbols = Vec::new();
        for symbol in file.symbols().chain(file.dynamic_symbols()) {
            budget.record()?;
            if symbol.is_definition() {
                let name = budget.name(symbol.name_bytes().map_err(Error::malformed)?)?;
                if !name.is_empty() {
                    symbols.push(Symbol {
                        address: Address(symbol.address()),
                        name,
                        size: symbol.size(),
                        kind: format!("{:?}", symbol.kind()).to_ascii_lowercase(),
                    });
                }
            }
        }
        let mut imports = Vec::new();
        for import in file.imports().map_err(Error::malformed)? {
            budget.record()?;
            let import = import.map_err(Error::malformed)?;
            imports.push(Import {
                library: budget.name(import.library())?,
                name: budget.symbol_name(import.name())?,
            });
        }
        let mut exports = Vec::new();
        for export in file.exports().map_err(Error::malformed)? {
            budget.record()?;
            let export = export.map_err(Error::malformed)?;
            let (address, target_detail) = match export.target() {
                ExportTarget::Address { address } => {
                    if format == Format::Pe && address < image_base {
                        return Err(Error::malformed("PE export virtual address overflow"));
                    }
                    (Some(Address(address)), None)
                }
                ExportTarget::Absolute { value } => (None, Some(format!("absolute 0x{value:X}"))),
                ExportTarget::Tls { offset } => (None, Some(format!("TLS offset 0x{offset:X}"))),
                ExportTarget::Resolver { resolver, .. } => {
                    (Some(Address(resolver)), Some("resolver".into()))
                }
                ExportTarget::Reexport { library, name } => {
                    let library = budget.name(library)?;
                    let name = budget.symbol_name(name)?;
                    (None, Some(format!("{library}!{name}")))
                }
                _ => (None, Some("unsupported export target".into())),
            };
            exports.push(Export {
                address,
                name: budget.symbol_name(export.name())?,
                target_detail,
            });
        }
        symbols.sort_unstable();
        symbols.dedup();
        imports.sort_unstable();
        imports.dedup();
        exports.sort_unstable();
        exports.dedup();
        budget.check()?;
        let entry = match (&file, file.entry()) {
            (object::File::Pe64(pe), _) if pe_entry_rva(pe) == 0 => None,
            (object::File::Pe64(_), address) if address < image_base => {
                return Err(Error::malformed("PE entry virtual address overflow"));
            }
            (_, 0) => None,
            (_, address) => Some(Address(address)),
        };
        Ok(Self {
            bytes,
            limits,
            mappings,
            metadata: Metadata {
                format,
                architecture: "x86-64",
                entry,
                image_base: Address(image_base),
                file_size: bytes.len(),
                sections,
                symbols,
                imports,
                exports,
            },
        })
    }

    /// Report the original, unrelocated image metadata.
    pub fn metadata(&self) -> &Metadata {
        &self.metadata
    }

    /// Map a virtual address to a unique original file byte, excluding zero-fill and overlays.
    pub fn file_offset(&self, address: Address) -> Result<Option<u64>, Error> {
        let mut result = None;
        for offset in self
            .mappings
            .iter()
            .filter_map(|map| map.file_offset(address.0))
        {
            if result.is_some_and(|previous| previous != offset) {
                return Err(Error::new(
                    ErrorKind::Address,
                    "virtual address has conflicting file mappings",
                ));
            }
            result = Some(offset);
        }
        Ok(result)
    }

    pub(crate) fn section_bytes(&self, index: usize) -> Result<(Address, &[u8]), Error> {
        let section = self
            .metadata
            .sections
            .get(index)
            .ok_or_else(|| Error::new(ErrorKind::Address, "section index is out of range"))?;
        if !section.execute || section.file_size == 0 {
            return Err(Error::new(
                ErrorKind::Address,
                "section has no file-backed executable bytes",
            ));
        }
        let size = section.file_size.min(section.size) as usize;
        let offset = section.file_offset.unwrap_or_default() as usize;
        let bytes = self
            .bytes
            .get(offset..offset + size)
            .ok_or_else(|| Error::malformed("section extends beyond the file"))?;
        Ok((section.address, bytes))
    }
}

fn pe_entry_rva(file: &object::read::pe::PeFile64<'_>) -> u32 {
    use object::read::pe::{ImageNtHeaders, ImageOptionalHeader};
    file.nt_headers().optional_header().address_of_entry_point()
}

fn validate_range(
    bytes: &[u8],
    address: u64,
    size: u64,
    offset: u64,
    file_size: u64,
) -> Result<(), Error> {
    let end = offset.checked_add(file_size);
    if address.checked_add(size).is_none()
        || (file_size != 0 && end.is_none_or(|end| end > bytes.len() as u64))
    {
        return Err(Error::malformed(
            "section or segment range exceeds address space or file bounds",
        ));
    }
    Ok(())
}
