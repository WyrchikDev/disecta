use std::collections::{BTreeMap, BTreeSet, VecDeque};

use iced_x86::{Decoder, DecoderOptions, FlowControl, Mnemonic, Register};
use serde::Serialize;

use crate::cfg::{ControlFlowGraph, EdgeKind, EdgeResolution};
use crate::decode::near_target;
use crate::image::{Address, Binary, Budget, Error, ErrorKind, Format, Import};

/// Additional limits for recursive analysis. The binary's time and total instruction budgets also apply.
#[derive(Clone, Copy, Debug)]
pub struct AnalysisLimits {
    /// Maximum number of function candidates visited.
    pub functions: usize,
    /// Maximum number of instructions visited for one function.
    pub per_function: usize,
}

impl Default for AnalysisLimits {
    fn default() -> Self {
        Self {
            functions: 4096,
            per_function: 4096,
        }
    }
}

/// Evidence-based assessment of an entry point.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Confidence {
    /// The executable entry, a code symbol, or a validated runtime table entry.
    Confirmed,
    /// An executable export or a destination of a direct call.
    Strong,
    /// The user explicitly selected an address without independent entry evidence.
    Heuristic,
    /// The entry could not be decoded or visited.
    Unknown,
}

/// A source of evidence for a possible function entry or extent.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Evidence {
    /// Executable header entry point.
    EntryPoint,
    /// A defined text symbol from the image.
    Symbol {
        /// Embedded symbol name.
        name: String,
        /// Size reported by the symbol table.
        size: u64,
    },
    /// A local export that points into executable bytes.
    Export {
        /// Embedded export name or ordinal.
        name: String,
    },
    /// Bounds declared by the PE x64 exception directory.
    RuntimeRange {
        /// Exclusive runtime-function end.
        end: Address,
    },
    /// A statically encoded direct call in a recovered instruction.
    DirectCall {
        /// Address of the call instruction.
        site: Address,
    },
    /// An address supplied explicitly for recursive decoding.
    Requested,
}

/// A recovered function candidate and the provenance used to analyze it.
#[derive(Clone, Debug, Serialize)]
pub struct Function {
    /// Candidate entry address.
    pub address: Address,
    /// Symbol or export names, if available.
    pub names: Vec<String>,
    /// Evidence before interpreting recovered control flow.
    pub evidence: Vec<Evidence>,
    /// Strength of the entry evidence.
    pub confidence: Confidence,
    /// Exclusive end from agreeing, usable metadata ranges.
    pub declared_end: Option<Address>,
    /// Earliest recovered instruction, if any.
    pub recovered_start: Option<Address>,
    /// Exclusive end of the highest recovered instruction, if any.
    pub recovered_end: Option<Address>,
    /// Whether a recovered extent intersects another candidate's extent.
    pub overlaps: bool,
    /// Whether multiple usable metadata records disagree about the end.
    pub conflicting_extent: bool,
    /// Count of distinct instructions reachable in the supported static model.
    pub instructions: usize,
    /// Whether a budget cut short the walk.
    pub limited: bool,
}

/// Statically extracted reference category.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReferenceKind {
    /// Direct near call with an encoded destination.
    Call,
    /// Indirect call. A static pointer slot can be reported as additional evidence.
    IndirectCall,
    /// An encoded direct branch or transaction abort branch.
    Branch,
    /// A statically computable instruction-pointer-relative operand.
    IpRelative,
}

/// Metadata available at a referenced address.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReferenceTarget {
    /// Regular PE import slot or ELF dynamic import relocation slot.
    ImportSlot,
    /// Address of a local export.
    Export,
    /// Address of a defined symbol.
    Symbol,
}

/// A reference observed in a decoded instruction. An indirect call's target remains unknown.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub struct Reference {
    /// Entry of the candidate that owns this recovered instruction.
    pub function: Address,
    /// Address of the source instruction.
    pub source: Address,
    /// Relationship encoded in the instruction.
    pub kind: ReferenceKind,
    /// Statically known address, if present.
    pub target: Option<Address>,
    /// Name-bearing metadata that starts at the target address, when recorded.
    pub target_kind: Option<ReferenceTarget>,
}

/// Address-specific projections of the reference inventory.
#[derive(Debug, Serialize)]
pub struct References<'a> {
    /// Query address.
    pub address: Address,
    /// References with the query address as their destination.
    pub incoming: Vec<&'a Reference>,
    /// References whose source instruction starts at the query address.
    pub outgoing: Vec<&'a Reference>,
    /// Whether a resource budget cut short program-wide analysis.
    pub limited: bool,
}

/// Static discovery, call sites, and references from reachable instructions.
#[derive(Debug, Serialize)]
pub struct Analysis {
    /// Report format version.
    pub schema: u32,
    /// Candidates in ascending address order.
    pub functions: Vec<Function>,
    /// Deterministically ordered reference records.
    pub references: Vec<Reference>,
    /// Names of statically mapped PE and ELF import slots.
    pub import_slots: BTreeMap<Address, Import>,
    /// Whether a budget prevented discovery or traversal from finishing.
    pub limited: bool,
}

impl Analysis {
    /// Find references to and from an exact virtual address.
    pub fn references_at(&self, address: Address) -> References<'_> {
        References {
            address,
            incoming: self
                .references
                .iter()
                .filter(|r| r.target == Some(address))
                .collect(),
            outgoing: self
                .references
                .iter()
                .filter(|r| r.source == address)
                .collect(),
            limited: self.limited,
        }
    }

    /// List call sites, optionally selecting incoming and outgoing calls for one function.
    pub fn calls(&self, function: Option<Address>) -> impl Iterator<Item = &Reference> {
        self.references.iter().filter(move |reference| {
            matches!(
                reference.kind,
                ReferenceKind::Call | ReferenceKind::IndirectCall
            ) && function
                .is_none_or(|entry| reference.function == entry || reference.target == Some(entry))
        })
    }
}

impl Binary<'_> {
    /// Discover functions from image evidence and recursively decoded call sites.
    pub fn analyze(&self, limits: AnalysisLimits) -> Result<Analysis, Error> {
        let mut analyzer = Analyzer::new(self, limits)?;
        let mut queue: BTreeSet<_> = analyzer
            .seeds
            .iter()
            .map(|(&entry, seed)| (seed.confidence(), entry))
            .collect();
        let mut functions = BTreeMap::new();
        let mut references = Vec::new();
        let mut limited = false;
        while let Some((_, entry)) = queue.pop_first() {
            if functions.len() == limits.functions
                || analyzer.remaining == 0
                || analyzer.budget.check().is_err()
            {
                limited = true;
                break;
            }
            let walk = analyzer.walk(entry);
            limited |= walk.limited;
            for instruction in walk.nodes.values() {
                analyzer.references(entry, instruction, &mut references);
                if let Some(target) = direct_call(instruction)
                    && target.0 != instruction.next_ip()
                    && analyzer.region(target).is_some()
                {
                    let already_known = analyzer.seeds.contains_key(&target);
                    if !already_known && analyzer.seeds.len() >= analyzer.seed_capacity {
                        limited = true;
                        continue;
                    }
                    analyzer.seeds.entry(target).or_default().evidence.insert(
                        Evidence::DirectCall {
                            site: Address(instruction.ip()),
                        },
                    );
                    if !already_known {
                        queue.insert((Confidence::Strong, target));
                    }
                }
            }
            functions.insert(entry, analyzer.function(entry, &walk));
        }
        let mut functions: Vec<_> = functions.into_values().collect();
        for function in &mut functions {
            // Calls in later functions are still evidence for candidates visited earlier.
            function.evidence = analyzer.seeds[&function.address]
                .evidence
                .iter()
                .cloned()
                .collect();
        }
        mark_overlaps(&mut functions);
        references.sort_unstable();
        references.dedup();
        Ok(Analysis {
            schema: 1,
            functions,
            references,
            import_slots: analyzer.imports,
            limited,
        })
    }

    /// Recover the reachable CFG rooted at a selected function address.
    pub fn cfg(&self, address: Address, limits: AnalysisLimits) -> Result<ControlFlowGraph, Error> {
        let mut analyzer = Analyzer::new(self, limits)?;
        if analyzer.region(address).is_none() {
            return Err(Error::new(
                ErrorKind::Address,
                "function entry has no unambiguous executable bytes",
            ));
        }
        analyzer.seeds.entry(address).or_insert_with(|| Seed {
            evidence: BTreeSet::from([Evidence::Requested]),
            ends: BTreeSet::new(),
        });
        let walk = analyzer.walk(address);
        let graph = ControlFlowGraph::build(&analyzer, address, walk);
        graph.validate()?;
        Ok(graph)
    }
}

#[derive(Default)]
struct Seed {
    evidence: BTreeSet<Evidence>,
    ends: BTreeSet<Address>,
}

impl Seed {
    fn confidence(&self) -> Confidence {
        if self.evidence.iter().any(|e| {
            matches!(
                e,
                Evidence::EntryPoint | Evidence::Symbol { .. } | Evidence::RuntimeRange { .. }
            )
        }) {
            Confidence::Confirmed
        } else if self.evidence.contains(&Evidence::Requested) {
            Confidence::Heuristic
        } else {
            Confidence::Strong
        }
    }

    fn end(&self) -> Option<Address> {
        (self.ends.len() == 1)
            .then(|| self.ends.first().copied())
            .flatten()
    }
}

#[derive(Clone, Copy)]
pub(crate) struct Region<'a> {
    start: Address,
    end: Address,
    // An overlapping cluster has no unique interpretation in this analysis.
    bytes: Option<&'a [u8]>,
    file_offset: u64,
}

impl Region<'_> {
    fn decode(&self, address: Address, end: Address) -> Option<iced_x86::Instruction> {
        let (bytes, _) = self.data(address, end)?;
        Some(Decoder::with_ip(64, bytes, address.0, DecoderOptions::NONE).decode())
    }

    pub(crate) fn data(&self, start: Address, end: Address) -> Option<(&[u8], u64)> {
        let base = self.bytes?;
        let first = usize::try_from(start.0.checked_sub(self.start.0)?).ok()?;
        let last = usize::try_from(end.0.checked_sub(self.start.0)?).ok()?;
        Some((base.get(first..last)?, self.file_offset + first as u64))
    }
}

pub(crate) struct Analyzer<'a> {
    regions: Vec<Region<'a>>,
    seeds: BTreeMap<Address, Seed>,
    labels: BTreeMap<Address, ReferenceTarget>,
    imports: BTreeMap<Address, Import>,
    budget: Budget,
    limits: AnalysisLimits,
    remaining: usize,
    seed_capacity: usize,
}

pub(crate) struct Walk {
    pub nodes: BTreeMap<Address, iced_x86::Instruction>,
    pub stops: BTreeMap<Address, EdgeResolution>,
    pub limited: bool,
}

impl<'a> Analyzer<'a> {
    fn new(binary: &'a Binary<'_>, limits: AnalysisLimits) -> Result<Self, Error> {
        if limits.functions == 0 || limits.per_function == 0 {
            return Err(Error::new(
                ErrorKind::Limit,
                "analysis limits must be positive",
            ));
        }
        let mut budget = Budget::new(binary.limits);
        let mut regions = Vec::new();
        let metadata = binary.metadata();
        for (index, section) in metadata.sections.iter().enumerate() {
            budget.check()?;
            if !section.execute || section.file_size.min(section.size) == 0 {
                continue;
            }
            let (start, bytes) = binary.section_bytes(index)?;
            regions.push(Region {
                start,
                end: Address(start.0 + bytes.len() as u64),
                bytes: Some(bytes),
                file_offset: section.file_offset.unwrap_or_default(),
            });
        }
        regions.sort_unstable_by_key(|region| region.start);
        let mut unique: Vec<Region<'_>> = Vec::new();
        for region in regions {
            if let Some(last) = unique.last_mut()
                && region.start < last.end
            {
                last.end = last.end.max(region.end);
                last.bytes = None;
            } else {
                unique.push(region);
            }
        }

        let (ranges, imports) = match metadata.format {
            Format::Pe => {
                let pe = crate::pe_analysis::read(binary.bytes, &mut budget)?;
                (pe.ranges, pe.imports)
            }
            Format::Elf => (Vec::new(), elf_imports(binary.bytes, &mut budget)?),
        };
        let mut analyzer = Self {
            regions: unique,
            seeds: BTreeMap::new(),
            labels: BTreeMap::new(),
            imports,
            budget,
            limits,
            remaining: binary.limits.instructions,
            seed_capacity: 0,
        };
        for symbol in &metadata.symbols {
            analyzer.budget.check()?;
            analyzer
                .labels
                .insert(symbol.address, ReferenceTarget::Symbol);
            if symbol.kind == "text" {
                let end = symbol.address.0.checked_add(symbol.size).map(Address);
                analyzer.seed(
                    symbol.address,
                    Evidence::Symbol {
                        name: symbol.name.clone(),
                        size: symbol.size,
                    },
                    end,
                );
            }
        }
        for export in &metadata.exports {
            analyzer.budget.check()?;
            if let Some(address) = export.address {
                analyzer.labels.insert(address, ReferenceTarget::Export);
                analyzer.seed(
                    address,
                    Evidence::Export {
                        name: export.name.clone(),
                    },
                    None,
                );
            }
        }
        for &slot in analyzer.imports.keys() {
            analyzer.labels.insert(slot, ReferenceTarget::ImportSlot);
        }
        for (start, end) in ranges {
            analyzer.budget.check()?;
            if analyzer
                .region(start)
                .is_some_and(|region| end <= region.end)
            {
                analyzer.seed(start, Evidence::RuntimeRange { end }, Some(end));
            }
        }
        if let Some(entry) = metadata.entry {
            analyzer.seed(entry, Evidence::EntryPoint, None);
        }
        analyzer.seed_capacity = analyzer.seeds.len().saturating_add(limits.functions);
        Ok(analyzer)
    }

    pub(crate) fn region(&self, address: Address) -> Option<&Region<'a>> {
        let index = self
            .regions
            .partition_point(|region| region.start <= address);
        let region = self.regions.get(index.checked_sub(1)?)?;
        (address < region.end && region.bytes.is_some()).then_some(region)
    }

    fn seed(&mut self, address: Address, evidence: Evidence, end: Option<Address>) {
        let Some(region) = self.region(address) else {
            return;
        };
        let ceiling = region.end;
        let seed = self.seeds.entry(address).or_default();
        seed.evidence.insert(evidence);
        if let Some(end) = end.filter(|end| address < *end && *end <= ceiling) {
            seed.ends.insert(end);
        }
    }

    fn walk(&mut self, entry: Address) -> Walk {
        let mut walk = Walk {
            nodes: BTreeMap::new(),
            stops: BTreeMap::new(),
            limited: false,
        };
        let Some(region) = self.region(entry).copied() else {
            return walk;
        };
        let end = self.seeds.get(&entry).and_then(Seed::end);
        let ceiling = end.unwrap_or(region.end);
        let floor = end.map_or(region.start, |_| entry);
        let mut queue = VecDeque::from([entry]);
        while let Some(address) = queue.pop_front() {
            if walk.nodes.contains_key(&address) || walk.stops.contains_key(&address) {
                continue;
            }
            let blocked = if self.region(address).is_none() {
                Some(EdgeResolution::Unmapped)
            } else if address != entry
                && self
                    .seeds
                    .get(&address)
                    .is_some_and(|seed| seed.confidence() == Confidence::Confirmed)
            {
                Some(EdgeResolution::OtherFunction)
            } else if address < floor || address >= ceiling {
                Some(EdgeResolution::OutsideExtent)
            } else if walk
                .nodes
                .range(..address)
                .next_back()
                .is_some_and(|(_, previous)| previous.next_ip() > address.0)
            {
                Some(EdgeResolution::OverlappingInstruction)
            } else {
                None
            };
            if let Some(reason) = blocked {
                walk.stops.insert(address, reason);
                continue;
            }
            if self.remaining == 0
                || walk.nodes.len() >= self.limits.per_function
                || self.budget.check().is_err()
            {
                walk.limited = true;
                break;
            }
            self.remaining -= 1;
            let Some(decoded) = region.decode(address, ceiling) else {
                walk.stops.insert(address, EdgeResolution::Unmapped);
                continue;
            };
            if decoded.is_invalid() {
                walk.stops
                    .insert(address, EdgeResolution::InvalidInstruction);
                continue;
            }
            if walk
                .nodes
                .range(address..Address(decoded.next_ip()))
                .next()
                .is_some()
            {
                walk.stops
                    .insert(address, EdgeResolution::OverlappingInstruction);
                continue;
            }
            for (kind, target) in steps(&decoded).into_iter().flatten() {
                if kind.follows()
                    && let Some(target) = target
                {
                    queue.push_back(target);
                }
            }
            walk.nodes.insert(address, decoded);
        }
        walk
    }

    pub(crate) fn function(&self, address: Address, walk: &Walk) -> Function {
        let seed = &self.seeds[&address];
        let names: BTreeSet<_> = seed
            .evidence
            .iter()
            .filter_map(|item| match item {
                Evidence::Symbol { name, .. } | Evidence::Export { name } => Some(name.clone()),
                _ => None,
            })
            .collect();
        Function {
            address,
            names: names.into_iter().collect(),
            confidence: if walk.nodes.contains_key(&address) {
                seed.confidence()
            } else {
                Confidence::Unknown
            },
            evidence: seed.evidence.iter().cloned().collect(),
            declared_end: seed.end(),
            recovered_start: walk.nodes.first_key_value().map(|(&start, _)| start),
            recovered_end: walk
                .nodes
                .last_key_value()
                .map(|(_, last)| Address(last.next_ip())),
            overlaps: false,
            conflicting_extent: seed.ends.len() > 1,
            instructions: walk.nodes.len(),
            limited: walk.limited,
        }
    }

    fn references(
        &self,
        function: Address,
        instruction: &iced_x86::Instruction,
        refs: &mut Vec<Reference>,
    ) {
        let source = Address(instruction.ip());
        let mut add = |kind, target| {
            refs.push(Reference {
                function,
                source,
                kind,
                target,
                target_kind: target.and_then(|address| self.labels.get(&address).copied()),
            })
        };
        for (kind, target) in steps(instruction).into_iter().flatten() {
            match (kind, target) {
                (EdgeKind::Call, Some(target)) => add(ReferenceKind::Call, Some(target)),
                (EdgeKind::Call, None) => add(ReferenceKind::IndirectCall, None),
                (EdgeKind::BranchTaken | EdgeKind::Jump, Some(target)) => {
                    add(ReferenceKind::Branch, Some(target))
                }
                _ => {}
            }
        }
        if instruction.is_ip_rel_memory_operand()
            && !matches!(instruction.segment_prefix(), Register::FS | Register::GS)
        {
            add(
                ReferenceKind::IpRelative,
                Some(Address(instruction.ip_rel_memory_address())),
            );
        }
    }
}

fn elf_imports(bytes: &[u8], budget: &mut Budget) -> Result<BTreeMap<Address, Import>, Error> {
    use object::{Object, ObjectSymbol, ObjectSymbolTable, RelocationFlags, RelocationTarget, elf};

    let file = object::read::elf::ElfFile64::<object::LittleEndian>::parse(bytes)
        .map_err(Error::malformed)?;
    let mut slots = BTreeMap::new();
    let (Some(relocations), Some(symbols)) =
        (file.dynamic_relocations(), file.dynamic_symbol_table())
    else {
        return Ok(slots);
    };
    for (address, relocation) in relocations {
        budget.record()?;
        let RelocationFlags::Elf { r_type } = relocation.flags() else {
            continue;
        };
        if r_type != elf::R_X86_64_JUMP_SLOT && r_type != elf::R_X86_64_GLOB_DAT {
            continue;
        }
        let RelocationTarget::Symbol(index) = relocation.target() else {
            continue;
        };
        let symbol = symbols.symbol_by_index(index).map_err(Error::malformed)?;
        if !symbol.is_undefined() {
            continue;
        }
        let raw = symbol.name_bytes().map_err(Error::malformed)?;
        if raw.is_empty() {
            continue;
        }
        let import = Import {
            name: budget.name(raw)?,
            library: String::new(),
        };
        let location = Address(address);
        if let Some(previous) = slots.get(&location)
            && previous != &import
        {
            return Err(Error::malformed("multiple imports claim the same ELF slot"));
        }
        slots.insert(location, import);
    }
    Ok(slots)
}

fn direct_call(instruction: &iced_x86::Instruction) -> Option<Address> {
    (instruction.mnemonic() == Mnemonic::Call)
        .then(|| near_target(instruction))
        .flatten()
}

pub(crate) fn steps(
    instruction: &iced_x86::Instruction,
) -> [Option<(EdgeKind, Option<Address>)>; 2] {
    let next = Some((EdgeKind::Fallthrough, Some(Address(instruction.next_ip()))));
    let destination = near_target(instruction);
    match instruction.flow_control() {
        FlowControl::Next => [next, None],
        FlowControl::ConditionalBranch => [Some((EdgeKind::BranchTaken, destination)), next],
        FlowControl::UnconditionalBranch | FlowControl::IndirectBranch => {
            [Some((EdgeKind::Jump, destination)), None]
        }
        FlowControl::Call | FlowControl::IndirectCall
            if instruction.mnemonic() == Mnemonic::Call =>
        {
            [Some((EdgeKind::Call, destination)), next]
        }
        FlowControl::Return => [Some((EdgeKind::Return, None)), None],
        FlowControl::Exception | FlowControl::Interrupt => [Some((EdgeKind::Trap, None)), None],
        _ => [Some((EdgeKind::Unsupported, destination)), None],
    }
}

fn mark_overlaps(functions: &mut [Function]) {
    let mut extents: Vec<_> = functions
        .iter()
        .enumerate()
        .filter_map(|(index, function)| {
            Some((function.recovered_start?, function.recovered_end?, index))
        })
        .collect();
    extents.sort_unstable();
    let mut furthest: Option<(Address, usize)> = None;
    for (start, end, index) in extents {
        if let Some((previous_end, previous_index)) = furthest
            && start < previous_end
        {
            functions[previous_index].overlaps = true;
            functions[index].overlaps = true;
        }
        if furthest.is_none_or(|(previous_end, _)| previous_end < end) {
            furthest = Some((end, index));
        }
    }
}
