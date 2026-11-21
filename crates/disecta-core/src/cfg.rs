use std::collections::{BTreeMap, BTreeSet};
use std::io::{self, Write};

use iced_x86::{FlowControl, IntelFormatter};
use serde::Serialize;

use crate::analysis::{Analyzer, Function, Walk, steps};
use crate::decode::{Instruction, describe};
use crate::image::{Address, Error};

/// Syntactic role of a control-flow edge.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EdgeKind {
    /// Sequential continuation, including the continuation of a returning call.
    Fallthrough,
    /// Taken side of a conditional near branch.
    BranchTaken,
    /// Unconditional jump.
    Jump,
    /// Call relationship. Interprocedural edges never drive this CFG's traversal.
    Call,
    /// Return from the current activation.
    Return,
    /// Trap or interrupt.
    Trap,
    /// Control-flow semantics outside the current model.
    Unsupported,
}

impl EdgeKind {
    pub(crate) fn follows(self) -> bool {
        matches!(self, Self::Fallthrough | Self::BranchTaken | Self::Jump)
    }

    /// Short human-readable edge type.
    pub fn label(self) -> &'static str {
        match self {
            Self::Fallthrough => "fallthrough",
            Self::BranchTaken => "taken",
            Self::Jump => "jump",
            Self::Call => "call",
            Self::Return => "return",
            Self::Trap => "trap",
            Self::Unsupported => "unsupported",
        }
    }
}

/// Explanation of how a control transfer was resolved.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EdgeResolution {
    /// Destination is a block in this function.
    Block,
    /// A direct call carries an encoded target, whether or not that target has been analyzed.
    DirectCall,
    /// Destination is a separately confirmed function entry.
    OtherFunction,
    /// Destination lies outside the chosen function extent.
    OutsideExtent,
    /// Destination is missing or has no unambiguous executable mapping.
    Unmapped,
    /// Decoding failed at the destination.
    InvalidInstruction,
    /// Destination or instruction overlaps a different decoded instruction.
    OverlappingInstruction,
    /// The traversal stopped at a resource limit.
    Limited,
    /// The destination requires runtime information or is a far transfer.
    Unresolved,
    /// Normal modeled exit from the current CFG.
    Exit,
    /// Transfer semantics are outside the current model.
    Unsupported,
}

impl EdgeResolution {
    /// Short explanation for a rendered control transfer.
    pub fn label(self) -> &'static str {
        match self {
            Self::Block => "block",
            Self::DirectCall => "direct call target",
            Self::OtherFunction => "other function",
            Self::OutsideExtent => "outside extent",
            Self::Unmapped => "unmapped",
            Self::InvalidInstruction => "invalid instruction",
            Self::OverlappingInstruction => "overlapping instruction",
            Self::Limited => "analysis limit",
            Self::Unresolved => "unresolved",
            Self::Exit => "exit",
            Self::Unsupported => "unsupported",
        }
    }
}

/// An edge from the last instruction of a basic block.
#[derive(Clone, Copy, Debug, Serialize)]
pub struct Edge {
    /// Source basic block.
    pub from: Address,
    /// Source instruction address.
    pub instruction: Address,
    /// Edge kind.
    pub kind: EdgeKind,
    /// Virtual destination when statically encoded, including external targets.
    pub target: Option<Address>,
    /// Destination block when recovered inside this CFG.
    pub block: Option<Address>,
    /// Why the destination is or is not in the graph.
    pub resolution: EdgeResolution,
}

/// A recovered sequential block.
#[derive(Debug, Serialize)]
pub struct Block {
    /// Start address and unique block identifier.
    pub start: Address,
    /// Exclusive end address.
    pub end: Address,
    /// Original instructions, ordered by address.
    pub instructions: Vec<Instruction>,
}

/// Bytes inside declared bounds that could not be reached by modeled edges.
#[derive(Debug, Serialize)]
pub struct UnrecoveredRange {
    /// Inclusive start.
    pub start: Address,
    /// Exclusive end.
    pub end: Address,
}

/// Function control flow recovered from recursively decoded instructions.
#[derive(Debug, Serialize)]
pub struct ControlFlowGraph {
    /// Report format version.
    pub schema: u32,
    /// Function identity, extent, and evidence.
    pub function: Function,
    /// Reason for an empty graph when the entry could not be analyzed.
    pub entry_status: Option<EdgeResolution>,
    /// Basic blocks in address order. The entry need not be the first numeric block.
    pub blocks: Vec<Block>,
    /// Modeled flow and explicit exits or unresolved transfers.
    pub edges: Vec<Edge>,
    /// Gaps inside declared bounds. They may contain data or targets of unknown edges.
    pub unrecovered_ranges: Vec<UnrecoveredRange>,
}

impl ControlFlowGraph {
    pub(crate) fn build(analyzer: &Analyzer<'_>, entry: Address, walk: Walk) -> Self {
        let function = analyzer.function(entry, &walk);
        let entry_status = if walk.nodes.contains_key(&entry) {
            None
        } else {
            Some(
                walk.stops
                    .get(&entry)
                    .copied()
                    .unwrap_or(EdgeResolution::Limited),
            )
        };
        let mut leaders = BTreeSet::from([entry]);
        for instruction in walk.nodes.values() {
            if instruction.flow_control() != FlowControl::Next {
                for (kind, target) in steps(instruction).into_iter().flatten() {
                    if kind.follows()
                        && let Some(target) = target
                    {
                        leaders.insert(target);
                    }
                }
            }
        }
        let mut formatter = IntelFormatter::new();
        let mut blocks: Vec<Block> = Vec::new();
        let mut previous_was_sequential = false;
        for (&address, raw) in &walk.nodes {
            let end = Address(raw.next_ip());
            let Some((bytes, offset)) = analyzer
                .region(address)
                .and_then(|region| region.data(address, end))
            else {
                continue;
            };
            let instruction = describe(raw, bytes, offset, &mut formatter);
            if let Some(block) = blocks.last_mut()
                && previous_was_sequential
                && block.end == address
                && !leaders.contains(&address)
            {
                block.instructions.push(instruction);
                block.end = end;
            } else {
                blocks.push(Block {
                    start: address,
                    end,
                    instructions: vec![instruction],
                });
            }
            previous_was_sequential = raw.flow_control() == FlowControl::Next;
        }

        let starts: BTreeSet<_> = blocks.iter().map(|block| block.start).collect();
        let mut edges = Vec::new();
        for block in &blocks {
            let Some(tail) = block.instructions.last() else {
                continue;
            };
            let Some(raw) = walk.nodes.get(&tail.address) else {
                continue;
            };
            for (kind, target) in steps(raw).into_iter().flatten() {
                let next_block =
                    target.filter(|address| kind.follows() && starts.contains(address));
                let resolution = match (kind, target, next_block) {
                    (_, _, Some(_)) => EdgeResolution::Block,
                    (EdgeKind::Call, Some(_), _) => EdgeResolution::DirectCall,
                    (EdgeKind::Return | EdgeKind::Trap, _, _) => EdgeResolution::Exit,
                    (EdgeKind::Unsupported, _, _) => EdgeResolution::Unsupported,
                    (_, None, _) => EdgeResolution::Unresolved,
                    (_, Some(target), _) => {
                        walk.stops.get(&target).copied().unwrap_or(if walk.limited {
                            EdgeResolution::Limited
                        } else {
                            EdgeResolution::Unmapped
                        })
                    }
                };
                edges.push(Edge {
                    from: block.start,
                    instruction: tail.address,
                    kind,
                    target,
                    block: next_block,
                    resolution,
                });
            }
        }
        let unrecovered_ranges = gaps(entry, function.declared_end, &blocks);
        Self {
            schema: 1,
            function,
            entry_status,
            blocks,
            edges,
            unrecovered_ranges,
        }
    }

    /// Check instruction ownership, edge endpoints, and entry reachability.
    pub fn validate(&self) -> Result<(), Error> {
        let invalid = || Error::malformed("invalid control-flow graph");
        let mut tails = BTreeMap::new();
        let mut end = None;
        let mut count = 0;
        for block in &self.blocks {
            if end.is_some_and(|end| end > block.start) || block.start >= block.end {
                return Err(invalid());
            }
            let mut address = block.start;
            for instruction in &block.instructions {
                if instruction.address != address || instruction.length == 0 || instruction.invalid
                {
                    return Err(invalid());
                }
                address = Address(
                    address
                        .0
                        .checked_add(instruction.length as u64)
                        .ok_or_else(invalid)?,
                );
                count += 1;
            }
            if address != block.end {
                return Err(invalid());
            }
            let last = block.instructions.last().ok_or_else(invalid)?;
            tails.insert(block.start, last.address);
            end = Some(block.end);
        }
        if count != self.function.instructions {
            return Err(invalid());
        }
        if self.blocks.is_empty() {
            return if self.edges.is_empty() && self.entry_status.is_some() {
                Ok(())
            } else {
                Err(invalid())
            };
        }
        if self.entry_status.is_some() || !tails.contains_key(&self.function.address) {
            return Err(invalid());
        }
        let mut successors: BTreeMap<Address, Vec<Address>> = BTreeMap::new();
        let mut sources = BTreeSet::new();
        for edge in &self.edges {
            if tails.get(&edge.from) != Some(&edge.instruction)
                || (edge.resolution == EdgeResolution::Block) != edge.block.is_some()
            {
                return Err(invalid());
            }
            sources.insert(edge.from);
            if let Some(block) = edge.block {
                if edge.target != Some(block) || !edge.kind.follows() || !tails.contains_key(&block)
                {
                    return Err(invalid());
                }
                successors.entry(edge.from).or_default().push(block);
            }
        }
        if sources.len() != tails.len() {
            return Err(invalid());
        }
        let mut visited = BTreeSet::new();
        let mut queue = vec![self.function.address];
        while let Some(block) = queue.pop() {
            if visited.insert(block)
                && let Some(next) = successors.get(&block)
            {
                queue.extend(next);
            }
        }
        if visited.len() != tails.len() {
            return Err(invalid());
        }
        Ok(())
    }

    /// Write a deterministic Graphviz DOT representation, including exits and unresolved edges.
    pub fn write_dot(&self, out: &mut impl Write) -> io::Result<()> {
        writeln!(out, "digraph cfg {{")?;
        writeln!(out, "  node [shape=box, fontname=\"monospace\"];")?;
        for block in &self.blocks {
            let mut label = format!("{}\\l", block.start);
            for instruction in &block.instructions {
                label.push_str(&format!(
                    "{}  {}\\l",
                    instruction.address,
                    dot_escape(&instruction.text)
                ));
            }
            writeln!(out, "  \"{}\" [label=\"{}\"];", block.start, label)?;
        }
        if let Some(reason) = self.entry_status {
            writeln!(
                out,
                "  \"{}\" [label=\"{}\\l{}\", style=dashed];",
                self.function.address,
                self.function.address,
                reason.label()
            )?;
        }
        for (index, edge) in self.edges.iter().enumerate() {
            let target = match edge.block {
                Some(block) => block.to_string(),
                None => {
                    let id = format!("exit_{index}");
                    let label = edge.target.map_or_else(
                        || edge.resolution.label().to_string(),
                        |address| format!("{}\\l{}", address, edge.resolution.label()),
                    );
                    writeln!(out, "  \"{id}\" [label=\"{label}\", style=dashed];")?;
                    id
                }
            };
            writeln!(
                out,
                "  \"{}\" -> \"{target}\" [label=\"{}\"];",
                edge.from,
                edge.kind.label()
            )?;
        }
        writeln!(out, "}}")
    }
}

fn gaps(entry: Address, end: Option<Address>, blocks: &[Block]) -> Vec<UnrecoveredRange> {
    let Some(end) = end else { return Vec::new() };
    let mut ranges = Vec::new();
    let mut start = entry;
    for block in blocks {
        if start < block.start {
            ranges.push(UnrecoveredRange {
                start,
                end: block.start,
            });
        }
        start = block.end;
    }
    if start < end {
        ranges.push(UnrecoveredRange { start, end });
    }
    ranges
}

fn dot_escape(text: &str) -> String {
    text.replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\n', "\\n")
        .replace('\r', "")
}
