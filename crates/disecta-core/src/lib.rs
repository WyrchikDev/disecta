//! Static binary inspection and x86-64 disassembly.
#![forbid(unsafe_code)]
#![warn(missing_docs)]

mod analysis;
mod cfg;
mod decode;
mod image;
mod pe_analysis;

pub use analysis::{
    Analysis, AnalysisLimits, Confidence, Evidence, Function, Reference, ReferenceKind,
    ReferenceTarget, References,
};
pub use cfg::{Block, ControlFlowGraph, Edge, EdgeKind, EdgeResolution, UnrecoveredRange};
pub use decode::{Disassembly, Instruction, Operand};
pub use image::{
    Address, Binary, Error, ErrorKind, Export, Format, Import, Limits, Metadata, Section, Symbol,
};

/// Bytes of the small, reproducible PE32+ example shipped with DISECTA.
pub const EXAMPLE_PE: &[u8] = include_bytes!("../../../tests/fixtures/branch.exe");
