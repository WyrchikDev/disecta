//! Static binary inspection and x86-64 disassembly.
#![forbid(unsafe_code)]
#![warn(missing_docs)]

mod decode;
mod image;

pub use decode::{Disassembly, Instruction, Operand};
pub use image::{
    Address, Binary, Error, ErrorKind, Export, Format, Import, Limits, Metadata, Section, Symbol,
};

/// Bytes of the small, reproducible PE32+ example shipped with DISECTA.
pub const EXAMPLE_PE: &[u8] = include_bytes!("../../../tests/fixtures/branch.exe");
