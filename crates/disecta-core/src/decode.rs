use iced_x86::{Decoder, DecoderOptions, FlowControl, Formatter, IntelFormatter, OpKind, Register};
use serde::Serialize;

use crate::image::{Address, Binary, Budget, Error, ErrorKind};

/// Decoded operand as stored in the instruction encoding.
#[derive(Debug, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Operand {
    /// Explicit register operand.
    Register {
        /// Architecture register name.
        name: String,
    },
    /// Immediate value, sign-extended when specified by the instruction.
    Immediate {
        /// Hexadecimal bit pattern.
        value: String,
    },
    /// A near control-flow target.
    NearBranch {
        /// Absolute virtual address of the target.
        target: Address,
    },
    /// A far control-flow target.
    FarBranch {
        /// Target segment selector.
        selector: u16,
        /// Encoded segment-relative offset.
        offset: Address,
    },
    /// Address expression and data size for a memory operand.
    Memory {
        /// Segment chosen by the decoder.
        segment: String,
        /// Base register if present.
        base: Option<String>,
        /// Index register if present.
        index: Option<String>,
        /// Multiplier for the index.
        scale: u32,
        /// Encoded displacement, sign-extended to the address size.
        displacement: String,
        /// RIP-relative resolved address when applicable.
        resolved_address: Option<Address>,
        /// Memory operand width in bytes, or zero if variable or unknown.
        width: usize,
        /// Addressing form for implicit string operands.
        addressing: String,
    },
}

/// Instruction and associated decoder metadata.
#[derive(Debug, Serialize)]
pub struct Instruction {
    /// Start address of this instruction.
    pub address: Address,
    /// Offset in the original binary.
    pub file_offset: u64,
    /// Encoded bytes as space-separated hexadecimal.
    pub bytes: String,
    /// Instruction length in bytes.
    pub length: usize,
    /// Intel-syntax instruction text.
    pub text: String,
    /// Architecture mnemonic.
    pub mnemonic: String,
    /// iced-x86 opcode identifier.
    pub opcode: String,
    /// Flow category returned by the decoder.
    pub flow: String,
    /// Absolute near branch or call destination, when encoded directly.
    pub target: Option<Address>,
    /// Explicit operands in encoding order.
    pub operands: Vec<Operand>,
    /// Whether decoding failed at this offset.
    pub invalid: bool,
}

/// A bounded page of linear disassembly.
#[derive(Debug, Serialize)]
pub struct Disassembly {
    /// Index in the image's section list.
    pub section: usize,
    /// Sequence in address order, including invalid entries.
    pub instructions: Vec<Instruction>,
    /// Continuation address when the page ended before the section did.
    pub next_address: Option<Address>,
}

impl Binary<'_> {
    /// Decode from a selected executable section. An explicit start is interpreted
    /// as a candidate instruction boundary, which the linear sweep cannot prove.
    pub fn disassemble(
        &self,
        section: usize,
        start: Option<Address>,
        count: usize,
    ) -> Result<Disassembly, Error> {
        if count == 0 || count > self.limits.instructions {
            return Err(Error::new(
                ErrorKind::Limit,
                "instruction count is outside the configured limit",
            ));
        }
        let budget = Budget::new(self.limits);
        let (base, bytes) = self.section_bytes(section)?;
        let address = start.unwrap_or(base);
        let skip = address
            .0
            .checked_sub(base.0)
            .and_then(|delta| usize::try_from(delta).ok())
            .filter(|&delta| delta < bytes.len())
            .ok_or_else(|| {
                Error::new(
                    ErrorKind::Address,
                    "start address is outside the executable bytes of the section",
                )
            })?;
        let file_start = self.metadata().sections[section]
            .file_offset
            .unwrap_or_default();
        let input = &bytes[skip..];
        let mut decoder = Decoder::with_ip(64, input, address.0, DecoderOptions::NONE);
        let mut formatter = IntelFormatter::new();
        let mut instructions = Vec::new();
        while decoder.can_decode() && instructions.len() < count {
            budget.check()?;
            let offset = decoder.position();
            let instruction = decoder.decode();
            instructions.push(describe(
                &instruction,
                &input[offset..decoder.position()],
                file_start + (skip + offset) as u64,
                &mut formatter,
            ));
        }
        Ok(Disassembly {
            section,
            instructions,
            next_address: decoder.can_decode().then(|| Address(decoder.ip())),
        })
    }
}

pub(crate) fn near_target(instruction: &iced_x86::Instruction) -> Option<Address> {
    (0..instruction.op_count())
        .any(|index| {
            matches!(
                instruction.op_kind(index),
                OpKind::NearBranch16 | OpKind::NearBranch32 | OpKind::NearBranch64
            )
        })
        .then(|| Address(instruction.near_branch_target()))
}

pub(crate) fn describe(
    instruction: &iced_x86::Instruction,
    bytes: &[u8],
    file_offset: u64,
    formatter: &mut IntelFormatter,
) -> Instruction {
    let mut text = String::new();
    formatter.format(instruction, &mut text);
    let target = match instruction.flow_control() {
        FlowControl::Call | FlowControl::ConditionalBranch | FlowControl::UnconditionalBranch => {
            near_target(instruction)
        }
        _ => None,
    };
    Instruction {
        address: Address(instruction.ip()),
        file_offset,
        bytes: bytes
            .iter()
            .map(|byte| format!("{byte:02X}"))
            .collect::<Vec<_>>()
            .join(" "),
        length: instruction.len(),
        text,
        mnemonic: format!("{:?}", instruction.mnemonic()).to_ascii_lowercase(),
        opcode: format!("{:?}", instruction.code()),
        flow: format!("{:?}", instruction.flow_control()),
        target,
        operands: (0..instruction.op_count())
            .map(|index| operand(instruction, index))
            .collect(),
        invalid: instruction.is_invalid(),
    }
}

fn register(name: Register) -> Option<String> {
    (name != Register::None).then(|| format!("{name:?}").to_ascii_lowercase())
}

fn operand(instruction: &iced_x86::Instruction, index: u32) -> Operand {
    let kind = instruction.op_kind(index);
    match kind {
        OpKind::Register => Operand::Register {
            name: format!("{:?}", instruction.op_register(index)).to_ascii_lowercase(),
        },
        OpKind::NearBranch16 | OpKind::NearBranch32 | OpKind::NearBranch64 => Operand::NearBranch {
            target: Address(instruction.near_branch_target()),
        },
        OpKind::FarBranch16 | OpKind::FarBranch32 => Operand::FarBranch {
            selector: instruction.far_branch_selector(),
            offset: Address(match kind {
                OpKind::FarBranch16 => u64::from(instruction.far_branch16()),
                _ => u64::from(instruction.far_branch32()),
            }),
        },
        OpKind::Immediate8
        | OpKind::Immediate8_2nd
        | OpKind::Immediate16
        | OpKind::Immediate32
        | OpKind::Immediate64
        | OpKind::Immediate8to16
        | OpKind::Immediate8to32
        | OpKind::Immediate8to64
        | OpKind::Immediate32to64 => Operand::Immediate {
            value: format!("0x{:X}", instruction.immediate(index)),
        },
        _ => {
            let (base, segment) = match kind {
                OpKind::MemorySegSI => (Register::SI, instruction.memory_segment()),
                OpKind::MemorySegESI => (Register::ESI, instruction.memory_segment()),
                OpKind::MemorySegRSI => (Register::RSI, instruction.memory_segment()),
                OpKind::MemorySegDI => (Register::DI, instruction.memory_segment()),
                OpKind::MemorySegEDI => (Register::EDI, instruction.memory_segment()),
                OpKind::MemorySegRDI => (Register::RDI, instruction.memory_segment()),
                OpKind::MemoryESDI => (Register::DI, Register::ES),
                OpKind::MemoryESEDI => (Register::EDI, Register::ES),
                OpKind::MemoryESRDI => (Register::RDI, Register::ES),
                _ => (instruction.memory_base(), instruction.memory_segment()),
            };
            let resolved_address = instruction
                .is_ip_rel_memory_operand()
                .then(|| Address(instruction.ip_rel_memory_address()));
            let displacement = match base {
                Register::RIP => instruction
                    .ip_rel_memory_address()
                    .wrapping_sub(instruction.next_ip()),
                Register::EIP => u64::from(
                    (instruction.ip_rel_memory_address() as u32)
                        .wrapping_sub(instruction.next_ip() as u32),
                ),
                _ => instruction.memory_displacement64(),
            };
            Operand::Memory {
                segment: format!("{segment:?}").to_ascii_lowercase(),
                base: register(base),
                index: register(instruction.memory_index()),
                scale: instruction.memory_index_scale(),
                displacement: format!("0x{displacement:X}"),
                resolved_address,
                width: instruction.memory_size().size(),
                addressing: format!("{kind:?}"),
            }
        }
    }
}
