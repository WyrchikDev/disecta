use std::time::Duration;

use disecta_core::{Address, Binary, EXAMPLE_PE, ErrorKind, Format, Limits, Operand};

const ELF: &[u8] = include_bytes!("../../../tests/fixtures/branch.elf");

#[test]
fn maps_pe_and_elf_and_excludes_zero_fill() {
    for (bytes, format, base, entry, offset, bss) in [
        (
            EXAMPLE_PE,
            Format::Pe,
            0x140000000,
            0x140001000,
            0x200,
            0x140004000,
        ),
        (ELF, Format::Elf, 0x400000, 0x401000, 0x1000, 0x402010),
    ] {
        let image = Binary::parse(bytes, Limits::default()).unwrap();
        let meta = image.metadata();
        assert_eq!(meta.format, format);
        assert_eq!(meta.image_base, Address(base));
        assert_eq!(meta.entry, Some(Address(entry)));
        assert_eq!(image.file_offset(Address(base)).unwrap(), Some(0));
        assert_eq!(image.file_offset(Address(entry)).unwrap(), Some(offset));
        assert_eq!(image.file_offset(Address(bss)).unwrap(), None);
        let code = meta.sections.iter().find(|s| s.name == ".text").unwrap();
        assert_eq!(code.read, Some(true));
        assert!(code.execute);
        assert!(!code.write);
    }
}

#[test]
fn decodes_real_bytes_and_resolves_relative_targets() {
    let image = Binary::parse(EXAMPLE_PE, Limits::default()).unwrap();
    let page = image.disassemble(0, None, 8).unwrap();
    assert_eq!(page.next_address, Some(Address(0x14000101A)));
    assert_eq!(page.instructions[0].text, "push rbp");
    assert_eq!(page.instructions[4].bytes, "E8 15 00 00 00");
    assert_eq!(page.instructions[4].target, Some(Address(0x140001024)));
    assert_eq!(page.instructions[6].target, Some(Address(0x14000101B)));
    assert!(
        matches!(&page.instructions[7].operands[1], Operand::Memory {
        base: Some(base), displacement, resolved_address: Some(Address(0x140002000)), ..
    } if base == "rip" && displacement == "0xFE6")
    );
}

#[test]
fn preserves_invalid_instruction_and_section_end() {
    let mut bytes = EXAMPLE_PE.to_vec();
    bytes[0x22F] = 0x0F;
    let image = Binary::parse(&bytes, Limits::default()).unwrap();
    let page = image.disassemble(0, Some(Address(0x14000102F)), 2).unwrap();
    assert_eq!(page.instructions.len(), 1);
    assert!(page.instructions[0].invalid);
    assert_eq!(page.instructions[0].bytes, "0F");
    assert_eq!(page.next_address, None);
    assert_eq!(
        image
            .disassemble(0, Some(Address(0x140001030)), 1)
            .unwrap_err()
            .kind,
        ErrorKind::Address
    );
}

#[test]
fn malformed_and_limited_inputs_fail_with_structured_errors() {
    for bytes in [&EXAMPLE_PE[..15], &EXAMPLE_PE[..0x300], &ELF[..0x2280]] {
        assert_eq!(
            Binary::parse(bytes, Limits::default()).unwrap_err().kind,
            ErrorKind::Malformed
        );
    }
    for limits in [
        Limits {
            file_bytes: 10,
            ..Limits::default()
        },
        Limits {
            metadata_entries: 1,
            ..Limits::default()
        },
        Limits {
            name_bytes: 1,
            ..Limits::default()
        },
        Limits {
            time: Duration::ZERO,
            ..Limits::default()
        },
    ] {
        assert_eq!(
            Binary::parse(EXAMPLE_PE, limits).unwrap_err().kind,
            ErrorKind::Limit
        );
    }
    let mut wrong_arch = EXAMPLE_PE.to_vec();
    wrong_arch[0x44..0x46].copy_from_slice(&0xaa64_u16.to_le_bytes());
    assert_eq!(
        Binary::parse(&wrong_arch, Limits::default())
            .unwrap_err()
            .kind,
        ErrorKind::Unsupported
    );
}

#[test]
fn disassembles_elf_without_section_headers() {
    let mut bytes = ELF.to_vec();
    bytes[40..48].fill(0);
    bytes[60..64].fill(0);
    let image = Binary::parse(&bytes, Limits::default()).unwrap();
    assert_eq!(image.metadata().sections[0].name, "PT_LOAD[0]");
    let page = image.disassemble(0, Some(Address(0x401000)), 5).unwrap();
    assert_eq!(page.instructions[4].target, Some(Address(0x401024)));
}

#[test]
fn rejects_pe_with_a_wrapped_image_address() {
    let mut bytes = EXAMPLE_PE.to_vec();
    bytes[0x70..0x78].copy_from_slice(&(u64::MAX - 0x7FF).to_le_bytes());
    assert_eq!(
        Binary::parse(&bytes, Limits::default()).unwrap_err().kind,
        ErrorKind::Malformed
    );
}
