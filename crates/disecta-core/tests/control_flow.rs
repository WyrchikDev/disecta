use disecta_core::{
    Address, AnalysisLimits, Binary, Confidence, EXAMPLE_PE, EdgeKind, EdgeResolution, Evidence,
    Limits, ReferenceKind,
};

const ENTRY: Address = Address(0x140001000);
const ELF: &[u8] = include_bytes!("../../../tests/fixtures/branch.elf");

#[test]
fn follows_calls_branches_and_rip_relative_targets_on_both_formats() {
    for (bytes, entry) in [(EXAMPLE_PE, ENTRY), (ELF, Address(0x401000))] {
        let image = Binary::parse(bytes, Limits::default()).unwrap();
        let report = image.analyze(AnalysisLimits::default()).unwrap();
        assert!(!report.limited);
        assert_eq!(report.functions.len(), 2);
        let entry_function = &report.functions[0];
        let callee = &report.functions[1];
        assert_eq!(entry_function.address, entry);
        assert_eq!(entry_function.confidence, Confidence::Confirmed);
        assert_eq!(callee.address, Address(entry.0 + 0x24));
        assert_eq!(callee.confidence, Confidence::Strong);
        assert_eq!(
            callee.evidence,
            [Evidence::DirectCall {
                site: Address(entry.0 + 0xA)
            }]
        );

        let reference = report.references_at(Address(entry.0 + 0x1000));
        assert_eq!(reference.incoming.len(), 1);
        assert_eq!(reference.incoming[0].kind, ReferenceKind::IpRelative);
        assert_eq!(reference.incoming[0].source, Address(entry.0 + 0x13));
        let calls: Vec<_> = report.calls(Some(callee.address)).collect();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].function, entry);

        let graph = image.cfg(entry, AnalysisLimits::default()).unwrap();
        graph.validate().unwrap();
        let starts: Vec<_> = graph.blocks.iter().map(|b| b.start.0 - entry.0).collect();
        assert_eq!(starts, [0, 0xF, 0x13, 0x1B]);
        let callers = graph
            .edges
            .iter()
            .filter(|edge| edge.block == Some(Address(entry.0 + 0x1B)))
            .count();
        assert_eq!(callers, 2);
        assert!(graph.edges.iter().any(|edge| matches!(
            (edge.kind, edge.target, edge.resolution),
            (EdgeKind::Call, Some(address), EdgeResolution::DirectCall) if address == callee.address
        )));
        assert!(
            !graph
                .blocks
                .iter()
                .any(|block| block.start == callee.address)
        );
    }
}

#[test]
fn retains_loop_edge_and_marks_indirect_jump_unresolved() {
    let bytes = with_text(&[0xB9, 3, 0, 0, 0, 0xFF, 0xC9, 0x75, 0xFC, 0xFF, 0xE0]);
    let image = Binary::parse(&bytes, Limits::default()).unwrap();
    let graph = image.cfg(ENTRY, AnalysisLimits::default()).unwrap();
    let loop_head = Address(ENTRY.0 + 5);
    assert!(
        graph
            .edges
            .iter()
            .any(|edge| edge.kind == EdgeKind::BranchTaken
                && edge.from == loop_head
                && edge.block == Some(loop_head))
    );
    assert!(graph.edges.iter().any(|edge| edge.kind == EdgeKind::Jump
        && edge.target.is_none()
        && edge.resolution == EdgeResolution::Unresolved));
}

#[test]
fn preserves_conflicting_instruction_boundaries_as_unresolved() {
    let bytes = with_text(&[0x31, 0xC0, 0x75, 1, 0xB8, 0x90, 0x90, 0x90, 0xC3, 0xC3]);
    let image = Binary::parse(&bytes, Limits::default()).unwrap();
    let graph = image.cfg(ENTRY, AnalysisLimits::default()).unwrap();
    assert!(
        graph
            .edges
            .iter()
            .any(|edge| edge.resolution == EdgeResolution::OverlappingInstruction)
    );
    graph.validate().unwrap();
}

#[test]
fn reads_runtime_extent_and_reports_unrecovered_bytes() {
    let mut bytes = EXAMPLE_PE.to_vec();
    // PE32+ exception directory, using a test record in existing .rdata.
    bytes[0xE0..0xE4].copy_from_slice(&0x2000_u32.to_le_bytes());
    bytes[0xE4..0xE8].copy_from_slice(&12_u32.to_le_bytes());
    bytes[0x400..0x404].copy_from_slice(&0x1000_u32.to_le_bytes());
    bytes[0x404..0x408].copy_from_slice(&0x1024_u32.to_le_bytes());
    bytes[0x408..0x40C].copy_from_slice(&0x200C_u32.to_le_bytes());
    let image = Binary::parse(&bytes, Limits::default()).unwrap();
    let graph = image.cfg(ENTRY, AnalysisLimits::default()).unwrap();
    assert_eq!(graph.function.declared_end, Some(Address(ENTRY.0 + 0x24)));
    assert!(graph.function.evidence.contains(&Evidence::RuntimeRange {
        end: Address(ENTRY.0 + 0x24)
    }));
    assert_eq!(graph.unrecovered_ranges.len(), 1);
    assert_eq!(graph.unrecovered_ranges[0].start, Address(ENTRY.0 + 0x21));
    assert_eq!(graph.unrecovered_ranges[0].end, Address(ENTRY.0 + 0x24));
}

#[test]
fn does_not_promote_call_to_next_instruction_and_keeps_unresolved_calls() {
    let bytes = with_text(&[0xE8, 0, 0, 0, 0, 0x58, 0xFF, 0xD0, 0xC3]);
    let image = Binary::parse(&bytes, Limits::default()).unwrap();
    let report = image.analyze(AnalysisLimits::default()).unwrap();
    assert_eq!(report.functions.len(), 1);
    let calls: Vec<_> = report.calls(None).collect();
    assert_eq!(calls.len(), 2);
    assert_eq!(calls[0].target, Some(Address(ENTRY.0 + 5)));
    assert_eq!(calls[1].target, None);
}

#[test]
fn marks_partial_analysis_and_keeps_valid_provenance() {
    let binary = Binary::parse(EXAMPLE_PE, Limits::default()).unwrap();
    let limits = AnalysisLimits {
        functions: 1,
        per_function: 3,
    };
    let report = binary.analyze(limits).unwrap();
    assert!(report.limited);
    assert_eq!(report.functions.len(), 1);
    assert_eq!(report.functions[0].instructions, 3);
    let graph = binary.cfg(ENTRY, limits).unwrap();
    assert!(graph.function.limited);
    assert!(
        graph
            .edges
            .iter()
            .any(|edge| edge.resolution == EdgeResolution::Limited)
    );
    graph.validate().unwrap();
}

#[test]
fn emits_expected_dot_for_single_return() {
    let bytes = with_text(&[0xC3]);
    let image = Binary::parse(&bytes, Limits::default()).unwrap();
    let graph = image.cfg(ENTRY, AnalysisLimits::default()).unwrap();
    let mut dot = Vec::new();
    graph.write_dot(&mut dot).unwrap();
    assert_eq!(
        String::from_utf8(dot).unwrap(),
        concat!(
            "digraph cfg {\n",
            "  node [shape=box, fontname=\"monospace\"];\n",
            "  \"0x140001000\" [label=\"0x140001000\\l0x140001000  ret\\l\"];\n",
            "  \"exit_0\" [label=\"exit\", style=dashed];\n",
            "  \"0x140001000\" -> \"exit_0\" [label=\"return\"];\n",
            "}\n",
        )
    );
}

fn with_text(code: &[u8]) -> Vec<u8> {
    let mut bytes = EXAMPLE_PE.to_vec();
    bytes[0x200..0x200 + code.len()].copy_from_slice(code);
    bytes
}
