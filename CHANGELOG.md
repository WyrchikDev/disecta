# Changelog

## Unreleased

- Recursive function discovery with entry, symbol, export, PE runtime range, and direct call provenance.
- Validated basic blocks with explicit unresolved transfers and JSON/DOT export.
- Static references, import slots, and caller/callee analysis.
- Function search and filtering, interactive CFG and call graph, and navigation between analysis and assembly.

## 0.1.0

- Inspect little-endian x86-64 PE32+ and ELF64 images.
- Decode file-backed code with structured operands and explicit invalid instructions.
- Browse sections, disassembly, symbols, imports and exports in a local workbench.
- Ship reproducible PE/ELF fixtures and Windows and Linux CI.
