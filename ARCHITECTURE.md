# Architecture

- **disecta-core** validates and interprets read-only x86-64 images. The object crate handles container structures. iced-x86 handles decoding and Intel formatting. DISECTA checks bounds, accounts for resource consumption, resolves file offsets, and constructs structured reports.
- **disecta** provides inspect and disasm commands plus an embedded loopback workbench. Both use the same library. The workbench uses plain HTML, CSS, and JavaScript with local assets.

## Image invariants

The PE address space is based on the preferred image base. RVAs are relative to that base. The ELF address space uses the original virtual addresses and load segments. File offsets are positions in the input. Zero-filled data and overlays have no corresponding mapped file byte. An address with conflicting file mappings produces an error.

The decoder accepts a section index, a start address, and an instruction count. A start address is a candidate boundary. A result includes original offsets, flow categories, the raw instruction encoding and typed operand descriptions. Unknown or incomplete encodings are explicit rows and carry no fabricated semantics.

The UI sends a chosen file to the running local process for each analysis request. It retains the current file, metadata and page in the browser tab. HTTP requests cannot supply disk paths. The engine analyzes bytes without executing them or resolving dependencies. File names and metadata are rendered as text.

## Next milestone

Discover entry candidates from code symbols, exports, entry points and validated direct calls. Then reconstruct basic blocks with provenance and unresolved edges, and expose DOT export after validating graph invariants.
