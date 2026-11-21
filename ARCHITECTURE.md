# Architecture

- **disecta-core** validates and interprets read-only x86-64 images. The object crate handles container structures. iced-x86 handles decoding and Intel formatting. DISECTA checks bounds, accounts for resource consumption, resolves file offsets, and constructs structured reports.
- **disecta** provides inspect and disasm commands plus an embedded loopback workbench. Both use the same library. The workbench uses plain HTML, CSS, and JavaScript with local assets.

## Image invariants

The PE address space is based on the preferred image base. RVAs are relative to that base. The ELF address space uses the original virtual addresses and load segments. File offsets are positions in the input. Zero-filled data and overlays have no corresponding mapped file byte. An address with conflicting file mappings produces an error.

The decoder accepts a section index, a start address, and an instruction count. A start address is a candidate boundary. A result includes original offsets, flow categories, the raw instruction encoding and typed operand descriptions. Unknown or incomplete encodings are explicit rows and carry no fabricated semantics.

The UI sends a chosen file to the running local process for each analysis request. It retains the current file, metadata and page in the browser tab. HTTP requests cannot supply disk paths. The engine analyzes bytes without executing them or resolving dependencies. File names and metadata are rendered as text.

## Function analysis

The analysis pass seeds entry candidates from the image entry, code symbols, executable exports and valid PE x64 runtime-function ranges. It then follows reachable fallthrough and directly encoded branches. A direct near call contributes a new candidate and an interprocedural edge. CFG traversal continues at the call's fallthrough as an explicit assumption. A call to its own next instruction does not seed another entry. Executable regions that overlap are excluded from recursive decoding because their instruction mapping is ambiguous.

The CFG separates block exits, recovered edges, direct call destinations and unresolved branches. The builder uses instruction boundaries found by the bounded walk, splits at branch destinations and continuations, and validates unique ordered blocks, edge endpoints, and root reachability. Other confirmed entries stop intraprocedural traversal. Usable metadata bounds constrain traversal when records agree. Disagreeing metadata bounds and overlapping recovered extents are reported. Unrecovered gaps can contain unvisited code or inline data and carry no reachability proof.

References are emitted only from recovered instructions. IP-relative operands point to encoded virtual locations. The address can identify a symbol, export, normal PE IAT slot, or an ELF `JUMP_SLOT`/`GLOB_DAT` dynamic relocation for an undefined symbol. The import pointer address and the indirect call target are separate facts. No dynamic relocations are applied.

## Analysis report format

- `functions --json` returns `schema`, `functions`, and `limited`. A function record includes its entry, names, confidence, evidence, declared extent, recovered extent and flags for uncertainty or limits.
- `cfg --json` uses a function record, ordered blocks, edges and unrecovered ranges. Each edge records the source block and machine instruction. `target` is an encoded address and can be present without a recovered `block`.
- `analyze --json` returns the function and reference inventories plus a map of import addresses to labels. The same recovered call sites power `calls --json`, and `xrefs --json` selects the incoming and outgoing relationships of an exact address.

All three reports carry schema version 1. Addresses use hexadecimal strings to preserve 64-bit precision. The local HTTP workbench serves these analyses directly from the library and retains results for the open file in memory.

## Next milestone

Use recovered blocks and their original instruction addresses as the input to typed IR. Start with widths, values, register slices, and explicit locations for memory and flags. Validate IR operands and terminators before exposing a lift command. Test integer register aliases and arithmetic flags independently against controlled x86-64 snippets. Only then extend lifting to branch predicates and stack operations and begin dominator and SSA work. Preserve explicit unsupported operations for every instruction outside the tested semantic subset.
