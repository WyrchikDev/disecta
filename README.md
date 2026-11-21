# DISECTA

DISECTA inspects x86-64 executables and decodes their machine instructions. It ships a Rust library, a command-line tool, and a local browser workbench.

| Capability | Current support |
| --- | --- |
| Executable images | Little-endian x86-64 PE32+ and ELF64 executables and shared libraries |
| Image inspection | Entry point, image base, section ranges and permissions, embedded symbols, imports and exports |
| Address resolution | Original virtual addresses to file-backed offsets, including ELF load segments |
| Disassembly | Intel syntax, encoded bytes, operands, invalid instructions, near branch and call targets |
| Function discovery | Image entry points, embedded code symbols, executable exports, PE x64 runtime ranges, and direct calls from recovered code |
| Control flow | Recursive decoding from a selected entry, basic blocks, branches, calls, returns, explicit unresolved edges, JSON and DOT |
| References and calls | Direct calls and branches, IP-relative operands, named PE IAT and selected ELF dynamic import slots |
| Workbench | Searchable function list, interactive CFG, caller/callee graph, bidirectional cross-references, address navigation and JSON export |

## Build

Install stable Rust and a native linker. The default Windows MSVC target needs the C++ Build Tools. On Linux, install your distribution's build toolchain.

```sh
cargo build --workspace --release --locked
```

The executable is `target/release/disecta` (`disecta.exe` on Windows). From the checkout, these examples use Cargo so that its location is platform-independent.

```sh
cargo run -- inspect tests/fixtures/branch.exe
cargo run -- inspect tests/fixtures/branch.elf --json
cargo run -- disasm tests/fixtures/branch.exe --start 0x140001000 --count 24
cargo run -- functions tests/fixtures/branch.exe --json
cargo run -- cfg tests/fixtures/branch.exe --function 0x140001000 --format dot
cargo run -- calls tests/fixtures/branch.exe --function 0x140001024
cargo run -- xrefs tests/fixtures/branch.exe --address 0x140002000
cargo run -- analyze tests/fixtures/branch.elf --json
cargo run -- gui
```

For the workbench, open the loopback URL printed by `gui`. Select **Open binary** or **Open example**. Use **Go to address** (or `g`) to enter a virtual address. Select an instruction to inspect its operands or follow a direct branch. The server processes uploads in memory and requires the local workbench as the browser origin. Press Ctrl+C in the terminal to stop it.

Open **Functions** to filter by name, address, or confidence. Select an entry to pan and zoom its CFG, inspect individual instructions, or jump back to assembly. **Calls** can show a one-hop caller/callee graph when filtered to a specific function. **References** lists incoming and outgoing references at an exact address. The right panel reports the evidence for the selected function and the reasons for unresolved edges.

## Limits and output

The defaults are 64 MiB per file, 100,000 metadata records, a conservative 4 MiB name budget, 100,000 decoded instructions per CLI page, and five seconds per parse or disassembly. CLI flags cover file size, metadata records, time, and page length. The time budget is cooperative. The embedded GUI uses 256 instructions per page.

Recursive analysis uses the same time and global instruction limits plus a configurable 4,096-function limit and 4,096 instructions per function. Use `--max-functions` and `--max-function-instructions` to tune those bounds. A report marks partial analysis when traversal hits a budget.

`--json` emits hexadecimal strings for virtual addresses to preserve 64-bit precision. File offsets are byte counts. Errors go to stderr. Exit codes are 0 (success), 1 (I/O or output), 2 (argument parsing), 3 (binary or address error), and 4 (resource limit).

The disassembly listing is a linear sweep. The CFG only visits entry-reachable instructions in its supported control-flow model. Indirect jumps, exception handlers and jump tables can leave paths unrecovered. Gaps inside declared extents remain byte ranges when there is insufficient code evidence. Relocations stay unapplied. Import labels identify pointer slots when supported. A slot name does not resolve an indirect runtime transfer. Separate debug data, semantic IR, decompilation, binary matching and equivalence verification are later milestones.

## Verify

```sh
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --locked
cargo build --workspace --release --locked
```

The checked-in PE32+ and ELF64 fixtures regenerate with `python tests/fixtures/generate.py`. The tests read their bytes without executing either image.

For a second check with compiler-produced inputs, build `tests/fixtures/linked.c` as a PE DLL with `clang -shared -O2` under MinGW and as an ELF shared object with `clang -shared -fPIC -nostdlib -O2` on Linux. Pass the release executable and compiled files to `python tests/fixtures/check_linked.py` to verify function recovery, CFG construction, and references to the platform-specific import.

With Python Playwright and Chromium installed, run `python tests/workbench/test_phase_a.py target/release/disecta` to verify graph navigation, the function filters, call routes and reference search. On Windows append `.exe` to the executable path.

See [architecture](ARCHITECTURE.md), [contributing](CONTRIBUTING.md), [security](SECURITY.md), and the [benchmark methodology](benchmarks/README.md). DISECTA is distributed under the [MIT License](LICENSE).
