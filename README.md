# DISECTA

DISECTA inspects x86-64 executables and decodes their machine instructions. It ships a Rust library, a command-line tool, and a local browser workbench.

| Capability | Current support |
| --- | --- |
| Executable images | Little-endian x86-64 PE32+ and ELF64 executables and shared libraries |
| Image inspection | Entry point, image base, section ranges and permissions, embedded symbols, imports and exports |
| Address resolution | Original virtual addresses to file-backed offsets, including ELF load segments |
| Disassembly | Intel syntax, encoded bytes, operands, invalid instructions, near branch and call targets |
| Workbench | Section browsing, symbol and import/export tables, address and branch navigation, JSON export |

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
cargo run -- gui
```

For the workbench, open the loopback URL printed by `gui`. Select **Open binary** or **Open example**. Use **Go to address** (or `g`) to enter a virtual address. Select an instruction to inspect its operands or follow a direct branch. The server processes uploads in memory and requires the local workbench as the browser origin. Press Ctrl+C in the terminal to stop it.

## Limits and output

The defaults are 64 MiB per file, 100,000 metadata records, a conservative 4 MiB name budget, 100,000 decoded instructions per CLI page, and five seconds per parse or disassembly. CLI flags cover file size, metadata records, time, and page length. The time budget is cooperative. The embedded GUI uses 256 instructions per page.

`--json` emits hexadecimal strings for virtual addresses to preserve 64-bit precision. File offsets are byte counts. Errors go to stderr. Exit codes are 0 (success), 1 (I/O or output), 2 (argument parsing), 3 (binary or address error), and 4 (resource limit).

The listing is a linear sweep. Data embedded in code sections can decode to valid-looking instructions. Relocations stay unapplied. PE import/export coverage follows the parser's supported entries, and ELF names come from embedded symbol tables. Separate debug data, function discovery, control-flow graphs, IR, binary matching and equivalence verification are future milestones.

## Verify

```sh
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --locked
cargo build --workspace --release --locked
```

The checked-in PE32+ and ELF64 fixtures regenerate with `python tests/fixtures/generate.py`. The tests read their bytes without executing either image.

For a second check with compiler-produced inputs, build `tests/fixtures/linked.c` as a PE DLL with `clang -shared -O2` under MinGW and as an ELF shared object with `clang -shared -fPIC -nostdlib -O2` on Linux. Run `inspect --json` on both outputs and check for the exported `fixture_adjust` and the platform-specific import.

See [architecture](ARCHITECTURE.md), [contributing](CONTRIBUTING.md), [security](SECURITY.md), and the [benchmark methodology](benchmarks/README.md). DISECTA is distributed under the [MIT License](LICENSE).
