# Benchmark methodology

Start with executable inspection and instruction decoding. Record the target triple, Rust version, Cargo.lock hash, source and input hashes, compiler versions and flags, OS, processor and memory. Build DISECTA in release mode with the lockfile. Report input size, instruction count and whether the run includes file I/O or JSON serialization.

Compile identical small, independently authored C programs with GCC and Clang at -O0 through -O3. Add MSVC at /Od, /O1 and /O2 where available. Retain unstripped images and linker maps as ground truth, plus independently stripped copies as inputs. Record inlining and identical-code folding in the ground truth. Measure repeated runs after a documented warm-up and report median, tail latency and peak RSS or working set.

Once function discovery ships, compare recovered entries against compiler/linker metadata and report precision and recall. For matching, label counterparts by source identity and build metadata, including many-to-one cases. Record top-1 accuracy and ambiguous outcomes. Once lifting and verification ship, report coverage, unsupported cases, solver timeouts and false equivalence against controlled ground truth.

This document defines the measurement procedure. No benchmark numbers have been published.
