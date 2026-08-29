# Vendored yara-x

Fork of [VirusTotal/yara-x](https://github.com/VirusTotal/yara-x) at **v1.14.0**
(BSD-3-Clause), vendored without git history. Consumed by
`crates/supply-stream-core` as a path dependency (`vendor/yara-x/lib`) and
excluded from the workspace in the root `Cargo.toml`.

## Local modifications vs upstream

- **Custom package-format modules** (see `rfd/0002-yara-x-package-modules.md`):
  - `lib/src/modules/npm.rs` — feature `npm-module`
  - `lib/src/modules/pypi.rs` — feature `pypi-module`
  - `lib/src/modules/crate_mod.rs` — feature `crate-module`
  - plus their protos in `lib/src/modules/protos/{npm,pypi,crate_mod}.proto`
    and pre-generated code in `lib/src/modules/protos/generated/`.
  - None are in `default-modules`; they must be enabled explicitly (the core
    crate does).
- **Workspace trimmed**: upstream's `cli`, `capi`, `py`, `go`, and `fmt`
  crates were dropped; only `lib`, `macros`, `parser`, `proto`, `proto-json`,
  `proto-yaml` remain.

## What is not committed

`lib/src/modules/**/*.zip` and `lib/src/modules/**/*.out` (~48MB) are
gitignored. These are upstream's module test corpora — real PE/Mach-O/.NET
malware samples and golden outputs — and upstream excludes exactly these
patterns from its published crate, so `cargo build` does not need them.
Consequence: `cargo test -p yara-x` fails for the pe/macho/dotnet/elf/crx/
lnk/dex/cuckoo modules (missing test files). The custom npm/pypi/crate
modules keep their tests, which use inline in-memory fixtures.

## Build caveat

`lib/build.rs` rewrites `src/modules/modules.rs`, `src/modules/add_modules.rs`,
and `src/modules/protos/generated/*.rs` in the source tree on every build, so
those tracked files may show as dirty after building. Set
`YRX_REGENERATE_MODULES_RS=false` to suppress the module-list regeneration.
