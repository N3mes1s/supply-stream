# RFD 0002: YARA-X Package Modules

- Status: Accepted
- Date: 2026-04-01

## Summary

`supply-stream` uses YARA-X for content-risk scanning.

For package ecosystems, the package-format authority is the YARA-X module, not
`supply-stream`.

That means:
- `import "npm"` parses npm tarballs
- `import "pypi"` parses wheels and sdists
- `import "crate"` parses `.crate` archives
- rules match against module fields and exported helper functions

`supply-stream` is only responsible for:
- passing the raw artifact bytes to YARA-X
- hot-reloading `.yar` rule files at runtime
- persisting matches, score, IOCs, and assessment inputs

## Problem

The initial content-risk implementation started drifting into product-side
package parsing and path heuristics.

That is the wrong split.

It creates two competing sources of truth:
- a generic product scanner guessing which files matter
- a package-format-aware YARA module trying to do the same job

That is exactly what the `pe` model avoids.

## Decision

### 1. Package-format parsing lives in YARA-X modules

For a supported ecosystem, the module must:
- parse the artifact format
- identify the canonical root package
- expose structured package metadata
- expose selected file contents for semantically important files
- export helper functions for rules

Examples:
- `npm.depends_on("koffi")`
- `npm.has_script("postinstall")`
- `npm.script_contains("postinstall", "FIXED_GATEWAY_TOKEN")`
- `npm.any_file_contains("entrypoint", "ws://")`

### 2. `supply-stream` does not re-implement package semantics

For ecosystems with a first-class module:
- do not hardcode manifest paths in `content_risk`
- do not guess install-script files in `content_risk`
- do not decide root-package ownership in `content_risk`

If content-risk rules need that information, it must come from the module.

### 3. Runtime rule reload and module rebuild are different things

`.yar` rule files are runtime data and may hot-reload.

Module Rust code is compile-time engine code.

Therefore:
- editing rule files should not require rebuilding the binary
- editing module code does require rebuilding the YARA-X build used by the product

This distinction must stay explicit in code comments and operator docs.

### 4. Source-of-truth order

For content-risk decisions:
1. YARA-X module output
2. YARA rule matches over that module output
3. `supply-stream` assessment fusion

Not the reverse.

## Operating Model

Current path:
- npm is the first ecosystem moving to a module-first archive scan
- PyPI and crates may temporarily use generic extracted-file scanning until
  their modules exist

Target path:
- `npm`, `pypi`, and `crate` all behave like `pe`
- `content_risk` becomes an ecosystem-agnostic YARA runner and persistence layer

## Consequences

Good:
- rules stay portable and package-aware
- false positives from product-side path guessing go down
- malware-family rules become easier to express and reuse

Bad:
- module changes require a custom YARA-X build step
- adding a new ecosystem module is a compile-time extension project, not only a rule-writing task

## Immediate Work From This RFD

1. Keep npm archive scanning module-first.
2. Remove npm path heuristics from `content_risk`.
3. Add regression tests that prove root-package parsing ignores vendored manifest noise.
4. Add first-class `pypi` and `crate` modules next.
