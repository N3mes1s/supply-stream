/*! YARA module that parses crates.io package archives.

This allows creating YARA rules based on crate metadata, build scripts,
entrypoints, and selected root-package file contents.
*/

use std::collections::{BTreeMap, BTreeSet};
use std::io::{Cursor, Read};

use flate2::read::GzDecoder;
use serde_json::Value;
use sha2::{Digest, Sha256};
use tar::Archive;

use crate::modules::prelude::*;
use crate::modules::protos::crate_mod::{
    Bin, Crate, Dependency, File as CrateFile,
};

const MAX_MANIFEST_TEXT_BYTES: usize = 512 * 1024;
const MAX_BUILD_SCRIPT_TEXT_BYTES: usize = 2 * 1024 * 1024;
const MAX_ENTRYPOINT_TEXT_BYTES: usize = 2 * 1024 * 1024;
const MODULE_ECOSYSTEM: &[u8] = b"crate";

#[derive(Debug, Clone)]
struct ArchiveFile {
    path: String,
    size_bytes: u64,
    sha256: String,
    text_content: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FileRole {
    Manifest,
    BuildScript,
    Entrypoint,
    Binary,
    Module,
}

impl FileRole {
    fn as_str(self) -> &'static str {
        match self {
            Self::Manifest => "manifest",
            Self::BuildScript => "build_script",
            Self::Entrypoint => "entrypoint",
            Self::Binary => "binary",
            Self::Module => "module",
        }
    }
}

#[derive(Default)]
struct ParsedCargoManifest {
    name: Option<String>,
    version: Option<String>,
    repository: Option<String>,
    dependencies: Vec<Dependency>,
    bins: Vec<ParsedBin>,
}

#[derive(Default, Clone)]
struct ParsedBin {
    name: Option<String>,
    path: Option<String>,
}

#[module_main]
fn main(data: &[u8], _meta: Option<&[u8]>) -> Result<Crate, ModuleError> {
    let mut module = Crate::new();
    module.set_is_crate(false);
    module.set_has_manifest(false);
    module.set_has_build_rs(false);
    module.set_has_bins(false);
    module.set_dependency_count(0);

    if let Some(meta) = _meta
        && meta != MODULE_ECOSYSTEM
    {
        return Ok(module);
    }

    let Some(entries) = extract_archive_entries(data) else {
        return Ok(module);
    };

    let Some(root_prefix) = select_root_prefix(&entries) else {
        return Ok(module);
    };

    let mut root_files = build_root_files(&entries, &root_prefix);
    let cargo_toml_path = root_files
        .keys()
        .find(|path| normalize_lookup(path) == "cargo.toml")
        .cloned();
    let Some(cargo_toml_path) = cargo_toml_path else {
        return Ok(module);
    };

    let build_rs_path = root_files
        .keys()
        .find(|path| normalize_lookup(path) == "build.rs")
        .cloned();
    let cargo_vcs_info_path = root_files
        .keys()
        .find(|path| normalize_lookup(path) == ".cargo_vcs_info.json")
        .cloned();

    module.set_is_crate(true);
    module.set_has_manifest(true);
    module.set_has_build_rs(build_rs_path.is_some());

    let mut parsed_manifest = ParsedCargoManifest::default();
    if let Some(content) = selected_text_content(&root_files, &cargo_toml_path) {
        module.set_cargo_toml_content(content.to_string());
        parsed_manifest = parse_cargo_toml(content);
    }

    if let Some(name) = parsed_manifest.name.as_ref() {
        module.set_name(name.to_ascii_lowercase());
    }
    if let Some(version) = parsed_manifest.version.as_ref() {
        module.set_version(version.clone());
    }
    if let Some(repository) = parsed_manifest.repository.as_ref() {
        module.set_repository(repository.clone());
    }

    parsed_manifest.dependencies.sort_by(|left, right| {
        left.name
            .cmp(&right.name)
            .then(left.section.cmp(&right.section))
            .then(left.spec.cmp(&right.spec))
    });
    parsed_manifest.dependencies.dedup_by(|left, right| {
        left.name == right.name && left.section == right.section && left.spec == right.spec
    });
    if !parsed_manifest.dependencies.is_empty() {
        module.set_dependency_count(parsed_manifest.dependencies.len() as i64);
        module.dependencies.extend(parsed_manifest.dependencies);
    }

    let mut entrypoint_paths = BTreeSet::new();
    if root_files.contains_key("src/main.rs") {
        entrypoint_paths.insert("src/main.rs".to_string());
    }
    if root_files.contains_key("src/lib.rs") {
        entrypoint_paths.insert("src/lib.rs".to_string());
    }
    for path in root_files
        .keys()
        .filter(|path| path.starts_with("src/bin/") && path.ends_with(".rs"))
    {
        entrypoint_paths.insert(path.clone());
    }

    let resolved_bins = collect_bins(
        &root_files,
        module.name.as_deref(),
        &parsed_manifest.bins,
        &entrypoint_paths,
    );
    module.set_has_bins(!resolved_bins.is_empty());
    for (_, path) in &resolved_bins {
        entrypoint_paths.insert(path.clone());
    }

    hydrate_selected_text_content(
        data,
        &root_prefix,
        &cargo_toml_path,
        build_rs_path.as_deref(),
        &entrypoint_paths,
        &mut root_files,
    );

    if let Some(path) = &build_rs_path
        && let Some(content) = selected_text_content(&root_files, path)
    {
        module.set_build_rs_content(content.to_string());
    }

    if let Some(path) = &cargo_vcs_info_path
        && let Some(content) = selected_text_content(&root_files, path)
        && let Some(sha) = parse_cargo_vcs_sha(content)
    {
        module.set_cargo_vcs_sha(sha);
    }

    for (name, path) in resolved_bins {
        let mut bin = Bin::new();
        bin.set_name(name);
        bin.set_path(path.clone());
        if let Some(content) = selected_text_content(&root_files, &path) {
            bin.set_content(content.to_string());
        }
        module.bins.push(bin);
    }

    for (path, file) in &root_files {
        let role = classify_file_role(path, path == &cargo_toml_path, build_rs_path.as_ref() == Some(path), &entrypoint_paths);
        let mut crate_file = CrateFile::new();
        crate_file.set_path(path.clone());
        crate_file.set_role(role.as_str().to_string());
        crate_file.set_is_root(true);
        crate_file.set_is_text(file.text_content.is_some());
        crate_file.set_size_bytes(file.size_bytes);
        crate_file.set_sha256(file.sha256.clone());
        if should_expose_file_content(role)
            && let Some(content) = &file.text_content
        {
            crate_file.set_content(content.clone());
        }
        module.files.push(crate_file);
    }

    Ok(module)
}

#[module_export(name = "depends_on")]
fn depends_on(ctx: &mut ScanContext, dependency: RuntimeString) -> Option<bool> {
    let dependency = dependency.to_str(ctx).ok()?.to_ascii_lowercase();
    let module = ctx.module_output::<Crate>()?;
    Some(
        module
            .dependencies
            .iter()
            .any(|dep| dep.name.as_deref() == Some(dependency.as_str())),
    )
}

#[module_export(name = "depends_on")]
fn depends_on_in_section(
    ctx: &mut ScanContext,
    dependency: RuntimeString,
    section: RuntimeString,
) -> Option<bool> {
    let dependency = dependency.to_str(ctx).ok()?.to_ascii_lowercase();
    let section = section.to_str(ctx).ok()?.to_ascii_lowercase();
    let module = ctx.module_output::<Crate>()?;
    Some(module.dependencies.iter().any(|dep| {
        dep.name.as_deref() == Some(dependency.as_str())
            && dep.section.as_deref() == Some(section.as_str())
    }))
}

#[module_export(name = "build_rs_contains")]
fn build_rs_contains(
    ctx: &mut ScanContext,
    needle: RuntimeString,
) -> Option<bool> {
    let needle = needle.to_str(ctx).ok()?.to_ascii_lowercase();
    let module = ctx.module_output::<Crate>()?;
    Some(
        module
            .build_rs_content
            .as_deref()
            .is_some_and(|value| contains_case_insensitive(value, &needle)),
    )
}

#[module_export(name = "has_bin")]
fn has_bin(ctx: &mut ScanContext, name: RuntimeString) -> Option<bool> {
    let name = name.to_str(ctx).ok()?.to_ascii_lowercase();
    let module = ctx.module_output::<Crate>()?;
    Some(
        module
            .bins
            .iter()
            .any(|bin| bin.name.as_deref() == Some(name.as_str())),
    )
}

#[module_export(name = "bin_contains")]
fn bin_contains(
    ctx: &mut ScanContext,
    name: RuntimeString,
    needle: RuntimeString,
) -> Option<bool> {
    let name = name.to_str(ctx).ok()?.to_ascii_lowercase();
    let needle = needle.to_str(ctx).ok()?.to_ascii_lowercase();
    let module = ctx.module_output::<Crate>()?;
    let bin = module
        .bins
        .iter()
        .find(|bin| bin.name.as_deref() == Some(name.as_str()))?;
    Some(
        bin.path
            .as_deref()
            .is_some_and(|value| contains_case_insensitive(value, &needle))
            || bin
                .content
                .as_deref()
                .is_some_and(|value| contains_case_insensitive(value, &needle)),
    )
}

#[module_export(name = "has_file")]
fn has_file(ctx: &mut ScanContext, path: RuntimeString) -> Option<bool> {
    let path = normalize_lookup(path.to_str(ctx).ok()?);
    let module = ctx.module_output::<Crate>()?;
    Some(find_file(module, &path).is_some())
}

#[module_export(name = "file_contains")]
fn file_contains(
    ctx: &mut ScanContext,
    path: RuntimeString,
    needle: RuntimeString,
) -> Option<bool> {
    let path = normalize_lookup(path.to_str(ctx).ok()?);
    let needle = needle.to_str(ctx).ok()?.to_ascii_lowercase();
    let module = ctx.module_output::<Crate>()?;
    let file = find_file(module, &path)?;
    Some(
        file.content
            .as_deref()
            .is_some_and(|content| contains_case_insensitive(content, &needle)),
    )
}

#[module_export(name = "any_file_contains")]
fn any_file_contains(
    ctx: &mut ScanContext,
    role: RuntimeString,
    needle: RuntimeString,
) -> Option<bool> {
    let role = role.to_str(ctx).ok()?.to_ascii_lowercase();
    let needle = needle.to_str(ctx).ok()?.to_ascii_lowercase();
    let module = ctx.module_output::<Crate>()?;
    Some(module.files.iter().any(|file| {
        file.role.as_deref() == Some(role.as_str())
            && file
                .content
                .as_deref()
                .is_some_and(|content| contains_case_insensitive(content, &needle))
    }))
}

#[module_export(name = "file_count")]
fn file_count(ctx: &mut ScanContext, role: RuntimeString) -> Option<i64> {
    let role = role.to_str(ctx).ok()?.to_ascii_lowercase();
    let module = ctx.module_output::<Crate>()?;
    Some(
        module
            .files
            .iter()
            .filter(|file| file.role.as_deref() == Some(role.as_str()))
            .count() as i64,
    )
}

fn extract_archive_entries(data: &[u8]) -> Option<BTreeMap<String, ArchiveFile>> {
    let decoder = GzDecoder::new(Cursor::new(data));
    let mut archive = Archive::new(decoder);
    let mut files = BTreeMap::new();

    let entries = archive.entries().ok()?;
    for entry in entries {
        let mut entry = entry.ok()?;
        if !entry.header().entry_type().is_file() {
            continue;
        }
        let path = normalize_path(&entry.path().ok()?.to_string_lossy());
        let mut bytes = Vec::new();
        if entry.read_to_end(&mut bytes).is_err() {
            return None;
        }
        let sha256 = format!("{:x}", Sha256::digest(&bytes));
        let text_content =
            if should_buffer_manifest_text(&path, bytes.len()) && looks_like_text(&bytes) {
                String::from_utf8(bytes.clone()).ok()
            } else {
                None
            };
        files.insert(
            path.clone(),
            ArchiveFile {
                path,
                size_bytes: bytes.len() as u64,
                sha256,
                text_content,
            },
        );
    }

    Some(files)
}

fn should_buffer_manifest_text(path: &str, len: usize) -> bool {
    len <= MAX_MANIFEST_TEXT_BYTES && is_manifest_candidate(path)
}

fn select_root_prefix(entries: &BTreeMap<String, ArchiveFile>) -> Option<String> {
    entries
        .keys()
        .filter(|path| normalize_lookup(path).ends_with("/cargo.toml") || normalize_lookup(path) == "cargo.toml")
        .min_by_key(|path| (path_depth(path), path.as_str()))
        .map(|path| root_prefix_for_path(path))
}

fn root_prefix_for_path(path: &str) -> String {
    match path.rsplit_once('/') {
        Some((prefix, _)) => format!("{prefix}/"),
        None => String::new(),
    }
}

fn build_root_files(
    entries: &BTreeMap<String, ArchiveFile>,
    root_prefix: &str,
) -> BTreeMap<String, ArchiveFile> {
    entries
        .iter()
        .filter_map(|(archive_path, file)| {
            let relative = if root_prefix.is_empty() {
                archive_path.as_str()
            } else {
                archive_path.strip_prefix(root_prefix)?
            };
            if relative.is_empty() {
                return None;
            }

            let mut file = file.clone();
            file.path = relative.to_string();
            Some((relative.to_string(), file))
        })
        .collect()
}

fn parse_cargo_toml(content: &str) -> ParsedCargoManifest {
    let mut parsed = ParsedCargoManifest::default();
    let mut section = String::new();
    let mut current_bin = ParsedBin::default();
    let mut in_bin_section = false;

    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        if trimmed.starts_with("[[") && trimmed.ends_with("]]") {
            if in_bin_section && (current_bin.name.is_some() || current_bin.path.is_some()) {
                parsed.bins.push(current_bin.clone());
                current_bin = ParsedBin::default();
            }
            section = trimmed.trim_matches(&['[', ']'][..]).to_ascii_lowercase();
            in_bin_section = section == "bin";
            continue;
        }
        if trimmed.starts_with('[') && trimmed.ends_with(']') {
            if in_bin_section && (current_bin.name.is_some() || current_bin.path.is_some()) {
                parsed.bins.push(current_bin.clone());
                current_bin = ParsedBin::default();
            }
            section = trimmed.trim_matches(&['[', ']'][..]).to_ascii_lowercase();
            in_bin_section = false;
            continue;
        }

        if section == "package" {
            if let Some(value) = toml_string_value(trimmed, "name") {
                parsed.name = Some(value);
            } else if let Some(value) = toml_string_value(trimmed, "version") {
                parsed.version = Some(value);
            } else if let Some(value) = toml_string_value(trimmed, "repository") {
                parsed.repository = Some(value);
            }
        } else if in_bin_section {
            if let Some(value) = toml_string_value(trimmed, "name") {
                current_bin.name = Some(value);
            } else if let Some(value) = toml_string_value(trimmed, "path") {
                current_bin.path = Some(value);
            }
        } else if is_dependency_section(&section)
            && let Some((name, spec)) = dependency_entry(trimmed)
        {
            let mut dependency = Dependency::new();
            dependency.set_name(name);
            dependency.set_section(section.clone());
            dependency.set_spec(spec);
            parsed.dependencies.push(dependency);
        }
    }

    if in_bin_section && (current_bin.name.is_some() || current_bin.path.is_some()) {
        parsed.bins.push(current_bin);
    }

    parsed
}

fn hydrate_selected_text_content(
    data: &[u8],
    root_prefix: &str,
    cargo_toml_path: &str,
    build_rs_path: Option<&str>,
    entrypoint_paths: &BTreeSet<String>,
    root_files: &mut BTreeMap<String, ArchiveFile>,
) {
    let decoder = GzDecoder::new(Cursor::new(data));
    let mut archive = Archive::new(decoder);
    let Ok(entries) = archive.entries() else {
        return;
    };

    for entry in entries {
        let Ok(mut entry) = entry else {
            return;
        };
        if !entry.header().entry_type().is_file() {
            continue;
        }
        let Ok(path) = entry.path() else {
            return;
        };
        let archive_path = normalize_path(&path.to_string_lossy());
        let relative = if root_prefix.is_empty() {
            archive_path.as_str()
        } else {
            let Some(relative) = archive_path.strip_prefix(root_prefix) else {
                continue;
            };
            relative
        };
        let Some(file) = root_files.get_mut(relative) else {
            continue;
        };
        if file.text_content.is_some() {
            continue;
        }
        let role = classify_file_role(
            relative,
            relative == cargo_toml_path,
            build_rs_path == Some(relative),
            entrypoint_paths,
        );
        let Some(limit) = selected_text_limit(role) else {
            continue;
        };
        if file.size_bytes as usize > limit {
            continue;
        }
        let mut bytes = Vec::new();
        if entry.read_to_end(&mut bytes).is_err() || !looks_like_text(&bytes) {
            continue;
        }
        file.text_content = String::from_utf8(bytes).ok();
    }
}

fn collect_bins(
    root_files: &BTreeMap<String, ArchiveFile>,
    package_name: Option<&str>,
    parsed_bins: &[ParsedBin],
    entrypoint_paths: &BTreeSet<String>,
) -> Vec<(String, String)> {
    let mut bins = BTreeMap::new();

    if root_files.contains_key("src/main.rs")
        && let Some(package_name) = package_name
    {
        bins.insert(package_name.to_string(), "src/main.rs".to_string());
    }

    for path in entrypoint_paths
        .iter()
        .filter(|path| path.starts_with("src/bin/") && path.ends_with(".rs"))
    {
        if let Some(stem) = std::path::Path::new(path)
            .file_stem()
            .and_then(|value| value.to_str())
        {
            bins.insert(stem.to_ascii_lowercase(), path.clone());
        }
    }

    for parsed in parsed_bins {
        let resolved_path = parsed
            .path
            .as_ref()
            .and_then(|path| resolve_relative_file(path, root_files))
            .or_else(|| {
                parsed.name.as_ref().and_then(|name| {
                    let candidate = format!("src/bin/{name}.rs");
                    root_files.contains_key(&candidate).then_some(candidate)
                })
            });
        let Some(path) = resolved_path else {
            continue;
        };
        let name = parsed
            .name
            .clone()
            .or_else(|| {
                std::path::Path::new(&path)
                    .file_stem()
                    .and_then(|value| value.to_str())
                    .map(str::to_string)
            })
            .unwrap_or_else(|| path.clone());
        bins.insert(name.to_ascii_lowercase(), path);
    }

    bins.into_iter().collect()
}

fn parse_cargo_vcs_sha(content: &str) -> Option<String> {
    let parsed = serde_json::from_str::<Value>(content).ok()?;
    parsed
        .pointer("/git/sha1")
        .and_then(Value::as_str)
        .map(|value| value.to_ascii_lowercase())
}

fn classify_file_role(
    path: &str,
    is_manifest: bool,
    is_build_script: bool,
    entrypoint_paths: &BTreeSet<String>,
) -> FileRole {
    if is_manifest {
        return FileRole::Manifest;
    }
    if is_build_script {
        return FileRole::BuildScript;
    }
    if entrypoint_paths.contains(path) {
        return FileRole::Entrypoint;
    }
    if is_binary_path(path) {
        return FileRole::Binary;
    }
    FileRole::Module
}

fn is_manifest_candidate(path: &str) -> bool {
    let lower = normalize_lookup(path);
    lower == "cargo.toml"
        || lower.ends_with("/cargo.toml")
        || lower == ".cargo_vcs_info.json"
        || lower.ends_with("/.cargo_vcs_info.json")
}

fn selected_text_limit(role: FileRole) -> Option<usize> {
    match role {
        FileRole::Manifest => Some(MAX_MANIFEST_TEXT_BYTES),
        FileRole::BuildScript => Some(MAX_BUILD_SCRIPT_TEXT_BYTES),
        FileRole::Entrypoint => Some(MAX_ENTRYPOINT_TEXT_BYTES),
        _ => None,
    }
}

fn should_expose_file_content(role: FileRole) -> bool {
    matches!(role, FileRole::Manifest | FileRole::BuildScript | FileRole::Entrypoint)
}

fn selected_text_content<'a>(
    files: &'a BTreeMap<String, ArchiveFile>,
    path: &str,
) -> Option<&'a str> {
    files.get(path).and_then(|file| file.text_content.as_deref())
}

fn resolve_relative_file(
    path: &str,
    root_files: &BTreeMap<String, ArchiveFile>,
) -> Option<String> {
    let normalized = normalize_path(path);
    let direct = normalize_lookup(&normalized);
    root_files
        .keys()
        .find(|candidate| normalize_lookup(candidate) == direct)
        .cloned()
}

fn toml_string_value(line: &str, key: &str) -> Option<String> {
    let (left, right) = line.split_once('=')?;
    if left.trim() != key {
        return None;
    }
    let value = right.trim().trim_matches(|ch| matches!(ch, '"' | '\''));
    if value.is_empty() {
        None
    } else {
        Some(value.to_string())
    }
}

fn is_dependency_section(section: &str) -> bool {
    section == "dependencies"
        || section == "build-dependencies"
        || section == "dev-dependencies"
        || section.ends_with(".dependencies")
        || section.ends_with(".build-dependencies")
        || section.ends_with(".dev-dependencies")
}

fn dependency_entry(line: &str) -> Option<(String, String)> {
    let (left, right) = line.split_once('=')?;
    let name = left.trim();
    if name.is_empty() {
        return None;
    }
    Some((name.to_ascii_lowercase(), right.trim().to_string()))
}

fn normalize_path(path: &str) -> String {
    path.trim_start_matches("./").replace('\\', "/")
}

fn normalize_lookup(path: &str) -> String {
    normalize_path(path).to_ascii_lowercase()
}

fn path_depth(path: &str) -> usize {
    path.split('/').count()
}

fn is_binary_path(path: &str) -> bool {
    let lower = path.to_ascii_lowercase();
    [".so", ".dll", ".dylib", ".exe"]
        .iter()
        .any(|suffix| lower.ends_with(suffix))
}

fn looks_like_text(bytes: &[u8]) -> bool {
    if bytes.is_empty() {
        return true;
    }
    !bytes.contains(&0) && std::str::from_utf8(bytes).is_ok()
}

fn contains_case_insensitive(haystack: &str, needle: &str) -> bool {
    haystack.to_ascii_lowercase().contains(needle)
}

fn find_file<'a>(module: &'a Crate, path: &str) -> Option<&'a CrateFile> {
    module
        .files
        .iter()
        .find(|file| file.path.as_deref().is_some_and(|value| normalize_lookup(value) == path))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tests::{rule_false, rule_true, test_rule};
    use flate2::{Compression, write::GzEncoder};
    use std::io::Write;
    use tar::{Builder, Header};

    #[test]
    fn parses_crate_manifest_build_rs_and_bins() {
        let bytes = build_crate(&[
            (
                "demo-1.0.0/Cargo.toml",
                "[package]\nname = \"demo\"\nversion = \"1.0.0\"\nrepository = \"https://github.com/example/demo\"\n\n[dependencies]\nreqwest = \"0.12\"\n\n[build-dependencies]\ncc = \"1\"\n\n[[bin]]\nname = \"helper\"\npath = \"src/bin/helper.rs\"\n",
            ),
            (
                "demo-1.0.0/build.rs",
                "fn main() { println!(\"cargo:rerun-if-changed=build.rs\"); let _ = \"https://example.com\"; }",
            ),
            ("demo-1.0.0/src/main.rs", "fn main() { println!(\"demo\"); }"),
            ("demo-1.0.0/src/bin/helper.rs", "fn main() { println!(\"helper\"); }"),
            (
                "demo-1.0.0/.cargo_vcs_info.json",
                "{\"git\":{\"sha1\":\"5869fde797bb2bfa6686fabdf8437f0e4d130b9c\"}}",
            ),
            (
                "demo-1.0.0/vendor/evil/Cargo.toml",
                "[package]\nname = \"evil\"\nversion = \"9.9.9\"\n",
            ),
        ]);

        let module = main(&bytes, None).expect("parse crate");
        assert!(module.is_crate());
        assert!(module.has_manifest());
        assert!(module.has_build_rs());
        assert_eq!(module.name.as_deref(), Some("demo"));
        assert_eq!(module.version.as_deref(), Some("1.0.0"));
        assert_eq!(
            module.cargo_vcs_sha.as_deref(),
            Some("5869fde797bb2bfa6686fabdf8437f0e4d130b9c")
        );
        assert!(module
            .files
            .iter()
            .any(|file| file.path.as_deref() == Some("build.rs")
                && file.role.as_deref() == Some("build_script")
                && file
                    .content
                    .as_deref()
                    .is_some_and(|content| content.contains("https://example.com"))));

        rule_true!(
            r#"
            import "crate"
            rule test {
              condition:
                crate.is_crate and
                crate.has_build_rs and
                crate.name == "demo" and
                crate.version == "1.0.0" and
                crate.depends_on("reqwest") and
                crate.depends_on("cc", "build-dependencies") and
                crate.build_rs_contains("https://example.com") and
                crate.has_bin("demo") and
                crate.has_bin("helper") and
                crate.bin_contains("helper", "println!(\"helper\")")
            }
            "#,
            &bytes
        );
    }

    #[test]
    fn does_not_expose_large_non_selected_module_content() {
        let large_module = "pub fn helper() {}\n".repeat(150_000);
        let bytes = build_crate(&[
            (
                "demo-1.0.0/Cargo.toml",
                "[package]\nname = \"demo\"\nversion = \"1.0.0\"\n",
            ),
            ("demo-1.0.0/src/main.rs", "fn main() { println!(\"demo\"); }"),
            ("demo-1.0.0/src/huge.rs", large_module.as_str()),
        ]);

        rule_false!(
            r#"
            import "crate"
            rule test {
              condition:
                crate.file_contains("src/huge.rs", "pub fn helper")
            }
            "#,
            &bytes
        );
    }

    fn build_crate(files: &[(&str, &str)]) -> Vec<u8> {
        let mut tar_data = Vec::new();
        {
            let mut builder = Builder::new(&mut tar_data);
            for (path, content) in files {
                let bytes = content.as_bytes();
                let mut header = Header::new_gnu();
                header.set_entry_type(tar::EntryType::Regular);
                header.set_mode(0o644);
                header.set_size(bytes.len() as u64);
                header.set_cksum();
                builder
                    .append_data(&mut header, *path, Cursor::new(bytes))
                    .expect("append file to crate archive");
            }
            builder.finish().expect("finish crate tar");
        }

        let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(&tar_data).expect("write tar data");
        encoder.finish().expect("finish crate gzip")
    }
}
