/*! YARA module that parses PyPI wheel and sdist package artifacts.

This allows creating YARA rules based on PyPI package metadata, build hooks,
console scripts, and selected root-package file contents.
*/

use std::collections::{BTreeMap, BTreeSet};
use std::io::{Cursor, Read};

use flate2::read::GzDecoder;
use sha2::{Digest, Sha256};
use tar::Archive;
use zip::ZipArchive;

use crate::modules::prelude::*;
use crate::modules::protos::pypi::{
    ConsoleScript, Dependency, File as PypiFile, Pypi,
};

const MAX_MANIFEST_TEXT_BYTES: usize = 512 * 1024;
const MAX_BUILD_SCRIPT_TEXT_BYTES: usize = 2 * 1024 * 1024;
const MAX_ENTRYPOINT_TEXT_BYTES: usize = 2 * 1024 * 1024;
const MODULE_ECOSYSTEM: &[u8] = b"pypi";

#[derive(Debug, Clone)]
struct ArchiveFile {
    path: String,
    size_bytes: u64,
    sha256: String,
    text_content: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ArtifactKind {
    WheelZip,
    SdistTarGz,
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

#[module_main]
fn main(data: &[u8], _meta: Option<&[u8]>) -> Result<Pypi, ModuleError> {
    let mut pypi = Pypi::new();
    pypi.set_is_pypi(false);
    pypi.set_is_wheel(false);
    pypi.set_is_sdist(false);
    pypi.set_has_pyproject(false);
    pypi.set_has_setup_py(false);
    pypi.set_has_setup_cfg(false);
    pypi.set_has_console_scripts(false);
    pypi.set_dependency_count(0);

    if let Some(meta) = _meta
        && meta != MODULE_ECOSYSTEM
    {
        return Ok(pypi);
    }

    let Some((kind, entries)) = extract_archive_entries(data) else {
        return Ok(pypi);
    };

    let (root_prefix, mut root_files) = match kind {
        ArtifactKind::WheelZip => (String::new(), entries),
        ArtifactKind::SdistTarGz => {
            let root_prefix = select_sdist_root_prefix(&entries).unwrap_or_default();
            let files = build_root_files(&entries, &root_prefix);
            (root_prefix, files)
        }
    };

    pypi.set_is_pypi(true);
    pypi.set_is_wheel(kind == ArtifactKind::WheelZip);
    pypi.set_is_sdist(kind == ArtifactKind::SdistTarGz);

    let pyproject_path = root_files
        .keys()
        .find(|path| normalize_lookup(path) == "pyproject.toml")
        .cloned();
    let setup_py_path = root_files
        .keys()
        .find(|path| normalize_lookup(path) == "setup.py")
        .cloned();
    let setup_cfg_path = root_files
        .keys()
        .find(|path| normalize_lookup(path) == "setup.cfg")
        .cloned();
    let metadata_path = select_metadata_path(&root_files);
    let entry_points_path = select_entry_points_path(&root_files);

    pypi.set_has_pyproject(pyproject_path.is_some());
    pypi.set_has_setup_py(setup_py_path.is_some());
    pypi.set_has_setup_cfg(setup_cfg_path.is_some());

    let mut name = None::<String>;
    let mut version = None::<String>;
    let mut build_backend = None::<String>;
    let mut dependencies = Vec::<Dependency>::new();

    if let Some(path) = &metadata_path
        && let Some(content) = selected_text_content(&root_files, path)
    {
        pypi.set_metadata_content(content.to_string());
        let parsed = parse_metadata(content);
        name = parsed.name;
        version = parsed.version;
        dependencies = parsed.dependencies;
    }

    if let Some(path) = &pyproject_path
        && let Some(content) = selected_text_content(&root_files, path)
    {
        pypi.set_pyproject_content(content.to_string());
        let parsed = parse_pyproject(content);
        if name.is_none() {
            name = parsed.name;
        }
        if version.is_none() {
            version = parsed.version;
        }
        if build_backend.is_none() {
            build_backend = parsed.build_backend;
        }
        merge_dependencies(&mut dependencies, parsed.dependencies);
    }

    if let Some(path) = &setup_cfg_path
        && let Some(content) = selected_text_content(&root_files, path)
    {
        let parsed = parse_setup_cfg(content);
        if name.is_none() {
            name = parsed.name;
        }
        if version.is_none() {
            version = parsed.version;
        }
    }

    if let Some(path) = &setup_py_path
        && let Some(content) = selected_text_content(&root_files, path)
    {
        pypi.set_setup_py_content(content.to_string());
        let parsed = parse_setup_py(content);
        if name.is_none() {
            name = parsed.name;
        }
        if version.is_none() {
            version = parsed.version;
        }
    }

    if let Some(name) = name {
        pypi.set_name(name.to_ascii_lowercase());
    }
    if let Some(version) = version {
        pypi.set_version(version);
    }
    if let Some(build_backend) = build_backend {
        pypi.set_build_backend(build_backend.to_ascii_lowercase());
    }

    let mut console_scripts = Vec::<(String, String, Option<String>)>::new();
    if let Some(path) = &entry_points_path
        && let Some(content) = selected_text_content(&root_files, path)
    {
        pypi.set_entry_points_content(content.to_string());
        console_scripts = parse_entry_points(content)
            .into_iter()
            .map(|(name, target)| {
                let module_path = resolve_python_module_target(&target, &root_files);
                (name, target, module_path)
            })
            .collect();
    }
    pypi.set_has_console_scripts(!console_scripts.is_empty());

    let build_script_paths = setup_py_path
        .clone()
        .into_iter()
        .collect::<BTreeSet<_>>();
    let mut entrypoint_paths = console_scripts
        .iter()
        .filter_map(|(_, _, module_path)| module_path.clone())
        .collect::<BTreeSet<_>>();
    for path in root_files.keys().filter(|path| {
        path.ends_with("/__main__.py")
            || path.as_str() == "__main__.py"
            || path.starts_with("bin/")
            || path.starts_with("scripts/")
    }) {
        entrypoint_paths.insert(path.clone());
    }

    hydrate_selected_text_content(
        kind,
        data,
        &root_prefix,
        &metadata_path,
        &pyproject_path,
        &setup_py_path,
        &setup_cfg_path,
        &entry_points_path,
        &build_script_paths,
        &entrypoint_paths,
        &mut root_files,
    );

    if let Some(path) = &metadata_path
        && pypi.metadata_content.is_none()
        && let Some(content) = selected_text_content(&root_files, path)
    {
        pypi.set_metadata_content(content.to_string());
    }
    if let Some(path) = &pyproject_path
        && pypi.pyproject_content.is_none()
        && let Some(content) = selected_text_content(&root_files, path)
    {
        pypi.set_pyproject_content(content.to_string());
    }
    if let Some(path) = &setup_py_path
        && pypi.setup_py_content.is_none()
        && let Some(content) = selected_text_content(&root_files, path)
    {
        pypi.set_setup_py_content(content.to_string());
    }
    if let Some(path) = &entry_points_path
        && pypi.entry_points_content.is_none()
        && let Some(content) = selected_text_content(&root_files, path)
    {
        pypi.set_entry_points_content(content.to_string());
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
    if !dependencies.is_empty() {
        pypi.set_dependency_count(dependencies.len() as i64);
        pypi.dependencies.extend(dependencies);
    }

    for (name, target, module_path) in console_scripts {
        let mut script = ConsoleScript::new();
        script.set_name(name.to_ascii_lowercase());
        script.set_target(target);
        if let Some(module_path) = module_path {
            script.set_module_path(module_path.clone());
            if let Some(content) = selected_text_content(&root_files, &module_path) {
                script.set_content(content.to_string());
            }
        }
        pypi.console_scripts.push(script);
    }

    for (path, file) in &root_files {
        let role = classify_file_role(
            path,
            path == pyproject_path.as_ref().unwrap_or(&String::new())
                || path == setup_cfg_path.as_ref().unwrap_or(&String::new())
                || path == metadata_path.as_ref().unwrap_or(&String::new())
                || path == entry_points_path.as_ref().unwrap_or(&String::new()),
            build_script_paths.contains(path),
            entrypoint_paths.contains(path),
        );

        let mut pypi_file = PypiFile::new();
        pypi_file.set_path(path.clone());
        pypi_file.set_role(role.as_str().to_string());
        pypi_file.set_is_root(true);
        pypi_file.set_is_text(file.text_content.is_some());
        pypi_file.set_size_bytes(file.size_bytes);
        pypi_file.set_sha256(file.sha256.clone());
        if should_expose_file_content(role) && let Some(content) = &file.text_content {
            pypi_file.set_content(content.clone());
        }
        pypi.files.push(pypi_file);
    }

    Ok(pypi)
}

#[module_export(name = "depends_on")]
fn depends_on(ctx: &mut ScanContext, dependency: RuntimeString) -> Option<bool> {
    let dependency = dependency.to_str(ctx).ok()?.to_ascii_lowercase();
    let pypi = ctx.module_output::<Pypi>()?;
    Some(
        pypi.dependencies
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
    let pypi = ctx.module_output::<Pypi>()?;
    Some(pypi.dependencies.iter().any(|dep| {
        dep.name.as_deref() == Some(dependency.as_str())
            && dep.section.as_deref() == Some(section.as_str())
    }))
}

#[module_export(name = "has_console_script")]
fn has_console_script(ctx: &mut ScanContext, name: RuntimeString) -> Option<bool> {
    let name = name.to_str(ctx).ok()?.to_ascii_lowercase();
    let pypi = ctx.module_output::<Pypi>()?;
    Some(
        pypi.console_scripts
            .iter()
            .any(|script| script.name.as_deref() == Some(name.as_str())),
    )
}

#[module_export(name = "console_script_contains")]
fn console_script_contains(
    ctx: &mut ScanContext,
    name: RuntimeString,
    needle: RuntimeString,
) -> Option<bool> {
    let name = name.to_str(ctx).ok()?.to_ascii_lowercase();
    let needle = needle.to_str(ctx).ok()?.to_ascii_lowercase();
    let pypi = ctx.module_output::<Pypi>()?;
    let script = pypi
        .console_scripts
        .iter()
        .find(|script| script.name.as_deref() == Some(name.as_str()))?;
    Some(
        script
            .target
            .as_deref()
            .is_some_and(|value| contains_case_insensitive(value, &needle))
            || script
                .module_path
                .as_deref()
                .is_some_and(|value| contains_case_insensitive(value, &needle))
            || script
                .content
                .as_deref()
                .is_some_and(|value| contains_case_insensitive(value, &needle)),
    )
}

#[module_export(name = "has_build_backend")]
fn has_build_backend(ctx: &mut ScanContext, backend: RuntimeString) -> Option<bool> {
    let backend = backend.to_str(ctx).ok()?.to_ascii_lowercase();
    let pypi = ctx.module_output::<Pypi>()?;
    Some(
        pypi.build_backend
            .as_deref()
            .is_some_and(|value| contains_case_insensitive(value, &backend)),
    )
}

#[module_export(name = "has_file")]
fn has_file(ctx: &mut ScanContext, path: RuntimeString) -> Option<bool> {
    let path = normalize_lookup(path.to_str(ctx).ok()?);
    let pypi = ctx.module_output::<Pypi>()?;
    Some(find_file(pypi, &path).is_some())
}

#[module_export(name = "file_contains")]
fn file_contains(
    ctx: &mut ScanContext,
    path: RuntimeString,
    needle: RuntimeString,
) -> Option<bool> {
    let path = normalize_lookup(path.to_str(ctx).ok()?);
    let needle = needle.to_str(ctx).ok()?.to_ascii_lowercase();
    let pypi = ctx.module_output::<Pypi>()?;
    let file = find_file(pypi, &path)?;
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
    let pypi = ctx.module_output::<Pypi>()?;
    Some(pypi.files.iter().any(|file| {
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
    let pypi = ctx.module_output::<Pypi>()?;
    Some(
        pypi.files
            .iter()
            .filter(|file| file.role.as_deref() == Some(role.as_str()))
            .count() as i64,
    )
}

#[derive(Default)]
struct ParsedMetadata {
    name: Option<String>,
    version: Option<String>,
    build_backend: Option<String>,
    dependencies: Vec<Dependency>,
}

fn extract_archive_entries(
    data: &[u8],
) -> Option<(ArtifactKind, BTreeMap<String, ArchiveFile>)> {
    if data.starts_with(b"PK\x03\x04")
        || data.starts_with(b"PK\x05\x06")
        || data.starts_with(b"PK\x07\x08")
    {
        return extract_zip_entries(data).map(|entries| (ArtifactKind::WheelZip, entries));
    }

    extract_tar_entries(data).map(|entries| (ArtifactKind::SdistTarGz, entries))
}

fn extract_zip_entries(data: &[u8]) -> Option<BTreeMap<String, ArchiveFile>> {
    let cursor = Cursor::new(data);
    let mut archive = ZipArchive::new(cursor).ok()?;
    let mut files = BTreeMap::new();

    for index in 0..archive.len() {
        let mut entry = archive.by_index(index).ok()?;
        if !entry.is_file() {
            continue;
        }
        let path = normalize_path(entry.name());
        let mut bytes = Vec::new();
        if entry.read_to_end(&mut bytes).is_err() {
            return None;
        }
        let sha256 = format!("{:x}", Sha256::digest(&bytes));
        let text_content = if should_buffer_manifest_text(&path, bytes.len()) && looks_like_text(&bytes)
        {
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

fn extract_tar_entries(data: &[u8]) -> Option<BTreeMap<String, ArchiveFile>> {
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
        let text_content = if should_buffer_manifest_text(&path, bytes.len()) && looks_like_text(&bytes)
        {
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

fn select_sdist_root_prefix(entries: &BTreeMap<String, ArchiveFile>) -> Option<String> {
    for preferred in ["pyproject.toml", "setup.py", "setup.cfg", "PKG-INFO"] {
        if entries.contains_key(preferred) {
            return Some(String::new());
        }
        if let Some(path) = entries
            .keys()
            .filter(|path| path.ends_with(&format!("/{preferred}")))
            .min_by_key(|path| (path_depth(path), path.as_str()))
        {
            return Some(root_prefix_for_path(path));
        }
    }
    None
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

fn select_metadata_path(files: &BTreeMap<String, ArchiveFile>) -> Option<String> {
    files.keys().find(|path| normalize_lookup(path) == "pkg-info").cloned().or_else(|| {
        files.keys()
            .filter(|path| {
                path.ends_with(".dist-info/METADATA") || path.ends_with(".egg-info/PKG-INFO")
            })
            .min_by_key(|path| (path_depth(path), path.as_str()))
            .cloned()
    })
}

fn select_entry_points_path(files: &BTreeMap<String, ArchiveFile>) -> Option<String> {
    files.keys()
        .filter(|path| {
            normalize_lookup(path) == "entry_points.txt"
                || path.ends_with(".dist-info/entry_points.txt")
                || path.ends_with(".egg-info/entry_points.txt")
        })
        .min_by_key(|path| (path_depth(path), path.as_str()))
        .cloned()
}

fn parse_metadata(content: &str) -> ParsedMetadata {
    let mut parsed = ParsedMetadata::default();
    for line in content.lines() {
        if let Some(value) = line.strip_prefix("Name: ") {
            parsed.name = Some(value.trim().to_string());
        } else if let Some(value) = line.strip_prefix("Version: ") {
            parsed.version = Some(value.trim().to_string());
        } else if let Some(value) = line.strip_prefix("Requires-Dist: ")
            && let Some(dependency) = dependency_from_requirement(value, "requires-dist")
        {
            parsed.dependencies.push(dependency);
        }
    }
    parsed
}

fn parse_pyproject(content: &str) -> ParsedMetadata {
    let mut parsed = ParsedMetadata::default();
    let mut section = String::new();

    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with('[') && trimmed.ends_with(']') {
            section = trimmed.trim_matches(&['[', ']'][..]).to_ascii_lowercase();
            continue;
        }
        if let Some(value) = toml_string_value(trimmed, "build-backend")
            && section == "build-system"
        {
            parsed.build_backend = Some(value);
        } else if let Some(value) = toml_string_value(trimmed, "name")
            && section == "project"
        {
            parsed.name = Some(value);
        } else if let Some(value) = toml_string_value(trimmed, "version")
            && section == "project"
        {
            parsed.version = Some(value);
        } else if trimmed.starts_with("dependencies") && section == "project" {
            for dependency in inline_array_entries(trimmed) {
                if let Some(dep) = dependency_from_requirement(&dependency, "project.dependencies") {
                    parsed.dependencies.push(dep);
                }
            }
        }
    }

    parsed
}

fn parse_setup_cfg(content: &str) -> ParsedMetadata {
    let mut parsed = ParsedMetadata::default();
    let mut section = String::new();
    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with('[') && trimmed.ends_with(']') {
            section = trimmed.trim_matches(&['[', ']'][..]).to_ascii_lowercase();
            continue;
        }
        if let Some(value) = ini_value(trimmed, "name")
            && section == "metadata"
        {
            parsed.name = Some(value);
        } else if let Some(value) = ini_value(trimmed, "version")
            && section == "metadata"
        {
            parsed.version = Some(value);
        }
    }
    parsed
}

fn parse_setup_py(content: &str) -> ParsedMetadata {
    let mut parsed = ParsedMetadata::default();
    if let Some(value) = python_kwarg_string(content, "name") {
        parsed.name = Some(value);
    }
    if let Some(value) = python_kwarg_string(content, "version") {
        parsed.version = Some(value);
    }
    parsed
}

fn parse_entry_points(content: &str) -> Vec<(String, String)> {
    let mut section = String::new();
    let mut scripts = Vec::new();
    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with('[') && trimmed.ends_with(']') {
            section = trimmed.trim_matches(&['[', ']'][..]).to_ascii_lowercase();
            continue;
        }
        if section != "console_scripts" || trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        if let Some((name, target)) = trimmed.split_once('=') {
            scripts.push((name.trim().to_ascii_lowercase(), target.trim().to_string()));
        }
    }
    scripts
}

fn resolve_python_module_target(
    target: &str,
    files: &BTreeMap<String, ArchiveFile>,
) -> Option<String> {
    let module = target.split(':').next()?.trim();
    if module.is_empty() {
        return None;
    }

    let base = module.replace('.', "/");
    for candidate in [format!("{base}.py"), format!("{base}/__init__.py")] {
        let normalized = normalize_lookup(&candidate);
        if let Some(path) = files
            .keys()
            .find(|path| normalize_lookup(path) == normalized || normalize_lookup(path).ends_with(&format!("/{normalized}")))
        {
            return Some(path.clone());
        }
    }

    None
}

#[allow(clippy::too_many_arguments)]
fn hydrate_selected_text_content(
    kind: ArtifactKind,
    data: &[u8],
    root_prefix: &str,
    metadata_path: &Option<String>,
    pyproject_path: &Option<String>,
    setup_py_path: &Option<String>,
    setup_cfg_path: &Option<String>,
    entry_points_path: &Option<String>,
    build_script_paths: &BTreeSet<String>,
    entrypoint_paths: &BTreeSet<String>,
    root_files: &mut BTreeMap<String, ArchiveFile>,
) {
    match kind {
        ArtifactKind::WheelZip => hydrate_selected_zip_text_content(
            data,
            metadata_path,
            pyproject_path,
            setup_py_path,
            setup_cfg_path,
            entry_points_path,
            build_script_paths,
            entrypoint_paths,
            root_files,
        ),
        ArtifactKind::SdistTarGz => hydrate_selected_tar_text_content(
            data,
            root_prefix,
            metadata_path,
            pyproject_path,
            setup_py_path,
            setup_cfg_path,
            entry_points_path,
            build_script_paths,
            entrypoint_paths,
            root_files,
        ),
    }
}

#[allow(clippy::too_many_arguments)]
fn hydrate_selected_zip_text_content(
    data: &[u8],
    metadata_path: &Option<String>,
    pyproject_path: &Option<String>,
    _setup_py_path: &Option<String>,
    setup_cfg_path: &Option<String>,
    entry_points_path: &Option<String>,
    build_script_paths: &BTreeSet<String>,
    entrypoint_paths: &BTreeSet<String>,
    root_files: &mut BTreeMap<String, ArchiveFile>,
) {
    let cursor = Cursor::new(data);
    let Ok(mut archive) = ZipArchive::new(cursor) else {
        return;
    };

    for index in 0..archive.len() {
        let Ok(mut entry) = archive.by_index(index) else {
            return;
        };
        if !entry.is_file() {
            continue;
        }
        let path = normalize_path(entry.name());
        let Some(file) = root_files.get_mut(&path) else {
            continue;
        };
        if file.text_content.is_some() {
            continue;
        }
        let role = classify_file_role(
            &path,
            is_manifest_path(&path, metadata_path, pyproject_path, setup_cfg_path, entry_points_path),
            build_script_paths.contains(&path),
            entrypoint_paths.contains(&path),
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

#[allow(clippy::too_many_arguments)]
fn hydrate_selected_tar_text_content(
    data: &[u8],
    root_prefix: &str,
    metadata_path: &Option<String>,
    pyproject_path: &Option<String>,
    _setup_py_path: &Option<String>,
    setup_cfg_path: &Option<String>,
    entry_points_path: &Option<String>,
    build_script_paths: &BTreeSet<String>,
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
            is_manifest_path(relative, metadata_path, pyproject_path, setup_cfg_path, entry_points_path),
            build_script_paths.contains(relative),
            entrypoint_paths.contains(relative),
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

fn selected_text_content<'a>(
    files: &'a BTreeMap<String, ArchiveFile>,
    path: &str,
) -> Option<&'a str> {
    files.get(path).and_then(|file| file.text_content.as_deref())
}

fn classify_file_role(
    path: &str,
    is_manifest: bool,
    is_build_script: bool,
    is_entrypoint: bool,
) -> FileRole {
    if is_manifest {
        return FileRole::Manifest;
    }
    if is_build_script {
        return FileRole::BuildScript;
    }
    if is_entrypoint {
        return FileRole::Entrypoint;
    }
    if is_binary_path(path) {
        return FileRole::Binary;
    }
    FileRole::Module
}

fn is_manifest_candidate(path: &str) -> bool {
    let lower = normalize_lookup(path);
    lower == "pyproject.toml"
        || lower.ends_with("/pyproject.toml")
        || lower == "setup.py"
        || lower.ends_with("/setup.py")
        || lower == "setup.cfg"
        || lower.ends_with("/setup.cfg")
        || lower == "pkg-info"
        || lower.ends_with("/pkg-info")
        || lower.ends_with(".dist-info/metadata")
        || lower.ends_with(".egg-info/pkg-info")
        || lower == "entry_points.txt"
        || lower.ends_with(".dist-info/entry_points.txt")
        || lower.ends_with(".egg-info/entry_points.txt")
}

fn is_manifest_path(
    path: &str,
    metadata_path: &Option<String>,
    pyproject_path: &Option<String>,
    setup_cfg_path: &Option<String>,
    entry_points_path: &Option<String>,
) -> bool {
    metadata_path.as_deref() == Some(path)
        || pyproject_path.as_deref() == Some(path)
        || setup_cfg_path.as_deref() == Some(path)
        || entry_points_path.as_deref() == Some(path)
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

fn merge_dependencies(into: &mut Vec<Dependency>, other: Vec<Dependency>) {
    into.extend(other);
}

fn dependency_from_requirement(value: &str, section: &str) -> Option<Dependency> {
    let requirement = value.split(';').next()?.trim();
    let requirement = requirement.split('[').next().unwrap_or(requirement).trim();
    let name = requirement
        .split(|ch: char| ch.is_whitespace() || ch == '(')
        .next()?
        .trim();
    if name.is_empty() {
        return None;
    }

    let mut dependency = Dependency::new();
    dependency.set_name(name.to_ascii_lowercase());
    dependency.set_section(section.to_ascii_lowercase());
    dependency.set_spec(value.trim().to_string());
    Some(dependency)
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

fn ini_value(line: &str, key: &str) -> Option<String> {
    let (left, right) = line.split_once('=')?;
    if left.trim().eq_ignore_ascii_case(key) {
        let value = right.trim();
        if value.is_empty() {
            None
        } else {
            Some(value.to_string())
        }
    } else {
        None
    }
}

fn inline_array_entries(line: &str) -> Vec<String> {
    let (_, right) = match line.split_once('=') {
        Some(parts) => parts,
        None => return Vec::new(),
    };
    let trimmed = right.trim();
    if !trimmed.starts_with('[') || !trimmed.ends_with(']') {
        return Vec::new();
    }
    trimmed[1..trimmed.len() - 1]
        .split(',')
        .map(|entry| entry.trim().trim_matches(|ch| matches!(ch, '"' | '\'')))
        .filter(|entry| !entry.is_empty())
        .map(str::to_string)
        .collect()
}

fn python_kwarg_string(content: &str, key: &str) -> Option<String> {
    for quote in ['"', '\''] {
        let needle = format!("{key}={quote}");
        let Some(start) = content.find(&needle) else {
            continue;
        };
        let start = start + needle.len();
        let rest = &content[start..];
        let Some(end) = rest.find(quote) else {
            continue;
        };
        let value = &rest[..end];
        if !value.is_empty() {
            return Some(value.to_string());
        }
    }
    None
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
    [".so", ".pyd", ".dll", ".dylib", ".exe"]
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

fn find_file<'a>(pypi: &'a Pypi, path: &str) -> Option<&'a PypiFile> {
    pypi.files
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
    use zip::CompressionMethod;
    use zip::write::FileOptions;

    #[test]
    fn parses_wheel_metadata_and_console_scripts() {
        let bytes = build_wheel(&[
            ("demo-1.0.0.dist-info/METADATA", "Name: demo\nVersion: 1.0.0\nRequires-Dist: requests (>=2.0)\n"),
            ("demo-1.0.0.dist-info/entry_points.txt", "[console_scripts]\ndemo = demo.cli:main\n"),
            ("pyproject.toml", "[build-system]\nbuild-backend = \"setuptools.build_meta\"\n[project]\nname = \"demo\"\nversion = \"1.0.0\"\n"),
            ("demo/cli.py", "import sys\nprint('demo')\n"),
        ]);

        let pypi = main(&bytes, None).expect("parse wheel");
        assert!(pypi.is_pypi());
        assert!(pypi.is_wheel());
        assert_eq!(pypi.name.as_deref(), Some("demo"));
        assert_eq!(pypi.version.as_deref(), Some("1.0.0"));
        assert_eq!(pypi.dependencies.len(), 1);
        assert!(pypi
            .console_scripts
            .iter()
            .any(|script| script.name.as_deref() == Some("demo")));

        rule_true!(
            r#"
            import "pypi"
            rule test {
              condition:
                pypi.is_pypi and
                pypi.is_wheel and
                pypi.name == "demo" and
                pypi.version == "1.0.0" and
                pypi.depends_on("requests") and
                pypi.has_build_backend("setuptools.build_meta") and
                pypi.has_console_script("demo") and
                pypi.console_script_contains("demo", "print('demo')")
            }
            "#,
            &bytes
        );
    }

    #[test]
    fn parses_sdist_setup_py_and_selects_root() {
        let bytes = build_sdist(&[
            ("demo-1.0.0/setup.py", "from setuptools import setup\nimport subprocess\nsetup(name='demo', version='1.0.0')\n"),
            ("demo-1.0.0/demo/__main__.py", "print('demo')\n"),
            ("demo-1.0.0/vendor/ignored/setup.py", "setup(name='ignored')\n"),
        ]);

        let pypi = main(&bytes, None).expect("parse sdist");
        assert!(pypi.is_pypi());
        assert!(pypi.is_sdist());
        assert!(pypi.has_setup_py());
        assert_eq!(pypi.name.as_deref(), Some("demo"));
        assert_eq!(pypi.version.as_deref(), Some("1.0.0"));
        assert!(pypi
            .files
            .iter()
            .any(|file| file.path.as_deref() == Some("setup.py")
                && file.role.as_deref() == Some("build_script")
                && file
                    .content
                    .as_deref()
                    .is_some_and(|content| content.contains("subprocess"))));
        assert!(pypi.files.iter().any(|file| file.path.as_deref() == Some("demo/__main__.py")
            && file.role.as_deref() == Some("entrypoint")
            && file
                .content
                .as_deref()
                .is_some_and(|content| content.contains("print('demo')"))));

        rule_true!(
            r#"
            import "pypi"
            rule test {
              condition:
                pypi.is_pypi and
                pypi.is_sdist and
                pypi.has_setup_py and
                pypi.name == "demo" and
                pypi.version == "1.0.0" and
                pypi.file_contains("setup.py", "subprocess") and
                pypi.file_count("build_script") == 1 and
                pypi.any_file_contains("entrypoint", "print('demo')")
            }
            "#,
            &bytes
        );
    }

    #[test]
    fn does_not_expose_large_non_selected_module_content() {
        let large_module = "print('not selected')\n".repeat(150_000);
        let bytes = build_wheel(&[
            ("demo-1.0.0.dist-info/METADATA", "Name: demo\nVersion: 1.0.0\n"),
            ("demo/main.py", "print('main')\n"),
            ("demo/payload.py", large_module.as_str()),
        ]);

        rule_false!(
            r#"
            import "pypi"
            rule test {
              condition:
                pypi.file_contains("demo/payload.py", "not selected")
            }
            "#,
            &bytes
        );
    }

    fn build_wheel(files: &[(&str, &str)]) -> Vec<u8> {
        let mut cursor = Cursor::new(Vec::new());
        {
            let mut writer = zip::ZipWriter::new(&mut cursor);
            let options: FileOptions<'_, ()> =
                FileOptions::default().compression_method(CompressionMethod::Deflated);
            for (path, content) in files {
                writer.start_file(*path, options).expect("start zip file");
                writer
                    .write_all(content.as_bytes())
                    .expect("write zip file content");
            }
            writer.finish().expect("finish wheel archive");
        }
        cursor.into_inner()
    }

    fn build_sdist(files: &[(&str, &str)]) -> Vec<u8> {
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
                    .expect("append file to sdist");
            }
            builder.finish().expect("finish sdist tar");
        }

        let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(&tar_data).expect("write tar data");
        encoder.finish().expect("finish sdist gzip")
    }
}
