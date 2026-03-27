use std::collections::BTreeMap;

use serde_json::Value;

pub fn has_npm_install_script(version_meta: &Value) -> bool {
    version_meta
        .get("scripts")
        .and_then(Value::as_object)
        .is_some_and(|scripts| {
            ["preinstall", "install", "postinstall"]
                .iter()
                .any(|name| scripts.contains_key(*name))
        })
}

pub fn npm_install_scripts_longstanding(raw: &Value, current_version: &str) -> bool {
    let Some(current_meta) = raw
        .get("versions")
        .and_then(Value::as_object)
        .and_then(|versions| versions.get(current_version))
    else {
        return false;
    };
    let current = npm_install_scripts(current_meta);
    if current.is_empty() {
        return false;
    }
    raw.get("versions")
        .and_then(Value::as_object)
        .into_iter()
        .flatten()
        .any(|(version, meta)| version != current_version && npm_install_scripts(meta) == current)
}

pub fn npm_install_scripts_benign(version_meta: &Value) -> bool {
    let scripts = npm_install_scripts(version_meta);
    !scripts.is_empty() && scripts.values().all(|script| script_looks_benign(script))
}

pub fn npm_install_scripts(version_meta: &Value) -> BTreeMap<String, String> {
    version_meta
        .get("scripts")
        .and_then(Value::as_object)
        .into_iter()
        .flatten()
        .filter_map(|(name, value)| {
            if !matches!(name.as_str(), "preinstall" | "install" | "postinstall") {
                return None;
            }
            value
                .as_str()
                .map(|value| (name.clone(), value.to_string()))
        })
        .collect()
}

fn script_looks_benign(script: &str) -> bool {
    let lower = script.to_ascii_lowercase();

    let clearly_risky = [
        "http://",
        "https://",
        "curl ",
        "wget ",
        "invoke-webrequest",
        "start-process",
        "powershell",
        "child_process",
        "spawn(",
        "exec(",
        "fetch(",
        "axios",
        "node scripts/",
        "npx ",
        "npm exec",
        "npm install",
        "pnpm ",
        "yarn ",
        "bash ",
        "sh ",
        "python ",
        "pip ",
    ];
    if clearly_risky.iter().any(|marker| lower.contains(marker)) {
        return false;
    }

    let informational = lower.starts_with("echo ")
        || lower.starts_with("printf ")
        || lower.contains("|| echo ")
        || lower.contains("|| printf ")
        || lower.starts_with("which ")
        || lower.starts_with("command -v ")
        || lower.contains("which ") && lower.contains("|| echo ")
        || lower.contains("command -v ") && lower.contains("|| echo ");
    if informational {
        return true;
    }

    let local_permission_fix = (lower.contains("chmodsync(") || lower.contains("chmod "))
        && (lower.contains("__dirname")
            || lower.contains("join(__dirname")
            || lower.contains("./bin"));
    if local_permission_fix {
        return true;
    }

    false
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::{
        has_npm_install_script, npm_install_scripts_benign, npm_install_scripts_longstanding,
    };

    #[test]
    fn detects_benign_informational_install_script() {
        let meta = json!({
            "scripts": {
                "postinstall": "which idb > /dev/null 2>&1 || echo 'optional install'"
            }
        });
        assert!(has_npm_install_script(&meta));
        assert!(npm_install_scripts_benign(&meta));
    }

    #[test]
    fn detects_benign_local_permission_fix_script() {
        let meta = json!({
            "scripts": {
                "postinstall": "node -e \"try{require('fs').chmodSync(require('path').join(__dirname,'bin','demo.cjs'),0o755)}catch(e){}\""
            }
        });
        assert!(npm_install_scripts_benign(&meta));
    }

    #[test]
    fn detects_risky_install_script() {
        let meta = json!({
            "scripts": {
                "postinstall": "node scripts/install.js"
            }
        });
        assert!(!npm_install_scripts_benign(&meta));
    }

    #[test]
    fn detects_longstanding_install_scripts() {
        let raw = json!({
            "versions": {
                "1.0.0": { "scripts": { "postinstall": "echo hi" } },
                "1.0.1": { "scripts": { "postinstall": "echo hi" } }
            }
        });
        assert!(npm_install_scripts_longstanding(&raw, "1.0.1"));
    }
}
