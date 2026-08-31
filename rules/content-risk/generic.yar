import "npm"
import "pypi"
import "crate"

rule npm_consolelofy_stealer_manifest : malware npm stealer
{
    meta:
        score = 9
        description = "npm package archive matches the ConsoleLofy stealer family manifest fingerprint"
    condition:
        npm.is_npm and
        npm.has_bin and
        npm.author == "consolelofy" and
        npm.package_manager == "pnpm@10.8.0" and
        not npm.has_repository and
        npm.windows_target and
        npm.depends_on("@primno/dpapi") and
        npm.depends_on("koffi") and
        npm.depends_on("sqlite3") and
        npm.depends_on("screenshot-desktop") and
        npm.depends_on("rcedit") and
        npm.depends_on("ws")
}

rule npm_base64_xor_self_unpacking_loader : malware npm loader
{
    meta:
        score = 10
        description = "npm main entrypoint is a base64/XOR self-unpacking JavaScript loader"
    condition:
        npm.is_npm and
        npm.main_contains("Buffer.from(") and
        npm.main_contains("base64") and
        npm.main_contains("new Function(\"require\",\"module\",\"exports\",\"__filename\",\"__dirname\"") and
        npm.main_contains("_r[_i]=_d[_i]^") and
        (
            npm.main_contains("_k.charCodeAt(") or
            npm.main_contains(".charCodeAt(")
        )
}

rule npm_nyx_hidden_obfuscated_loader : malware npm stealer loader
{
    meta:
        score = 10
        description = "npm main entrypoint uses a Nyx-style hidden launcher and obfuscated loader"
    condition:
        npm.is_npm and
        npm.main_contains("(function(_0x") and
        npm.main_contains("process.env._NYX_HIDDEN") and
        (
            npm.author == "consolelofy" or
            (
                npm.has_bin and
                npm.windows_target and
                not npm.has_repository and
                npm.depends_on("@primno/dpapi") and
                npm.depends_on("koffi") and
                npm.depends_on("sqlite3") and
                npm.depends_on("screenshot-desktop") and
                npm.depends_on("rcedit") and
                npm.depends_on("ws")
            )
        )
}

rule npm_runtime_encoded_remote_loader : malware npm runtime loader
{
    meta:
        score = 10
        description = "npm runtime module decodes embedded remote endpoint or header material, downloads attacker-controlled JavaScript, and executes it dynamically"
    condition:
        npm.is_npm and
        npm.file_count("entrypoint") > 0 and
        (
            npm.any_file_contains("entrypoint", "atob(") or
            (
                npm.any_file_contains("entrypoint", "Buffer.from(") and
                npm.any_file_contains("entrypoint", "base64")
            )
        ) and
        (
            npm.any_file_contains("entrypoint", "axios.get(") or
            npm.any_file_contains("entrypoint", "fetch(") or
            npm.any_file_contains("entrypoint", "http.get(") or
            npm.any_file_contains("entrypoint", "https.get(") or
            npm.any_file_contains("entrypoint", "request.get(") or
            npm.any_file_contains("entrypoint", "request(")
        ) and
        (
            npm.any_file_contains("entrypoint", "new Function.constructor(") or
            npm.any_file_contains("entrypoint", "eval(") or
            npm.any_file_contains("entrypoint", "vm.runInThisContext(") or
            npm.any_file_contains("entrypoint", "vm.runInNewContext(") or
            npm.any_file_contains("entrypoint", "Module._compile(")
        ) and
        (
            npm.any_file_contains("entrypoint", "constructor(\"require\"") or
            npm.any_file_contains("entrypoint", "constructor('require'") or
            npm.any_file_contains("entrypoint", "handler(require)") or
            npm.any_file_contains("entrypoint", ".data.logger") or
            npm.any_file_contains("entrypoint", ".data.payload") or
            npm.any_file_contains("entrypoint", ".data.script") or
            npm.any_file_contains("entrypoint", ".data.code")
        )
}

rule npm_openclaw_hardcoded_installer_secrets : malware npm installer
{
    meta:
        score = 9
        description = "npm install script contains hardcoded OpenClaw secrets and local bootstrap behavior"
    condition:
        npm.is_npm and
        npm.has_script("postinstall") and
        npm.script_contains("postinstall", "FIXED_GATEWAY_TOKEN") and
        npm.script_contains("postinstall", "FIXED_ZAI_API_KEY") and
        npm.script_contains("postinstall", ".openclaw/.env") and
        npm.script_contains("postinstall", "mkcert")
}

rule npm_native_credential_theft_toolchain : malware npm theft generic
{
    meta:
        score = 8
        description = "npm package combines native credential access, local browser/session storage access, and exfiltration-oriented tooling"
    condition:
        npm.is_npm and
        npm.has_bin and
        (
            npm.windows_target or
            not npm.has_repository
        ) and
        (
            (
                npm.depends_on("@primno/dpapi") and
                npm.depends_on("sqlite3")
            ) or
            (
                npm.depends_on("koffi") and
                npm.depends_on("sqlite3")
            ) or
            (
                npm.depends_on("sqlite3") and
                npm.depends_on("screenshot-desktop")
            )
        ) and
        (
            npm.depends_on("archiver") or
            npm.depends_on("adm-zip") or
            npm.depends_on("tar") or
            npm.depends_on("form-data") or
            npm.depends_on("ws")
        ) and
        (
            npm.depends_on("rcedit") or
            npm.any_file_contains("entrypoint", "discord_desktop_core") or
            npm.any_file_contains("entrypoint", "Local Storage\\\\leveldb") or
            npm.any_file_contains("entrypoint", "Local State")
        )
}

rule npm_hidden_windows_script_launcher : malware npm stealth c2
{
    meta:
        score = 10
        description = "npm entrypoint contains hidden Windows launcher, persistence, and live C2 markers"
    condition:
        npm.is_npm and
        (
            npm.any_file_contains("entrypoint", "ws://") or
            npm.any_file_contains("entrypoint", "wss://")
        ) and
        (
            npm.any_file_contains("entrypoint", "wscript.exe") or
            npm.any_file_contains("entrypoint", "_NYX_HIDDEN")
        ) and
        (
            npm.any_file_contains("entrypoint", "Software\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Run") or
            npm.any_file_contains("entrypoint", "Start Menu\\\\Programs\\\\Startup") or
            npm.any_file_contains("entrypoint", "Add-MpPreference")
        )
}

rule npm_exfil_channel_with_theft_markers : malware npm exfil generic
{
    meta:
        score = 8
        description = "npm runtime contains an exfiltration channel together with browser, wallet, or session theft markers"
    condition:
        npm.is_npm and
        (
            npm.any_file_contains("entrypoint", "discord.com/api/webhooks/") or
            npm.any_file_contains("entrypoint", "discordapp.com/api/webhooks/") or
            npm.any_file_contains("entrypoint", "ptb.discord.com/api/webhooks/") or
            npm.any_file_contains("entrypoint", "api.telegram.org/bot")
        ) and
        (
            npm.any_file_contains("entrypoint", "discord_desktop_core") or
            npm.any_file_contains("entrypoint", "Local Storage\\\\leveldb") or
            npm.any_file_contains("entrypoint", "Local State") or
            npm.any_file_contains("entrypoint", "chrome-extension://") or
            npm.any_file_contains("entrypoint", "Exodus") or
            npm.any_file_contains("entrypoint", "Telegram Desktop")
        )
}

rule npm_downloader_pipe_to_shell_installer : malware npm downloader installer
{
    meta:
        score = 9
        description = "npm install-time lifecycle target pipes downloaded content directly into a shell interpreter or uses PowerShell download cradles"
    condition:
        npm.is_npm and
        npm.has_install_script and
        npm.file_count("install_script") > 0 and
        (
            npm.any_file_contains("install_script", "| bash") or
            npm.any_file_contains("install_script", "| sh") or
            npm.any_file_contains("install_script", "|bash") or
            npm.any_file_contains("install_script", "|sh") or
            npm.any_file_contains("install_script", "Invoke-Expression") or
            npm.any_file_contains("install_script", "IEX(") or
            npm.any_file_contains("install_script", "DownloadString(")
        ) and
        (
            npm.any_file_contains("install_script", "curl ") or
            npm.any_file_contains("install_script", "wget ") or
            npm.any_file_contains("install_script", "https.get(") or
            npm.any_file_contains("install_script", "http.get(") or
            npm.any_file_contains("install_script", "Invoke-WebRequest") or
            npm.any_file_contains("install_script", "fetch(")
        )
}

rule npm_install_remote_payload_shell_exec : malware npm downloader loader
{
    meta:
        score = 9
        description = "npm install-time lifecycle target downloads remote content and runs it through a shell command interpreter or dynamic code evaluation, executing attacker-controlled code at install time"
    condition:
        npm.is_npm and
        npm.has_install_script and
        npm.file_count("install_script") > 0 and
        (
            npm.any_file_contains("install_script", "https.get(") or
            npm.any_file_contains("install_script", "http.get(") or
            npm.any_file_contains("install_script", "https.request(") or
            npm.any_file_contains("install_script", "fetch(") or
            npm.any_file_contains("install_script", "axios.get(") or
            npm.any_file_contains("install_script", "axios(") or
            npm.any_file_contains("install_script", "Invoke-WebRequest")
        ) and
        (
            // Shell-command and dynamic-eval sinks. A legitimate native binary
            // bootstrap runs the downloaded file with execFile/spawn on a path;
            // it never feeds the response into bash -c, eval, or new Function.
            npm.any_file_contains("install_script", "bash -c") or
            npm.any_file_contains("install_script", "sh -c") or
            npm.any_file_contains("install_script", "eval(") or
            npm.any_file_contains("install_script", "new Function(") or
            npm.any_file_contains("install_script", "Invoke-Expression") or
            npm.any_file_contains("install_script", "IEX(")
        )
}

rule npm_binding_gyp_python_sandbox_escape : malware npm installer loader
{
    meta:
        score = 9
        description = "npm binding.gyp build config embeds Python sandbox-escape primitives in its node-gyp-evaluated conditions, launching an out-of-sandbox process at install time without any package.json lifecycle script"
    condition:
        npm.is_npm and
        npm.has_native_gyp and
        npm.file_count("build_config") > 0 and
        (
            (
                // The canonical CPython class-hierarchy escape: enumerate
                // __subclasses__ and pivot through catch_warnings/__builtins__
                // to reach eval/exec. No legitimate binding.gyp contains any
                // of these dunder primitives, so two co-occurring ones are
                // already a confident match.
                npm.any_file_contains("build_config", "__subclasses__") and
                (
                    npm.any_file_contains("build_config", "catch_warnings") or
                    npm.any_file_contains("build_config", "__builtins__") or
                    npm.any_file_contains("build_config", "__globals__")
                )
            ) or
            (
                // A single dunder primitive is corroborated by a launch or
                // eval indicator, which legitimate gyp conditions (target,
                // OS checks, include_dirs) never carry.
                (
                    npm.any_file_contains("build_config", "__subclasses__") or
                    npm.any_file_contains("build_config", "__class__.__base__") or
                    npm.any_file_contains("build_config", "catch_warnings") or
                    npm.any_file_contains("build_config", "__builtins__") or
                    npm.any_file_contains("build_config", "__globals__") or
                    npm.any_file_contains("build_config", "__import__")
                ) and
                (
                    npm.any_file_contains("build_config", "node ") or
                    npm.any_file_contains("build_config", "subprocess") or
                    npm.any_file_contains("build_config", "exec(") or
                    npm.any_file_contains("build_config", "eval(") or
                    npm.any_file_contains("build_config", "os.system") or
                    npm.any_file_contains("build_config", "getattr(") or
                    npm.any_file_contains("build_config", "compile(") or
                    npm.any_file_contains("build_config", "open(")
                )
            ) or
            (
                // Unicode/hex-escaped underscores hide dunder identifiers
                // (\u005f\u005fimport\u005f\u005f, \x5f\x5fglobals\x5f\x5f) from
                // the literal-token branches. No legitimate binding.gyp ever
                // escapes an underscore, so an escaped underscore plus a
                // launch/eval indicator is malicious on its own.
                (
                    npm.any_file_contains("build_config", "\\u005f") or
                    npm.any_file_contains("build_config", "\\U005f") or
                    npm.any_file_contains("build_config", "\\x5f")
                ) and
                (
                    npm.any_file_contains("build_config", "node ") or
                    npm.any_file_contains("build_config", "subprocess") or
                    npm.any_file_contains("build_config", "exec(") or
                    npm.any_file_contains("build_config", "eval(") or
                    npm.any_file_contains("build_config", "os.system")
                )
            )
        )
}

rule npm_downloader_and_exec_installer : suspicious npm downloader installer
{
    meta:
        score = 6
        description = "npm install-time lifecycle target downloads remote content and executes it through a shell or dynamic runtime (may be a legitimate native binary bootstrap)"
    condition:
        npm.is_npm and
        npm.has_install_script and
        npm.file_count("install_script") > 0 and
        not npm.has_repository and
        (
            npm.any_file_contains("install_script", "https.get(") or
            npm.any_file_contains("install_script", "http.get(") or
            npm.any_file_contains("install_script", "fetch(") or
            npm.any_file_contains("install_script", "axios.get(") or
            npm.any_file_contains("install_script", "curl ") or
            npm.any_file_contains("install_script", "wget ") or
            npm.any_file_contains("install_script", "Invoke-WebRequest")
        ) and
        (
            npm.any_file_contains("install_script", "bash -c") or
            npm.any_file_contains("install_script", "sh -c") or
            npm.any_file_contains("install_script", "powershell -") or
            npm.any_file_contains("install_script", "eval(") or
            npm.any_file_contains("install_script", "new Function(") or
            npm.any_file_contains("install_script", "Start-Process")
        )
}

rule npm_install_environment_callback_probe : suspicious npm installer callback
{
    meta:
        score = 8
        description = "npm install-time lifecycle target collects environment or system identity data and sends it to a remote callback"
    condition:
        npm.is_npm and
        npm.has_install_script and
        npm.file_count("install_script") > 0 and
        (
            npm.any_file_contains("install_script", "dns.resolve(") or
            npm.any_file_contains("install_script", "dns.lookup(") or
            npm.any_file_contains("install_script", "https.request(") or
            npm.any_file_contains("install_script", "http.request(")
        ) and
        (
            npm.any_file_contains("install_script", "os.networkInterfaces(") or
            npm.any_file_contains("install_script", "os.homedir(") or
            npm.any_file_contains("install_script", "os.tmpdir(") or
            npm.any_file_contains("install_script", "os.hostname(") or
            npm.any_file_contains("install_script", "os.userInfo(") or
            npm.any_file_contains("install_script", "process.env.PATH") or
            npm.any_file_contains("install_script", "process.env.HOME") or
            npm.any_file_contains("install_script", "process.env.USER") or
            npm.any_file_contains("install_script", "process.env.USERNAME") or
            npm.any_file_contains("install_script", "process.cwd(") or
            npm.any_file_contains("install_script", "process.pid") or
            npm.any_file_contains("install_script", "process.argv")
        ) and
        (
            npm.any_file_contains("install_script", "whoami") or
            npm.any_file_contains("install_script", "execSync(") or
            npm.any_file_contains("install_script", "spawnSync(") or
            npm.any_file_contains("install_script", "child_process") or
            npm.any_file_contains("install_script", "ifconfig") or
            npm.any_file_contains("install_script", "ip a") or
            npm.any_file_contains("install_script", "/etc/resolv.conf") or
            npm.any_file_contains("install_script", "dns.getServers(")
        )
}

rule npm_install_secrets_harvesting_c2_agent : malware npm installer c2
{
    meta:
        score = 10
        description = "npm install-time lifecycle target harvests secrets and infrastructure data, then enters a polling C2 loop"
    condition:
        npm.is_npm and
        npm.has_install_script and
        npm.file_count("install_script") > 0 and
        npm.any_file_contains("install_script", "http.request(") and
        npm.any_file_contains("install_script", "child_process") and
        npm.any_file_contains("install_script", "fs.readFileSync(") and
        npm.any_file_contains("install_script", "/c2/") and
        npm.any_file_contains("install_script", "/poll") and
        npm.any_file_contains("install_script", "setTimeout(") and
        (
            npm.any_file_contains("install_script", "find / -maxdepth") or
            npm.any_file_contains("install_script", "find / -name '.env") or
            npm.any_file_contains("install_script", "find / -name \".env")
        ) and
        (
            npm.any_file_contains("install_script", "KEYS *") or
            npm.any_file_contains("install_script", "DBSIZE") or
            npm.any_file_contains("install_script", "new net.Socket()")
        ) and
        (
            npm.any_file_contains("install_script", "/var/run/secrets/kubernetes.io/serviceaccount/token") or
            npm.any_file_contains("install_script", "/run/secrets/") or
            npm.any_file_contains("install_script", "/var/run/docker.sock")
        ) and
        (
            npm.any_file_contains("install_script", "id_rsa") or
            npm.any_file_contains("install_script", "*.pem") or
            npm.any_file_contains("install_script", "wallet") or
            npm.any_file_contains("install_script", "*private*") or
            npm.any_file_contains("install_script", "*secret*")
        )
}

rule npm_install_multiphase_secrets_exfil_agent : malware npm installer exfil c2
{
    meta:
        score = 10
        description = "npm install-time lifecycle target harvests secrets or infrastructure data and exfiltrates them over tagged HTTP callbacks"
    condition:
        npm.is_npm and
        npm.has_install_script and
        npm.file_count("install_script") > 0 and
        (
            npm.any_file_contains("install_script", "http.request(") or
            npm.any_file_contains("install_script", "https.request(")
        ) and
        (
            npm.any_file_contains("install_script", "child_process") or
            npm.any_file_contains("install_script", "execSync(") or
            npm.any_file_contains("install_script", "spawnSync(") or
            npm.any_file_contains("install_script", "spawn(")
        ) and
        (
            npm.any_file_contains("install_script", ".env") or
            npm.any_file_contains("install_script", "process.env") or
            npm.any_file_contains("install_script", "/var/run/docker.sock") or
            npm.any_file_contains("install_script", "/run/secrets/") or
            npm.any_file_contains("install_script", "kubernetes.io/serviceaccount/token") or
            npm.any_file_contains("install_script", "id_rsa") or
            npm.any_file_contains("install_script", "*.pem") or
            npm.any_file_contains("install_script", "wallet") or
            npm.any_file_contains("install_script", "deploy-keys") or
            npm.any_file_contains("install_script", ".dockercfg") or
            npm.any_file_contains("install_script", "KEYS *") or
            npm.any_file_contains("install_script", "DBSIZE") or
            npm.any_file_contains("install_script", "new net.Socket()") or
            npm.any_file_contains("install_script", "redisCmd(")
        ) and
        (
            npm.any_file_contains("install_script", "/poll") or
            npm.any_file_contains("install_script", "/beacon") or
            npm.any_file_contains("install_script", "/result") or
            npm.any_file_contains("install_script", "/docker") or
            npm.any_file_contains("install_script", "/wallet") or
            npm.any_file_contains("install_script", "/keys") or
            npm.any_file_contains("install_script", "/redis") or
            npm.any_file_contains("install_script", "/env") or
            npm.any_file_contains("install_script", "/config") or
            npm.any_file_contains("install_script", "/deploy-keys") or
            npm.any_file_contains("install_script", "/docker-sock") or
            npm.any_file_contains("install_script", "/db")
        )
}

rule npm_install_redis_reverse_shell_dropper : malware npm installer redis shell
{
    meta:
        score = 10
        description = "npm install-time lifecycle target plants or executes a reverse shell through Redis or a downloaded shell payload"
    condition:
        npm.is_npm and
        npm.has_install_script and
        npm.file_count("install_script") > 0 and
        (
            npm.any_file_contains("install_script", "curl -s http://") or
            npm.any_file_contains("install_script", "curl http://") or
            npm.any_file_contains("install_script", "wget http://") or
            npm.any_file_contains("install_script", "/shell.sh|bash") or
            npm.any_file_contains("install_script", "/shell.sh -o /tmp/")
        ) and
        (
            npm.any_file_contains("install_script", "bash -i >& /dev/tcp/") or
            npm.any_file_contains("install_script", "socket.socket();s.connect((") or
            npm.any_file_contains("install_script", "subprocess.call(['\\/bin\\/bash','-i'])") or
            npm.any_file_contains("install_script", "subprocess.call([\\'/bin/bash\\',\\'-i\\'])") or
            npm.any_file_contains("install_script", "nohup bash /tmp/") or
            npm.any_file_contains("install_script", "nohup bash -c")
        ) and
        (
            npm.any_file_contains("install_script", "CONFIG SET dir") or
            npm.any_file_contains("install_script", "dbfilename") or
            npm.any_file_contains("install_script", "redisCmd(") or
            npm.any_file_contains("install_script", "new net.Socket()") or
            npm.any_file_contains("install_script", "/var/lib/redis")
        )
}

rule npm_install_persistent_shell_backdoor : malware npm installer shell backdoor
{
    meta:
        score = 10
        description = "npm install-time lifecycle target installs a detached polling shell backdoor with command execution or cron persistence"
    condition:
        npm.is_npm and
        npm.has_install_script and
        npm.file_count("install_script") > 0 and
        (
            npm.any_file_contains("install_script", "http.request(") or
            npm.any_file_contains("install_script", "https.request(")
        ) and
        (
            npm.any_file_contains("install_script", "/shell/poll") or
            npm.any_file_contains("install_script", "/bshell/poll") or
            npm.any_file_contains("install_script", "/shell/result") or
            npm.any_file_contains("install_script", "/bshell/result")
        ) and
        (
            npm.any_file_contains("install_script", "exec(d.trim()") or
            npm.any_file_contains("install_script", "execSync(d.trim()") or
            npm.any_file_contains("install_script", "child_process').execSync") or
            npm.any_file_contains("install_script", "child_process\").execSync")
        ) and
        (
            npm.any_file_contains("install_script", "detached: true") or
            npm.any_file_contains("install_script", "child.unref()") or
            npm.any_file_contains("install_script", "unref();") or
            npm.any_file_contains("install_script", "crontab -l") or
            npm.any_file_contains("install_script", "pgrep -f") or
            npm.any_file_contains("install_script", "/tmp/.node_")
        )
}

rule npm_runtime_environment_callback_probe : malware npm runtime recon exfil
{
    meta:
        score = 8
        description = "npm runtime entrypoint fingerprints the host or user context and exfiltrates it to a collaborator-style callback"
    condition:
        npm.is_npm and
        npm.file_count("entrypoint") > 0 and
        (
            npm.any_file_contains("entrypoint", "dns.resolve(") or
            npm.any_file_contains("entrypoint", "dns.lookup(") or
            npm.any_file_contains("entrypoint", "dns.getServers(") or
            npm.any_file_contains("entrypoint", "https.request(") or
            npm.any_file_contains("entrypoint", "http.request(") or
            npm.any_file_contains("entrypoint", "fetch(")
        ) and
        (
            npm.any_file_contains("entrypoint", ".oast.") or
            npm.any_file_contains("entrypoint", ".oastify.com") or
            npm.any_file_contains("entrypoint", ".interact.sh") or
            npm.any_file_contains("entrypoint", "burpcollaborator") or
            npm.any_file_contains("entrypoint", "hookbin.com") or
            npm.any_file_contains("entrypoint", "webhook.site")
        ) and
        (
            npm.any_file_contains("entrypoint", "req.write(") or
            npm.any_file_contains("entrypoint", "body: JSON.stringify(") or
            npm.any_file_contains("entrypoint", "body: payload") or
            npm.any_file_contains("entrypoint", "JSON.stringify(payload)") or
            npm.any_file_contains("entrypoint", "JSON.stringify(data)") or
            npm.any_file_contains("entrypoint", "JSON.stringify({") or
            npm.any_file_contains("entrypoint", "new URLSearchParams(")
        ) and
        (
            npm.any_file_contains("entrypoint", "execSync(") or
            npm.any_file_contains("entrypoint", "spawnSync(") or
            npm.any_file_contains("entrypoint", "child_process")
        ) and
        (
            npm.any_file_contains("entrypoint", "os.networkInterfaces(") or
            npm.any_file_contains("entrypoint", "os.homedir(") or
            npm.any_file_contains("entrypoint", "os.tmpdir(") or
            npm.any_file_contains("entrypoint", "os.hostname(") or
            npm.any_file_contains("entrypoint", "os.userInfo(") or
            npm.any_file_contains("entrypoint", "process.env.PATH") or
            npm.any_file_contains("entrypoint", "process.env.HOME") or
            npm.any_file_contains("entrypoint", "process.env.USER") or
            npm.any_file_contains("entrypoint", "process.env.USERNAME") or
            npm.any_file_contains("entrypoint", "process.cwd(") or
            npm.any_file_contains("entrypoint", "process.pid") or
            npm.any_file_contains("entrypoint", "process.argv")
        ) and
        (
            npm.any_file_contains("entrypoint", "whoami") or
            npm.any_file_contains("entrypoint", "execSync('id'") or
            npm.any_file_contains("entrypoint", "execSync(\"id\"") or
            npm.any_file_contains("entrypoint", "spawnSync('id'") or
            npm.any_file_contains("entrypoint", "spawnSync(\"id\"") or
            npm.any_file_contains("entrypoint", "execSync('pwd'") or
            npm.any_file_contains("entrypoint", "execSync(\"pwd\"") or
            npm.any_file_contains("entrypoint", "spawnSync('pwd'") or
            npm.any_file_contains("entrypoint", "spawnSync(\"pwd\"") or
            npm.any_file_contains("entrypoint", "/etc/resolv.conf") or
            npm.any_file_contains("entrypoint", "ifconfig") or
            npm.any_file_contains("entrypoint", "ip a") or
            npm.any_file_contains("entrypoint", "uname -a")
        )
}

rule npm_wallet_or_session_theft_markers : malware npm theft
{
    meta:
        score = 7
        description = "npm entrypoint contains multiple browser, wallet, Discord, or local session theft markers"
    condition:
        npm.is_npm and
        npm.any_file_contains("entrypoint", "discord_desktop_core") and
        (
            npm.any_file_contains("entrypoint", "Local Storage\\\\leveldb") or
            npm.any_file_contains("entrypoint", "Local State") or
            npm.any_file_contains("entrypoint", "chrome-extension://") or
            npm.any_file_contains("entrypoint", "Exodus") or
            npm.any_file_contains("entrypoint", "Telegram Desktop")
        )
}

rule npm_openclaw_qbot_family : malware npm campaign
{
    meta:
        score = 8
        description = "npm package matches the OpenClaw qbot family manifest fingerprint"
    condition:
        npm.is_npm and
        npm.has_bin_named("qb-qbot-claw") and
        npm.depends_on("koffi") and
        npm.depends_on("tar") and
        npm.depends_on("ws")
}

rule generic_discord_or_telegram_exfil : malware exfil
{
    meta:
        score = 6
        description = "content embeds a Discord webhook or Telegram bot token for exfiltration"
    strings:
        $discord = "discord.com/api/webhooks/" nocase
        $discord_app = "discordapp.com/api/webhooks/" nocase
        $discord_ptb = "ptb.discord.com/api/webhooks/" nocase
        $telegram = /[0-9]{8,10}:AA[A-Za-z0-9_-]{33}/
    condition:
        1 of them
}

rule pypi_build_hook_downloader : malware pypi build
{
    meta:
        score = 8
        description = "Python build script downloads remote content and pipes it to exec or runs it via subprocess shell"
    condition:
        pypi.is_pypi and
        pypi.file_count("build_script") > 0 and
        (
            pypi.any_file_contains("build_script", "urllib.request.urlopen(") or
            pypi.any_file_contains("build_script", "requests.get(")
        ) and
        (
            pypi.any_file_contains("build_script", "exec(") or
            pypi.any_file_contains("build_script", "eval(") or
            pypi.any_file_contains("build_script", "os.system(") or
            pypi.any_file_contains("build_script", "subprocess.call(") or
            pypi.any_file_contains("build_script", "subprocess.Popen(") or
            pypi.any_file_contains("build_script", "subprocess.run(")
        )
}

rule pypi_setup_remote_payload_exec : malware pypi build downloader loader
{
    meta:
        score = 9
        description = "PyPI setup.py build script downloads remote content and executes it dynamically via exec/eval/shell at build time, running attacker-controlled code during pip install"
    condition:
        pypi.is_pypi and
        pypi.file_count("build_script") > 0 and
        (
            // Remote-content sources. A legitimate bootstrap downloads a
            // prebuilt binary/wheel as a file; it does not fetch an HTTP
            // body to interpret. `curl`/`wget` are covered by the
            // pipe-to-shell rules and the generic archive-view rules.
            pypi.any_file_contains("build_script", "urllib.request.urlopen(") or
            pypi.any_file_contains("build_script", "urlopen(") or
            pypi.any_file_contains("build_script", "requests.get(") or
            pypi.any_file_contains("build_script", "requests.post(") or
            pypi.any_file_contains("build_script", "httpx.")
        ) and
        (
            // Dynamic-execution sinks: the fetched content (or content
            // derived from it) runs through exec/eval/compile or a shell
            // interpreter. subprocess with shell=True interprets an
            // attacker-controlled command string; a benign build runs a
            // FIXED argv (subprocess.run(["curl", ...])) or a fixed binary
            // path after writing the download to disk.
            pypi.any_file_contains("build_script", "exec(") or
            pypi.any_file_contains("build_script", "eval(") or
            pypi.any_file_contains("build_script", "os.system(") or
            pypi.any_file_contains("build_script", "shell=True") or
            pypi.any_file_contains("build_script", "shell = True") or
            pypi.any_file_contains("build_script", "exec(compile(") or
            pypi.any_file_contains("build_script", "eval(compile(")
        )
}

rule pypi_in_memory_payload_loader : malware pypi loader generic
{
    meta:
        score = 9
        description = "PyPI package entrypoint loads a remote payload into memory using Linux memfd-style execution"
    condition:
        pypi.is_pypi and
        pypi.file_count("entrypoint") > 0 and
        (
            pypi.any_file_contains("entrypoint", "memfd_create") or
            pypi.any_file_contains("entrypoint", "/proc/self/fd")
        ) and
        (
            pypi.any_file_contains("entrypoint", "http://") or
            pypi.any_file_contains("entrypoint", "https://")
        ) and
        (
            pypi.any_file_contains("entrypoint", "subprocess") or
            pypi.any_file_contains("entrypoint", "os.system") or
            pypi.any_file_contains("entrypoint", "requests.get(") or
            pypi.any_file_contains("entrypoint", "urllib.request")
        )
}

rule pypi_exfil_channel_with_theft_markers : malware pypi exfil generic
{
    meta:
        score = 8
        description = "PyPI package code contains an exfiltration endpoint together with browser, wallet, or session theft markers"
    condition:
        pypi.is_pypi and
        (
            pypi.any_file_contains("build_script", "discord.com/api/webhooks/") or
            pypi.any_file_contains("build_script", "discordapp.com/api/webhooks/") or
            pypi.any_file_contains("build_script", "ptb.discord.com/api/webhooks/") or
            pypi.any_file_contains("build_script", "api.telegram.org/bot") or
            pypi.any_file_contains("entrypoint", "discord.com/api/webhooks/") or
            pypi.any_file_contains("entrypoint", "discordapp.com/api/webhooks/") or
            pypi.any_file_contains("entrypoint", "ptb.discord.com/api/webhooks/") or
            pypi.any_file_contains("entrypoint", "api.telegram.org/bot")
        ) and
        (
            pypi.any_file_contains("build_script", "discord_desktop_core") or
            pypi.any_file_contains("build_script", "Local Storage\\\\leveldb") or
            pypi.any_file_contains("build_script", "Local State") or
            pypi.any_file_contains("build_script", "chrome-extension://") or
            pypi.any_file_contains("build_script", "Exodus") or
            pypi.any_file_contains("build_script", "Telegram Desktop") or
            pypi.any_file_contains("entrypoint", "discord_desktop_core") or
            pypi.any_file_contains("entrypoint", "Local Storage\\\\leveldb") or
            pypi.any_file_contains("entrypoint", "Local State") or
            pypi.any_file_contains("entrypoint", "chrome-extension://") or
            pypi.any_file_contains("entrypoint", "Exodus") or
            pypi.any_file_contains("entrypoint", "Telegram Desktop")
        )
}

rule crate_build_script_downloader : malware crates build
{
    meta:
        score = 7
        description = "Rust build script uses an HTTP client library or shell download command to fetch and execute remote content"
    condition:
        crate.is_crate and
        crate.has_build_rs and
        (
            crate.build_rs_contains("reqwest") or
            crate.build_rs_contains("ureq") or
            crate.build_rs_contains("Command::new(\"curl\"") or
            crate.build_rs_contains("Command::new(\"wget\"")
        ) and
        (
            crate.build_rs_contains("Command::new(\"sh\"") or
            crate.build_rs_contains("Command::new(\"bash\"") or
            crate.build_rs_contains("Command::new(\"cmd\"") or
            crate.build_rs_contains("Command::new(\"powershell\"") or
            crate.build_rs_contains("chmod") or
            crate.build_rs_contains("fs::write(")
        )
}

rule crate_build_remote_payload_exec : malware crates build downloader loader
{
    meta:
        score = 9
        description = "Rust build.rs downloads remote content and pipes the fetched bytes into a shell interpreter or a -c command string, executing attacker-controlled code during cargo build"
    condition:
        crate.is_crate and
        crate.has_build_rs and
        (
            // Remote-content sources: an HTTP client in the build script or
            // an external downloader process. A legitimate build that needs
            // a prebuilt artifact fetches it and writes it to OUT_DIR.
            crate.build_rs_contains("reqwest::") or
            crate.build_rs_contains("ureq::") or
            crate.build_rs_contains("Command::new(\"curl\"") or
            crate.build_rs_contains("Command::new(\"wget\"")
        ) and
        (
            // Shell sinks with an interpret command string or a piped
            // stdin. A downloaded file run via a fixed path (or sh with a
            // fixed script argument) never carries -c or stdin piping.
            crate.build_rs_contains("Command::new(\"sh\"") or
            crate.build_rs_contains("Command::new(\"bash\"") or
            crate.build_rs_contains("Command::new(\"/bin/sh\"") or
            crate.build_rs_contains("Command::new(\"/bin/bash\"")
        ) and
        (
            crate.build_rs_contains(".arg(\"-c\")") or
            crate.build_rs_contains("Stdio::piped()") or
            crate.build_rs_contains("stdin(")
        )
}

rule crate_exfil_channel_with_theft_markers : malware crates exfil generic
{
    meta:
        score = 8
        description = "Rust crate runtime contains an exfiltration endpoint together with browser, wallet, or session theft markers"
    condition:
        crate.is_crate and
        crate.file_count("entrypoint") > 0 and
        (
            crate.any_file_contains("entrypoint", "discord.com/api/webhooks/") or
            crate.any_file_contains("entrypoint", "discordapp.com/api/webhooks/") or
            crate.any_file_contains("entrypoint", "ptb.discord.com/api/webhooks/") or
            crate.any_file_contains("entrypoint", "api.telegram.org/bot")
        ) and
        (
            crate.any_file_contains("entrypoint", "discord_desktop_core") or
            crate.any_file_contains("entrypoint", "Local Storage\\\\leveldb") or
            crate.any_file_contains("entrypoint", "Local State") or
            crate.any_file_contains("entrypoint", "chrome-extension://") or
            crate.any_file_contains("entrypoint", "Exodus") or
            crate.any_file_contains("entrypoint", "Telegram Desktop")
        )
}

// ---------------------------------------------------------------------------
//  NPM — obfuscation, crypto theft, credential theft, persistence, miners
// ---------------------------------------------------------------------------

rule npm_string_construction_obfuscation : suspicious npm obfuscation
{
    meta:
        score = 7
        description = "npm entrypoint constructs strings dynamically via bracket-notation fromCharCode or hex replacement to hide API calls, a technique used by typosquatting stealers and encoded loaders"
    condition:
        npm.is_npm and
        npm.file_count("entrypoint") > 0 and
        not npm.has_repository and
        (
            npm.any_file_contains("entrypoint", "String['fromCharCode'](") or
            npm.any_file_contains("entrypoint", "String[\"fromCharCode\"](") or
            npm.any_file_contains("entrypoint", "parseInt(match, 16))")
        ) and
        (
            npm.any_file_contains("entrypoint", "child_process") or
            npm.any_file_contains("entrypoint", "eval(") or
            npm.any_file_contains("entrypoint", "new Function(")
        ) and
        (
            npm.any_file_contains("entrypoint", "https.get(") or
            npm.any_file_contains("entrypoint", "http.get(") or
            npm.any_file_contains("entrypoint", "https.request(") or
            npm.any_file_contains("entrypoint", "http.request(")
        )
}

rule npm_indirect_eval_payload : malware npm obfuscation loader
{
    meta:
        score = 9
        description = "npm entrypoint uses indirect eval (0,eval)() or chunked config with Module._compile to execute a hidden payload, as seen in SANDWORM and chalk/debug compromises"
    condition:
        npm.is_npm and
        npm.file_count("entrypoint") > 0 and
        (
            npm.any_file_contains("entrypoint", "(0,eval)(") or
            npm.any_file_contains("entrypoint", "(0, eval)(")
        ) and
        (
            npm.any_file_contains("entrypoint", "zlib.inflateSync(") or
            npm.any_file_contains("entrypoint", "_cfg_0")
        )
}

rule npm_bulk_env_exfiltration : malware npm exfil recon
{
    meta:
        score = 9
        description = "npm code serializes process.env in bulk and sends it to a remote endpoint, a hallmark of dependency confusion and typosquatting probes"
    condition:
        npm.is_npm and
        (
            npm.any_file_contains("entrypoint", "JSON.stringify(process.env)") or
            npm.any_file_contains("entrypoint", "JSON.stringify(process['env'])") or
            npm.any_file_contains("install_script", "JSON.stringify(process.env)") or
            npm.any_file_contains("install_script", "JSON.stringify(process['env'])")
        ) and
        (
            npm.any_file_contains("entrypoint", "https.request(") or
            npm.any_file_contains("entrypoint", "http.request(") or
            npm.any_file_contains("entrypoint", "fetch(") or
            npm.any_file_contains("entrypoint", "axios") or
            npm.any_file_contains("install_script", "https.request(") or
            npm.any_file_contains("install_script", "http.request(") or
            npm.any_file_contains("install_script", "fetch(") or
            npm.any_file_contains("install_script", "dns.resolve(")
        )
}

rule npm_ssh_or_cloud_credential_theft : malware npm theft credential
{
    meta:
        score = 9
        description = "npm entrypoint reads SSH private keys, AWS credentials, or cloud config files and combines with network exfiltration"
    condition:
        npm.is_npm and
        npm.file_count("entrypoint") > 0 and
        not npm.has_repository and
        (
            npm.any_file_contains("entrypoint", "fs.readFileSync(") or
            npm.any_file_contains("entrypoint", "fs.readFile(") or
            npm.any_file_contains("entrypoint", "fs.promises.readFile(")
        ) and
        (
            npm.any_file_contains("entrypoint", ".ssh/id_rsa") or
            npm.any_file_contains("entrypoint", ".ssh/id_ed25519") or
            npm.any_file_contains("entrypoint", ".aws/credentials") or
            npm.any_file_contains("entrypoint", ".kube/config") or
            npm.any_file_contains("entrypoint", ".git-credentials") or
            npm.any_file_contains("entrypoint", "application_default_credentials.json") or
            npm.any_file_contains("entrypoint", ".config/solana/id.json")
        ) and
        (
            npm.any_file_contains("entrypoint", "https.request(") or
            npm.any_file_contains("entrypoint", "http.request(") or
            npm.any_file_contains("entrypoint", "discord.com/api/webhooks/") or
            npm.any_file_contains("entrypoint", "api.telegram.org/bot")
        )
}

rule npm_install_ssh_or_cloud_credential_theft : malware npm theft credential installer
{
    meta:
        score = 9
        description = "npm install script reads SSH, cloud, or registry credentials and exfiltrates them"
    condition:
        npm.is_npm and
        npm.has_install_script and
        npm.file_count("install_script") > 0 and
        (
            npm.any_file_contains("install_script", "fs.readFileSync(") or
            npm.any_file_contains("install_script", "fs.readFile(") or
            npm.any_file_contains("install_script", "child_process")
        ) and
        (
            npm.any_file_contains("install_script", ".ssh/id_rsa") or
            npm.any_file_contains("install_script", ".ssh/id_ed25519") or
            npm.any_file_contains("install_script", ".aws/credentials") or
            npm.any_file_contains("install_script", ".npmrc") or
            npm.any_file_contains("install_script", ".git-credentials") or
            npm.any_file_contains("install_script", ".kube/config") or
            npm.any_file_contains("install_script", ".docker/config.json") or
            npm.any_file_contains("install_script", "application_default_credentials.json")
        ) and
        (
            npm.any_file_contains("install_script", "https.request(") or
            npm.any_file_contains("install_script", "http.request(") or
            npm.any_file_contains("install_script", "fetch(") or
            npm.any_file_contains("install_script", "dns.resolve(") or
            npm.any_file_contains("install_script", "axios") or
            npm.any_file_contains("install_script", "discord.com/api/webhooks/") or
            npm.any_file_contains("install_script", "api.telegram.org/bot")
        )
}

rule npm_crypto_wallet_file_theft : malware npm theft crypto
{
    meta:
        score = 9
        description = "npm entrypoint accesses cryptocurrency wallet files or Solana keypair for theft, as seen in wallet-draining campaigns"
    condition:
        npm.is_npm and
        npm.file_count("entrypoint") > 0 and
        not npm.has_repository and
        (
            npm.any_file_contains("entrypoint", "fs.readFileSync(") or
            npm.any_file_contains("entrypoint", "fs.readFile(") or
            npm.any_file_contains("entrypoint", "fs.readdirSync(")
        ) and
        (
            npm.any_file_contains("entrypoint", "exodus.wallet") or
            npm.any_file_contains("entrypoint", "seed.seco") or
            npm.any_file_contains("entrypoint", "wallet.dat") or
            npm.any_file_contains("entrypoint", ".electrum/wallets") or
            npm.any_file_contains("entrypoint", ".ethereum/keystore") or
            npm.any_file_contains("entrypoint", ".bitmonero") or
            npm.any_file_contains("entrypoint", ".config/solana/id.json") or
            npm.any_file_contains("entrypoint", ".bitcoin/wallet.dat")
        ) and
        (
            npm.any_file_contains("entrypoint", "https.request(") or
            npm.any_file_contains("entrypoint", "http.request(") or
            npm.any_file_contains("entrypoint", "discord.com/api/webhooks/") or
            npm.any_file_contains("entrypoint", "api.telegram.org/bot") or
            npm.any_file_contains("entrypoint", "form-data")
        )
}

rule npm_electron_app_injection : malware npm injection electron
{
    meta:
        score = 9
        description = "npm entrypoint writes into Electron app.asar or wallet application files to backdoor desktop apps, as seen in pdf-to-office and Discord injection campaigns"
    condition:
        npm.is_npm and
        npm.file_count("entrypoint") > 0 and
        not npm.has_repository and
        (
            npm.any_file_contains("entrypoint", "discord_desktop_core/index.js") or
            npm.any_file_contains("entrypoint", "electron/vendors.")
        ) and
        (
            npm.any_file_contains("entrypoint", "fs.writeFileSync(") or
            npm.any_file_contains("entrypoint", "fs.writeFile(") or
            npm.any_file_contains("entrypoint", "fs.appendFileSync(") or
            npm.any_file_contains("entrypoint", "fs.copyFileSync(")
        )
}

rule npm_shell_profile_persistence : malware npm persistence
{
    meta:
        score = 9
        description = "npm install script silently writes to shell profiles (.bashrc, .zshrc) for persistence, as seen in GhostClaw campaign"
    condition:
        npm.is_npm and
        npm.has_install_script and
        npm.file_count("install_script") > 0 and
        (
            npm.any_file_contains("install_script", ".bashrc") or
            npm.any_file_contains("install_script", ".zshrc") or
            npm.any_file_contains("install_script", ".bash_profile") or
            npm.any_file_contains("install_script", ".zshenv")
        ) and
        (
            npm.any_file_contains("install_script", "fs.appendFileSync(") or
            npm.any_file_contains("install_script", "fs.writeFileSync(") or
            npm.any_file_contains("install_script", ">> ~/") or
            npm.any_file_contains("install_script", "echo ")
        )
}

rule npm_git_hook_injection : malware npm persistence worm
{
    meta:
        score = 10
        description = "npm code injects git hooks or modifies git template directories for worm-like propagation, as seen in SANDWORM_MODE"
    condition:
        npm.is_npm and
        (
            npm.any_file_contains("entrypoint", "git config --global init.templateDir") or
            npm.any_file_contains("entrypoint", ".git-templates") or
            npm.any_file_contains("entrypoint", ".git/hooks/pre-commit") or
            npm.any_file_contains("entrypoint", ".git/hooks/pre-push") or
            npm.any_file_contains("entrypoint", ".git/hooks/post-commit") or
            npm.any_file_contains("install_script", "git config --global init.templateDir") or
            npm.any_file_contains("install_script", ".git-templates") or
            npm.any_file_contains("install_script", ".git/hooks/pre-commit") or
            npm.any_file_contains("install_script", ".git/hooks/pre-push")
        ) and
        (
            npm.any_file_contains("entrypoint", "fs.writeFileSync(") or
            npm.any_file_contains("entrypoint", "child_process") or
            npm.any_file_contains("entrypoint", "execSync(") or
            npm.any_file_contains("install_script", "fs.writeFileSync(") or
            npm.any_file_contains("install_script", "child_process") or
            npm.any_file_contains("install_script", "execSync(")
        )
}

rule npm_mcp_server_injection : malware npm persistence ai
{
    meta:
        score = 10
        description = "npm code injects a rogue MCP server configuration into AI coding tools (Claude Code, Cursor, VS Code Continue, Windsurf), as documented in SANDWORM_MODE"
    condition:
        npm.is_npm and
        not npm.depends_on("@modelcontextprotocol/sdk") and
        not npm.depends_on("@modelcontextprotocol/sdk", "devDependencies") and
        (
            npm.any_file_contains("entrypoint", ".claude/settings.json") or
            npm.any_file_contains("entrypoint", ".cursor/mcp.json") or
            npm.any_file_contains("entrypoint", ".continue/config.json") or
            npm.any_file_contains("entrypoint", ".windsurf/mcp.json") or
            npm.any_file_contains("entrypoint", "MCP_SERVER_NAME") or
            npm.any_file_contains("install_script", ".claude/settings.json") or
            npm.any_file_contains("install_script", ".cursor/mcp.json") or
            npm.any_file_contains("install_script", ".continue/config.json") or
            npm.any_file_contains("install_script", ".windsurf/mcp.json")
        ) and
        (
            npm.any_file_contains("entrypoint", "fs.writeFileSync(") or
            npm.any_file_contains("install_script", "fs.writeFileSync(")
        ) and
        (
            npm.any_file_contains("entrypoint", "mcpServers") or
            npm.any_file_contains("entrypoint", "command") or
            npm.any_file_contains("install_script", "mcpServers") or
            npm.any_file_contains("install_script", "command")
        )
}

rule npm_ethereum_transaction_hook : malware npm crypto hook
{
    meta:
        score = 10
        description = "npm code intercepts Ethereum transaction methods via proxy or prototype replacement to redirect cryptocurrency, as seen in the September 2025 chalk/debug compromise"
    condition:
        npm.is_npm and
        npm.file_count("entrypoint") > 0 and
        (
            npm.any_file_contains("entrypoint", "stealthProxyControl") or
            npm.any_file_contains("entrypoint", "Proxy(window.ethereum") or
            npm.any_file_contains("entrypoint", "new Proxy(")
        ) and
        (
            npm.any_file_contains("entrypoint", "0x095ea7b3") or
            npm.any_file_contains("entrypoint", "0xa9059cbb") or
            npm.any_file_contains("entrypoint", "0x23b872dd") or
            npm.any_file_contains("entrypoint", "0xd505accf")
        ) and
        (
            npm.any_file_contains("entrypoint", "window.ethereum") or
            npm.any_file_contains("entrypoint", "ethereum.request(")
        )
}

rule npm_npm_token_worm_propagation : malware npm worm
{
    meta:
        score = 10
        description = "npm code extracts npm auth tokens and calls registry APIs to enumerate and republish packages, enabling worm-like self-propagation as seen in Shai-Hulud"
    condition:
        npm.is_npm and
        (
            npm.any_file_contains("entrypoint", "registry.npmjs.org/-/whoami") or
            npm.any_file_contains("entrypoint", "registry.npmjs.org/-/user") or
            npm.any_file_contains("install_script", "registry.npmjs.org/-/whoami") or
            npm.any_file_contains("install_script", "registry.npmjs.org/-/user")
        ) and
        (
            npm.any_file_contains("entrypoint", ".npmrc") or
            npm.any_file_contains("entrypoint", "NPM_TOKEN") or
            npm.any_file_contains("entrypoint", "npm_config_") or
            npm.any_file_contains("entrypoint", "NODE_AUTH_TOKEN") or
            npm.any_file_contains("install_script", ".npmrc") or
            npm.any_file_contains("install_script", "NPM_TOKEN")
        )
}

rule npm_installer_bun_downloader_local_payload : suspicious npm downloader installer loader
{
    meta:
        score = 8
        description = "npm install script downloads Bun from release artifacts, extracts a local runtime, and executes a package-local JavaScript payload"
    condition:
        npm.is_npm and
        npm.has_install_script and
        npm.file_count("install_script") > 0 and
        npm.any_file_contains("install_script", "github.com/oven-sh/bun/releases/download/bun-v") and
        (
            npm.any_file_contains("install_script", "execFileSync(binPath, [\"") or
            npm.any_file_contains("install_script", "spawnSync(binPath, [\"") or
            npm.any_file_contains("install_script", "spawn(binPath, [\"")
        ) and
        (
            npm.any_file_contains("install_script", "extractFromZip(") or
            npm.any_file_contains("install_script", "_bun_tmp.zip") or
            npm.any_file_contains("install_script", "bun-linux-x64-baseline") or
            npm.any_file_contains("install_script", "bun-windows-x64-baseline")
        ) and
        (
            npm.any_file_contains("install_script", "dist.js") or
            npm.any_file_contains("install_script", "bw1.js")
        )
}

rule npm_github_actions_secret_artifact_exfil : malware npm ci exfil theft
{
    meta:
        score = 10
        description = "npm code writes or embeds a GitHub Actions workflow that serializes secrets into an uploaded artifact"
    condition:
        npm.is_npm and
        (
            npm.any_file_contains("entrypoint", "toJSON(secrets)") or
            npm.any_file_contains("install_script", "toJSON(secrets)")
        ) and
        (
            npm.any_file_contains("entrypoint", "actions/upload-artifact") or
            npm.any_file_contains("install_script", "actions/upload-artifact")
        ) and
        (
            npm.any_file_contains("entrypoint", "format-results") or
            npm.any_file_contains("entrypoint", "VARIABLE_STORE") or
            npm.any_file_contains("install_script", "format-results") or
            npm.any_file_contains("install_script", "VARIABLE_STORE")
        )
}

rule npm_github_actions_runner_memory_secret_scrape : malware npm ci theft recon
{
    meta:
        score = 10
        description = "npm code targets GitHub Actions Runner.Worker process memory to scrape in-memory secret values"
    condition:
        npm.is_npm and
        (
            npm.any_file_contains("entrypoint", "Runner.Worker") or
            npm.any_file_contains("install_script", "Runner.Worker")
        ) and
        (
            npm.any_file_contains("entrypoint", "/proc/") or
            npm.any_file_contains("entrypoint", "/maps") or
            npm.any_file_contains("install_script", "/proc/") or
            npm.any_file_contains("install_script", "/maps")
        ) and
        (
            npm.any_file_contains("entrypoint", "/mem") or
            npm.any_file_contains("install_script", "/mem")
        ) and
        (
            npm.any_file_contains("entrypoint", "isSecret") or
            npm.any_file_contains("entrypoint", "tr -d") or
            npm.any_file_contains("entrypoint", "sort -u") or
            npm.any_file_contains("install_script", "isSecret") or
            npm.any_file_contains("install_script", "tr -d") or
            npm.any_file_contains("install_script", "sort -u")
        )
}

rule npm_cloud_secret_manager_exfiltration : malware npm theft cloud exfil
{
    meta:
        score = 10
        description = "npm code reads cloud secret-manager APIs and combines the access with an exfiltration path"
    condition:
        npm.is_npm and
        (
            (
                (
                    npm.any_file_contains("entrypoint", "SecretManagerServiceClient") or
                    npm.any_file_contains("install_script", "SecretManagerServiceClient")
                ) and
                (
                    npm.any_file_contains("entrypoint", "accessSecretVersion") or
                    npm.any_file_contains("install_script", "accessSecretVersion")
                )
            ) or
            (
                (
                    npm.any_file_contains("entrypoint", "DescribeParameters") or
                    npm.any_file_contains("install_script", "DescribeParameters")
                ) and
                (
                    npm.any_file_contains("entrypoint", "WithDecryption") or
                    npm.any_file_contains("install_script", "WithDecryption")
                )
            ) or
            (
                (
                    npm.any_file_contains("entrypoint", "GetSecretValue") or
                    npm.any_file_contains("install_script", "GetSecretValue")
                ) and
                (
                    npm.any_file_contains("entrypoint", "ListSecrets") or
                    npm.any_file_contains("install_script", "ListSecrets")
                )
            ) or
            (
                (
                    npm.any_file_contains("entrypoint", "KeyVault") or
                    npm.any_file_contains("install_script", "KeyVault")
                ) and
                (
                    npm.any_file_contains("entrypoint", "listSecrets") or
                    npm.any_file_contains("install_script", "listSecrets")
                )
            )
        ) and
        (
            npm.any_file_contains("entrypoint", "createOrUpdateFileContents") or
            npm.any_file_contains("entrypoint", "audit.checkmarx") or
            npm.any_file_contains("entrypoint", "v1/telemetry") or
            npm.any_file_contains("entrypoint", "LongLiveTheResistanceAgainstMachines") or
            npm.any_file_contains("install_script", "createOrUpdateFileContents") or
            npm.any_file_contains("install_script", "audit.checkmarx") or
            npm.any_file_contains("install_script", "v1/telemetry") or
            npm.any_file_contains("install_script", "LongLiveTheResistanceAgainstMachines")
        )
}

rule npm_npm_token_publish_worm_propagation : malware npm worm
{
    meta:
        score = 10
        description = "npm code validates npm tokens, rewrites packages with install-time payloads, and publishes infected tarballs"
    condition:
        npm.is_npm and
        (
            npm.any_file_contains("entrypoint", "/-/npm/v1/tokens") or
            npm.any_file_contains("entrypoint", "registry.npmjs.org/-/npm/v1/tokens") or
            npm.any_file_contains("install_script", "/-/npm/v1/tokens") or
            npm.any_file_contains("install_script", "registry.npmjs.org/-/npm/v1/tokens")
        ) and
        (
            npm.any_file_contains("entrypoint", "bypass_2fa") or
            npm.any_file_contains("entrypoint", "/-/whoami") or
            npm.any_file_contains("install_script", "bypass_2fa") or
            npm.any_file_contains("install_script", "/-/whoami")
        ) and
        (
            npm.any_file_contains("entrypoint", "bun publish") or
            npm.any_file_contains("entrypoint", "package-updated.tgz") or
            npm.any_file_contains("entrypoint", "preinstall") and
            npm.any_file_contains("entrypoint", "setup.mjs") and
            npm.any_file_contains("entrypoint", "dist.js") or
            npm.any_file_contains("install_script", "bun publish") or
            npm.any_file_contains("install_script", "package-updated.tgz") or
            npm.any_file_contains("install_script", "preinstall") and
            npm.any_file_contains("install_script", "setup.mjs") and
            npm.any_file_contains("install_script", "dist.js")
        )
}

rule npm_ci_environment_targeting : suspicious npm recon ci
{
    meta:
        score = 8
        description = "npm code checks for CI/CD environment variables to selectively activate in build pipelines, a technique used in dependency confusion and CI-targeted attacks"
    condition:
        npm.is_npm and
        (
            npm.any_file_contains("entrypoint", "process.env.CI") or
            npm.any_file_contains("entrypoint", "process.env.GITHUB_ACTIONS") or
            npm.any_file_contains("entrypoint", "process.env.GITLAB_CI") or
            npm.any_file_contains("entrypoint", "process.env.CIRCLECI") or
            npm.any_file_contains("entrypoint", "process.env.JENKINS_URL") or
            npm.any_file_contains("entrypoint", "process.env.BUILDKITE") or
            npm.any_file_contains("install_script", "process.env.CI") or
            npm.any_file_contains("install_script", "process.env.GITHUB_ACTIONS") or
            npm.any_file_contains("install_script", "process.env.GITLAB_CI") or
            npm.any_file_contains("install_script", "process.env.JENKINS_URL")
        ) and
        (
            npm.any_file_contains("entrypoint", "https.request(") or
            npm.any_file_contains("entrypoint", "http.request(") or
            npm.any_file_contains("entrypoint", "fetch(") or
            npm.any_file_contains("entrypoint", "dns.resolve(") or
            npm.any_file_contains("entrypoint", "child_process") or
            npm.any_file_contains("install_script", "https.request(") or
            npm.any_file_contains("install_script", "http.request(") or
            npm.any_file_contains("install_script", "dns.resolve(") or
            npm.any_file_contains("install_script", "child_process")
        )
}

rule npm_windows_defender_evasion : malware npm evasion windows
{
    meta:
        score = 10
        description = "npm code disables Windows Defender or adds exclusions to evade detection before dropping a payload"
    condition:
        npm.is_npm and
        (
            npm.any_file_contains("entrypoint", "Add-MpPreference -ExclusionPath") or
            npm.any_file_contains("entrypoint", "Set-MpPreference -DisableRealtimeMonitoring") or
            npm.any_file_contains("entrypoint", "Set-MpPreference -DisableScriptScanning") or
            npm.any_file_contains("entrypoint", "Set-MpPreference -DisableIntrusionPreventionSystem") or
            npm.any_file_contains("install_script", "Add-MpPreference -ExclusionPath") or
            npm.any_file_contains("install_script", "Set-MpPreference -DisableRealtimeMonitoring") or
            npm.any_file_contains("install_script", "Set-MpPreference -DisableScriptScanning") or
            npm.any_file_contains("install_script", "Set-MpPreference -DisableIntrusionPreventionSystem")
        )
}

rule npm_discord_bot_rat : malware npm rat c2
{
    meta:
        score = 9
        description = "npm code implements a Discord-based RAT with command execution, screenshot, or file exfiltration capabilities, as seen in NodeCordRAT"
    condition:
        npm.is_npm and
        npm.file_count("entrypoint") > 0 and
        not npm.has_repository and
        npm.depends_on("discord.js") and
        (
            npm.any_file_contains("entrypoint", "child_process") or
            npm.any_file_contains("entrypoint", "execSync(") or
            npm.any_file_contains("entrypoint", "spawn(") or
            npm.any_file_contains("entrypoint", "spawnSync(")
        ) and
        (
            npm.any_file_contains("entrypoint", "!run") or
            npm.any_file_contains("entrypoint", "!sendfile") or
            npm.any_file_contains("entrypoint", "!screenshot") or
            npm.any_file_contains("entrypoint", "!grab") or
            npm.any_file_contains("entrypoint", "!cmd") or
            npm.any_file_contains("entrypoint", "!shell")
        )
}

rule npm_macos_payload_dropper : malware npm dropper macos
{
    meta:
        score = 10
        description = "npm code drops and executes a macOS binary payload via codesign bypass or hidden Library cache, as documented in BlueNoroff/Lazarus Axios campaign"
    condition:
        npm.is_npm and
        (
            (
                npm.any_file_contains("entrypoint", "codesign --force --deep --sign -") or
                npm.any_file_contains("entrypoint", "/Library/Caches/com.apple.") or
                npm.any_file_contains("install_script", "codesign --force --deep --sign -") or
                npm.any_file_contains("install_script", "/Library/Caches/com.apple.")
            ) and
            (
                npm.any_file_contains("entrypoint", "nohup") or
                npm.any_file_contains("entrypoint", "chmod +x") or
                npm.any_file_contains("install_script", "nohup") or
                npm.any_file_contains("install_script", "chmod +x")
            )
        ) or
        (
            npm.has_install_script and
            npm.file_count("install_script") > 0 and
            (
                npm.any_file_contains("install_script", "osascript") or
                npm.any_file_contains("install_script", "codesign --force")
            ) and
            (
                npm.any_file_contains("install_script", "https.get(") or
                npm.any_file_contains("install_script", "http.get(") or
                npm.any_file_contains("install_script", "curl ") or
                npm.any_file_contains("install_script", "wget ")
            )
        )
}

rule npm_powershell_hidden_execution : malware npm dropper windows
{
    meta:
        score = 9
        description = "npm code launches hidden PowerShell with execution policy bypass or hidden window to run dropped scripts"
    condition:
        npm.is_npm and
        (
            npm.any_file_contains("entrypoint", "powershell") or
            npm.any_file_contains("install_script", "powershell")
        ) and
        (
            (
                // Hidden window execution - always malicious
                npm.any_file_contains("entrypoint", "-w hidden") or
                npm.any_file_contains("entrypoint", "-WindowStyle Hidden") or
                npm.any_file_contains("install_script", "-w hidden") or
                npm.any_file_contains("install_script", "-WindowStyle Hidden")
            ) or
            (
                // Execution policy bypass combined with code execution (not just download)
                (
                    npm.any_file_contains("entrypoint", "-ep bypass") or
                    npm.any_file_contains("entrypoint", "-executionpolicy bypass") or
                    npm.any_file_contains("install_script", "-ep bypass") or
                    npm.any_file_contains("install_script", "-executionpolicy bypass")
                ) and
                (
                    npm.any_file_contains("entrypoint", "Invoke-Expression") or
                    npm.any_file_contains("entrypoint", "IEX(") or
                    npm.any_file_contains("entrypoint", "DownloadString(") or
                    npm.any_file_contains("install_script", "Invoke-Expression") or
                    npm.any_file_contains("install_script", "IEX(") or
                    npm.any_file_contains("install_script", "DownloadString(")
                )
            )
        )
}

rule npm_github_propagation_worm : malware npm worm propagation
{
    meta:
        score = 10
        description = "npm code enumerates GitHub repositories and creates branches or PRs to propagate malware through the developer's repos, as seen in Shai-Hulud and SANDWORM"
    condition:
        npm.is_npm and
        (
            npm.any_file_contains("entrypoint", "api.github.com/user/repos") or
            npm.any_file_contains("entrypoint", "enableAutoMerge") or
            npm.any_file_contains("entrypoint", "/user/repos?per_page=") or
            npm.any_file_contains("install_script", "api.github.com/user/repos") or
            npm.any_file_contains("install_script", "enableAutoMerge")
        ) and
        (
            npm.any_file_contains("entrypoint", "GITHUB_TOKEN") or
            npm.any_file_contains("entrypoint", "ghp_") or
            npm.any_file_contains("entrypoint", "gho_") or
            npm.any_file_contains("entrypoint", "github_pat_") or
            npm.any_file_contains("install_script", "GITHUB_TOKEN") or
            npm.any_file_contains("install_script", "ghp_")
        )
}

rule npm_install_github_commit_secret_exfil : malware npm installer exfil theft worm
{
    meta:
        score = 10
        description = "npm install-time code harvests tokens or local secrets and writes exfiltrated data into GitHub commits, matching TeamPCP-style public repo exfiltration"
    condition:
        npm.is_npm and
        npm.has_install_script and
        npm.file_count("install_script") > 0 and
        (
            npm.any_file_contains("install_script", "createOrUpdateFileContents") or
            npm.any_file_contains("install_script", "repos.createOrUpdateFileContents")
        ) and
        (
            npm.any_file_contains("install_script", "createForAuthenticatedUser") or
            npm.any_file_contains("install_script", "auto_init") or
            npm.any_file_contains("install_script", "/user/repos") or
            npm.any_file_contains("install_script", "users.getAuthenticated")
        ) and
        (
            npm.any_file_contains("install_script", "GITHUB_TOKEN") or
            npm.any_file_contains("install_script", "ghp_") or
            npm.any_file_contains("install_script", "gho_") or
            npm.any_file_contains("install_script", "github_pat_")
        ) and
        (
            npm.any_file_contains("install_script", ".npmrc") or
            npm.any_file_contains("install_script", "NPM_TOKEN") or
            npm.any_file_contains("install_script", "NODE_AUTH_TOKEN") or
            npm.any_file_contains("install_script", "npmtoken") or
            npm.any_file_contains("install_script", ".ssh/id_rsa") or
            npm.any_file_contains("install_script", ".ssh/id_ed25519") or
            npm.any_file_contains("install_script", ".git-credentials") or
            npm.any_file_contains("install_script", ".aws/credentials") or
            npm.any_file_contains("install_script", ".kube/config") or
            npm.any_file_contains("install_script", "application_default_credentials.json") or
            npm.any_file_contains("install_script", ".env")
        )
}

rule npm_browser_wallet_extension_theft : malware npm theft crypto browser
{
    meta:
        score = 8
        description = "npm entrypoint targets specific browser wallet extension IDs (MetaMask, Phantom, Coinbase, etc.) for credential extraction"
    condition:
        npm.is_npm and
        npm.file_count("entrypoint") > 0 and
        (
            npm.any_file_contains("entrypoint", "nkbihfbeogaeaoehlefnkodbefgpgknn") or
            npm.any_file_contains("entrypoint", "bfnaelmomeimhlpmgjnjophhpkkoljpa") or
            npm.any_file_contains("entrypoint", "hnfanknocfeofbddgcijnmhnfnkdnaad") or
            npm.any_file_contains("entrypoint", "ibnejdfjmmkpcnlpebklmnkoeoihofec") or
            npm.any_file_contains("entrypoint", "fhbohimaelbohpjbbldcngcnapndodjp") or
            npm.any_file_contains("entrypoint", "egjidjbpglichdcondbcbdnbeeppgdph") or
            npm.any_file_contains("entrypoint", "fnjhmkhhmkbjkkabndcnnogagogbneec") or
            npm.any_file_contains("entrypoint", "dmkamcknogkgcdfhhbddcghachkejeap")
        ) and
        (
            npm.any_file_contains("entrypoint", "fs.readFileSync(") or
            npm.any_file_contains("entrypoint", "fs.readdirSync(") or
            npm.any_file_contains("entrypoint", "leveldb") or
            npm.any_file_contains("entrypoint", "Local Storage")
        )
}

rule npm_password_manager_theft : malware npm theft credential
{
    meta:
        score = 10
        description = "npm code invokes password manager CLIs (Bitwarden, 1Password, LastPass) to extract sensitive vault entries, as documented in SANDWORM_MODE"
    condition:
        npm.is_npm and
        (
            npm.any_file_contains("entrypoint", "bw list items") or
            npm.any_file_contains("entrypoint", "op item list") or
            npm.any_file_contains("entrypoint", "lpass ls") or
            npm.any_file_contains("install_script", "bw list items") or
            npm.any_file_contains("install_script", "op item list") or
            npm.any_file_contains("install_script", "lpass ls")
        ) and
        (
            npm.any_file_contains("entrypoint", "seed") or
            npm.any_file_contains("entrypoint", "mnemonic") or
            npm.any_file_contains("entrypoint", "wallet") or
            npm.any_file_contains("entrypoint", "metamask") or
            npm.any_file_contains("entrypoint", "bitcoin") or
            npm.any_file_contains("entrypoint", "private") or
            npm.any_file_contains("install_script", "seed") or
            npm.any_file_contains("install_script", "mnemonic") or
            npm.any_file_contains("install_script", "wallet")
        )
}

rule npm_release_toolchain_poisoning : malware npm persistence worm
{
    meta:
        score = 10
        description = "npm code injects into semantic-release or release-it configs to execute malicious code during CI/CD publish workflows, as seen in SANDWORM_MODE"
    condition:
        npm.is_npm and
        (
            npm.any_file_contains("entrypoint", ".releaserc") or
            npm.any_file_contains("entrypoint", ".release-it.json") or
            npm.any_file_contains("entrypoint", "@semantic-release/exec") or
            npm.any_file_contains("install_script", ".releaserc") or
            npm.any_file_contains("install_script", ".release-it.json") or
            npm.any_file_contains("install_script", "@semantic-release/exec")
        ) and
        (
            npm.any_file_contains("entrypoint", "prepareCmd") or
            npm.any_file_contains("entrypoint", "publishCmd") or
            npm.any_file_contains("entrypoint", "fs.writeFileSync(") or
            npm.any_file_contains("install_script", "prepareCmd") or
            npm.any_file_contains("install_script", "publishCmd") or
            npm.any_file_contains("install_script", "fs.writeFileSync(")
        )
}

rule npm_trufflehog_gitleaks_scanner : malware npm recon worm
{
    meta:
        score = 9
        description = "npm install script downloads and executes TruffleHog or Gitleaks to scan repositories for secrets, as seen in Shai-Hulud worm"
    condition:
        npm.is_npm and
        npm.has_install_script and
        npm.file_count("install_script") > 0 and
        (
            npm.any_file_contains("install_script", "trufflehog") or
            npm.any_file_contains("install_script", "gitleaks") or
            npm.any_file_contains("install_script", "truffler-cache")
        ) and
        (
            npm.any_file_contains("install_script", "child_process") or
            npm.any_file_contains("install_script", "execSync(") or
            npm.any_file_contains("install_script", "spawnSync(") or
            npm.any_file_contains("install_script", "curl ") or
            npm.any_file_contains("install_script", "wget ")
        )
}

rule npm_ethereum_smart_contract_c2 : malware npm c2 crypto
{
    meta:
        score = 9
        description = "npm code retrieves C2 configuration from an Ethereum smart contract and executes retrieved code dynamically, as seen in the October 2024 Puppeteer typosquatting campaign"
    condition:
        npm.is_npm and
        npm.file_count("entrypoint") > 0 and
        (
            npm.any_file_contains("entrypoint", "ethers.Contract") or
            npm.any_file_contains("entrypoint", "ethers.providers") or
            npm.any_file_contains("entrypoint", "web3.eth.Contract")
        ) and
        (
            npm.any_file_contains("entrypoint", "getString(") or
            npm.any_file_contains("entrypoint", "getAddress(")
        ) and
        (
            npm.any_file_contains("entrypoint", "eval(") or
            npm.any_file_contains("entrypoint", "new Function(") or
            npm.any_file_contains("entrypoint", "child_process") or
            npm.any_file_contains("entrypoint", "vm.runInThisContext(")
        )
}

rule npm_sandworm_markers : malware npm worm campaign
{
    meta:
        score = 10
        description = "npm code uses SANDWORM_MODE environment variables or DNS propagation infrastructure for worm behavior"
    condition:
        npm.is_npm and
        (
            npm.any_file_contains("entrypoint", "process.env.SANDWORM_MODE") or
            npm.any_file_contains("entrypoint", "process.env.SANDWORM_DNS_DOMAIN") or
            npm.any_file_contains("entrypoint", "process.env['SANDWORM_MODE']") or
            npm.any_file_contains("entrypoint", "process.env[\"SANDWORM_MODE\"]") or
            npm.any_file_contains("install_script", "process.env.SANDWORM_MODE") or
            npm.any_file_contains("install_script", "SANDWORM_MODE") or
            npm.any_file_contains("install_script", "SANDWORM_DNS_DOMAIN")
        )
}

rule npm_ghostclaw_markers : malware npm stealer campaign
{
    meta:
        score = 10
        description = "npm code contains GhostClaw persistence markers in shell profiles"
    condition:
        npm.is_npm and
        (
            npm.any_file_contains("entrypoint", "NPM Telemetry Integration Service") or
            npm.any_file_contains("entrypoint", "Node.js Telemetry Collection") or
            npm.any_file_contains("install_script", "NPM Telemetry Integration Service") or
            npm.any_file_contains("install_script", "Node.js Telemetry Collection")
        )
}

rule npm_cloudflare_workers_exfil : malware npm exfil c2
{
    meta:
        score = 8
        description = "npm code exfiltrates data through Cloudflare Workers endpoints with exfil or drain paths"
    condition:
        npm.is_npm and
        (
            npm.any_file_contains("entrypoint", "workers.dev") or
            npm.any_file_contains("install_script", "workers.dev")
        ) and
        (
            npm.any_file_contains("entrypoint", "/exfil") or
            npm.any_file_contains("entrypoint", "/drain") or
            npm.any_file_contains("entrypoint", "/collect") or
            npm.any_file_contains("install_script", "/exfil") or
            npm.any_file_contains("install_script", "/drain") or
            npm.any_file_contains("install_script", "/collect")
        )
}

// ---------------------------------------------------------------------------
//  PyPI — setup.py abuse, obfuscation, credential theft, RATs, shells
// ---------------------------------------------------------------------------

rule pypi_setup_cmdclass_override : suspicious pypi build hook
{
    meta:
        score = 7
        description = "PyPI package overrides setuptools install command and downloads or executes remote code during pip install"
    condition:
        pypi.is_pypi and
        pypi.file_count("build_script") > 0 and
        (
            pypi.any_file_contains("build_script", "from setuptools.command.install import install") or
            pypi.any_file_contains("build_script", "from setuptools.command.develop import develop") or
            pypi.any_file_contains("build_script", "from distutils.command.install import install")
        ) and
        (
            pypi.any_file_contains("build_script", "urllib.request.urlopen(") or
            pypi.any_file_contains("build_script", "requests.get(") or
            pypi.any_file_contains("build_script", "requests.post(") or
            pypi.any_file_contains("build_script", "exec(") or
            pypi.any_file_contains("build_script", "eval(") or
            pypi.any_file_contains("build_script", "os.system(")
        )
}

rule pypi_base64_exec_chain : malware pypi obfuscation loader
{
    meta:
        score = 9
        description = "PyPI package decodes base64 and pipes directly to exec/eval, the most common obfuscation pattern in W4SP Stealer and similar malware"
    condition:
        pypi.is_pypi and
        (
            pypi.any_file_contains("build_script", "exec(base64.b64decode(") or
            pypi.any_file_contains("build_script", "eval(base64.b64decode(") or
            pypi.any_file_contains("build_script", "exec(b64decode(") or
            pypi.any_file_contains("entrypoint", "exec(base64.b64decode(") or
            pypi.any_file_contains("entrypoint", "eval(base64.b64decode(") or
            pypi.any_file_contains("entrypoint", "exec(b64decode(") or
            pypi.any_file_contains("module", "exec(base64.b64decode(") or
            pypi.any_file_contains("module", "eval(base64.b64decode(") or
            pypi.any_file_contains("module", "exec(b64decode(")
        )
}

rule pypi_marshal_zlib_obfuscation : malware pypi obfuscation loader
{
    meta:
        score = 9
        description = "PyPI package uses marshal.loads with zlib decompression to execute obfuscated bytecode, seen in Pupy RAT and various stealers"
    condition:
        pypi.is_pypi and
        (
            pypi.any_file_contains("build_script", "marshal.loads(") or
            pypi.any_file_contains("entrypoint", "marshal.loads(") or
            pypi.any_file_contains("module", "marshal.loads(")
        ) and
        (
            pypi.any_file_contains("build_script", "zlib.decompress(") or
            pypi.any_file_contains("entrypoint", "zlib.decompress(") or
            pypi.any_file_contains("module", "zlib.decompress(") or
            pypi.any_file_contains("build_script", "exec(") or
            pypi.any_file_contains("entrypoint", "exec(") or
            pypi.any_file_contains("module", "exec(")
        )
}

rule pypi_hex_encoded_execution : malware pypi obfuscation loader
{
    meta:
        score = 8
        description = "PyPI package uses bytes.fromhex() piped to exec/eval to hide malicious code"
    condition:
        pypi.is_pypi and
        (
            pypi.any_file_contains("build_script", "bytes.fromhex(") or
            pypi.any_file_contains("entrypoint", "bytes.fromhex(") or
            pypi.any_file_contains("module", "bytes.fromhex(")
        ) and
        (
            pypi.any_file_contains("build_script", "exec(") or
            pypi.any_file_contains("build_script", "eval(") or
            pypi.any_file_contains("entrypoint", "exec(") or
            pypi.any_file_contains("entrypoint", "eval(") or
            pypi.any_file_contains("module", "exec(") or
            pypi.any_file_contains("module", "eval(")
        )
}

rule pypi_getattr_builtins_indirection : malware pypi obfuscation
{
    meta:
        score = 9
        description = "PyPI package uses getattr/__import__ builtins indirection to hide exec/eval calls, the W4SP Stealer signature obfuscation technique"
    condition:
        pypi.is_pypi and
        (
            pypi.any_file_contains("build_script", "__import__('builtins').exec(") or
            pypi.any_file_contains("build_script", "__import__(\"builtins\").exec(") or
            pypi.any_file_contains("build_script", "getattr(__import__(") or
            pypi.any_file_contains("build_script", "__builtins__.__getattribute__(") or
            pypi.any_file_contains("entrypoint", "__import__('builtins').exec(") or
            pypi.any_file_contains("entrypoint", "__import__(\"builtins\").exec(") or
            pypi.any_file_contains("entrypoint", "getattr(__import__(") or
            pypi.any_file_contains("entrypoint", "__builtins__.__getattribute__(") or
            pypi.any_file_contains("module", "__import__('builtins').exec(") or
            pypi.any_file_contains("module", "__import__(\"builtins\").exec(") or
            pypi.any_file_contains("module", "getattr(__import__(") or
            pypi.any_file_contains("module", "__builtins__.__getattribute__(")
        )
}

rule pypi_fernet_encrypted_payload : malware pypi obfuscation loader
{
    meta:
        score = 8
        description = "PyPI package decrypts a Fernet-encrypted payload and executes it, documented in pyquest/ultrarequests and March 2024 campaign"
    condition:
        pypi.is_pypi and
        (
            pypi.any_file_contains("build_script", "from cryptography.fernet import Fernet") or
            pypi.any_file_contains("entrypoint", "from cryptography.fernet import Fernet") or
            pypi.any_file_contains("module", "from cryptography.fernet import Fernet")
        ) and
        (
            pypi.any_file_contains("build_script", ".decrypt(") or
            pypi.any_file_contains("entrypoint", ".decrypt(") or
            pypi.any_file_contains("module", ".decrypt(")
        ) and
        (
            pypi.any_file_contains("build_script", "exec(") or
            pypi.any_file_contains("entrypoint", "exec(") or
            pypi.any_file_contains("module", "exec(")
        )
}

rule pypi_remote_code_fetch_exec : malware pypi loader
{
    meta:
        score = 9
        description = "PyPI package fetches remote code and immediately executes it via exec/eval"
    condition:
        pypi.is_pypi and
        (
            pypi.any_file_contains("build_script", "urllib.request.urlopen(") or
            pypi.any_file_contains("build_script", "requests.get(") or
            pypi.any_file_contains("build_script", "httpx.get(") or
            pypi.any_file_contains("entrypoint", "urllib.request.urlopen(") or
            pypi.any_file_contains("entrypoint", "requests.get(") or
            pypi.any_file_contains("entrypoint", "httpx.get(")
        ) and
        (
            pypi.any_file_contains("build_script", ".read())") or
            pypi.any_file_contains("build_script", ".text)") or
            pypi.any_file_contains("build_script", ".content)") or
            pypi.any_file_contains("entrypoint", ".read())") or
            pypi.any_file_contains("entrypoint", ".text)") or
            pypi.any_file_contains("entrypoint", ".content)")
        ) and
        (
            pypi.any_file_contains("build_script", "exec(") or
            pypi.any_file_contains("build_script", "eval(") or
            pypi.any_file_contains("entrypoint", "exec(") or
            pypi.any_file_contains("entrypoint", "eval(")
        )
}

rule pypi_ssh_cloud_credential_theft : malware pypi theft credential
{
    meta:
        score = 9
        description = "PyPI package reads SSH keys, cloud credentials, or registry tokens and exfiltrates them"
    condition:
        pypi.is_pypi and
        (
            pypi.any_file_contains("build_script", ".ssh/id_rsa") or
            pypi.any_file_contains("build_script", ".ssh/id_ed25519") or
            pypi.any_file_contains("build_script", ".aws/credentials") or
            pypi.any_file_contains("build_script", ".kube/config") or
            pypi.any_file_contains("build_script", ".docker/config.json") or
            pypi.any_file_contains("build_script", "application_default_credentials.json") or
            pypi.any_file_contains("build_script", ".npmrc") or
            pypi.any_file_contains("build_script", ".git-credentials") or
            pypi.any_file_contains("build_script", ".netrc") or
            pypi.any_file_contains("build_script", ".vault-token") or
            pypi.any_file_contains("entrypoint", ".ssh/id_rsa") or
            pypi.any_file_contains("entrypoint", ".ssh/id_ed25519") or
            pypi.any_file_contains("entrypoint", ".aws/credentials") or
            pypi.any_file_contains("entrypoint", ".kube/config") or
            pypi.any_file_contains("entrypoint", ".docker/config.json") or
            pypi.any_file_contains("entrypoint", "application_default_credentials.json") or
            pypi.any_file_contains("entrypoint", ".git-credentials") or
            pypi.any_file_contains("entrypoint", ".vault-token")
        ) and
        (
            pypi.any_file_contains("build_script", "requests.post(") or
            pypi.any_file_contains("build_script", "urllib.request") or
            pypi.any_file_contains("build_script", "http.client") or
            pypi.any_file_contains("build_script", "discord.com/api/webhooks/") or
            pypi.any_file_contains("build_script", "api.telegram.org/bot") or
            pypi.any_file_contains("entrypoint", "requests.post(") or
            pypi.any_file_contains("entrypoint", "urllib.request") or
            pypi.any_file_contains("entrypoint", "http.client") or
            pypi.any_file_contains("entrypoint", "discord.com/api/webhooks/") or
            pypi.any_file_contains("entrypoint", "api.telegram.org/bot")
        )
}

rule pypi_crypto_wallet_theft : malware pypi theft crypto
{
    meta:
        score = 9
        description = "PyPI package accesses cryptocurrency wallet files for theft"
    condition:
        pypi.is_pypi and
        (
            pypi.any_file_contains("build_script", "exodus.wallet") or
            pypi.any_file_contains("build_script", "wallet.dat") or
            pypi.any_file_contains("build_script", ".electrum/wallets") or
            pypi.any_file_contains("build_script", ".ethereum/keystore") or
            pypi.any_file_contains("build_script", ".config/solana/id.json") or
            pypi.any_file_contains("build_script", "seed.seco") or
            pypi.any_file_contains("entrypoint", "exodus.wallet") or
            pypi.any_file_contains("entrypoint", "wallet.dat") or
            pypi.any_file_contains("entrypoint", ".electrum/wallets") or
            pypi.any_file_contains("entrypoint", ".ethereum/keystore") or
            pypi.any_file_contains("entrypoint", ".config/solana/id.json") or
            pypi.any_file_contains("entrypoint", "seed.seco")
        ) and
        (
            pypi.any_file_contains("build_script", "requests.post(") or
            pypi.any_file_contains("build_script", "urllib.request") or
            pypi.any_file_contains("build_script", "discord.com/api/webhooks/") or
            pypi.any_file_contains("build_script", "api.telegram.org/bot") or
            pypi.any_file_contains("entrypoint", "requests.post(") or
            pypi.any_file_contains("entrypoint", "urllib.request") or
            pypi.any_file_contains("entrypoint", "discord.com/api/webhooks/") or
            pypi.any_file_contains("entrypoint", "api.telegram.org/bot")
        )
}

rule pypi_browser_credential_theft : malware pypi theft browser
{
    meta:
        score = 9
        description = "PyPI package reads browser credential databases and exfiltrates via webhook or HTTP POST"
    condition:
        pypi.is_pypi and
        (
            pypi.any_file_contains("entrypoint", "Login Data") or
            pypi.any_file_contains("entrypoint", "Local Storage\\\\leveldb") or
            pypi.any_file_contains("entrypoint", "logins.json") or
            pypi.any_file_contains("entrypoint", "key4.db") or
            pypi.any_file_contains("module", "Login Data") or
            pypi.any_file_contains("module", "Local Storage\\\\leveldb") or
            pypi.any_file_contains("module", "logins.json") or
            pypi.any_file_contains("module", "key4.db")
        ) and
        (
            pypi.any_file_contains("entrypoint", "CryptUnprotectData") or
            pypi.any_file_contains("entrypoint", "discord.com/api/webhooks/") or
            pypi.any_file_contains("entrypoint", "api.telegram.org/bot") or
            pypi.any_file_contains("module", "CryptUnprotectData") or
            pypi.any_file_contains("module", "discord.com/api/webhooks/") or
            pypi.any_file_contains("module", "api.telegram.org/bot")
        )
}

rule pypi_reverse_shell : malware pypi shell
{
    meta:
        score = 10
        description = "PyPI package contains a reverse shell connecting back to an attacker-controlled host"
    condition:
        pypi.is_pypi and
        (
            pypi.any_file_contains("build_script", "socket.socket(") or
            pypi.any_file_contains("entrypoint", "socket.socket(") or
            pypi.any_file_contains("module", "socket.socket(")
        ) and
        (
            pypi.any_file_contains("build_script", ".connect((") or
            pypi.any_file_contains("entrypoint", ".connect((") or
            pypi.any_file_contains("module", ".connect((")
        ) and
        (
            pypi.any_file_contains("build_script", "subprocess.call(") or
            pypi.any_file_contains("build_script", "os.dup2(") or
            pypi.any_file_contains("build_script", "pty.spawn(") or
            pypi.any_file_contains("build_script", "/bin/bash") or
            pypi.any_file_contains("build_script", "/bin/sh") or
            pypi.any_file_contains("entrypoint", "subprocess.call(") or
            pypi.any_file_contains("entrypoint", "os.dup2(") or
            pypi.any_file_contains("entrypoint", "pty.spawn(") or
            pypi.any_file_contains("entrypoint", "/bin/bash") or
            pypi.any_file_contains("entrypoint", "/bin/sh") or
            pypi.any_file_contains("module", "subprocess.call(") or
            pypi.any_file_contains("module", "os.dup2(") or
            pypi.any_file_contains("module", "pty.spawn(")
        )
}

rule pypi_clipboard_crypto_hijack : malware pypi crypto clipboard
{
    meta:
        score = 9
        description = "PyPI package monitors clipboard for cryptocurrency wallet addresses and replaces them with attacker-controlled addresses, as documented in 451-package Phylum campaign"
    condition:
        pypi.is_pypi and
        (
            pypi.any_file_contains("entrypoint", "pyperclip") or
            pypi.any_file_contains("entrypoint", "clipboard") or
            pypi.any_file_contains("module", "pyperclip") or
            pypi.any_file_contains("module", "clipboard")
        ) and
        (
            pypi.any_file_contains("entrypoint", "paste()") or
            pypi.any_file_contains("entrypoint", "copy(") or
            pypi.any_file_contains("module", "paste()") or
            pypi.any_file_contains("module", "copy(")
        ) and
        (
            pypi.any_file_contains("entrypoint", "0x[a-fA-F0-9]{40}") or
            pypi.any_file_contains("entrypoint", "bc1") or
            pypi.any_file_contains("entrypoint", "re.search(") or
            pypi.any_file_contains("entrypoint", "re.match(") or
            pypi.any_file_contains("module", "0x[a-fA-F0-9]{40}") or
            pypi.any_file_contains("module", "bc1") or
            pypi.any_file_contains("module", "re.search(") or
            pypi.any_file_contains("module", "re.match(")
        )
}

rule pypi_keylogger : malware pypi keylogger
{
    meta:
        score = 9
        description = "PyPI package hooks keyboard input via pynput/pyxhook and exfiltrates keystrokes"
    condition:
        pypi.is_pypi and
        (
            pypi.depends_on("pynput") or
            pypi.depends_on("pyxhook") or
            pypi.any_file_contains("entrypoint", "from pynput") or
            pypi.any_file_contains("entrypoint", "import pynput") or
            pypi.any_file_contains("entrypoint", "import pyxhook") or
            pypi.any_file_contains("module", "from pynput") or
            pypi.any_file_contains("module", "import pyxhook")
        ) and
        (
            pypi.any_file_contains("entrypoint", "on_press") or
            pypi.any_file_contains("entrypoint", "Listener(") or
            pypi.any_file_contains("module", "on_press") or
            pypi.any_file_contains("module", "Listener(")
        ) and
        (
            pypi.any_file_contains("entrypoint", "requests.post(") or
            pypi.any_file_contains("entrypoint", "smtp") or
            pypi.any_file_contains("entrypoint", "discord.com/api/webhooks/") or
            pypi.any_file_contains("entrypoint", "api.telegram.org/bot") or
            pypi.any_file_contains("module", "requests.post(") or
            pypi.any_file_contains("module", "discord.com/api/webhooks/") or
            pypi.any_file_contains("module", "api.telegram.org/bot")
        )
}

rule pypi_anti_analysis_evasion : suspicious pypi evasion
{
    meta:
        score = 7
        description = "PyPI package detects debuggers, analysis tools, or VMs before executing, as documented in JFrog's anti-debug research"
    condition:
        pypi.is_pypi and
        (
            pypi.any_file_contains("entrypoint", "ProcessHacker") or
            pypi.any_file_contains("entrypoint", "wireshark") or
            pypi.any_file_contains("entrypoint", "fiddler") or
            pypi.any_file_contains("entrypoint", "x64dbg") or
            pypi.any_file_contains("entrypoint", "vmGuestLib.dll") or
            pypi.any_file_contains("entrypoint", "vboxmrxnp.dll") or
            pypi.any_file_contains("entrypoint", "VMwareService.exe") or
            pypi.any_file_contains("entrypoint", "VMwareTray.exe") or
            pypi.any_file_contains("module", "ProcessHacker") or
            pypi.any_file_contains("module", "wireshark") or
            pypi.any_file_contains("module", "vmGuestLib.dll") or
            pypi.any_file_contains("module", "vboxmrxnp.dll")
        ) and
        (
            pypi.any_file_contains("entrypoint", "psutil.process_iter(") or
            pypi.any_file_contains("entrypoint", "proc.kill()") or
            pypi.any_file_contains("entrypoint", "sys.exit(") or
            pypi.any_file_contains("entrypoint", "os._exit(") or
            pypi.any_file_contains("module", "psutil.process_iter(") or
            pypi.any_file_contains("module", "proc.kill()")
        )
}

rule pypi_environment_fingerprint_exfil : suspicious pypi recon exfil
{
    meta:
        score = 8
        description = "PyPI build script fingerprints the host environment and exfiltrates it to a remote callback"
    condition:
        pypi.is_pypi and
        pypi.file_count("build_script") > 0 and
        (
            pypi.any_file_contains("build_script", "platform.node(") or
            pypi.any_file_contains("build_script", "platform.uname(") or
            pypi.any_file_contains("build_script", "socket.gethostname(") or
            pypi.any_file_contains("build_script", "os.getlogin(") or
            pypi.any_file_contains("build_script", "getpass.getuser(") or
            pypi.any_file_contains("build_script", "uuid.getnode(")
        ) and
        (
            pypi.any_file_contains("build_script", "requests.post(") or
            pypi.any_file_contains("build_script", "requests.get(") or
            pypi.any_file_contains("build_script", "urllib.request") or
            pypi.any_file_contains("build_script", "http.client") or
            pypi.any_file_contains("build_script", "discord.com/api/webhooks/") or
            pypi.any_file_contains("build_script", "api.telegram.org/bot") or
            pypi.any_file_contains("build_script", ".oastify.com") or
            pypi.any_file_contains("build_script", ".interact.sh") or
            pypi.any_file_contains("build_script", "webhook.site")
        )
}

rule pypi_smtp_exfiltration : malware pypi exfil
{
    meta:
        score = 8
        description = "PyPI package uses SMTP to exfiltrate stolen data via email"
    condition:
        pypi.is_pypi and
        (
            pypi.any_file_contains("entrypoint", "smtplib.SMTP") or
            pypi.any_file_contains("entrypoint", "smtplib.SMTP_SSL") or
            pypi.any_file_contains("module", "smtplib.SMTP") or
            pypi.any_file_contains("module", "smtplib.SMTP_SSL")
        ) and
        (
            pypi.any_file_contains("entrypoint", ".login(") or
            pypi.any_file_contains("entrypoint", "send_message(") or
            pypi.any_file_contains("entrypoint", "sendmail(") or
            pypi.any_file_contains("module", ".login(") or
            pypi.any_file_contains("module", "send_message(") or
            pypi.any_file_contains("module", "sendmail(")
        ) and
        (
            pypi.any_file_contains("entrypoint", "password") or
            pypi.any_file_contains("entrypoint", "token") or
            pypi.any_file_contains("entrypoint", "credential") or
            pypi.any_file_contains("entrypoint", "wallet") or
            pypi.any_file_contains("entrypoint", "cookie") or
            pypi.any_file_contains("entrypoint", ".ssh/") or
            pypi.any_file_contains("module", "password") or
            pypi.any_file_contains("module", "token")
        )
}

rule pypi_aws_imds_recon : malware pypi recon cloud
{
    meta:
        score = 9
        description = "PyPI package queries AWS IMDS or Secrets Manager for cloud credential theft and lateral movement"
    condition:
        pypi.is_pypi and
        (
            pypi.any_file_contains("build_script", "169.254.169.254") or
            pypi.any_file_contains("build_script", "169.254.170.2") or
            pypi.any_file_contains("build_script", "metadata.google.internal") or
            pypi.any_file_contains("entrypoint", "169.254.169.254") or
            pypi.any_file_contains("entrypoint", "169.254.170.2") or
            pypi.any_file_contains("entrypoint", "metadata.google.internal")
        ) and
        (
            pypi.any_file_contains("build_script", "requests") or
            pypi.any_file_contains("build_script", "urllib") or
            pypi.any_file_contains("build_script", "http.client") or
            pypi.any_file_contains("entrypoint", "requests") or
            pypi.any_file_contains("entrypoint", "urllib") or
            pypi.any_file_contains("entrypoint", "http.client")
        )
}

rule pypi_discord_token_theft : malware pypi theft discord
{
    meta:
        score = 9
        description = "PyPI package targets Discord token storage paths for credential theft"
    condition:
        pypi.is_pypi and
        (
            pypi.any_file_contains("entrypoint", "discord") or
            pypi.any_file_contains("entrypoint", "discordcanary") or
            pypi.any_file_contains("entrypoint", "discordptb") or
            pypi.any_file_contains("module", "discord") or
            pypi.any_file_contains("module", "discordcanary") or
            pypi.any_file_contains("module", "discordptb")
        ) and
        (
            pypi.any_file_contains("entrypoint", "leveldb") or
            pypi.any_file_contains("entrypoint", "Local Storage") or
            pypi.any_file_contains("entrypoint", "Local State") or
            pypi.any_file_contains("module", "leveldb") or
            pypi.any_file_contains("module", "Local Storage") or
            pypi.any_file_contains("module", "Local State")
        ) and
        (
            pypi.any_file_contains("entrypoint", "re.findall(") or
            pypi.any_file_contains("entrypoint", "open(") or
            pypi.any_file_contains("entrypoint", "requests.post(") or
            pypi.any_file_contains("module", "re.findall(") or
            pypi.any_file_contains("module", "open(") or
            pypi.any_file_contains("module", "requests.post(")
        )
}

rule pypi_persistence_systemd_or_autostart : malware pypi persistence
{
    meta:
        score = 9
        description = "PyPI package creates systemd services, autostart entries, or LaunchAgents for persistence, as seen in TeamPCP and ESET campaigns"
    condition:
        pypi.is_pypi and
        (
            pypi.any_file_contains("entrypoint", "systemd/user/") or
            pypi.any_file_contains("entrypoint", ".config/autostart/") or
            pypi.any_file_contains("entrypoint", "LaunchAgents/") or
            pypi.any_file_contains("entrypoint", "CurrentVersion\\\\Run") or
            pypi.any_file_contains("entrypoint", "Start Menu\\\\Programs\\\\Startup") or
            pypi.any_file_contains("build_script", "systemd/user/") or
            pypi.any_file_contains("build_script", ".config/autostart/") or
            pypi.any_file_contains("build_script", "LaunchAgents/") or
            pypi.any_file_contains("build_script", "CurrentVersion\\\\Run") or
            pypi.any_file_contains("build_script", "Start Menu\\\\Programs\\\\Startup") or
            pypi.any_file_contains("module", "systemd/user/") or
            pypi.any_file_contains("module", ".config/autostart/") or
            pypi.any_file_contains("module", "LaunchAgents/")
        ) and
        (
            pypi.any_file_contains("entrypoint", "open(") or
            pypi.any_file_contains("entrypoint", "os.makedirs(") or
            pypi.any_file_contains("entrypoint", "subprocess") or
            pypi.any_file_contains("build_script", "open(") or
            pypi.any_file_contains("build_script", "os.makedirs(") or
            pypi.any_file_contains("build_script", "subprocess") or
            pypi.any_file_contains("module", "open(") or
            pypi.any_file_contains("module", "subprocess")
        )
}

rule pypi_ci_environment_targeting : suspicious pypi recon ci
{
    meta:
        score = 7
        description = "PyPI build script checks for CI/CD environment variables to selectively activate"
    condition:
        pypi.is_pypi and
        pypi.file_count("build_script") > 0 and
        (
            pypi.any_file_contains("build_script", "GITHUB_ACTIONS") or
            pypi.any_file_contains("build_script", "GITLAB_CI") or
            pypi.any_file_contains("build_script", "CIRCLECI") or
            pypi.any_file_contains("build_script", "JENKINS_URL") or
            pypi.any_file_contains("build_script", "BUILDKITE")
        ) and
        (
            pypi.any_file_contains("build_script", "subprocess") or
            pypi.any_file_contains("build_script", "os.system(") or
            pypi.any_file_contains("build_script", "requests.") or
            pypi.any_file_contains("build_script", "urllib") or
            pypi.any_file_contains("build_script", "exec(")
        )
}

rule pypi_browser_process_kill_and_theft : malware pypi theft browser
{
    meta:
        score = 9
        description = "PyPI package kills browser processes to unlock credential database files for theft"
    condition:
        pypi.is_pypi and
        (
            pypi.any_file_contains("entrypoint", "taskkill /f /im chrome") or
            pypi.any_file_contains("entrypoint", "taskkill /f /im msedge") or
            pypi.any_file_contains("entrypoint", "taskkill /f /im firefox") or
            pypi.any_file_contains("entrypoint", "taskkill /f /im brave") or
            pypi.any_file_contains("entrypoint", "pkill chrome") or
            pypi.any_file_contains("entrypoint", "pkill firefox") or
            pypi.any_file_contains("module", "taskkill /f /im chrome") or
            pypi.any_file_contains("module", "taskkill /f /im msedge") or
            pypi.any_file_contains("module", "pkill chrome")
        ) and
        (
            pypi.any_file_contains("entrypoint", "Login Data") or
            pypi.any_file_contains("entrypoint", "Cookies") or
            pypi.any_file_contains("entrypoint", "Web Data") or
            pypi.any_file_contains("entrypoint", "Local State") or
            pypi.any_file_contains("module", "Login Data") or
            pypi.any_file_contains("module", "Cookies") or
            pypi.any_file_contains("module", "Web Data")
        )
}

rule pypi_bulk_env_exfiltration : malware pypi exfil recon
{
    meta:
        score = 9
        description = "PyPI package dumps all environment variables in bulk and exfiltrates them"
    condition:
        pypi.is_pypi and
        (
            pypi.any_file_contains("build_script", "dict(os.environ)") or
            pypi.any_file_contains("build_script", "str(os.environ)") or
            pypi.any_file_contains("build_script", "json.dumps(os.environ") or
            pypi.any_file_contains("entrypoint", "dict(os.environ)") or
            pypi.any_file_contains("entrypoint", "str(os.environ)") or
            pypi.any_file_contains("entrypoint", "json.dumps(os.environ") or
            pypi.any_file_contains("module", "dict(os.environ)") or
            pypi.any_file_contains("module", "str(os.environ)") or
            pypi.any_file_contains("module", "json.dumps(os.environ")
        ) and
        (
            pypi.any_file_contains("build_script", "requests.post(") or
            pypi.any_file_contains("build_script", "urllib.request") or
            pypi.any_file_contains("build_script", "http.client") or
            pypi.any_file_contains("build_script", "discord.com/api/webhooks/") or
            pypi.any_file_contains("entrypoint", "requests.post(") or
            pypi.any_file_contains("entrypoint", "urllib.request") or
            pypi.any_file_contains("entrypoint", "discord.com/api/webhooks/") or
            pypi.any_file_contains("module", "requests.post(") or
            pypi.any_file_contains("module", "urllib.request")
        )
}

rule pypi_steganographic_payload : malware pypi obfuscation steganography
{
    meta:
        score = 9
        description = "PyPI package extracts executable code hidden in image LSB data, as documented by Datadog GuardDog"
    condition:
        pypi.is_pypi and
        (
            pypi.any_file_contains("entrypoint", "lsb.reveal(") or
            pypi.any_file_contains("entrypoint", "lsb_reveal(") or
            pypi.any_file_contains("entrypoint", "stegano") or
            pypi.any_file_contains("module", "lsb.reveal(") or
            pypi.any_file_contains("module", "stegano")
        ) and
        (
            pypi.any_file_contains("entrypoint", "exec(") or
            pypi.any_file_contains("entrypoint", "eval(") or
            pypi.any_file_contains("entrypoint", "subprocess") or
            pypi.any_file_contains("module", "exec(") or
            pypi.any_file_contains("module", "eval(")
        )
}

rule pypi_pyarmor_obfuscation : suspicious pypi obfuscation
{
    meta:
        score = 7
        description = "PyPI package uses PyArmor obfuscation to hide its code, commonly seen in malicious packages"
    condition:
        pypi.is_pypi and
        (
            pypi.any_file_contains("entrypoint", "__pyarmor__") or
            pypi.any_file_contains("entrypoint", "pyarmor_runtime") or
            pypi.any_file_contains("entrypoint", "pytransform") or
            pypi.any_file_contains("module", "__pyarmor__") or
            pypi.any_file_contains("module", "pyarmor_runtime") or
            pypi.any_file_contains("module", "pytransform")
        )
}

rule pypi_windows_defender_evasion : malware pypi evasion windows
{
    meta:
        score = 10
        description = "PyPI package disables Windows Defender or adds exclusions"
    condition:
        pypi.is_pypi and
        (
            pypi.any_file_contains("build_script", "Add-MpPreference -ExclusionPath") or
            pypi.any_file_contains("build_script", "Set-MpPreference -DisableRealtimeMonitoring") or
            pypi.any_file_contains("entrypoint", "Add-MpPreference -ExclusionPath") or
            pypi.any_file_contains("entrypoint", "Set-MpPreference -DisableRealtimeMonitoring") or
            pypi.any_file_contains("module", "Add-MpPreference -ExclusionPath") or
            pypi.any_file_contains("module", "Set-MpPreference -DisableRealtimeMonitoring")
        )
}

// ---------------------------------------------------------------------------
//  Crate — build.rs abuse, ctor hooks, credential theft, shells, miners
// ---------------------------------------------------------------------------

rule crate_build_script_env_exfil : malware crates build exfil
{
    meta:
        score = 9
        description = "Rust build script reads CI/cloud credentials and sends them to an exfiltration endpoint, as seen in CrateDepression and the 2023 Telegram campaign"
    condition:
        crate.is_crate and
        crate.has_build_rs and
        (
            crate.build_rs_contains("std::env::vars(") or
            crate.build_rs_contains("env::vars(")
        ) and
        (
            crate.build_rs_contains("reqwest") or
            crate.build_rs_contains("ureq") or
            crate.build_rs_contains("TcpStream") or
            crate.build_rs_contains("api.telegram.org") or
            crate.build_rs_contains("discord.com/api/webhooks/")
        )
}

rule crate_build_script_file_read_exfil : malware crates build theft
{
    meta:
        score = 9
        description = "Rust build script reads SSH keys or cloud credentials and has network access for exfiltration"
    condition:
        crate.is_crate and
        crate.has_build_rs and
        (
            crate.build_rs_contains(".ssh/id_rsa") or
            crate.build_rs_contains(".ssh/id_ed25519") or
            crate.build_rs_contains(".aws/credentials") or
            crate.build_rs_contains(".config/solana/id.json") or
            crate.build_rs_contains(".git-credentials")
        ) and
        (
            crate.build_rs_contains("reqwest") or
            crate.build_rs_contains("ureq") or
            crate.build_rs_contains("TcpStream") or
            crate.build_rs_contains("api.telegram.org") or
            crate.build_rs_contains("discord.com/api/webhooks/")
        )
}

rule crate_build_script_persistence : malware crates build persistence
{
    meta:
        score = 9
        description = "Rust build script installs persistence via shell profiles, crontab, or startup locations"
    condition:
        crate.is_crate and
        crate.has_build_rs and
        (
            crate.build_rs_contains(".bashrc") or
            crate.build_rs_contains(".zshrc") or
            crate.build_rs_contains("crontab") or
            crate.build_rs_contains("LaunchAgents") or
            crate.build_rs_contains("CurrentVersion\\\\Run")
        ) and
        (
            crate.build_rs_contains("fs::write(") or
            crate.build_rs_contains("Command::new(\"bash\"") or
            crate.build_rs_contains("Command::new(\"sh\"")
        )
}

rule crate_build_script_obfuscated_payload : malware crates build obfuscation
{
    meta:
        score = 8
        description = "Rust build script decodes a base64 or XOR payload and executes it via shell, as seen in CrateDepression's XOR-encoded dropper"
    condition:
        crate.is_crate and
        crate.has_build_rs and
        (
            crate.build_rs_contains("base64::decode") or
            crate.build_rs_contains("BASE64.decode") or
            crate.build_rs_contains("b64decode") or
            crate.build_rs_contains("^ key")
        ) and
        (
            crate.build_rs_contains("Command::new(\"sh\"") or
            crate.build_rs_contains("Command::new(\"bash\"") or
            crate.build_rs_contains("Command::new(\"cmd\"") or
            crate.build_rs_contains("Command::new(\"powershell\"") or
            crate.build_rs_contains("reqwest") or
            crate.build_rs_contains("ureq")
        )
}

rule crate_ctor_auto_init_network : suspicious crates runtime hook
{
    meta:
        score = 7
        description = "Rust crate uses #[ctor] auto-initialization combined with HTTP client or process execution, as seen in evm-units/uniswap-utils payload delivery"
    condition:
        crate.is_crate and
        crate.depends_on("ctor") and
        (
            crate.any_file_contains("entrypoint", "#[ctor::ctor]") or
            crate.any_file_contains("entrypoint", "#[ctor]")
        ) and
        (
            crate.depends_on("reqwest") or
            crate.depends_on("ureq") or
            crate.any_file_contains("entrypoint", "TcpStream::connect") or
            crate.any_file_contains("entrypoint", "Command::new")
        )
}

rule crate_ctor_auto_init_antivirus_check : malware crates runtime hook evasion
{
    meta:
        score = 10
        description = "Rust crate uses #[ctor] auto-init combined with antivirus or sandbox evasion checks, as seen in evm-units checking for qhsafetray.exe"
    condition:
        crate.is_crate and
        (
            crate.any_file_contains("entrypoint", "#[ctor::ctor]") or
            crate.any_file_contains("entrypoint", "#[ctor]") or
            crate.any_file_contains("module", "#[ctor::ctor]") or
            crate.any_file_contains("module", "#[ctor]")
        ) and
        (
            crate.any_file_contains("entrypoint", "qhsafetray") or
            crate.any_file_contains("entrypoint", "danger_accept_invalid_certs") or
            crate.any_file_contains("entrypoint", "CREATE_NO_WINDOW") or
            crate.any_file_contains("entrypoint", "0x08000000") or
            crate.any_file_contains("module", "qhsafetray") or
            crate.any_file_contains("module", "danger_accept_invalid_certs") or
            crate.any_file_contains("module", "CREATE_NO_WINDOW")
        )
}

rule crate_runtime_credential_theft : malware crates theft credential
{
    meta:
        score = 9
        description = "Rust crate reads sensitive credential files and exfiltrates them, as seen in finch-rust/sha-rust and faster_log campaigns"
    condition:
        crate.is_crate and
        (
            crate.any_file_contains("entrypoint", ".ssh/id_rsa") or
            crate.any_file_contains("entrypoint", ".ssh/id_ed25519") or
            crate.any_file_contains("entrypoint", ".aws/credentials") or
            crate.any_file_contains("entrypoint", ".kube/config") or
            crate.any_file_contains("entrypoint", ".git-credentials") or
            crate.any_file_contains("entrypoint", ".config/solana/id.json") or
            crate.any_file_contains("module", ".ssh/id_rsa") or
            crate.any_file_contains("module", ".ssh/id_ed25519") or
            crate.any_file_contains("module", ".aws/credentials") or
            crate.any_file_contains("module", ".config/solana/id.json")
        ) and
        (
            crate.any_file_contains("entrypoint", "fs::read_to_string") or
            crate.any_file_contains("entrypoint", "fs::read(") or
            crate.any_file_contains("module", "fs::read_to_string") or
            crate.any_file_contains("module", "fs::read(")
        ) and
        (
            crate.any_file_contains("entrypoint", "reqwest") or
            crate.any_file_contains("entrypoint", "ureq") or
            crate.any_file_contains("entrypoint", "TcpStream") or
            crate.any_file_contains("entrypoint", "hyper") or
            crate.any_file_contains("entrypoint", "http://") or
            crate.any_file_contains("entrypoint", "https://") or
            crate.any_file_contains("module", "reqwest") or
            crate.any_file_contains("module", "ureq") or
            crate.any_file_contains("module", "TcpStream")
        )
}

rule crate_runtime_crypto_key_scanner : malware crates theft crypto
{
    meta:
        score = 9
        description = "Rust crate scans source files for cryptocurrency private keys or wallet addresses and exfiltrates them, as seen in faster_log/async_println"
    condition:
        crate.is_crate and
        (
            crate.any_file_contains("entrypoint", "pack_rust_files") or
            crate.any_file_contains("entrypoint", "pack_directory") or
            crate.any_file_contains("entrypoint", "send_results") or
            crate.any_file_contains("module", "pack_rust_files") or
            crate.any_file_contains("module", "send_results")
        ) and
        (
            crate.any_file_contains("entrypoint", "Regex::new") or
            crate.any_file_contains("entrypoint", "walkdir") or
            crate.any_file_contains("module", "Regex::new") or
            crate.any_file_contains("module", "walkdir")
        ) and
        (
            crate.any_file_contains("entrypoint", "reqwest") or
            crate.any_file_contains("entrypoint", "send_results") or
            crate.any_file_contains("entrypoint", "workers.dev") or
            crate.any_file_contains("entrypoint", "http://") or
            crate.any_file_contains("entrypoint", "https://") or
            crate.any_file_contains("module", "reqwest") or
            crate.any_file_contains("module", "send_results") or
            crate.any_file_contains("module", "workers.dev")
        )
}

rule crate_reverse_shell : malware crates shell
{
    meta:
        score = 10
        description = "Rust crate implements a reverse shell by connecting a TCP stream to a shell process"
    condition:
        crate.is_crate and
        (
            crate.any_file_contains("entrypoint", "TcpStream::connect") or
            crate.any_file_contains("module", "TcpStream::connect")
        ) and
        (
            crate.any_file_contains("entrypoint", "Command::new(\"/bin/sh\")") or
            crate.any_file_contains("entrypoint", "Command::new(\"/bin/bash\")") or
            crate.any_file_contains("entrypoint", "Command::new(\"cmd\")") or
            crate.any_file_contains("entrypoint", "Command::new(\"powershell\")") or
            crate.any_file_contains("entrypoint", "Stdio::from(") or
            crate.any_file_contains("module", "Command::new(\"/bin/sh\")") or
            crate.any_file_contains("module", "Command::new(\"/bin/bash\")") or
            crate.any_file_contains("module", "Command::new(\"cmd\")") or
            crate.any_file_contains("module", "Stdio::from(")
        )
}

rule crate_build_script_platform_payload : malware crates build dropper
{
    meta:
        score = 9
        description = "Rust build script downloads and executes platform-specific payloads via shell, as seen in evm-units and CrateDepression"
    condition:
        crate.is_crate and
        crate.has_build_rs and
        (
            crate.build_rs_contains("reqwest") or
            crate.build_rs_contains("ureq") or
            crate.build_rs_contains("Command::new(\"curl\"") or
            crate.build_rs_contains("Command::new(\"wget\"")
        ) and
        (
            crate.build_rs_contains("chmod +x") or
            crate.build_rs_contains("nohup") or
            crate.build_rs_contains("Command::new(\"bash\"") or
            crate.build_rs_contains("Command::new(\"sh\"") or
            crate.build_rs_contains("Command::new(\"powershell\"") or
            crate.build_rs_contains("osascript")
        )
}

rule crate_runtime_obfuscated_strings : suspicious crates obfuscation
{
    meta:
        score = 7
        description = "Rust crate contains base64-encoded URLs or obfuscated function names, a technique seen in finch-rust/sha-rust and evm-units"
    condition:
        crate.is_crate and
        (
            crate.any_file_contains("entrypoint", "aHR0c") or
            crate.any_file_contains("entrypoint", "base64::decode") or
            crate.any_file_contains("entrypoint", "BASE64.decode") or
            crate.any_file_contains("module", "aHR0c") or
            crate.any_file_contains("module", "base64::decode") or
            crate.any_file_contains("module", "BASE64.decode")
        ) and
        (
            crate.any_file_contains("entrypoint", "reqwest") or
            crate.any_file_contains("entrypoint", "TcpStream") or
            crate.any_file_contains("entrypoint", "Command::new") or
            crate.any_file_contains("entrypoint", "fs::read_to_string") or
            crate.any_file_contains("module", "reqwest") or
            crate.any_file_contains("module", "TcpStream") or
            crate.any_file_contains("module", "Command::new")
        )
}

rule crate_ci_pipeline_targeting : malware crates build ci
{
    meta:
        score = 8
        description = "Rust crate selectively activates in CI/CD pipelines by checking CI environment variables, as seen in CrateDepression targeting GitLab CI"
    condition:
        crate.is_crate and
        (
            crate.build_rs_contains("GITLAB_CI") or
            crate.build_rs_contains("GITHUB_ACTIONS") or
            crate.build_rs_contains("CIRCLECI") or
            crate.build_rs_contains("JENKINS_URL") or
            crate.any_file_contains("entrypoint", "GITLAB_CI") or
            crate.any_file_contains("entrypoint", "GITHUB_ACTIONS") or
            crate.any_file_contains("module", "GITLAB_CI") or
            crate.any_file_contains("module", "GITHUB_ACTIONS")
        ) and
        (
            crate.build_rs_contains("http://") or
            crate.build_rs_contains("https://") or
            crate.build_rs_contains("Command::new") or
            crate.any_file_contains("entrypoint", "reqwest") or
            crate.any_file_contains("entrypoint", "Command::new") or
            crate.any_file_contains("module", "reqwest")
        )
}

rule crate_aws_imds_recon : malware crates recon cloud
{
    meta:
        score = 9
        description = "Rust crate queries cloud metadata services (AWS IMDS, GCP metadata) for credential theft"
    condition:
        crate.is_crate and
        (
            crate.any_file_contains("entrypoint", "169.254.169.254") or
            crate.any_file_contains("entrypoint", "169.254.170.2") or
            crate.any_file_contains("entrypoint", "metadata.google.internal") or
            crate.build_rs_contains("169.254.169.254") or
            crate.build_rs_contains("169.254.170.2") or
            crate.build_rs_contains("metadata.google.internal") or
            crate.any_file_contains("module", "169.254.169.254") or
            crate.any_file_contains("module", "metadata.google.internal")
        )
}

rule crate_windows_defender_evasion : malware crates evasion windows
{
    meta:
        score = 10
        description = "Rust crate disables Windows Defender or adds exclusion paths"
    condition:
        crate.is_crate and
        (
            crate.any_file_contains("entrypoint", "Add-MpPreference") or
            crate.any_file_contains("entrypoint", "Set-MpPreference") or
            crate.any_file_contains("entrypoint", "DisableRealtimeMonitoring") or
            crate.build_rs_contains("Add-MpPreference") or
            crate.build_rs_contains("Set-MpPreference") or
            crate.any_file_contains("module", "Add-MpPreference") or
            crate.any_file_contains("module", "Set-MpPreference")
        )
}

// ---------------------------------------------------------------------------
//  Generic (cross-ecosystem) — string-based detection
// ---------------------------------------------------------------------------

rule generic_cryptocurrency_miner : malware miner
{
    meta:
        score = 8
        description = "content contains cryptocurrency mining pool URLs or miner command-line patterns"
    strings:
        $stratum_tcp = "stratum+tcp://" nocase
        $stratum_ssl = "stratum+ssl://" nocase
        $pool1 = "pool.monero.org" nocase
        $pool2 = "minexmr.com" nocase
        $pool3 = "monerohash.com" nocase
        $pool4 = "xmr.nanopool.org" nocase
        $pool5 = "pool.hashvault.pro" nocase
        $pool6 = "nicehash.com" nocase
        $pool7 = "minergate.com" nocase
        $pool8 = "dwarfpool.com" nocase
        $miner1 = "xmrig" nocase
        $miner2 = "cpuminer" nocase
        $miner3 = "cryptonight" nocase
        $miner4 = "randomx" nocase
        $flag1 = "--donate-level=" nocase
        $flag2 = "--cpu-priority=" nocase
        $flag3 = "--algo=rx/0" nocase
        $flag4 = "--algo=cryptonight" nocase
    condition:
        2 of them
}

rule generic_reverse_shell_bash : malware shell
{
    meta:
        score = 10
        description = "content contains bash reverse shell patterns"
    strings:
        $bash_tcp = "bash -i >& /dev/tcp/"
        $bash_pipe = "| /bin/bash"
        $sh_pipe = "| /bin/sh"
        $mkfifo = "mkfifo /tmp/"
        $nc_exec = "nc -e /bin/sh"
        $ncat_exec = "ncat -e /bin/sh"
        $socat = "socat exec:"
        $bash_nohup = "nohup bash -c"
        $dev_tcp = "/dev/tcp/"
    condition:
        ($bash_tcp) or
        ($dev_tcp and ($bash_pipe or $sh_pipe)) or
        ($mkfifo and ($bash_pipe or $sh_pipe)) or
        ($nc_exec or $ncat_exec) or
        ($socat and ($bash_pipe or $sh_pipe)) or
        ($bash_nohup and $dev_tcp)
}

rule generic_ssh_private_key_exfil : malware theft credential
{
    meta:
        score = 8
        description = "content references SSH private key paths combined with network or exfiltration indicators"
    strings:
        $ssh1 = ".ssh/id_rsa"
        $ssh2 = ".ssh/id_ed25519"
        $ssh3 = ".ssh/id_ecdsa"
        $ssh4 = ".ssh/id_dsa"
        $pem_header = "-----BEGIN RSA PRIVATE KEY-----"
        $openssh_header = "-----BEGIN OPENSSH PRIVATE KEY-----"
        $ec_header = "-----BEGIN EC PRIVATE KEY-----"
        $chan1 = "discord.com/api/webhooks/"
        $chan2 = "api.telegram.org/bot"
        $chan3 = "createOrUpdateFileContents"
        $net1 = "requests.post("
        $net2 = "fetch("
        $net3 = "https.request("
        $net4 = "http.request("
        $net5 = "urllib.request.urlopen("
    condition:
        // Real key theft reads the key and exfiltrates in the same file, so
        // the network marker must sit within a 4KB window of the key
        // reference; SSH tooling (ansible, git2, libssh2) mentions key paths
        // and network verbs in unrelated places. Bare PEM headers show up in
        // every crypto library's test fixtures, so they only count next to a
        // hardcoded exfil channel.
        for any i in (1..#ssh1) : (
            1 of ($net*, $chan*) in (@ssh1[i] - 4096 .. @ssh1[i] + 4096)
        ) or
        for any i in (1..#ssh2) : (
            1 of ($net*, $chan*) in (@ssh2[i] - 4096 .. @ssh2[i] + 4096)
        ) or
        for any i in (1..#ssh3) : (
            1 of ($net*, $chan*) in (@ssh3[i] - 4096 .. @ssh3[i] + 4096)
        ) or
        for any i in (1..#ssh4) : (
            1 of ($net*, $chan*) in (@ssh4[i] - 4096 .. @ssh4[i] + 4096)
        ) or
        for any i in (1..#pem_header) : (
            1 of ($chan*) in (@pem_header[i] - 4096 .. @pem_header[i] + 4096)
        ) or
        for any i in (1..#openssh_header) : (
            1 of ($chan*) in (@openssh_header[i] - 4096 .. @openssh_header[i] + 4096)
        ) or
        for any i in (1..#ec_header) : (
            1 of ($chan*) in (@ec_header[i] - 4096 .. @ec_header[i] + 4096)
        )
}

rule generic_cloud_credential_paths : suspicious theft cloud
{
    meta:
        score = 7
        description = "content references multiple cloud provider credential file paths"
    strings:
        $aws = ".aws/credentials"
        $gcp = "application_default_credentials.json"
        $azure1 = ".azure/accessTokens.json"
        $azure2 = ".azure/msal_token_cache.json"
        $kube = ".kube/config"
        $docker = ".docker/config.json"
        $terraform = ".terraform.d/credentials.tfrc.json"
        $vault = ".vault-token"
    condition:
        2 of them
}

rule generic_cloud_metadata_service : suspicious recon cloud
{
    meta:
        score = 7
        description = "content queries cloud instance metadata services for credential theft or reconnaissance"
    strings:
        $aws_imds = "169.254.169.254"
        $aws_ecs = "169.254.170.2"
        $gcp_meta = "metadata.google.internal"
        $azure_meta = "169.254.169.254/metadata/"
        $kube_sa = "/var/run/secrets/kubernetes.io/serviceaccount/token"
    condition:
        1 of them
}

rule generic_oast_callback : suspicious recon callback
{
    meta:
        score = 7
        description = "content sends data to out-of-band application security testing (OAST) callback infrastructure"
    strings:
        $oast1 = ".oast." nocase
        $oast2 = ".oastify.com" nocase
        $oast3 = ".interact.sh" nocase
        $oast4 = "burpcollaborator" nocase
        $oast5 = "hookbin.com" nocase
        $oast6 = "webhook.site" nocase
        $oast7 = ".m.pipedream.net" nocase
    condition:
        1 of them
}

rule generic_git_token_patterns : suspicious theft credential
{
    meta:
        score = 7
        description = "content contains GitHub, GitLab, or npm token prefix patterns together with network exfiltration"
    strings:
        $ghp = "ghp_"
        $gho = "gho_"
        $ghs = "ghs_"
        $github_pat = "github_pat_"
        $glpat = "glpat-"
        $npm_token = "NPM_TOKEN"
        $node_auth = "NODE_AUTH_TOKEN"
        $net1 = "discord.com/api/webhooks/"
        $net2 = "api.telegram.org/bot"
        $net3 = "requests.post("
        $net4 = "https.request("
        $net5 = "http.request("
        $net6 = "fetch("
    condition:
        2 of ($ghp, $gho, $ghs, $github_pat, $glpat, $npm_token, $node_auth) and
        1 of ($net*)
}

rule generic_windows_persistence : malware persistence windows
{
    meta:
        score = 8
        description = "content installs Windows persistence via registry run keys, startup folder, or scheduled tasks"
    strings:
        $run_key = "Software\\Microsoft\\Windows\\CurrentVersion\\Run" nocase
        $startup = "Start Menu\\Programs\\Startup" nocase
        $schtasks = "schtasks /create" nocase
        $wscript = "wscript.exe" nocase
        $vbs_hidden = "window style 0" nocase
        $ps_hidden = "-WindowStyle Hidden" nocase
        $ps_bypass = "-executionpolicy bypass" nocase
    condition:
        2 of them
}

rule generic_browser_credential_database : suspicious theft browser
{
    meta:
        score = 7
        description = "content references browser credential database file names used for password, cookie, or credit card theft"
    strings:
        $login = "Login Data"
        $webdata = "Web Data"
        $local_state = "Local State"
        $cookies_sqlite = "cookies.sqlite"
        $logins_json = "logins.json"
        $key4 = "key4.db"
        $dpapi = "CryptUnprotectData"
    condition:
        2 of them
}

rule generic_crypto_wallet_paths : suspicious theft crypto
{
    meta:
        score = 7
        description = "content references multiple cryptocurrency wallet file paths or storage locations"
    strings:
        $exodus = "exodus.wallet"
        $seed = "seed.seco"
        $wallet_dat = "wallet.dat"
        $electrum = ".electrum/wallets"
        $eth_keystore = ".ethereum/keystore"
        $solana = ".config/solana/id.json"
        $bitmonero = ".bitmonero"
        $bitcoin = ".bitcoin/wallet.dat"
        $metamask_ext = "nkbihfbeogaeaoehlefnkodbefgpgknn"
        $phantom_ext = "bfnaelmomeimhlpmgjnjophhpkkoljpa"
    condition:
        2 of them
}

rule generic_self_deletion_destructive : malware destructive
{
    meta:
        score = 10
        description = "content contains destructive file shredding or mass deletion patterns used as a dead-man switch, as seen in SANDWORM failsafe"
    strings:
        // Specific enough to stand alone: these appear in real wipers, not
        // in ordinary docs or examples.
        $shred = "shred -uvz"
        $del_all = "del /F /Q /S \"%USERPROFILE%"
        $cipher_wipe = "cipher /W:"
        $xargs_shred = "xargs -0 shred"
        // "rm -rf /" and "rm -rf ~/" turn up in README examples, test
        // templates, and security-tool keyword lists, so they only count as a
        // dead-man switch alongside a second destructive marker (the
        // cross-platform failsafe shape).
        $rm_rf_home = /rm -rf ['"]?~\/?[\s'";)&|]/
        $rm_rf_slash = /rm -rf ['"]?\/\*?[\s'";)&|]/
    condition:
        1 of ($shred, $del_all, $cipher_wipe, $xargs_shred) or
        2 of them
}

// Packed/obfuscated payloads (XOR integer tables, AES-GCM hex blobs,
// obfuscator.io output) carry no literal IOC strings, so string rules miss
// them. This rule matches their structural shape instead: a long flat
// integer-array literal or a long contiguous hex blob, in the same content
// as decode-and-execute code.
//
// Corpus evidence behind every threshold:
//
//   - The longest legitimate contiguous digit/comma run in the benign
//     corpus is 1721 bytes (the SHA-256 constant table vendored inside
//     swagger-ui bundles); timezone tables, prime lists, and TTF glyph
//     data stay below that. The Trinitite-style XOR table is megabytes
//     of flat "1,2,3,..." — three orders of magnitude past the threshold.
//   - Legitimate contiguous hex tokens (web3 contract ABI 29.5KB, aws
//     chunk-signing test vectors, .so binaries) are data without decode
//     loops; none of those packages carry two decode markers.
//   - Wholesale entropy is useless as a separator: benign colormap and
//     OUI-table files reach 6.48 bits/byte, above anything the malicious
//     corpus reaches. The shape is matched structurally instead.
//   - The decode markers never appear in the benign data files that carry
//     the blob shapes; requiring two of them in the same scanned content
//     separates a data blob from a payload that code unpacks and runs.
//
// Engine note: the blob patterns are deliberately fixed-length literals.
// yara-x cannot verify unbounded {N,} class runs over large data (the
// FastVM scan window aborts), so {2048} is used instead of {2048,}; the
// benign corpus tops out at 1721 anyway, and scanning a genuine packed
// array completes well inside the 60s scan timeout.
rule generic_packed_high_entropy_payload : suspicious obfuscation packed
{
    meta:
        score = 4
        description = "content embeds a packed payload as a long flat integer-array or contiguous hex blob together with decode-and-execute code, the XOR/AES-packed worm payload shape"
    strings:
        $num_array = /[\d,]{2048}/
        $hex_blob = /[0-9a-fA-F]{2048}/
        $xor1 = "charCodeAt(" nocase
        $xor2 = "fromCharCode(" nocase
        $dec1 = "atob(" nocase
        $dec2 = "Buffer.from(" nocase
        $dec3 = "createDecipheriv(" nocase
        $dec4 = "eval(" nocase
    condition:
        filesize > 50 * 1024 and
        1 of ($num_array, $hex_blob) and
        2 of ($xor*, $dec*)
}
