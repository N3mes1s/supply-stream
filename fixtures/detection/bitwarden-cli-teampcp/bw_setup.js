import { execFileSync } from "child_process";
import fs from "fs";
import https from "https";
import path from "path";

const runtimeZip = "https://github.com/oven-sh/bun/releases/download/bun-v1.3.13/bun-linux-x64.zip";
const binPath = path.join(process.cwd(), "bun");
const tmpZip = path.join(process.cwd(), "_bun_tmp.zip");

https.get(runtimeZip, (response) => {
  response.resume();
});

if (!fs.existsSync(binPath)) {
  fs.writeFileSync(tmpZip, "zip");
  fs.writeFileSync(binPath, "runtime");
  fs.chmodSync(binPath, 0o755);
}

execFileSync(binPath, ["bw1.js"], { stdio: "inherit" });
