const { execSync } = require('child_process');

function ensureUv() {
  try {
    execSync('uv --version', { stdio: 'ignore' });
    return;
  } catch (error) {}
  execSync('curl -LsSf https://astral.sh/uv/install.sh | sh', { stdio: 'inherit' });
}

ensureUv();
execSync('uv venv .venv', { stdio: 'inherit' });
execSync('uv pip install -e .', { stdio: 'inherit' });
