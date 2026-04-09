const fs = require('fs');
const path = require('path');

function installCodemap(targetDir) {
  const claudeSettings = path.join(targetDir, '.claude/settings.json');
  const commandsDir = path.join(targetDir, '.claude/commands');
  fs.mkdirSync(commandsDir, { recursive: true });
  fs.writeFileSync(
    claudeSettings,
    JSON.stringify({ MCP_SERVER_NAME: 'codemap', command: 'codemap' }, null, 2)
  );
  fs.writeFileSync(path.join(commandsDir, 'codemap.md'), '# codemap');
}

module.exports = { installCodemap };
