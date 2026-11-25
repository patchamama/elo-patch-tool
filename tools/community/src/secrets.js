'use strict';
// Local secrets file (tools/community/secrets.local.env): KEY=value lines for the ELO Community account and the
// AI keys. It is git-ignored, only a fixed list of keys is read, environment variables always win, and the file
// is refused when git does not ignore it (so it can never be committed by accident).
const fs = require('node:fs');
const path = require('node:path');
const cp = require('node:child_process');

const ALLOWED = ['ELO_COMMUNITY_USER', 'ELO_COMMUNITY_PASSWORD', 'OPENAI_API_KEY', 'ANTHROPIC_API_KEY'];
const DEFAULT_FILE = path.join(__dirname, '..', 'secrets.local.env');

function parseEnvFile(text) {
  const values = {};
  for (const raw of String(text).split(/\r?\n/)) {
    const line = raw.trim();
    if (!line || line.startsWith('#')) continue;
    const m = /^([A-Z][A-Z0-9_]*)\s*=\s*(.*)$/.exec(line);
    if (!m || !ALLOWED.includes(m[1])) continue;
    let v = m[2].trim();
    if ((v.startsWith('"') && v.endsWith('"') && v.length >= 2) || (v.startsWith("'") && v.endsWith("'") && v.length >= 2)) v = v.slice(1, -1);
    if (v) values[m[1]] = v;
  }
  return values;
}

// Returns true/false when git can tell, null when git is not available or the folder is not a repository.
function isGitIgnored(file, spawn = cp.spawnSync) {
  const r = spawn('git', ['check-ignore', '-q', '--', file], { cwd: path.dirname(file), encoding: 'utf8' });
  if (r.error) return null;
  if (r.status === 0) return true;
  if (r.status === 1) return false;
  return null;
}

function loadSecrets({ file = DEFAULT_FILE, env = process.env, spawn = cp.spawnSync, exists = fs.existsSync, read = p => fs.readFileSync(p, 'utf8') } = {}) {
  if (!exists(file)) return { loaded: [], file, present: false };
  if (isGitIgnored(file, spawn) === false) throw new Error('secrets_file_not_ignored: ' + path.basename(file) + ' is inside a git repository but not git-ignored; add it to .gitignore before using it');
  const values = parseEnvFile(read(file));
  const loaded = [];
  for (const [key, value] of Object.entries(values)) {
    if (!env[key]) { env[key] = value; loaded.push(key); }
  }
  return { loaded, file, present: true };
}

module.exports = { ALLOWED, DEFAULT_FILE, parseEnvFile, isGitIgnored, loadSecrets };
