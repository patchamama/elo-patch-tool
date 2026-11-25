'use strict';
// Nothing is installed unless the person says yes. The core tool (ELO-Patch-Tools.bat) needs no installation at
// all; only the OPTIONAL community helper needs one npm package, and only to read community.elo.com.
const cp = require('node:child_process');
const fs = require('node:fs');
const path = require('node:path');
const readline = require('node:readline');

const ROOT = path.resolve(__dirname, '..');

function chromePath(exists = fs.existsSync, env = process.env) {
  const candidates = [env.ProgramFiles, env['ProgramFiles(x86)'], env.LOCALAPPDATA].filter(Boolean).map(base => path.join(base, 'Google', 'Chrome', 'Application', 'chrome.exe'));
  return candidates.find(c => exists(c)) || null;
}

function dependencyInstalled(root = ROOT, exists = fs.existsSync) {
  return exists(path.join(root, 'node_modules', 'playwright-core', 'package.json'));
}

function describePlan({ forCommunity, installed, chrome, nodeVersion }) {
  const lines = [];
  lines.push('ELO Community access - what this needs');
  lines.push('');
  lines.push('  Accounts and credentials');
  lines.push('  - Your ELO Community account (user name or e-mail + password) for https://community.elo.com .');
  lines.push('    They are typed into the official sign-in form only; they are read from environment variables or');
  lines.push('    tools/community/secrets.local.env (git-ignored) and are never written to a draft, a log or the repository.');
  lines.push('  - For AI analysis: an API key (OpenAI / Anthropic) or a local Ollama. Only the article text is sent to the provider.');
  lines.push('');
  lines.push('  Extra software (nothing else on this server changes)');
  lines.push('  - Node.js >= 18: ' + (nodeVersion ? 'found (' + nodeVersion + ')' : 'NOT found - install it from https://nodejs.org first'));
  lines.push('  - npm package "playwright-core" (~14 MB) into tools/community/node_modules: ' + (installed ? 'already installed' : 'WILL BE INSTALLED by "setup"'));
  lines.push('  - Google Chrome (used through Playwright; no browser download): ' + (chrome ? 'found (' + chrome + ')' : 'NOT found - install Chrome or pass --channel msedge'));
  lines.push('');
  lines.push('  Network: https://registry.npmjs.org (install), https://community.elo.com (articles) and your AI provider.');
  if (!forCommunity) lines.push('  The patch tool itself (scan, update, mitigation, restore, catalog) needs none of this.');
  return lines.join('\n');
}

async function confirm(question, { yes = false, isTTY = process.stdin.isTTY, input = process.stdin, output = process.stdout } = {}) {
  if (yes) return true;
  if (!isTTY) return false;
  const rl = readline.createInterface({ input, output });
  try { const answer = await new Promise(resolve => rl.question(question + ' Type "yes" to continue: ', resolve)); return String(answer).trim().toLowerCase() === 'yes'; }
  finally { rl.close(); }
}

async function setup(options = {}, deps = {}) {
  const out = deps.out || (s => process.stdout.write(s));
  const installed = dependencyInstalled(ROOT, deps.exists);
  const plan = describePlan({ forCommunity: true, installed, chrome: chromePath(deps.exists, deps.env), nodeVersion: process.version });
  out(plan + '\n\n');
  if (installed) { out('Nothing to install.\n'); return 0; }
  const ok = await (deps.confirm || confirm)('Install the npm package above?', { yes: Boolean(options.yes) });
  if (!ok) { out('Cancelled. Nothing was installed. (Use --yes to confirm without a prompt.)\n'); return 1; }
  const spawn = deps.spawn || cp.spawnSync;
  const r = spawn(process.platform === 'win32' ? 'npm.cmd' : 'npm', ['install', '--prefix', ROOT, '--no-audit', '--no-fund', '--ignore-scripts'], { stdio: 'inherit', shell: process.platform === 'win32' });
  if (r.status !== 0) { out('npm install failed; nothing else was changed.\n'); return r.status || 1; }
  out('Installed playwright-core. You can now run: node tools/community/bin/elo-community.js run --since 30d\n');
  return 0;
}

// Gate for fetch/run: show the plan, require consent (--yes or an interactive "yes"), and never install anything.
async function requireCommunityConsent(options, deps = {}) {
  const installed = dependencyInstalled(ROOT, deps.exists);
  const out = deps.out || (s => process.stderr.write(s));
  out(describePlan({ forCommunity: true, installed, chrome: chromePath(deps.exists, deps.env), nodeVersion: process.version }) + '\n\n');
  if (!installed) throw new Error('dependency_missing: run "node tools/community/bin/elo-community.js setup" first (it asks before installing anything)');
  const ok = await (deps.confirm || confirm)('Sign in to community.elo.com with your credentials?', { yes: Boolean(options.yes) });
  if (!ok) throw new Error('consent_required: nothing was contacted (add --yes to confirm in scripts)');
  return true;
}

module.exports = { chromePath, dependencyInstalled, describePlan, confirm, setup, requireCommunityConsent, ROOT };
