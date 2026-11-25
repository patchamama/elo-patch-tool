'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const cp = require('node:child_process');
const { parseArgs, defaultOutDir, analyzeArticles, renderReport, main } = require('../src/cli');
const { buildDraftDb } = require('../src/draft');
const { article, analysis, flagAnalysis } = require('./helpers');

const now = new Date('2026-11-25T10:00:00Z');
const cfg = { provider: 'ollama', model: 'llama3.1' };

test('argument parsing is strict', () => {
  assert.deepEqual(parseArgs(['fetch', '--since', '3m', '--max', '5']).options, { since: '3m', max: '5' });
  assert.equal(parseArgs([]).command, 'help');
  for (const bad of [['fetch', '--password', 'x'], ['fetch', '--since'], ['fetch', 'extra'], ['analyze', '--out', '--since']]) assert.throws(() => parseArgs(bad), /unknown_option|missing_value|unexpected_argument/);
});

test('drafts go to the quarantine folder by default', () => {
  assert.equal(defaultOutDir(now, { ProgramData: 'C:\\ProgramData' }), path.join('C:\\ProgramData', 'ELO-Patch-Tools', 'quarantine', 'drafts', '20261125100000'));
});

test('analyze drafts one entry per report article, skips failures and never aborts the batch', async () => {
  const answers = [analysis(), flagAnalysis(), 'boom', { isVulnerabilityReport: false }];
  let call = 0;
  const callProvider = async () => { const a = answers[call++]; if (a === 'boom') throw new Error('ai_http_500: upstream'); return a; };
  const articles = [0, 1, 2, 3].map(n => ({ ...article, url: article.url + n, title: 'Article ' + n }));
  const r = await analyzeArticles(articles, cfg, now, { callProvider });
  assert.equal(r.entries.length, 2);
  assert.equal(r.failures.length, 2);
  assert.ok(r.failures.some(f => /ai_http_500/.test(f.reason)));
  assert.ok(r.entries.every(e => e.status === 'draft'));
  const md = renderReport({ entries: r.entries, failures: r.failures, since: '2026-10-26', provider: 'ollama', model: 'llama3.1', outDir: 'C:\\q\\d' });
  assert.match(md, /Draft vulnerability catalog/);
  assert.match(md, /--catalog-validate/);
  assert.match(md, /Skipped articles/);
});

test('run end to end with a fake browser and a fake AI writes the four files and installs nothing', async () => {
  const out = fs.mkdtempSync(path.join(os.tmpdir(), 'elo-community-test-'));
  const community = {
    login: async () => 'signed-in',
    listArticles: async () => [{ url: article.url, title: article.title, date: article.date }],
    readArticle: async (page, c, a) => ({ ...a, text: article.text })
  };
  const chromium = { launch: async () => ({ newContext: async () => ({ newPage: async () => ({}) }), close: async () => {} }) };
  const chunks = []; const realWrite = process.stdout.write.bind(process.stdout);
  process.stdout.write = s => { chunks.push(String(s)); return true; };
  try {
    const code = await main(['run', '--since', '30d', '--max', '2', '--provider', 'ollama', '--model', 'llama3.1', '--out', out], { now, community, chromium, callProvider: async () => analysis() });
    assert.equal(code, 0);
  } finally { process.stdout.write = realWrite; }
  for (const f of ['articles.json', 'analysis.json', 'draft-vulndb.json', 'report.md']) assert.ok(fs.existsSync(path.join(out, f)), f);
  const draft = JSON.parse(fs.readFileSync(path.join(out, 'draft-vulndb.json'), 'utf8'));
  assert.equal(draft.vulnerabilities[0].status, 'draft');
  assert.match(draft.sources[0].url, /community\.elo\.com/);
  assert.ok(!fs.readFileSync(path.join(out, 'articles.json'), 'utf8').match(/password/i));
  assert.match(chunks.join(''), /Nothing was installed/);
  fs.rmSync(out, { recursive: true, force: true });
});

test('a generated draft passes the real catalog validator and simulation of the app (Windows PowerShell 5.1)', { skip: process.platform !== 'win32' }, async () => {
  const articles = [article, { ...article, url: article.url + '2', title: 'Flag report' }];
  const answers = [analysis(), flagAnalysis()]; let i = 0;
  const r = await analyzeArticles(articles, cfg, now, { callProvider: async () => answers[i++] });
  assert.equal(r.entries.length, 2);
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'elo-community-ps-'));
  const file = path.join(dir, 'draft-vulndb.json');
  fs.writeFileSync(file, JSON.stringify(buildDraftDb(r.entries, [{ id: 's', type: 'elo-community', title: 't', url: 'https://community.elo.com/x', access: 'login' }], '2026-11-25')), 'utf8');
  const dev = path.resolve(__dirname, '..', '..', '..', 'dev').replace(/\\/g, '\\\\');
  const script = [
    `. '${path.join(dev, 'vulndb.ps1')}'`, `. '${path.join(dev, 'scan.ps1')}'`,
    `$db = Read-EloVulnDbFile '${file}'`,
    `$out = @($db.vulnerabilities | ForEach-Object { $s = Invoke-EloVulnSimulation $_ $db; @{ id = $_.id; passed = [bool]$s.Passed; status = $_.status } })`,
    `$out | ConvertTo-Json -Compress`
  ].join('; ');
  const ps = cp.spawnSync('powershell', ['-NoProfile', '-Command', script], { encoding: 'utf8' });
  assert.equal(ps.status, 0, ps.stderr + ps.stdout);
  const results = [].concat(JSON.parse(ps.stdout));
  assert.equal(results.length, 2);
  assert.ok(results.every(x => x.passed && x.status === 'draft'), ps.stdout);
  fs.rmSync(dir, { recursive: true, force: true });
});
