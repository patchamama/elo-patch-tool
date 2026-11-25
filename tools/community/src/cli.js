'use strict';
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const cp = require('node:child_process');
const { parseSince, parseMax } = require('./since');
const { callProvider, PROVIDERS } = require('./providers');
const { SYSTEM, userPrompt } = require('./prompt');
const { buildDraftEntry, validateEntry, buildDraftDb } = require('./draft');
const { loadSecrets } = require('./secrets');
const { setup, requireCommunityConsent } = require('./setup');

const HELP = `ELO Community vulnerability helper (optional, drafts only)

Usage: node tools/community/bin/elo-community.js <command> [options]

Commands
  setup    Show what the community helper needs and install it ONLY after you say yes.
  fetch    Sign in to the ELO Community board, list the latest articles and save their text.
  analyze  Send saved articles to an AI provider and write DRAFT catalog entries (vulndb.json format).
  run      fetch + analyze.
  check    Validate and simulate a draft with the app (needs ELO-Patch-Tools.bat; Windows).
  help     This text.

Limits
  --since 30d|8w|3m|1y|YYYY-MM-DD   Only articles newer than this (required for fetch/run).
  --max N                           At most N articles (default 20, hard limit 200).

AI (analyze/run)
  --provider openai|anthropic|ollama   --model NAME   [--base-url URL]   or   --ai config/ai.json
  The API key is read from the environment variable named by apiKeyEnv (OPENAI_API_KEY,
  ANTHROPIC_API_KEY). Ollama needs no key.

Nothing is installed by default. The patch tool needs no installation; the community helper needs the npm package
playwright-core and your ELO Community credentials. fetch/run print that plan first and ask for consent (--yes in scripts).

Credentials / keys: environment variables ELO_COMMUNITY_USER, ELO_COMMUNITY_PASSWORD, OPENAI_API_KEY, ANTHROPIC_API_KEY,
or the git-ignored file tools/community/secrets.local.env (KEY=value lines). Environment variables win.

Output: --out DIR (default: %ProgramData%\\ELO-Patch-Tools\\quarantine\\drafts\\<timestamp>, i.e. the quarantine
folder). Files: articles.json, analysis.json, draft-vulndb.json, report.md. Nothing is ever installed
automatically: review the draft, then  ELO-Patch-Tools.bat --cli --catalog-validate FILE,
--catalog-simulate FILE and finally --catalog-install FILE --confirm-admin.
`;

function parseArgs(argv) {
  const out = { command: argv[0] && !argv[0].startsWith('--') ? argv[0] : 'help', options: {} };
  const valued = ['since', 'max', 'provider', 'model', 'base-url', 'ai', 'out', 'articles', 'draft', 'channel', 'config'];
  const flags = ['headed', 'help', 'yes'];
  for (let i = out.command === 'help' && !argv[0] ? 0 : 1; i < argv.length; i++) {
    const a = argv[i];
    if (!a.startsWith('--')) throw new Error('unexpected_argument: ' + a);
    const name = a.slice(2);
    if (flags.includes(name)) { out.options[name] = true; continue; }
    if (!valued.includes(name)) throw new Error('unknown_option: ' + a);
    if (i + 1 >= argv.length || argv[i + 1].startsWith('--')) throw new Error('missing_value: ' + a);
    out.options[name] = argv[++i];
  }
  return out;
}

function defaultOutDir(now = new Date(), env = process.env) {
  const stamp = now.toISOString().replace(/[-:T]/g, '').slice(0, 14);
  const base = env.ProgramData ? path.join(env.ProgramData, 'ELO-Patch-Tools', 'quarantine', 'drafts') : path.join(process.cwd(), 'drafts');
  return path.join(base, stamp);
}

function readJson(file) { return JSON.parse(fs.readFileSync(file, 'utf8')); }
function writeJson(file, value) { fs.writeFileSync(file, JSON.stringify(value, null, 2) + '\n', 'utf8'); }

function aiConfig(options, root) {
  let cfg = {};
  const file = options.ai || path.join(root, 'config', 'ai.json');
  if (fs.existsSync(file)) cfg = readJson(file);
  if (options.provider) cfg.provider = options.provider;
  if (options.model) cfg.model = options.model;
  if (options['base-url']) cfg.baseUrl = options['base-url'];
  if (cfg.provider === 'openai' && !cfg.apiKeyEnv) cfg.apiKeyEnv = 'OPENAI_API_KEY';
  if (cfg.provider === 'anthropic' && !cfg.apiKeyEnv) cfg.apiKeyEnv = 'ANTHROPIC_API_KEY';
  if (!PROVIDERS.includes(cfg.provider)) throw new Error('ai_provider_invalid: pass --provider openai|anthropic|ollama');
  return cfg;
}

async function fetchArticles(options, root, now, deps = {}) {
  const since = parseSince(options.since, now);
  const cfg = readJson(path.join(root, 'config', 'community.json'));
  const max = parseMax(options.max, cfg.limits.maxArticlesHard);
  const community = deps.community || require('./community');
  const chromium = deps.chromium || require('playwright-core').chromium;
  const browser = await chromium.launch({ channel: options.channel || 'chrome', headless: !options.headed });
  try {
    const page = await (await browser.newContext({ viewport: { width: 1280, height: 900 } })).newPage();
    await community.login(page, cfg, { user: process.env.ELO_COMMUNITY_USER, password: process.env.ELO_COMMUNITY_PASSWORD });
    const listed = await community.listArticles(page, cfg, { since, max, now });
    const articles = [];
    for (const item of listed) {
      articles.push(await community.readArticle(page, cfg, item));
      await new Promise(resolve => setTimeout(resolve, cfg.limits.politenessMs));
    }
    return { fetchedUtc: now.toISOString(), since: since.toISOString().slice(0, 10), max, board: cfg.board.url, articles };
  } finally { await browser.close(); }
}

async function analyzeArticles(articles, cfg, now, deps = {}) {
  const call = deps.callProvider || callProvider;
  const entries = []; const analyses = []; const failures = [];
  for (const article of articles) {
    try {
      const analysis = await call(cfg, SYSTEM, userPrompt(article));
      analyses.push({ url: article.url, analysis });
      const { entry, issues } = buildDraftEntry(analysis, article, { provider: cfg.provider, model: cfg.model, stamp: now.toISOString().replace(/[-:T]/g, '').slice(0, 14), today: now.toISOString().slice(0, 10), createdUtc: now.toISOString() });
      if (!entry) { failures.push({ url: article.url, reason: issues.join(' ') }); continue; }
      const problems = validateEntry(entry);
      if (problems.length) { failures.push({ url: article.url, reason: 'draft rejected: ' + problems.join(', ') }); continue; }
      if (entries.some(e => e.id === entry.id)) entry.id = entry.id.slice(0, 55) + '-' + (entries.length + 1);
      entries.push(entry);
    } catch (e) { failures.push({ url: article.url, reason: String(e.message || e).slice(0, 300) }); }
  }
  return { entries, analyses, failures };
}

function renderReport({ entries, failures, since, provider, model, outDir }) {
  const lines = ['# Draft vulnerability catalog', '', `Provider: ${provider} (${model}) - articles since ${since || 'n/a'}`, '',
    '| Id | Severity | Solution reported | Simulation | Open issues |', '|---|---|---|---|---|'];
  for (const e of entries) {
    const solution = e.review.issues.some(i => /No solution reported/.test(i)) ? 'no' : 'yes';
    lines.push(`| ${e.id} | ${e.severity} | ${solution} | ${e.simulation ? 'yes' : 'no'} | ${e.review.issues.length} |`);
  }
  for (const e of entries) {
    lines.push('', `## ${e.id} - ${e.title.en}`, '', `Severity: **${e.severity}**${e.review.severityReason ? ' - ' + e.review.severityReason : ''}`, `Article: ${e.review.article.url}`, '', 'Review before installing:', ...(e.review.issues.length ? e.review.issues.map(i => '- ' + i) : ['- (none reported)']));
  }
  if (failures.length) lines.push('', '## Skipped articles', '', ...failures.map(f => `- ${f.url}: ${f.reason}`));
  lines.push('', '## Next steps', '', '```', `ELO-Patch-Tools.bat --cli --catalog-validate "${path.join(outDir, 'draft-vulndb.json')}"`, `ELO-Patch-Tools.bat --cli --catalog-simulate "${path.join(outDir, 'draft-vulndb.json')}"`, '# after a human review: set "status": "active" on the entries you accept, then', `ELO-Patch-Tools.bat --cli --catalog-install "${path.join(outDir, 'draft-vulndb.json')}" --confirm-admin`, '```', '');
  return lines.join('\n');
}

async function main(argv, deps = {}) {
  const root = path.resolve(__dirname, '..');
  const now = deps.now || new Date();
  const { command, options } = parseArgs(argv);
  if (command === 'help' || options.help) { process.stdout.write(HELP); return 0; }
  if (command === 'setup') return setup(options, deps.setupDeps);
  const secrets = (deps.loadSecrets || loadSecrets)();
  if (secrets.loaded.length) process.stderr.write('Loaded from ' + path.basename(secrets.file) + ': ' + secrets.loaded.join(', ') + ' (names only)\n');
  const outDir = path.resolve(options.out || defaultOutDir(now));
  if (command === 'check') {
    const draft = path.resolve(options.draft || path.join(outDir, 'draft-vulndb.json'));
    const bat = path.resolve(root, '..', '..', 'ELO-Patch-Tools.bat');
    for (const verb of ['--catalog-validate', '--catalog-simulate']) {
      const r = cp.spawnSync('cmd.exe', ['/c', bat, '--cli', verb, draft, '--json'], { encoding: 'utf8' });
      let shown = (r.stdout || '').slice(0, 2000);
      try { const j = JSON.parse(r.stdout); shown = JSON.stringify(j.error ? { error: j.error } : j.action && j.action.result, null, 2); } catch (_) { /* keep raw text */ }
      process.stdout.write(`${verb}: exit ${r.status}\n${shown}\n`);
      if (r.status !== 0) return r.status || 1;
    }
    return 0;
  }
  fs.mkdirSync(outDir, { recursive: true });
  let articlesDoc;
  if (command === 'fetch' || command === 'run') {
    await (deps.consent || requireCommunityConsent)(options);
    articlesDoc = await fetchArticles(options, root, now, deps);
    writeJson(path.join(outDir, 'articles.json'), articlesDoc);
    process.stdout.write(`Fetched ${articlesDoc.articles.length} article(s) since ${articlesDoc.since} -> ${path.join(outDir, 'articles.json')}\n`);
    if (command === 'fetch') return 0;
  } else if (command === 'analyze') {
    articlesDoc = readJson(path.resolve(options.articles || path.join(outDir, 'articles.json')));
  } else throw new Error('unknown_command: ' + command);
  const cfg = aiConfig(options, root);
  const result = await analyzeArticles(articlesDoc.articles, cfg, now, deps);
  const community = readJson(path.join(root, 'config', 'community.json'));
  const sources = [{ id: 'elo-community-kbb103', type: 'elo-community', title: community.board.name, url: community.board.url, access: 'login required; credentials come from the environment, never from this file' }];
  writeJson(path.join(outDir, 'analysis.json'), result.analyses);
  writeJson(path.join(outDir, 'draft-vulndb.json'), buildDraftDb(result.entries, sources, now.toISOString().slice(0, 10)));
  fs.writeFileSync(path.join(outDir, 'report.md'), renderReport({ entries: result.entries, failures: result.failures, since: articlesDoc.since, provider: cfg.provider, model: cfg.model, outDir }), 'utf8');
  process.stdout.write(`Drafted ${result.entries.length} entr${result.entries.length === 1 ? 'y' : 'ies'} (${result.failures.length} skipped) in ${outDir}\nNothing was installed. Read report.md, then validate and simulate the draft.\n`);
  return 0;
}

module.exports = { main, parseArgs, defaultOutDir, analyzeArticles, renderReport, aiConfig, HELP };
