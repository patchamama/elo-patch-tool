'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { resolveConfig, buildResearchRequest, extractResearchText, callProviderResearch } = require('../src/providers');
const { analyzeArticles, refineArticle, testAccess, summarize } = require('../src/cli');
const { buildDraftEntry, validateEntry } = require('../src/draft');
const { refinePrompt, REFINE_SYSTEM } = require('../src/prompt');
const { article, analysis, flagAnalysis } = require('./helpers');

const now = new Date('2026-11-25T10:00:00Z');
const cfg = { provider: 'openai', model: 'gpt-6-sol' };
const withSummary = () => ({ ...analysis(), summary: { en: 'English text', de: 'Deutscher Text', es: 'Texto en español' }, scriptWorthwhile: true, scriptReason: 'A version check detects it', solutionHints: ['Check the vendor advisory', '<b>x</b>'], title: { en: 'Java flaw', de: 'Java-Fehler', es: 'Fallo de Java' } });

test('pasted API keys are trimmed (a trailing newline no longer causes a 401)', () => {
  const c = resolveConfig({ provider: 'openai', model: 'gpt-4o', apiKeyEnv: 'OPENAI_API_KEY' }, { OPENAI_API_KEY: '  sk-abc \r\n' });
  assert.equal(c.apiKey, 'sk-abc');
});

test('web research uses the provider search tools; Ollama is refused with a clear message', () => {
  const o = buildResearchRequest(resolveConfig({ provider: 'openai', model: 'gpt-6-sol', apiKeyEnv: 'OPENAI_API_KEY' }, { OPENAI_API_KEY: 'k' }), 'SYS', 'USER');
  assert.equal(o.url, 'https://api.openai.com/v1/responses'); assert.deepEqual(o.body.tools, [{ type: 'web_search' }]); assert.equal(o.body.instructions, 'SYS');
  const a = buildResearchRequest(resolveConfig({ provider: 'anthropic', model: 'claude-x', apiKeyEnv: 'ANTHROPIC_API_KEY' }, { ANTHROPIC_API_KEY: 'k' }), 'SYS', 'USER');
  assert.equal(a.body.tools[0].type, 'web_search_20250305'); assert.equal(a.headers['x-api-key'], 'k');
  assert.throws(() => buildResearchRequest(resolveConfig({ provider: 'ollama', model: 'llama3' }, {}), 'S', 'U'), /research_unsupported/);
});

test('research answers are read from the Responses API and from Anthropic content blocks', async () => {
  assert.equal(extractResearchText('openai', { output_text: '{"a":1}' }), '{"a":1}');
  assert.equal(extractResearchText('openai', { output: [{ type: 'web_search_call' }, { type: 'message', content: [{ type: 'output_text', text: '{"b":' }, { type: 'output_text', text: '2}' }] }] }), '{"b":2}');
  assert.equal(extractResearchText('anthropic', { content: [{ type: 'tool_use' }, { type: 'text', text: '{"c":3}' }] }), '{"c":3}');
  const fetchImpl = async () => ({ ok: true, json: async () => ({ output_text: 'Result: {"x":1}' }) });
  assert.deepEqual(await callProviderResearch({ provider: 'openai', model: 'm', apiKeyEnv: 'OPENAI_API_KEY' }, 'S', 'U', fetchImpl, { OPENAI_API_KEY: 'k' }), { x: 1 });
  const denied = async () => ({ ok: false, status: 401, text: async () => 'bad key sk-secret' });
  await assert.rejects(() => callProviderResearch({ provider: 'openai', model: 'm', apiKeyEnv: 'OPENAI_API_KEY' }, 'S', 'U', denied, { OPENAI_API_KEY: 'sk-secret' }), e => /ai_http_401/.test(e.message) && !e.message.includes('sk-secret'));
});

test('a draft keeps the summary, the Spanish texts, the script verdict and cleaned hints for the reviewer', () => {
  const { entry } = buildDraftEntry(withSummary(), article, { stamp: '20261125100000', today: '2026-11-25' });
  assert.equal(entry.title.es, 'Fallo de Java');
  assert.equal(entry.review.summary.es, 'Texto en español'); assert.equal(entry.review.scriptWorthwhile, true); assert.equal(entry.review.scriptReason, 'A version check detects it');
  assert.deepEqual(entry.review.solutionHints, ['Check the vendor advisory', 'x'], 'markup is stripped from the hints');
  assert.deepEqual(validateEntry(entry), []);
  const noEs = buildDraftEntry({ ...analysis(), title: { en: 'T', de: 'T' } }, article, { stamp: '20261125100000', today: '2026-11-25' }).entry;
  assert.equal(noEs.title.es, undefined, 'a missing Spanish text is simply absent (the app falls back to English)');
});

test('every article gets a summary record: drafted, not a report, rejected or error (with the cause)', async () => {
  const answers = [withSummary(), { isVulnerabilityReport: false, summary: { en: 'Not about security', de: 'x' } }, 'boom401', 'boom500'];
  let i = 0;
  const callProvider = async () => { const a = answers[i++]; if (a === 'boom401') throw new Error('ai_http_401: bad key'); if (a === 'boom500') throw new Error('ai_http_500: upstream'); return a; };
  const articles = [0, 1, 2, 3].map(n => ({ ...article, url: article.url + n, title: 'Article ' + n }));
  const r = await analyzeArticles(articles, cfg, now, { callProvider });
  assert.deepEqual(r.summaries.map(s => s.status), ['drafted', 'not-a-report', 'error', 'error']);
  assert.equal(r.summaries[0].severity, 'high'); assert.equal(r.summaries[0].scriptWorthwhile, true); assert.equal(r.summaries[0].summary.es, 'Texto en español'); assert.equal(r.summaries[0].draftId, 'CVE-2026-114938');
  assert.match(r.summaries[2].error, /^ai_http_401: the AI rejected the API key/); assert.match(r.summaries[3].error, /ai_http_500/);
  assert.equal(r.summaries[2].draftId, null);
  assert.equal(summarize(article, 5, null, null, [], 'error', 'x').summary, null);
});

function makeRun() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'elo-refine-test-'));
  const articles = [{ ...article, url: article.url + '0' }, { ...article, url: article.url + '1', title: 'Flag report' }];
  fs.writeFileSync(path.join(dir, 'articles.json'), JSON.stringify({ articles }));
  return { dir, articles };
}

test('refine re-analyzes ONE article with the administrator solution text and replaces its draft', async () => {
  const { dir, articles } = makeRun();
  const first = await analyzeArticles(articles, cfg, now, { callProvider: async () => flagAnalysis() });
  fs.writeFileSync(path.join(dir, 'analysis.json'), JSON.stringify(first.analyses));
  fs.writeFileSync(path.join(dir, 'draft-vulndb.json'), JSON.stringify({ schemaVersion: 1, vulnerabilities: first.entries }));
  fs.writeFileSync(path.join(dir, 'analysis-summary.json'), JSON.stringify(first.summaries));
  const hint = path.join(dir, 'hint.txt'); fs.writeFileSync(hint, 'Fix: update to 17.0.21.1+2');
  let seen;
  const callProvider = async (c, system, user) => { seen = { system, user }; return withSummary(); };
  const out = await refineArticle({ run: dir, article: '0', 'hint-file': hint, provider: 'openai', model: 'gpt-6-sol' }, path.resolve(__dirname, '..'), now, { callProvider });
  assert.equal(out.record.status, 'drafted'); assert.equal(out.entry.detection.method, 'version-table'); assert.equal(out.entry.review.refined.by, 'administrator-hint');
  assert.match(seen.user, /<hint>\nFix: update to 17\.0\.21\.1\+2/); assert.match(seen.user, /<previous-analysis>/); assert.equal(seen.system, REFINE_SYSTEM);
  const db = JSON.parse(fs.readFileSync(path.join(dir, 'draft-vulndb.json'), 'utf8'));
  assert.equal(db.vulnerabilities.length, 2, 'the other draft is untouched'); assert.equal(db.vulnerabilities[0].detection.method, 'version-table');
  const sums = JSON.parse(fs.readFileSync(path.join(dir, 'analysis-summary.json'), 'utf8'));
  assert.equal(sums.find(s => s.index === 0).scriptWorthwhile, true);
  fs.rmSync(dir, { recursive: true, force: true });
});

test('refine with research calls the research function; without hint or research it refuses; bad folders and indexes are rejected', async () => {
  const { dir } = makeRun();
  let usedResearch = false;
  const base = { run: dir, article: '1', provider: 'openai', model: 'gpt-6-sol' };
  const root = path.resolve(__dirname, '..');
  await refineArticle({ ...base, research: true }, root, now, { callProviderResearch: async () => { usedResearch = true; return withSummary(); }, callProvider: async () => { throw new Error('must not be used'); } });
  assert.equal(usedResearch, true);
  await assert.rejects(() => refineArticle(base, root, now, {}), /refine_needs_hint_or_research/);
  await assert.rejects(() => refineArticle({ ...base, article: '9', research: true }, root, now, {}), /article_index_invalid/);
  await assert.rejects(() => refineArticle({ ...base, run: path.join(dir, 'missing'), research: true }, root, now, {}), /run_folder_invalid/);
  fs.rmSync(dir, { recursive: true, force: true });
});

test('the access test signs in through the community module and counts the visible articles without reading any', async () => {
  const log = [];
  const page = { evaluate: async () => 27, waitForSelector: async sel => { log.push(['wait', sel]); } };
  const community = { login: async (p, c, creds) => { log.push(['login', creds.user]); } };
  const chromium = { launch: async () => ({ newContext: async () => ({ newPage: async () => page }), close: async () => { log.push(['close']); } }) };
  process.env.ELO_COMMUNITY_USER = 'me@example.org'; process.env.ELO_COMMUNITY_PASSWORD = 'pw';
  const result = await testAccess({}, path.resolve(__dirname, '..'), { community, chromium });
  assert.deepEqual(result, { ok: true, articlesOnPage: 27 });
  assert.deepEqual(log.map(l => l[0]), ['login', 'wait', 'close'], 'the browser is always closed');
  assert.ok(!JSON.stringify(result).includes('pw'));
});
