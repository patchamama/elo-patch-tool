'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { buildDraftEntry, validateEntry, buildDraftDb, clean, toJsRegex } = require('../src/draft');
const { article, analysis, flagAnalysis } = require('./helpers');

const meta = { stamp: '20261125100000', today: '2026-11-25', provider: 'ollama', model: 'llama3.1', createdUtc: '2026-11-25T10:00:00Z' };

test('a Java-build report becomes a draft with a version table, mitigation and simulation', () => {
  const { entry, issues } = buildDraftEntry(analysis(), article, meta);
  assert.equal(entry.id, 'CVE-2026-114938');
  assert.equal(entry.status, 'draft');
  assert.equal(entry.origin, 'ai-draft');
  assert.equal(entry.severity, 'high', 'High is normalized');
  assert.equal(entry.detection.method, 'version-table');
  assert.deepEqual(entry.detection.vendors.Temurin.fixed, ['17.0.21.1+2', '21.0.13.1+2']);
  assert.equal(entry.detection.vendors.Temurin.parser, 'temurin-build');
  const mit = entry.actions.find(a => a.type === 'jvm-option');
  assert.equal(mit.option, '-XX:-UseBASE64Intrinsics');
  assert.equal(mit.conflictPattern, 'UseBASE64Intrinsics');
  assert.equal(mit.verify.mustBe, 'false');
  assert.deepEqual(entry.actions.map(a => a.type), ['runtime-update', 'jvm-option', 'restore-backup']);
  assert.equal(entry.simulation.expected.status, 'PotentiallyVulnerable');
  assert.match(entry.simulation.probes.version, /Temurin-17\.0\.1\+1/);
  assert.equal(entry.advisories[0].url, article.url);
  assert.equal(entry.review.required, true);
  assert.deepEqual(validateEntry(entry), []);
  assert.deepEqual(issues, []);
});

test('a configuration-flag report becomes a probe-expect draft with its simulation', () => {
  const { entry, issues } = buildDraftEntry(flagAnalysis(), article, meta);
  assert.equal(entry.severity, 'medium', 'mittel is normalized');
  assert.equal(entry.detection.method, 'probe-expect');
  assert.equal(entry.detection.rule.probe, 'flags');
  assert.ok(toJsRegex(entry.detection.rule.vulnerablePattern).test(entry.simulation.probes.flags));
  assert.match(entry.id, /^ELO-/, 'a missing CVE id gets a generated one');
  assert.ok(issues.some(i => /No CVE id/.test(i)));
  assert.ok(issues.some(i => /No solution reported/.test(i)), 'a missing solution is flagged for the human');
  assert.deepEqual(validateEntry(entry), []);
});

test('hostile or malformed AI output is cleaned, never trusted', () => {
  const evil = analysis();
  evil.detection.probes = [
    { id: 'version', args: ['-version', '; calc'], expect: [] },
    { id: 'bad', args: ['C:\\evil.exe'], expect: [] },
    { id: 'ok', args: ['-XX:+PrintFlagsFinal'], expect: [{ id: 'x', pattern: '([', meaning: 'broken' }] }
  ];
  evil.mitigationOption = '-javaagent:evil.jar';
  evil.title = { en: '<img src=x onerror=alert(1)>Title {evil}', de: '' };
  evil.severity = 'catastrophic';
  evil.detection.vendors.Temurin.fixedSource = 'http://example.org/x';
  const { entry, issues } = buildDraftEntry(evil, article, meta);
  assert.deepEqual(entry.actions.map(a => a.type), ['runtime-update', 'restore-backup'], 'only a single -XX flag can become a mitigation');
  assert.equal(entry.severity, 'medium');
  assert.ok(!/[<>]/.test(entry.title.en) && !entry.title.en.includes('{evil}'), 'markup and unknown placeholders removed');
  assert.equal(entry.detection.method, 'probe-expect', 'an http fixed source is refused, so the version table is not used');
  assert.equal(entry.detection.rule.vulnerablePattern, '(?!)', 'placeholder that detects nothing');
  for (const probe of entry.detection.probes) assert.ok(probe.args.every(a => /^-[A-Za-z0-9:+=_.\-]{1,64}$/.test(a)));
  assert.ok(issues.length >= 4);
  assert.deepEqual(validateEntry(entry), []);
});

test('non-reports, empty answers and bad ids', () => {
  assert.equal(buildDraftEntry({ isVulnerabilityReport: false }, article, meta).entry, null);
  const { entry } = buildDraftEntry({}, { title: '!!!', url: 'http://insecure.example/x' }, meta);
  assert.match(entry.id, /^[A-Za-z0-9._-]{3,64}$/);
  assert.deepEqual(entry.advisories, [], 'only https article links are kept');
  assert.equal(entry.status, 'draft');
});

test('the draft database wraps entries with the shared sources and the review warning', () => {
  const { entry } = buildDraftEntry(analysis(), article, meta);
  const db = buildDraftDb([entry], [{ id: 's', type: 'elo-community', url: 'https://community.elo.com/x' }], '2026-11-25');
  assert.equal(db.schemaVersion, 1);
  assert.match(db.description, /DRAFT/);
  assert.equal(JSON.stringify(db).match(/password|apiKey|secret/i), null, 'no credentials in a draft');
});

test('clean() strips tags and control characters and caps the length', () => {
  assert.equal(clean('<b>a</b>\u0000 b   c', 100), 'a b c');
  assert.equal(clean('x'.repeat(50), 10).length, 10);
  assert.equal(clean(42, 10), '');
});
