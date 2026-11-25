'use strict';
// Turns the (untrusted) AI analysis into a DRAFT catalog entry for dev/vulndb.json.
// Everything the model returns is cleaned and re-validated here with the same rules as the app's validator
// (vulndb.ps1): only plain java options as probe arguments, only one -XX flag as mitigation, only https links,
// only known placeholders. Anything that does not pass is dropped and listed in review.issues for a human.
// A draft is status "draft": the scan ignores it until a person reviews, validates, simulates and installs it.
const fs = require('node:fs');
const path = require('node:path');

const PLACEHOLDERS = ['vendor', 'version', 'id', 'alias', 'option', 'runtime', 'count', 'vulnerable', 'n', 'list', 'variable', 'old', 'new', 'kind'];
const PROBE_ARG = /^-[A-Za-z0-9:+=_.\-]{1,64}$/;
const ID_RE = /^[A-Za-z0-9._\-]{3,64}$/;
const FIXED_RE = /^[0-9]{1,3}(\.[0-9]{1,9}){0,3}\+[0-9]{1,9}$/;
const HTTPS_RE = /^https:\/\/[A-Za-z0-9.\-]+\/[^\s"<>]{0,512}$/;
const SEVERITY = { high: 'high', critical: 'high', hoch: 'high', kritisch: 'high', medium: 'medium', mittel: 'medium', moderate: 'medium', low: 'low', niedrig: 'low', gering: 'low' };

const clean = (value, max) => {
  if (typeof value !== 'string') return '';
  let s = value.replace(/<[^>]*>/g, ' ').replace(/[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/g, ' ').replace(/[ \t]+/g, ' ').trim();
  s = s.replace(/\{([A-Za-z]+)\}/g, (m, name) => (PLACEHOLDERS.includes(name) ? m : '(' + name + ')'));
  return s.slice(0, max);
};
const bilingual = (value, max, fallback) => {
  const en = clean(value && value.en, max) || clean(fallback && fallback.en, max);
  const de = clean(value && value.de, max) || en;
  return { en: en || 'Not provided', de: de || 'Nicht angegeben' };
};
const normalizeUrl = value => {
  if (typeof value !== 'string') return null;
  let v = value.trim(); if (/^https:\/\/[A-Za-z0-9.\-]+$/.test(v)) v += '/';
  return HTTPS_RE.test(v) ? v : null;
};
// Catalog patterns are .NET regular expressions: leading inline flags like (?i) or (?m) are mapped to JS flags
// only to test them here; the app evaluates the original pattern with a 2 second timeout.
const toJsRegex = pattern => {
  let flags = ''; let body = pattern;
  for (let m = /^\(\?([imsx]+)\)/.exec(body); m; m = /^\(\?([imsx]+)\)/.exec(body)) {
    for (const f of m[1]) { if (f === 'x') throw new Error('unsupported_flag'); if (!flags.includes(f)) flags += f; }
    body = body.slice(m[0].length);
  }
  return new RegExp(body, flags);
};
const safeRegex = pattern => {
  if (typeof pattern !== 'string' || !pattern || pattern.length > 512) return false;
  try { toJsRegex(pattern); return true; } catch (_) { return false; }
};
const slug = text => String(text || '').toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-+|-+$/g, '').slice(0, 24);

function loadTemplates() {
  const file = path.join(__dirname, '..', '..', '..', 'dev', 'vulndb.json');
  try {
    const db = JSON.parse(fs.readFileSync(file, 'utf8'));
    const base = db.vulnerabilities[0];
    return { summary: base.actions.find(a => a.type === 'jvm-option').summary, messages: base.messages, labels: base.actions };
  } catch (_) {
    const t = { en: 'Set {option} in MACHINE {variable}. Previous value: {old} (type {kind}); new value [{new}].', de: 'Setze {option} in der systemweiten Variable {variable}. Alter Wert: {old} (Typ {kind}); neuer Wert [{new}].' };
    return { summary: t, messages: {}, labels: [] };
  }
}

function buildSimulationVersionText(build) {
  const release = build.split('+')[0];
  return `openjdk version "${release}" 2026-01-01\nOpenJDK Runtime Environment Temurin-${build} (build ${build})\nOpenJDK 64-Bit Server VM Temurin-${build} (build ${build}, mixed mode, sharing)\n`;
}

function buildDraftEntry(analysis, article, meta = {}, templates = loadTemplates()) {
  const issues = [];
  const a = analysis && typeof analysis === 'object' ? analysis : {};
  if (a.isVulnerabilityReport === false) return { entry: null, issues: ['The article is not a vulnerability report.'] };

  const rawId = typeof a.id === 'string' ? a.id.trim() : '';
  let id = /^CVE-\d{4}-\d{4,}$/.test(rawId) ? rawId : '';
  if (!id) { id = ('ELO-' + (slug(article && article.title) || 'article') + '-' + String(meta.stamp || '').slice(0, 8)).replace(/-+$/, ''); issues.push('No CVE id in the analysis; generated id ' + id + '. Replace it if the article names one.'); }
  if (!ID_RE.test(id)) id = 'ELO-DRAFT-' + String(meta.stamp || Date.now()).slice(-8);

  const severity = SEVERITY[String(a.severity || '').toLowerCase()];
  if (!severity) issues.push('Severity missing or unknown; defaulted to medium. Review it.');

  const title = bilingual(a.title, 300, { en: article && article.title });
  const problem = bilingual(a.problem, 1500, { en: 'Potentially affected runtimes were found: {list}.' });
  const solution = bilingual(a.solution, 1500, { en: 'Follow the vendor guidance in the referenced advisory.' });
  if (!(a.solution && a.solution.en)) issues.push('The article does not give a solution; the solution text is generic. Complete it by hand.');
  if (!Array.isArray(a.solutionsReported) || !a.solutionsReported.some(s => s && s.kind && s.kind !== 'none')) issues.push('No solution reported in the article.');

  // --- detection
  const detection = { method: 'probe-expect', probes: [], unknownVendor: 'inconclusive' };
  const det = a.detection || {};
  const probes = [];
  const seenProbe = new Set();
  for (const p of Array.isArray(det.probes) ? det.probes.slice(0, 4) : []) {
    const pid = typeof p.id === 'string' && /^[a-z0-9\-]{1,32}$/.test(p.id) ? p.id : null;
    const args = Array.isArray(p.args) ? p.args : [];
    if (!pid || seenProbe.has(pid) || args.length < 1 || args.length > 6 || !args.every(x => typeof x === 'string' && PROBE_ARG.test(x))) { issues.push('A probe was dropped: arguments must be plain java options such as -version.'); continue; }
    seenProbe.add(pid);
    const expect = [];
    for (const e of Array.isArray(p.expect) ? p.expect.slice(0, 8) : []) {
      if (typeof e.id === 'string' && /^[a-z0-9\-]{1,32}$/.test(e.id) && safeRegex(e.pattern)) expect.push({ id: e.id, pattern: e.pattern, meaning: clean(e.meaning, 200) });
      else issues.push('An expect pattern was dropped (invalid id or regular expression).');
    }
    probes.push({ id: pid, args, timeoutSec: 15, expect });
  }
  let simulation = null;
  const sim = a.simulation || {};
  const simText = clean(sim.version, 8000) ? String(sim.version).replace(/[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/g, '').slice(0, 8000) : '';
  if (det.method === 'version-table' && det.vendors && det.vendors.Temurin) {
    const fixed = (Array.isArray(det.vendors.Temurin.fixed) ? det.vendors.Temurin.fixed : []).filter(f => typeof f === 'string' && FIXED_RE.test(f)).slice(0, 64);
    const fixedSource = normalizeUrl(det.vendors.Temurin.fixedSource);
    if (fixed.length && fixedSource) {
      detection.method = 'version-table';
      if (!probes.length) probes.push({ id: 'version', args: ['-version'], timeoutSec: 15, expect: [{ id: 'vendor-temurin', pattern: '(?i)\\bTemurin\\b', meaning: 'The runtime is Eclipse Temurin' }] });
      detection.probes = probes;
      detection.vendors = { Temurin: { parser: 'temurin-build', fixed, fixedSource } };
      const first = fixed[0].split('+')[0].split('.')[0];
      const sample = `${first}.0.1+1`;
      simulation = { description: clean(sim.description, 400) || 'Makes a runtime look like a Temurin build before the fix.', probes: { version: buildSimulationVersionText(sample) }, expected: { status: 'PotentiallyVulnerable', vendor: 'Temurin', version: sample } };
    } else issues.push('version-table detection needs valid fixed builds (like 17.0.21.1+2) and an https fixedSource; falling back to manual review.');
  }
  if (detection.method !== 'version-table') {
    const rule = det.rule || {};
    const probeId = typeof rule.probe === 'string' ? rule.probe : '';
    if (det.method === 'probe-expect' && probes.some(p => p.id === probeId) && safeRegex(rule.vulnerablePattern) && (rule.safePattern == null || safeRegex(rule.safePattern))) {
      detection.probes = probes;
      detection.rule = { probe: probeId, vulnerablePattern: rule.vulnerablePattern, ...(rule.safePattern ? { safePattern: rule.safePattern } : {}) };
      const text = simText || clean(sim.flags, 2000);
      if (text && toJsRegex(rule.vulnerablePattern).test(text)) simulation = { description: clean(sim.description, 400) || 'Replays the output of the probe on a vulnerable runtime.', probes: { [probeId]: text }, expected: { status: 'PotentiallyVulnerable' } };
      else issues.push('The simulated probe output does not match the vulnerable pattern; add a simulation by hand.');
    } else {
      // Placeholder that can never match: the entry documents the finding but detects nothing until a person completes it.
      detection.probes = probes.length ? probes : [{ id: 'version', args: ['-version'], timeoutSec: 15, expect: [] }];
      detection.rule = { probe: detection.probes[0].id, vulnerablePattern: '(?!)' };
      issues.push('Detection could not be derived safely from the article: the entry is a placeholder and detects nothing until a person writes the probe and patterns.');
    }
  }

  // --- actions
  const actions = [
    { id: 'update-runtime', type: 'runtime-update', recommended: true, label: { en: 'Update Java runtime', de: 'Java-Runtime aktualisieren' } }
  ];
  const option = typeof a.mitigationOption === 'string' ? a.mitigationOption.trim() : '';
  if (option) {
    const m = /^-XX:([+-])([A-Za-z0-9_]{1,64})$/.exec(option);
    if (m) {
      actions.push({ id: 'mitigate', type: 'jvm-option', scope: 'machine-environment', variable: 'JAVA_TOOL_OPTIONS', option, conflictPattern: m[2],
        label: { en: 'Temporary mitigation', de: 'Vorlaeufige Risikominderung' },
        verify: { args: ['-XX:+PrintFlagsFinal', '-version'], expect: `(?m)^\\s*bool\\s+${m[2]}\\s*(?::=|=)\\s*(true|false)\\b[^\\r\\n]*$`, mustBe: m[1] === '-' ? 'false' : 'true' },
        summary: templates.summary });
    } else issues.push('The mitigation option is not a single -XX:+/-Flag and was dropped.');
  }
  actions.push({ id: 'restore-backup', type: 'restore-backup', label: { en: 'Restore this backup', de: 'Dieses Backup wiederherstellen' } });

  const advisories = [];
  for (const url of [article && article.url, a.advisoryUrl]) {
    const u = normalizeUrl(url);
    if (u && !advisories.some(x => x.url === u)) advisories.push({ id: 'source-' + (advisories.length + 1), url: u, title: { en: 'ELO Community article: ' + clean(article && article.title, 200), de: 'ELO-Community-Artikel: ' + clean(article && article.title, 200) }, provenance: 'Supplied', provenanceNote: 'Article read by an AI-assisted draft; not independently verified.' });
  }

  const entry = {
    id, aliases: [], severity: severity || 'medium', status: 'draft', origin: 'ai-draft',
    title, verifiedOn: (meta.today || new Date().toISOString().slice(0, 10)),
    advisories, detection, problem, solution, actions,
    messages: templates.messages || {},
    report: { headline: { en: '{id}: potentially vulnerable runtimes were found', de: '{id}: potenziell verwundbare Runtimes wurden gefunden' } },
    review: { required: true, severityReason: clean(a.severityReason, 500), issues, provider: meta.provider || null, model: meta.model || null, createdUtc: meta.createdUtc || new Date().toISOString(),
      article: { url: article && article.url || null, title: clean(article && article.title, 300), date: article && article.date || null } }
  };
  if (simulation) entry.simulation = simulation;
  return { entry, issues };
}

// JS-side mirror of the app validator (subset that matters for safety); the authoritative check is the app's --catalog-validate.
function validateEntry(entry) {
  const problems = [];
  if (!entry || !ID_RE.test(entry.id || '')) problems.push('invalid id');
  if (!['high', 'medium', 'low'].includes(entry.severity)) problems.push('severity');
  if (entry.status !== 'draft') problems.push('drafts must have status draft');
  for (const f of ['title', 'problem', 'solution']) if (!entry[f] || !entry[f].en || !entry[f].de) problems.push(f + ' needs English and German text');
  for (const p of (entry.detection && entry.detection.probes) || []) if (!Array.isArray(p.args) || !p.args.every(x => PROBE_ARG.test(x))) problems.push('probe args');
  for (const a of entry.actions || []) {
    if (!['runtime-update', 'jvm-option', 'restore-backup'].includes(a.type)) problems.push('action type');
    if (a.type === 'jvm-option' && (a.variable !== 'JAVA_TOOL_OPTIONS' || !/^-XX:[+-][A-Za-z0-9_]{1,64}$/.test(a.option))) problems.push('mitigation');
  }
  for (const adv of entry.advisories || []) if (!HTTPS_RE.test(adv.url)) problems.push('advisory url');
  return problems;
}

function buildDraftDb(entries, sources, today = new Date().toISOString().slice(0, 10)) {
  return { schemaVersion: 1, updated: today, description: 'AI-assisted DRAFT catalog. Review, validate (--catalog-validate), simulate (--catalog-simulate) and only then install.', sources, vulnerabilities: entries };
}

module.exports = { toJsRegex, safeRegex, buildDraftEntry, validateEntry, buildDraftDb, clean, normalizeUrl, loadTemplates, PROBE_ARG, SEVERITY };
