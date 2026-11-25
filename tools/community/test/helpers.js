'use strict';
// A realistic AI analysis of a (fictional) article, plus variants used to prove the sanitizing.
const article = { url: 'https://community.elo.com/community/plugin/de.elo.ix.plugin.proxy/wf/apps/app/sol.knowledge.apps.KnowledgeBoard/#/article?id=KBA1', title: 'Security notice: Java flaw CVE-2026-114938', date: '2026-11-20', text: 'Affected: Temurin before 17.0.21.1+2. Update Java or set -XX:-UseBASE64Intrinsics.' };
const analysis = () => ({
  isVulnerabilityReport: true, id: 'CVE-2026-114938',
  title: { en: 'Java flaw', de: 'Java-Fehler' }, severity: 'High', severityReason: 'CVSS 8.1',
  javaRelated: true,
  solutionsReported: [{ kind: 'update', summary: 'Update Temurin' }, { kind: 'mitigation', summary: 'Disable BASE64 intrinsics' }],
  problem: { en: '{n} runtime(s) are affected: {list}.', de: '{n} Runtime(s) betroffen: {list}.' },
  solution: { en: 'Update Java.', de: 'Java aktualisieren.' },
  detection: {
    method: 'version-table',
    probes: [{ id: 'version', args: ['-version'], expect: [{ id: 'vendor-temurin', pattern: '(?i)\\bTemurin\\b', meaning: 'Temurin' }] }],
    vendors: { Temurin: { fixed: ['17.0.21.1+2', '21.0.13.1+2'], fixedSource: 'https://adoptium.net/news/2026/11/x/' } }, rule: null
  },
  mitigationOption: '-XX:-UseBASE64Intrinsics',
  simulation: { description: 'looks vulnerable', version: 'openjdk version "17.0.2"', flags: null, expectedVendor: 'Temurin', expectedVersion: '17.0.2+8' }
});
const flagAnalysis = () => ({
  isVulnerabilityReport: true, id: null, title: { en: 'Config flag exposes data', de: 'Konfigurationsflag' }, severity: 'mittel',
  solutionsReported: [{ kind: 'none', summary: '' }],
  problem: { en: 'Flag enabled on {n} runtime(s).', de: 'Flag aktiv auf {n}.' }, solution: { en: '', de: '' },
  detection: {
    method: 'probe-expect', probes: [{ id: 'flags', args: ['-XX:+PrintFlagsFinal', '-version'], expect: [] }], vendors: null,
    rule: { probe: 'flags', vulnerablePattern: '(?m)^\\s*bool\\s+DemoFlag\\s*=\\s*true', safePattern: '(?m)^\\s*bool\\s+DemoFlag\\s*=\\s*false' }
  },
  mitigationOption: null, simulation: { description: 'flag on', version: '     bool DemoFlag = true {product}', flags: null }
});
module.exports = { article, analysis, flagAnalysis };
