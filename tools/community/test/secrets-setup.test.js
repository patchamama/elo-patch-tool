'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { parseEnvFile, isGitIgnored, loadSecrets } = require('../src/secrets');
const { describePlan, setup, requireCommunityConsent, dependencyInstalled, chromePath } = require('../src/setup');
const { main } = require('../src/cli');

test('secrets file: only known keys, quotes and comments handled, empty values ignored', () => {
  const v = parseEnvFile('# comment\nELO_COMMUNITY_USER = "me@example.org"\nELO_COMMUNITY_PASSWORD=\'pw with spaces\'\nOPENAI_API_KEY=sk-123\nANTHROPIC_API_KEY=\nPATH=C:\\evil\nrandom line\n');
  assert.deepEqual(v, { ELO_COMMUNITY_USER: 'me@example.org', ELO_COMMUNITY_PASSWORD: 'pw with spaces', OPENAI_API_KEY: 'sk-123' });
});

test('environment variables win over the file and only missing ones are filled', () => {
  const env = { OPENAI_API_KEY: 'from-env' };
  const r = loadSecrets({ file: 'C:\\x\\secrets.local.env', env, spawn: () => ({ status: 0 }), exists: () => true, read: () => 'OPENAI_API_KEY=from-file\nELO_COMMUNITY_USER=u' });
  assert.deepEqual(r.loaded, ['ELO_COMMUNITY_USER']);
  assert.equal(env.OPENAI_API_KEY, 'from-env');
  assert.equal(env.ELO_COMMUNITY_USER, 'u');
});

test('a secrets file that git does not ignore is refused; unknown git state and a missing file are fine', () => {
  assert.throws(() => loadSecrets({ file: 'C:\\x\\secrets.local.env', env: {}, spawn: () => ({ status: 1 }), exists: () => true, read: () => '' }), /secrets_file_not_ignored/);
  assert.equal(isGitIgnored('C:\\x\\f', () => ({ error: new Error('no git') })), null);
  assert.deepEqual(loadSecrets({ file: 'C:\\x\\none', env: {}, exists: () => false }).loaded, []);
  assert.deepEqual(loadSecrets({ file: 'C:\\x\\s', env: {}, spawn: () => ({ error: new Error('no git') }), exists: () => true, read: () => 'OPENAI_API_KEY=k' }).loaded, ['OPENAI_API_KEY']);
});

test('the real secrets file of this repository is git-ignored', () => {
  const path = require('node:path');
  assert.notEqual(isGitIgnored(path.join(__dirname, '..', 'secrets.local.env')), false);
});

test('the plan states credentials, the extra software and that the patch tool itself needs none of it', () => {
  const text = describePlan({ forCommunity: false, installed: false, chrome: null, nodeVersion: 'v24' });
  assert.match(text, /community\.elo\.com/);
  assert.match(text, /password/);
  assert.match(text, /playwright-core.*WILL BE INSTALLED/);
  assert.match(text, /Chrome.*NOT found/);
  assert.match(text, /patch tool itself .* needs none of this/);
  assert.match(describePlan({ forCommunity: true, installed: true, chrome: 'C:\\c.exe', nodeVersion: 'v24' }), /already installed/);
});

test('setup installs only after consent and never when cancelled', async () => {
  const out = []; const calls = [];
  const deps = { out: s => out.push(s), exists: () => false, env: {}, spawn: (cmd, args) => { calls.push([cmd, args]); return { status: 0 }; } };
  assert.equal(await setup({}, { ...deps, confirm: async () => false }), 1);
  assert.equal(calls.length, 0, 'declined: nothing installed');
  assert.match(out.join(''), /Cancelled\. Nothing was installed/);
  assert.equal(await setup({ yes: true }, { ...deps, confirm: async (q, o) => o.yes }), 0);
  assert.equal(calls.length, 1);
  assert.ok(calls[0][1].includes('--ignore-scripts') && calls[0][1].includes('install'));
  const again = []; calls.length = 0;
  assert.equal(await setup({}, { out: s => again.push(s), exists: () => true, env: {}, spawn: () => { throw new Error('must not run'); } }), 0);
  assert.match(again.join(''), /Nothing to install/);
});

test('fetch/run need the dependency and an explicit yes; nothing is contacted otherwise', async () => {
  const out = [];
  await assert.rejects(() => requireCommunityConsent({}, { out: s => out.push(s), exists: () => false, env: {} }), /dependency_missing.*setup/);
  assert.match(out.join(''), /Your ELO Community account/);
  await assert.rejects(() => requireCommunityConsent({}, { out: () => {}, exists: () => true, env: {}, confirm: async () => false }), /consent_required/);
  assert.equal(await requireCommunityConsent({ yes: true }, { out: () => {}, exists: () => true, env: {}, confirm: async (q, o) => o.yes }), true);
});

test('the cli refuses to contact the community without consent and loads secrets by name only', async () => {
  const err = []; const realErr = process.stderr.write.bind(process.stderr);
  process.stderr.write = s => { err.push(String(s)); return true; };
  try {
    let contacted = false;
    await assert.rejects(() => main(['fetch', '--since', '30d'], {
      consent: async () => { throw new Error('consent_required: nothing was contacted'); },
      loadSecrets: () => ({ loaded: ['ELO_COMMUNITY_PASSWORD'], file: 'C:\\x\\secrets.local.env', present: true }),
      community: { login: async () => { contacted = true; } }
    }), /consent_required/);
    assert.equal(contacted, false);
  } finally { process.stderr.write = realErr; }
  assert.match(err.join(''), /Loaded from secrets\.local\.env: ELO_COMMUNITY_PASSWORD \(names only\)/);
  assert.ok(!err.join('').includes('C:\\x'), 'no secret values are printed');
  assert.equal(typeof dependencyInstalled(), 'boolean');
  assert.ok(chromePath(() => false, {}) === null);
});
