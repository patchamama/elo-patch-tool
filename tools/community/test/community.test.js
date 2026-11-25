'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { selectArticles, login, sameHost } = require('../src/community');

const host = 'community.elo.com';
const since = new Date('2026-10-26T00:00:00Z');
const item = (n, date) => ({ href: `https://${host}/community/x#/article?id=${n}`, text: `Article ${n}`, date });

test('selectArticles keeps recent and undated entries, drops old ones, dedupes and respects the count limit', () => {
  const items = [item(1, '2026-11-20'), item(2, '20.11.2026'), item(2, '20.11.2026'), item(3, null), item(4, '2026-09-01'), item(5, '2026-11-01')];
  const r = selectArticles(items, { since, max: 3, allowedHost: host });
  assert.deepEqual(r.picked.map(p => p.title), ['Article 1', 'Article 2', 'Article 3']);
  assert.equal(r.picked[1].date, '2026-11-20');
  assert.equal(r.picked[2].date, null);
  const all = selectArticles(items, { since, max: 10, allowedHost: host });
  assert.equal(all.picked.length, 4, 'article 4 is older than the limit');
});

test('paging stops once every dated entry is older than the limit', () => {
  const r = selectArticles([item(7, '2026-09-01'), item(8, '2026-08-01')], { since, max: 10, allowedHost: host });
  assert.equal(r.stop, true);
  assert.equal(r.picked.length, 0);
  assert.equal(selectArticles([item(9, '2026-11-01')], { since, max: 10, allowedHost: host }).stop, false);
});

test('links outside the community host or without https are never read', () => {
  const items = [{ href: 'https://evil.example/x', text: 'a', date: '2026-11-20' }, { href: 'http://community.elo.com/x', text: 'b', date: '2026-11-20' }, { href: 'javascript:alert(1)', text: 'c' }, { href: 'https://community.elo.com.evil.example/x', text: 'd' }];
  assert.equal(selectArticles(items, { since, max: 10, allowedHost: host }).picked.length, 0);
  assert.equal(sameHost('https://community.elo.com/a', host), true);
  assert.equal(sameHost('https://community.elo.com@evil.example/a', host), false);
});

// A minimal Playwright page double: records what is typed and clicked.
function fakePage({ rejects = false } = {}) {
  const log = [];
  let formShown = true; let url = 'https://community.elo.com/auth2/sign-in';
  return {
    log,
    goto: async u => { log.push(['goto', u]); },
    waitForTimeout: async () => {},
    waitForLoadState: async () => {},
    url: () => url,
    fill: async (sel, value) => { log.push(['fill', sel, value]); },
    locator: sel => ({
      count: async () => (sel === '#eloLoginForm' ? (formShown ? 1 : 0) : 1),
      first: () => ({ click: async () => { log.push(['click', sel]); if (!rejects) { formShown = false; url = 'https://community.elo.com/board'; } } })
    })
  };
}
const cfg = { board: { url: 'https://community.elo.com/board#/?board=KBB103&page=1', allowedHost: host }, login: { form: '#eloLoginForm', username: 'input[name=username]', password: 'input[name=password]', submit: '#eloLoginForm button' }, list: { waitMs: 0 } };

test('login types the credentials into the official form and reports success', async () => {
  const page = fakePage();
  assert.equal(await login(page, cfg, { user: 'me@example.org', password: 'pw-123' }), 'signed-in');
  assert.deepEqual(page.log.filter(l => l[0] === 'fill').map(l => l[1]), ['input[name=username]', 'input[name=password]']);
});

test('login failure and missing credentials are reported without echoing the password', async () => {
  await assert.rejects(() => login(fakePage({ rejects: true }), cfg, { user: 'u', password: 'secret-pw' }), e => /login_failed/.test(e.message) && !e.message.includes('secret-pw'));
  await assert.rejects(() => login(fakePage(), cfg, { user: '', password: '' }), /credentials_missing/);
});
