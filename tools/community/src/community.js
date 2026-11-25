'use strict';
// ELO Community access with Playwright. Credentials come from the environment (ELO_COMMUNITY_USER,
// ELO_COMMUNITY_PASSWORD), are typed into the official sign-in form and are never logged or written.
// Only pages on the allowed host are read. The board markup is an AngularJS SPA whose list/article selectors
// are configurable (config/community.json) because they cannot be verified without an account.
const { parseArticleDate } = require('./since');

function sleep(ms) { return new Promise(resolve => setTimeout(resolve, ms)); }

function sameHost(url, host) {
  try { const u = new URL(url); return u.protocol === 'https:' && u.hostname === host; } catch (_) { return false; }
}

// Pure: choose which listed articles to read. items: [{href, text, date}] in board order (newest first).
function selectArticles(items, { since, max, allowedHost, seen = new Set() }) {
  const picked = []; let olderSeen = 0; let datedSeen = 0;
  for (const item of items) {
    if (!item || typeof item.href !== 'string' || !sameHost(item.href, allowedHost) || seen.has(item.href)) continue;
    const date = parseArticleDate(item.date) || parseArticleDate(item.text);
    if (date) { datedSeen++; if (date < since) { olderSeen++; continue; } }
    seen.add(item.href);
    picked.push({ url: item.href, title: String(item.text || '').replace(/\s+/g, ' ').trim().slice(0, 300), date: date ? date.toISOString().slice(0, 10) : null });
    if (picked.length >= max) break;
  }
  // The page is exhausted for this window when every dated entry on it is older than the limit.
  return { picked, stop: datedSeen > 0 && olderSeen === datedSeen };
}

async function login(page, cfg, credentials) {
  if (!credentials || !credentials.user || !credentials.password) throw new Error('credentials_missing: set ELO_COMMUNITY_USER and ELO_COMMUNITY_PASSWORD');
  await page.goto(cfg.board.url, { waitUntil: 'domcontentloaded', timeout: 60000 });
  await page.waitForTimeout(cfg.list.waitMs);
  if (!(await page.locator(cfg.login.form).count())) return 'already-signed-in';
  await page.fill(cfg.login.username, credentials.user);
  await page.fill(cfg.login.password, credentials.password);
  await page.locator(cfg.login.submit).first().click();
  await page.waitForLoadState('domcontentloaded').catch(() => {});
  await page.waitForTimeout(cfg.list.waitMs);
  if (await page.locator(cfg.login.form).count()) throw new Error('login_failed: the community rejected the credentials');
  if (!sameHost(page.url(), cfg.board.allowedHost)) throw new Error('unexpected_host_after_login');
  return 'signed-in';
}

async function listArticles(page, cfg, { since, max, now = new Date(), maxPages = 10 }) {
  const all = []; const seen = new Set();
  for (let pageNo = 1; pageNo <= maxPages && all.length < max; pageNo++) {
    const url = cfg.board.url.replace(/([?&]page=)\d+/, '$1' + pageNo);
    if (pageNo === 1) { if (!/board=/.test(page.url())) await page.goto(url, { waitUntil: 'domcontentloaded' }); }
    else await page.evaluate(h => { window.location.hash = h; }, new URL(url).hash);
    await page.waitForTimeout(cfg.list.waitMs);
    const items = await page.evaluate(({ item, dateAttr }) => [...document.querySelectorAll(item)].map(a => {
      const row = a.closest('li, tr, article, div') || a;
      const t = row.querySelector(dateAttr);
      return { href: a.href, text: (a.innerText || a.textContent || '').trim(), date: t ? t.getAttribute('datetime') || t.textContent : (row.innerText || '').slice(0, 400) };
    }), { item: cfg.list.item, dateAttr: cfg.list.dateAttr });
    const { picked, stop } = selectArticles(items, { since, max: max - all.length, allowedHost: cfg.board.allowedHost, seen });
    all.push(...picked);
    if (stop || items.length === 0) break;
    await sleep(cfg.limits.politenessMs);
  }
  return all.slice(0, max);
}

async function readArticle(page, cfg, article) {
  if (!sameHost(article.url, cfg.board.allowedHost)) throw new Error('article_host_rejected');
  await page.goto(article.url, { waitUntil: 'domcontentloaded', timeout: 60000 });
  await page.waitForTimeout(cfg.article.waitMs);
  const data = await page.evaluate(sel => {
    const body = document.querySelector(sel);
    const h = document.querySelector('h1, h2');
    const t = document.querySelector('time[datetime]');
    return { text: body ? body.innerText : '', title: h ? h.innerText : document.title, date: t ? t.getAttribute('datetime') : null };
  }, cfg.article.body);
  const date = parseArticleDate(data.date) || parseArticleDate(data.text.slice(0, 600));
  return { url: article.url, title: (data.title || article.title || '').trim().slice(0, 300), date: date ? date.toISOString().slice(0, 10) : article.date, text: String(data.text).replace(/\r/g, '').slice(0, cfg.limits.maxCharsPerArticle) };
}

module.exports = { selectArticles, login, listArticles, readArticle, sameHost };
