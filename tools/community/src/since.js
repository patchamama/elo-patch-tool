'use strict';
// Limits for the article analysis: "last 30 days", "3 months", "1 year" or an explicit date.
const UNITS = { d: 1, w: 7, m: 30, y: 365 };

function parseSince(text, now = new Date()) {
  if (text === undefined || text === null || String(text).trim() === '') throw new Error('since_required');
  const s = String(text).trim().toLowerCase();
  const rel = /^(\d{1,4})\s*([dwmy])$/.exec(s);
  if (rel) {
    const days = Number(rel[1]) * UNITS[rel[2]];
    if (days < 1 || days > 3650) throw new Error('since_out_of_range');
    return new Date(now.getTime() - days * 86400000);
  }
  const iso = /^(\d{4})-(\d{2})-(\d{2})$/.exec(s);
  if (iso) {
    const d = new Date(Date.UTC(Number(iso[1]), Number(iso[2]) - 1, Number(iso[3])));
    if (d.getUTCFullYear() !== Number(iso[1]) || d.getUTCMonth() !== Number(iso[2]) - 1 || d.getUTCDate() !== Number(iso[3])) throw new Error('since_invalid_date');
    if (d.getTime() > now.getTime()) throw new Error('since_in_the_future');
    return d;
  }
  throw new Error('since_invalid');
}

function parseMax(text, hard = 200) {
  if (text === undefined || text === null) return 20;
  if (!/^\d{1,4}$/.test(String(text))) throw new Error('max_invalid');
  const n = Number(text);
  if (n < 1 || n > hard) throw new Error('max_out_of_range');
  return n;
}

// Month names as the board prints them in German ("18. Nov. 2026", "3. M\u00e4rz 2026") and English ("Nov 18, 2026").
const MONTHS = { jan: 0, feb: 1, mar: 2, 'm\u00e4r': 2, apr: 3, mai: 4, may: 4, jun: 5, jul: 6, aug: 7, sep: 8, okt: 9, oct: 9, nov: 10, dez: 11, dec: 11 };
const monthIndex = name => MONTHS[String(name).toLowerCase().replace(/\.$/, '').slice(0, 3)];
const validDate = (y, m, d) => { const date = new Date(Date.UTC(y, m, d)); return date.getUTCFullYear() === y && date.getUTCMonth() === m && date.getUTCDate() === d ? date : null; };

// Dates as shown by the board: ISO (also datetime attributes), dd.mm.yyyy, "18. Nov. 2026" or "Nov 18, 2026".
// mm/dd/yyyy is NOT guessed.
function parseArticleDate(text) {
  if (!text) return null;
  const s = String(text).trim();
  let m = /(\d{4})-(\d{2})-(\d{2})/.exec(s);
  if (m) return validDate(Number(m[1]), Number(m[2]) - 1, Number(m[3]));
  m = /(\d{1,2})\.(\d{1,2})\.(\d{4})/.exec(s);
  if (m) return validDate(Number(m[3]), Number(m[2]) - 1, Number(m[1]));
  m = /(\d{1,2})\.?\s+([A-Za-z\u00e4\u00c4]{3,9})\.?\s+(\d{4})/.exec(s);
  if (m && monthIndex(m[2]) !== undefined) return validDate(Number(m[3]), monthIndex(m[2]), Number(m[1]));
  m = /([A-Za-z]{3,9})\.?\s+(\d{1,2}),?\s+(\d{4})/.exec(s);
  if (m && monthIndex(m[1]) !== undefined) return validDate(Number(m[3]), monthIndex(m[1]), Number(m[2]));
  return null;
}

module.exports = { parseSince, parseMax, parseArticleDate };
