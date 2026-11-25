'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { parseSince, parseMax, parseArticleDate } = require('../src/since');

const now = new Date('2026-11-25T12:00:00Z');

test('relative limits: days, weeks, months, years', () => {
  assert.equal(parseSince('30d', now).toISOString().slice(0, 10), '2026-10-26');
  assert.equal(parseSince('2w', now).toISOString().slice(0, 10), '2026-11-11');
  assert.equal(parseSince('3m', now).toISOString().slice(0, 10), '2026-08-27');
  assert.equal(parseSince('1y', now).toISOString().slice(0, 10), '2025-11-25');
});

test('explicit date and rejections', () => {
  assert.equal(parseSince('2026-01-15', now).toISOString().slice(0, 10), '2026-01-15');
  for (const bad of ['', 'abc', '0d', '9999y', '2026-02-30', '2027-01-01', '5x', '-3d', '3 months']) assert.throws(() => parseSince(bad, now), /since_/, bad);
  assert.throws(() => parseSince(undefined, now), /since_required/);
});

test('article count limit', () => {
  assert.equal(parseMax(undefined), 20);
  assert.equal(parseMax('50'), 50);
  for (const bad of ['0', '201', 'x', '1.5', '-1']) assert.throws(() => parseMax(bad), /max_/, bad);
});

test('board dates: ISO and German format', () => {
  assert.equal(parseArticleDate('2026-11-20T10:00:00Z').toISOString().slice(0, 10), '2026-11-20');
  assert.equal(parseArticleDate('Erstellt am 20.11.2026').toISOString().slice(0, 10), '2026-11-20');
  assert.equal(parseArticleDate('yesterday'), null);
  assert.equal(parseArticleDate(null), null);
});
