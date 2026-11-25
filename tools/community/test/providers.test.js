'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { resolveConfig, buildRequest, buildListRequest, extractModels, listModels, extractText, parseJsonLoose, callProvider } = require('../src/providers');

const env = { OPENAI_API_KEY: 'sk-secret-openai', ANTHROPIC_API_KEY: 'sk-ant-secret' };
const openai = { provider: 'openai', model: 'gpt-4o', apiKeyEnv: 'OPENAI_API_KEY' };

test('OpenAI request shape (JSON mode, bearer key)', () => {
  const r = buildRequest(resolveConfig(openai, env), 'SYS', 'USER');
  assert.equal(r.url, 'https://api.openai.com/v1/chat/completions');
  assert.equal(r.headers.Authorization, 'Bearer sk-secret-openai');
  assert.deepEqual(r.body.response_format, { type: 'json_object' });
  assert.equal(r.body.messages[0].role, 'system');
});

test('Anthropic request shape (x-api-key, version header, system prompt)', () => {
  const cfg = resolveConfig({ provider: 'anthropic', model: 'claude-sonnet-5-5', apiKeyEnv: 'ANTHROPIC_API_KEY' }, env);
  const r = buildRequest(cfg, 'SYS', 'USER');
  assert.equal(r.url, 'https://api.anthropic.com/v1/messages');
  assert.equal(r.headers['x-api-key'], 'sk-ant-secret');
  assert.equal(r.headers['anthropic-version'], '2023-06-01');
  assert.equal(r.body.system, 'SYS');
  assert.equal(r.body.messages[0].content, 'USER');
});

test('Ollama request shape (local, no key, JSON format, no streaming)', () => {
  const r = buildRequest(resolveConfig({ provider: 'ollama', model: 'llama3.1' }, {}), 'SYS', 'USER');
  assert.equal(r.url, 'http://127.0.0.1:11434/api/chat');
  assert.equal(r.body.format, 'json');
  assert.equal(r.body.stream, false);
  assert.equal(r.headers.Authorization, undefined);
});

test('configuration is validated; keys only by environment variable name', () => {
  assert.throws(() => resolveConfig({ provider: 'gemini', model: 'x' }, env), /ai_provider_invalid/);
  assert.throws(() => resolveConfig({ ...openai, model: 'bad model!' }, env), /ai_model_invalid/);
  assert.throws(() => resolveConfig({ ...openai, apiKeyEnv: 'sk-live-abc' }, env), /ai_key_env_name_invalid/);
  assert.throws(() => resolveConfig(openai, {}), /ai_key_missing/);
  assert.throws(() => resolveConfig({ ...openai, baseUrl: 'http://example.org' }, env), /https/);
  assert.throws(() => resolveConfig({ ...openai, baseUrl: 'https://user:pw@example.org' }, env), /ai_base_url_invalid/);
  assert.equal(resolveConfig({ provider: 'ollama', model: 'm', baseUrl: 'http://localhost:11434/' }, {}).baseUrl, 'http://localhost:11434');
  assert.throws(() => resolveConfig({ provider: 'ollama', model: 'm', baseUrl: 'http://10.0.0.5:11434' }, {}), /https/);
});

test('response extraction for each provider and tolerant JSON parsing', () => {
  assert.equal(extractText('openai', { choices: [{ message: { content: '{"a":1}' } }] }), '{"a":1}');
  assert.equal(extractText('anthropic', { content: [{ type: 'text', text: '{"a"' }, { type: 'text', text: ':1}' }] }), '{"a":1}');
  assert.equal(extractText('ollama', { message: { content: '{"a":1}' } }), '{"a":1}');
  assert.deepEqual(parseJsonLoose('Here you go:\n```json\n{"a":1}\n```'), { a: 1 });
  assert.throws(() => parseJsonLoose('no json here'), /ai_response_not_json/);
  assert.throws(() => parseJsonLoose(undefined), /ai_empty_response/);
});

test('callProvider uses the request, parses the answer and never leaks the key', async () => {
  let seen;
  const ok = async (url, init) => { seen = { url, init }; return { ok: true, json: async () => ({ choices: [{ message: { content: '{"isVulnerabilityReport":true}' } }] }) }; };
  assert.deepEqual(await callProvider(openai, 'S', 'U', ok, env), { isVulnerabilityReport: true });
  assert.equal(seen.init.redirect, 'error');
  assert.equal(JSON.parse(seen.init.body).model, 'gpt-4o');
  const leaky = async () => ({ ok: false, status: 401, text: async () => 'bad key sk-secret-openai' });
  await assert.rejects(() => callProvider(openai, 'S', 'U', leaky, env), e => /ai_http_401/.test(e.message) && !e.message.includes('sk-secret-openai'));
  const net = async () => { throw new Error('connect failed for Bearer sk-secret-openai'); };
  await assert.rejects(() => callProvider(openai, 'S', 'U', net, env), e => !e.message.includes('sk-secret-openai'));
});

test('OpenAI requests do not force a temperature (newer models only accept the default)', () => {
  const r = buildRequest(resolveConfig(openai, env), 'SYS', 'USER');
  assert.equal(r.body.temperature, undefined);
});

test('model list requests per provider', () => {
  assert.deepEqual(buildListRequest(resolveConfig(openai, env)), { url: 'https://api.openai.com/v1/models', headers: { Authorization: 'Bearer sk-secret-openai' } });
  const a = buildListRequest(resolveConfig({ provider: 'anthropic', model: 'x', apiKeyEnv: 'ANTHROPIC_API_KEY' }, env));
  assert.equal(a.url, 'https://api.anthropic.com/v1/models?limit=100'); assert.equal(a.headers['x-api-key'], 'sk-ant-secret');
  assert.equal(buildListRequest(resolveConfig({ provider: 'ollama', model: 'x' }, {})).url, 'http://127.0.0.1:11434/api/tags');
});

test('model lists are parsed, de-duplicated, sorted and limited to safe ids; non-chat models are dropped for OpenAI', () => {
  assert.deepEqual(extractModels('openai', { data: [{ id: 'gpt-6-sol' }, { id: 'text-embedding-3-large' }, { id: 'gpt-5' }, { id: 'gpt-5' }, { id: 'whisper-1' }, { id: 'bad id!' }, { id: 7 }, null] }), ['gpt-5', 'gpt-6-sol']);
  assert.deepEqual(extractModels('anthropic', { data: [{ id: 'claude-b' }, { id: 'claude-a' }] }), ['claude-a', 'claude-b']);
  assert.deepEqual(extractModels('ollama', { models: [{ name: 'llama3.1:8b' }, { model: 'qwen2' }] }), ['llama3.1:8b', 'qwen2']);
  assert.deepEqual(extractModels('openai', {}), []);
});

test('listModels needs no model in the config, redacts the key and reports HTTP errors by code', async () => {
  let seen;
  const ok = async (url, init) => { seen = { url, init }; return { ok: true, json: async () => ({ data: [{ id: 'gpt-6-sol' }] }) }; };
  assert.deepEqual(await listModels({ provider: 'openai', apiKeyEnv: 'OPENAI_API_KEY' }, ok, env), ['gpt-6-sol']);
  assert.equal(seen.init.method, 'GET'); assert.equal(seen.init.redirect, 'error');
  const denied = async () => ({ ok: false, status: 401, text: async () => 'Incorrect API key sk-secret-openai' });
  await assert.rejects(() => listModels({ provider: 'openai', apiKeyEnv: 'OPENAI_API_KEY' }, denied, env), e => /ai_http_401/.test(e.message) && !e.message.includes('sk-secret-openai'));
  await assert.rejects(() => listModels({ provider: 'openai', apiKeyEnv: 'OPENAI_API_KEY' }, ok, {}), /ai_key_missing/);
});
