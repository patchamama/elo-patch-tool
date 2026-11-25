'use strict';
// AI providers: OpenAI, Anthropic and Ollama over plain HTTPS/HTTP. No SDK, no dependency.
// The API key is read from the environment variable NAMED in the config (never from a file) and is
// redacted from every error message.
const PROVIDERS = ['openai', 'anthropic', 'ollama'];

function resolveConfig(config, env = process.env) {
  if (!config || !PROVIDERS.includes(config.provider)) throw new Error('ai_provider_invalid: use openai, anthropic or ollama');
  if (typeof config.model !== 'string' || !/^[A-Za-z0-9._:\-/]{1,100}$/.test(config.model)) throw new Error('ai_model_invalid');
  const defaults = { openai: 'https://api.openai.com/v1', anthropic: 'https://api.anthropic.com', ollama: 'http://127.0.0.1:11434' };
  const baseUrl = String(config.baseUrl || defaults[config.provider]).replace(/\/+$/, '');
  let url;
  try { url = new URL(baseUrl); } catch (_) { throw new Error('ai_base_url_invalid'); }
  const loopback = ['127.0.0.1', 'localhost', '[::1]'].includes(url.hostname);
  if (url.username || url.password || url.search || url.hash) throw new Error('ai_base_url_invalid');
  if (url.protocol !== 'https:' && !(config.provider === 'ollama' && url.protocol === 'http:' && loopback) && !(url.protocol === 'http:' && loopback)) throw new Error('ai_base_url_must_be_https');
  let apiKey = null;
  if (config.provider !== 'ollama' || config.apiKeyEnv) {
    const name = config.apiKeyEnv;
    if (typeof name !== 'string' || !/^[A-Z][A-Z0-9_]{2,63}$/.test(name)) throw new Error('ai_key_env_name_invalid: set apiKeyEnv to the NAME of the environment variable');
    apiKey = env[name];
    if (!apiKey) throw new Error('ai_key_missing: environment variable ' + name + ' is not set');
  }
  return { provider: config.provider, model: config.model, baseUrl, apiKey, maxTokens: Number(config.maxTokens) > 0 ? Math.min(Number(config.maxTokens), 16000) : 4096 };
}

function buildRequest(cfg, system, user) {
  const json = { 'Content-Type': 'application/json' };
  if (cfg.provider === 'openai') {
    return { url: cfg.baseUrl + '/chat/completions', headers: { ...json, Authorization: 'Bearer ' + cfg.apiKey },
      body: { model: cfg.model, temperature: 0, response_format: { type: 'json_object' }, messages: [{ role: 'system', content: system }, { role: 'user', content: user }] } };
  }
  if (cfg.provider === 'anthropic') {
    return { url: cfg.baseUrl + '/v1/messages', headers: { ...json, 'x-api-key': cfg.apiKey, 'anthropic-version': '2023-06-01' },
      body: { model: cfg.model, max_tokens: cfg.maxTokens, temperature: 0, system, messages: [{ role: 'user', content: user }] } };
  }
  return { url: cfg.baseUrl + '/api/chat', headers: { ...json, ...(cfg.apiKey ? { Authorization: 'Bearer ' + cfg.apiKey } : {}) },
    body: { model: cfg.model, stream: false, format: 'json', options: { temperature: 0 }, messages: [{ role: 'system', content: system }, { role: 'user', content: user }] } };
}

function extractText(provider, data) {
  if (provider === 'openai') return data && data.choices && data.choices[0] && data.choices[0].message && data.choices[0].message.content;
  if (provider === 'anthropic') return Array.isArray(data && data.content) ? data.content.filter(p => p.type === 'text').map(p => p.text).join('') : undefined;
  return data && data.message && data.message.content;
}

function redact(text, cfg) {
  let out = String(text);
  if (cfg && cfg.apiKey) out = out.split(cfg.apiKey).join('[redacted]');
  return out.slice(0, 500);
}

// Tolerant JSON extraction: models sometimes wrap the object in a fence or add a sentence around it.
function parseJsonLoose(text) {
  if (typeof text !== 'string') throw new Error('ai_empty_response');
  const unfenced = text.replace(/```(?:json)?/gi, '');
  const start = unfenced.indexOf('{'); const end = unfenced.lastIndexOf('}');
  if (start < 0 || end <= start) throw new Error('ai_response_not_json');
  try { return JSON.parse(unfenced.slice(start, end + 1)); } catch (_) { throw new Error('ai_response_not_json'); }
}

async function callProvider(config, system, user, fetchImpl = fetch, env = process.env) {
  const cfg = resolveConfig(config, env);
  const req = buildRequest(cfg, system, user);
  let res;
  try {
    res = await fetchImpl(req.url, { method: 'POST', headers: req.headers, body: JSON.stringify(req.body), redirect: 'error', signal: AbortSignal.timeout(120000) });
  } catch (e) { throw new Error('ai_network_error: ' + redact(e && e.message, cfg)); }
  if (!res.ok) {
    let detail = ''; try { detail = await res.text(); } catch (_) { /* ignore */ }
    throw new Error('ai_http_' + res.status + ': ' + redact(detail, cfg));
  }
  let data; try { data = await res.json(); } catch (_) { throw new Error('ai_response_not_json'); }
  return parseJsonLoose(extractText(cfg.provider, data));
}

module.exports = { PROVIDERS, resolveConfig, buildRequest, extractText, parseJsonLoose, callProvider, redact };
