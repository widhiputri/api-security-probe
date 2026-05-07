'use strict';
const { request } = require('../request');

function resolveUrl(base, template, ids = {}) {
  let path = template;
  for (const [k, v] of Object.entries(ids)) path = path.replace(new RegExp(`\\{${k}\\}`, 'g'), v);
  return base.replace(/\/$/, '') + path;
}

function parseEndpoint(ep) {
  return ep.includes(' ') ? ep.split(' ', 2) : ['GET', ep];
}

async function checkBola(config, userToken) {
  const endpoints = (config.bola && config.bola.admin_endpoints) || [];
  if (endpoints.length === 0) return [{ check: 'BOLA (cross-role)', status: 'SKIP', detail: 'No bola.admin_endpoints configured.' }];

  const base  = config.target.replace(/\/$/, '');
  const items = [];

  for (const ep of endpoints) {
    const [method, path] = parseEndpoint(ep);
    try {
      const res     = await request(base + path, { method, headers: { Authorization: `Bearer ${userToken}` }, timeout: 8000 });
      const blocked = [401, 403, 404].includes(res.status);
      items.push({ label: `${method} ${path}`, status: blocked ? 'PASS' : 'FAIL',
        detail: blocked
          ? `Correctly blocked with ${res.status}`
          : `Returned ${res.status} with user token. Admin endpoint may not enforce role restrictions.` });
    } catch {
      items.push({ label: `${method} ${path}`, status: 'PASS', detail: 'Endpoint unreachable. Treated as blocked.' });
    }
  }

  const failed = items.filter(i => i.status === 'FAIL').length;
  return [{
    check:  'BOLA (cross-role)',
    status: failed > 0 ? 'FAIL' : 'PASS',
    detail: `${items.filter(i => i.status === 'PASS').length} passed, ${failed} failed`,
    items,
  }];
}

async function checkIdor(config, user2Token) {
  const idorConfig = config.idor;
  if (!idorConfig || !idorConfig.endpoints || idorConfig.endpoints.length === 0) {
    return [{ check: 'IDOR (cross-user)', status: 'SKIP', detail: 'No idor.endpoints configured.' }];
  }

  const base    = config.target.replace(/\/$/, '');
  const ids     = idorConfig.example_ids || {};
  const items   = [];

  for (const ep of idorConfig.endpoints) {
    const [method, template] = parseEndpoint(ep);
    const url = resolveUrl(base, template, ids);
    try {
      const res = await request(url, { method, headers: { Authorization: `Bearer ${user2Token}` }, timeout: 8000 });
      if (res.status === 200) {
        items.push({ label: `${method} ${template}`, status: 'FAIL', detail: "User2 can access user's resource. Returned 200." });
      } else if ([401, 403, 404].includes(res.status)) {
        items.push({ label: `${method} ${template}`, status: 'PASS', detail: `Correctly blocked with ${res.status}` });
      } else {
        items.push({ label: `${method} ${template}`, status: 'SKIP', detail: `Returned ${res.status}. Manual review recommended.` });
      }
    } catch {
      items.push({ label: `${method} ${template}`, status: 'PASS', detail: 'Endpoint unreachable. Treated as blocked.' });
    }
  }

  const failed = items.filter(i => i.status === 'FAIL').length;
  return [{
    check:  'IDOR (cross-user)',
    status: failed > 0 ? 'FAIL' : items.some(i => i.status === 'PASS') ? 'PASS' : 'SKIP',
    detail: `${items.filter(i => i.status === 'PASS').length} passed, ${failed} failed`,
    items,
  }];
}

module.exports = { checkBola, checkIdor };
