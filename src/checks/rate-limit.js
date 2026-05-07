'use strict';
const { request } = require('../request');

async function checkAuthRateLimit(config) {
  const body = new URLSearchParams({
    grant_type: 'password',
    client_id:  config.auth.client_id,
    username:   'probe-ratelimit@nonexistent.invalid',
    password:   'wrongpassword-probe-' + Date.now(),
    ...(config.auth.client_secret ? { client_secret: config.auth.client_secret } : {}),
  }).toString();

  let got429 = false;
  for (let i = 0; i < 20; i++) {
    try {
      const res = await request(config.auth.url, {
        method:  'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body,
        timeout: 5000,
      });
      if (res.status === 429) { got429 = true; break; }
    } catch {}
  }

  return {
    check:  'Auth Rate Limit',
    status: got429 ? 'PASS' : 'FAIL',
    detail: got429
      ? '429 received after rapid auth requests'
      : 'No 429 after 20 rapid auth requests. Brute-force protection may be missing.',
  };
}

async function checkApiRateLimit(config, token) {
  const endpoints = (config.rate_limit && config.rate_limit.api_endpoints) || [];
  if (endpoints.length === 0) return [];

  const base    = config.target.replace(/\/$/, '');
  const results = [];

  for (const ep of endpoints) {
    const [method, path] = ep.includes(' ') ? ep.split(' ', 2) : ['GET', ep];
    const url = base + path;
    let got429 = false;
    for (let i = 0; i < 10; i++) {
      try {
        const res = await request(url, { method, headers: { Authorization: `Bearer ${token}` }, timeout: 5000 });
        if (res.status === 429) { got429 = true; break; }
      } catch {}
    }
    results.push({
      check:  `API Rate Limit (${path})`,
      status: got429 ? 'PASS' : 'FAIL',
      detail: got429 ? '429 received' : 'No 429 after 10 rapid requests. Endpoint may lack rate limiting.',
    });
  }
  return results;
}

module.exports = { checkAuthRateLimit, checkApiRateLimit };
