'use strict';
const crypto = require('crypto');
const { request } = require('../request');
const { getTokenFull, logout } = require('../auth');

const EXPIRED_TOKEN = 'eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJwcm9iZS10ZXN0IiwiZXhwIjoxfQ.INVALIDSIGNATURE';

function b64url(buf) {
  return buf.toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function buildTamperedToken(token) {
  const parts = token.split('.');
  return `${parts[0]}.${parts[1]}.INVALIDSIGNATUREXXX`;
}

function buildAlgNoneToken(token) {
  const parts  = token.split('.');
  const header = b64url(Buffer.from(JSON.stringify({ alg: 'none', typ: 'JWT' })));
  return `${header}.${parts[1]}.`;
}

function buildHs256ConfusionToken(token, jwks) {
  const rsaKey = (jwks.keys || []).find(k => k.use === 'sig' && k.kty === 'RSA');
  if (!rsaKey) return null;
  const parts    = token.split('.');
  const header   = b64url(Buffer.from(JSON.stringify({ alg: 'HS256', typ: 'JWT' })));
  const padding  = '=='.slice(0, (4 - rsaKey.n.length % 4) % 4);
  const keyBytes = Buffer.from(rsaKey.n.replace(/-/g, '+').replace(/_/g, '/') + padding, 'base64');
  const input    = `${header}.${parts[1]}`;
  const sig      = b64url(crypto.createHmac('sha256', keyBytes).update(input).digest());
  return `${header}.${parts[1]}.${sig}`;
}

async function probe(url, token) {
  try {
    const res = await request(url, { headers: { Authorization: `Bearer ${token}` }, timeout: 8000 });
    return res.status;
  } catch { return null; }
}

async function checkSession(config, adminToken) {
  const ep = config.session && config.session.probe_endpoint;
  if (!ep) return [{ check: 'Session Management', status: 'SKIP', detail: 'No session.probe_endpoint configured.' }];

  const url   = config.target.replace(/\/$/, '') + ep;
  const items = [];

  // 1. Tampered signature
  const s1 = await probe(url, buildTamperedToken(adminToken));
  items.push({ label: 'Tampered JWT signature', status: s1 === 401 ? 'PASS' : 'FAIL',
    detail: s1 === 401 ? 'Correctly rejected with 401' : `Returned ${s1}. Signature validation may be missing.` });

  // 2. Expired token
  const s2 = await probe(url, EXPIRED_TOKEN);
  items.push({ label: 'Expired token', status: s2 === 401 ? 'PASS' : 'FAIL',
    detail: s2 === 401 ? 'Correctly rejected with 401' : `Returned ${s2}. Token expiry may not be enforced.` });

  // 3. Token after logout
  if (config.auth.logout_url && config.roles && config.roles.admin) {
    try {
      const full = await getTokenFull(config.auth, config.roles.admin.username, config.roles.admin.password);
      await logout(config.auth, full.refresh_token);
      const s3 = await probe(url, full.access_token);
      items.push({ label: 'Token reuse after logout', status: s3 === 401 ? 'PASS' : 'FAIL',
        detail: s3 === 401 ? 'Token correctly invalidated after logout (401)' : `Returned ${s3}. Tokens may not be invalidated on logout.` });
    } catch (e) {
      items.push({ label: 'Token reuse after logout', status: 'SKIP', detail: `Could not complete logout test: ${e.message}` });
    }
  } else {
    items.push({ label: 'Token reuse after logout', status: 'SKIP', detail: 'No auth.logout_url configured.' });
  }

  // 4. alg:none attack
  const s4 = await probe(url, buildAlgNoneToken(adminToken));
  items.push({ label: 'Algorithm: none attack', status: s4 === 401 ? 'PASS' : 'FAIL',
    detail: s4 === 401 ? 'Token with alg:none correctly rejected (401)' : `Returned ${s4}. JWT algorithm is not enforced. Critical auth bypass risk.` });

  // 5. RS256 to HS256 algorithm confusion
  if (config.auth.jwks_url) {
    try {
      const res  = await request(config.auth.jwks_url, { timeout: 8000 });
      const jwks = JSON.parse(res.body);
      const confToken = buildHs256ConfusionToken(adminToken, jwks);
      if (confToken) {
        const s5 = await probe(url, confToken);
        items.push({ label: 'RS256 to HS256 algorithm confusion', status: s5 === 401 ? 'PASS' : 'FAIL',
          detail: s5 === 401 ? 'Algorithm confusion token correctly rejected (401)' : `Returned ${s5}. JWT library may be vulnerable to algorithm confusion.` });
      } else {
        items.push({ label: 'RS256 to HS256 algorithm confusion', status: 'SKIP', detail: 'No RSA key found in JWKS.' });
      }
    } catch {
      items.push({ label: 'RS256 to HS256 algorithm confusion', status: 'SKIP', detail: 'JWKS endpoint unreachable.' });
    }
  } else {
    items.push({ label: 'RS256 to HS256 algorithm confusion', status: 'SKIP', detail: 'No auth.jwks_url configured.' });
  }

  const failed = items.filter(i => i.status === 'FAIL').length;
  return [{
    check:  'Session Management',
    status: failed > 0 ? 'FAIL' : 'PASS',
    detail: `${items.filter(i => i.status === 'PASS').length} passed, ${failed} failed`,
    items,
  }];
}

module.exports = { checkSession };
