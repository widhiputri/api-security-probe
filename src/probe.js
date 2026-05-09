'use strict';
const { getToken }                                    = require('./auth');
const { checkAuthRateLimit, checkApiRateLimit }       = require('./checks/rate-limit');
const { checkSession }                                = require('./checks/session');
const { checkBola, checkIdor }                        = require('./checks/bola');
const { checkSecurityHeaders, checkTlsCert, checkOpenPorts } = require('./checks/headers');

const ALL_TESTS = ['rate-limit', 'api-rate-limit', 'session', 'bola', 'idor', 'headers', 'tls', 'ports'];

async function timed(fn) {
  const start   = Date.now();
  const results = await fn();
  const ms      = Date.now() - start;
  const arr     = Array.isArray(results) ? results : [results];
  if (arr.length > 0) arr[0] = { ...arr[0], duration_ms: ms };
  return arr;
}

async function runProbe(config, { tests } = {}) {
  const active  = tests ? tests.map(t => t.trim().toLowerCase()) : (config.tests || ALL_TESTS);
  const should  = t => active.includes(t);
  const results = [];

  const needsAdmin = should('session') || should('api-rate-limit') || should('bola') || should('headers');
  const needsUser  = should('bola');
  const needsUser2 = should('idor');

  let adminToken = null;
  let userToken  = null;
  let user2Token = null;

  if (needsAdmin && config.roles && config.roles.admin) {
    try { adminToken = await getToken(config.auth, config.roles.admin.username, config.roles.admin.password); }
    catch (e) { console.error(`[!] Could not get admin token: ${e.message}`); }
  }
  if (needsUser && config.roles && config.roles.user) {
    try { userToken = await getToken(config.auth, config.roles.user.username, config.roles.user.password); }
    catch (e) { console.error(`[!] Could not get user token: ${e.message}`); }
  }
  if (needsUser2 && config.roles && config.roles.user2) {
    try { user2Token = await getToken(config.auth, config.roles.user2.username, config.roles.user2.password); }
    catch (e) { console.error(`[!] Could not get user2 token: ${e.message}`); }
  }

  if (should('rate-limit'))                     results.push(...await timed(() => checkAuthRateLimit(config)));
  if (should('api-rate-limit') && adminToken)   results.push(...await timed(() => checkApiRateLimit(config, adminToken)));
  if (should('session')        && adminToken)   results.push(...await timed(() => checkSession(config, adminToken)));
  if (should('bola')           && userToken)    results.push(...await timed(() => checkBola(config, userToken)));
  if (should('idor')           && user2Token)   results.push(...await timed(() => checkIdor(config, user2Token)));
  if (should('headers'))                        results.push(...await timed(() => checkSecurityHeaders(config, adminToken)));
  if (should('tls'))                            results.push(...await timed(() => checkTlsCert(config)));
  if (should('ports'))                          results.push(...await timed(() => checkOpenPorts(config)));

  return results;
}

module.exports = { runProbe };
