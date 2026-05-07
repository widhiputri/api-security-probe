'use strict';
const { request } = require('./request');

function buildBody(auth, extra = {}) {
  return new URLSearchParams({
    client_id: auth.client_id,
    ...(auth.client_secret ? { client_secret: auth.client_secret } : {}),
    ...extra,
  }).toString();
}

async function getToken(auth, username, password) {
  const res = await request(auth.url, {
    method:  'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body:    buildBody(auth, { grant_type: 'password', username, password }),
  });
  if (res.status !== 200) throw new Error(`Auth failed for ${username}: HTTP ${res.status}`);
  return JSON.parse(res.body).access_token;
}

async function getTokenFull(auth, username, password) {
  const res = await request(auth.url, {
    method:  'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body:    buildBody(auth, { grant_type: 'password', username, password }),
  });
  if (res.status !== 200) throw new Error(`Auth failed for ${username}: HTTP ${res.status}`);
  return JSON.parse(res.body);
}

async function logout(auth, refreshToken) {
  if (!auth.logout_url) return;
  await request(auth.logout_url, {
    method:  'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body:    buildBody(auth, { refresh_token: refreshToken }),
  }).catch(() => {});
}

module.exports = { getToken, getTokenFull, logout };
