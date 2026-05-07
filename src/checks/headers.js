'use strict';
const tls = require('tls');
const net = require('net');
const { request } = require('../request');

const REQUIRED_HEADERS = {
  'strict-transport-security': 'Forces HTTPS, prevents downgrade attacks.',
  'x-content-type-options':    'Prevents MIME sniffing.',
  'x-frame-options':           'Prevents clickjacking.',
  'content-security-policy':   'Restricts resource loading, mitigates XSS.',
  'referrer-policy':           'Controls referrer information leakage.',
};

const DEFAULT_PORTS = [22, 23, 3306, 5432, 6379, 27017, 8080, 8443, 9200];

async function checkSecurityHeaders(config, token) {
  const base = config.target.replace(/\/$/, '');
  const ep   = (config.headers && config.headers.probe_endpoint)
             || (config.session && config.session.probe_endpoint)
             || '/';
  const url  = base + ep;
  const items = [];

  try {
    const res = await request(url, { headers: token ? { Authorization: `Bearer ${token}` } : {}, timeout: 8000 });
    for (const [header, desc] of Object.entries(REQUIRED_HEADERS)) {
      const present = header in res.headers;
      items.push({ label: header, status: present ? 'PASS' : 'FAIL',
        detail: present ? 'Header present' : `Header missing. ${desc}` });
    }
  } catch (e) {
    return [{ check: 'Security Headers', status: 'SKIP', detail: `Could not probe headers: ${e.message}` }];
  }

  const failed = items.filter(i => i.status === 'FAIL').length;
  return [{
    check:  'Security Headers',
    status: failed > 0 ? 'FAIL' : 'PASS',
    detail: `${items.filter(i => i.status === 'PASS').length} present, ${failed} missing`,
    items,
  }];
}

function checkTlsCert(config) {
  const hostname = new URL(config.target).hostname;
  return new Promise(resolve => {
    const socket = tls.connect(443, hostname, { servername: hostname, rejectUnauthorized: false }, () => {
      const cert = socket.getPeerCertificate();
      socket.end();
      if (!cert || !cert.valid_to) return resolve({ check: 'TLS Certificate', status: 'SKIP', detail: 'Could not retrieve certificate.' });
      const expiry    = new Date(cert.valid_to);
      const daysLeft  = Math.floor((expiry - Date.now()) / 86400000);
      const expiryStr = expiry.toISOString().slice(0, 10);
      if (daysLeft < 14) {
        resolve({ check: 'TLS Certificate', status: 'FAIL', detail: `Expires in ${daysLeft} day(s) on ${expiryStr}. Renew immediately.` });
      } else if (daysLeft < 30) {
        resolve({ check: 'TLS Certificate', status: 'FAIL', detail: `Expires in ${daysLeft} day(s) on ${expiryStr}. Renew soon.` });
      } else {
        resolve({ check: 'TLS Certificate', status: 'PASS', detail: `Valid. Expires ${expiryStr} (${daysLeft} days remaining).` });
      }
    });
    socket.on('error', () => resolve({ check: 'TLS Certificate', status: 'SKIP', detail: 'TLS check failed.' }));
    socket.setTimeout(5000, () => { socket.destroy(); resolve({ check: 'TLS Certificate', status: 'SKIP', detail: 'TLS check timed out.' }); });
  });
}

async function checkOpenPorts(config) {
  const hostname = new URL(config.target).hostname;
  const ports    = (config.ports && config.ports.check) || DEFAULT_PORTS;
  const items    = [];

  await Promise.all(ports.map(port => new Promise(res => {
    const socket = new net.Socket();
    socket.setTimeout(1000);
    socket.on('connect', () => { socket.destroy(); items.push({ label: `Port ${port}`, status: 'FAIL', detail: `Port ${port} is open on ${hostname}. Verify this is expected.` }); res(); });
    socket.on('timeout', () => { socket.destroy(); res(); });
    socket.on('error',   () => { socket.destroy(); res(); });
    socket.connect(port, hostname);
  })));

  const failed = items.length;
  return [{
    check:  'Open Ports',
    status: failed > 0 ? 'FAIL' : 'PASS',
    detail: failed > 0 ? `${failed} unexpected port(s) open` : `No unexpected ports open (checked: ${ports.join(', ')})`,
    items,
  }];
}

module.exports = { checkSecurityHeaders, checkTlsCert, checkOpenPorts };
