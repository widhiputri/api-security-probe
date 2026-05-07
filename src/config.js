'use strict';
const fs   = require('fs');
const path = require('path');
const yaml = require('js-yaml');

function resolveEnv(value) {
  if (typeof value !== 'string') return value;
  return value.replace(/\$\{([^}]+)\}/g, (_, name) => {
    const v = process.env[name];
    if (v == null) throw new Error(`Environment variable not set: ${name}`);
    return v;
  });
}

function resolveAll(obj) {
  if (typeof obj === 'string')  return resolveEnv(obj);
  if (Array.isArray(obj))       return obj.map(resolveAll);
  if (obj && typeof obj === 'object') {
    const out = {};
    for (const [k, v] of Object.entries(obj)) out[k] = resolveAll(v);
    return out;
  }
  return obj;
}

function loadConfig(filePath) {
  const abs  = path.resolve(filePath);
  const raw  = fs.readFileSync(abs, 'utf8');
  const ext  = path.extname(filePath).toLowerCase();
  const data = ext === '.json' ? JSON.parse(raw) : yaml.load(raw);
  return resolveAll(data);
}

module.exports = { loadConfig };
