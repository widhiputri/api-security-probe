#!/usr/bin/env node
'use strict';

const fs   = require('fs');
const path = require('path');
const { loadConfig } = require('../src/config');
const { runProbe }   = require('../src/probe');

const args = process.argv.slice(2);

if (args.length === 0 || args.includes('--help') || args.includes('-h')) {
  console.log(`
Usage:
  api-security-probe --config <file> [options]

Options:
  --config, -c <file>   Path to probe config file (YAML or JSON)
  --tests  <list>       Comma-separated list of tests to run (default: all)
                        rate-limit, api-rate-limit, session, bola, idor, headers, tls, ports
  --output <file>       Write results to a JSON file
  --help,  -h           Show this help

Examples:
  api-security-probe --config probe.config.yml
  api-security-probe --config probe.config.yml --tests session,bola,idor
  api-security-probe --config probe.config.yml --output results.json
`);
  process.exit(0);
}

let configFile = null;
let testsArg   = null;
let outputFile = null;

for (let i = 0; i < args.length; i++) {
  if ((args[i] === '--config' || args[i] === '-c') && args[i + 1]) configFile = args[++i];
  else if (args[i] === '--tests'  && args[i + 1]) testsArg   = args[++i].split(',');
  else if (args[i] === '--output' && args[i + 1]) outputFile = args[++i];
}

if (!configFile) { console.error('Error: --config is required'); process.exit(1); }
if (!fs.existsSync(configFile)) { console.error(`Error: config file not found: ${configFile}`); process.exit(1); }

const R = '\x1b[0m', RED = '\x1b[31m', GREEN = '\x1b[32m', YELLOW = '\x1b[33m', BOLD = '\x1b[1m', DIM = '\x1b[2m';

function col(s) {
  if (s === 'PASS') return `${GREEN}PASS${R}`;
  if (s === 'FAIL') return `${RED}FAIL${R}`;
  return `${YELLOW}SKIP${R}`;
}

async function main() {
  let config;
  try { config = loadConfig(configFile); }
  catch (e) { console.error(`Error loading config: ${e.message}`); process.exit(1); }

  console.log(`\n${BOLD}API Security Probe${R}`);
  console.log(`${DIM}Target: ${config.target}${R}`);
  if (testsArg) console.log(`${DIM}Tests:  ${testsArg.join(', ')}${R}`);
  console.log('');

  let results;
  try { results = await runProbe(config, { tests: testsArg }); }
  catch (e) { console.error(`Probe failed: ${e.message}`); process.exit(1); }

  for (const r of results) {
    console.log(`  ${col(r.status)}  ${BOLD}${r.check}${R}`);
    console.log(`        ${DIM}${r.detail}${R}`);
    if (r.items) {
      for (const item of r.items) {
        console.log(`        ${col(item.status)}  ${item.label}`);
        console.log(`               ${DIM}${item.detail}${R}`);
      }
    }
    console.log('');
  }

  const passed  = results.filter(r => r.status === 'PASS').length;
  const failed  = results.filter(r => r.status === 'FAIL').length;
  const skipped = results.filter(r => r.status === 'SKIP').length;

  const verdict = failed > 0 ? `${RED}${BOLD}FAILED${R}` : `${GREEN}${BOLD}PASSED${R}`;
  console.log(`${verdict}  ${passed} passed, ${failed} failed, ${skipped} skipped\n`);

  if (outputFile) {
    fs.writeFileSync(outputFile, JSON.stringify({ target: config.target, results }, null, 2));
    console.log(`Results written to: ${path.resolve(outputFile)}`);
  }

  if (failed > 0) process.exit(1);
}

main();
