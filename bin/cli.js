#!/usr/bin/env node
'use strict';

const fs   = require('fs');
const path = require('path');
const { loadConfig } = require('../src/config');
const { runProbe }   = require('../src/probe');

const R    = '\x1b[0m';
const BOLD = '\x1b[1m';
const DIM  = '\x1b[2m';
const RED  = '\x1b[31m';
const GRN  = '\x1b[32m';
const YLW  = '\x1b[33m';

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

function statusColour(s) {
  if (s === 'PASS') return `${GRN}${BOLD}PASS${R}`;
  if (s === 'FAIL') return `${RED}${BOLD}FAIL${R}`;
  return `${YLW}${BOLD}SKIP${R}`;
}

function itemColour(s) {
  if (s === 'PASS') return `${GRN}PASS${R}`;
  if (s === 'FAIL') return `${RED}FAIL${R}`;
  return `${YLW}SKIP${R}`;
}

function fmtDuration(ms) {
  if (!ms) return '';
  return ms >= 1000 ? `${(ms / 1000).toFixed(1)}s` : `${ms}ms`;
}

function fmtTimestamp(d) {
  return d.toISOString().replace('T', ' ').slice(0, 19);
}

function printGroup(results, status) {
  const group = results.filter(r => r.status === status);
  if (group.length === 0) return;

  const label   = status === 'PASS' ? `${GRN}${BOLD}PASSED${R}` : status === 'FAIL' ? `${RED}${BOLD}FAILED${R}` : `${YLW}${BOLD}SKIPPED${R}`;
  const line    = '─'.repeat(50);
  console.log(`\n${label} ${DIM}${line}${R}\n`);

  for (const r of group) {
    const dur = r.duration_ms ? `  ${DIM}${fmtDuration(r.duration_ms)}${R}` : '';
    console.log(`  ${statusColour(r.status)}  ${BOLD}${r.check}${R}${dur}`);
    console.log(`        ${DIM}${r.detail}${R}`);
    if (r.items && r.items.length > 0) {
      for (const item of r.items) {
        console.log(`        ${itemColour(item.status)}  ${item.label}`);
        if (item.status === 'FAIL' || item.status === 'SKIP') {
          console.log(`               ${DIM}${item.detail}${R}`);
        }
      }
    }
    console.log('');
  }
}

function printSummaryTable(results) {
  const line = '─'.repeat(54);
  console.log(`${DIM}${line}${R}`);
  console.log(`  ${BOLD}${'Check'.padEnd(30)}${'PASS'.padStart(6)}${'FAIL'.padStart(6)}${'SKIP'.padStart(6)}${R}`);
  console.log(`  ${DIM}${line}${R}`);

  for (const r of results) {
    const items   = r.items || [];
    const p = items.length > 0 ? items.filter(i => i.status === 'PASS').length : (r.status === 'PASS' ? 1 : 0);
    const f = items.length > 0 ? items.filter(i => i.status === 'FAIL').length : (r.status === 'FAIL' ? 1 : 0);
    const s = items.length > 0 ? items.filter(i => i.status === 'SKIP').length : (r.status === 'SKIP' ? 1 : 0);
    const pc = p > 0 ? `${GRN}${String(p).padStart(6)}${R}` : `${DIM}${'-'.padStart(6)}${R}`;
    const fc = f > 0 ? `${RED}${String(f).padStart(6)}${R}` : `${DIM}${'-'.padStart(6)}${R}`;
    const sc = s > 0 ? `${YLW}${String(s).padStart(6)}${R}` : `${DIM}${'-'.padStart(6)}${R}`;
    console.log(`  ${r.check.padEnd(30)}${pc}${fc}${sc}`);
  }

  const totalPass = results.reduce((n, r) => {
    const items = r.items || [];
    return n + (items.length > 0 ? items.filter(i => i.status === 'PASS').length : (r.status === 'PASS' ? 1 : 0));
  }, 0);
  const totalFail = results.reduce((n, r) => {
    const items = r.items || [];
    return n + (items.length > 0 ? items.filter(i => i.status === 'FAIL').length : (r.status === 'FAIL' ? 1 : 0));
  }, 0);
  const totalSkip = results.reduce((n, r) => {
    const items = r.items || [];
    return n + (items.length > 0 ? items.filter(i => i.status === 'SKIP').length : (r.status === 'SKIP' ? 1 : 0));
  }, 0);

  console.log(`  ${DIM}${line}${R}`);
  const tp = totalPass > 0 ? `${GRN}${String(totalPass).padStart(6)}${R}` : `${DIM}${'-'.padStart(6)}${R}`;
  const tf = totalFail > 0 ? `${RED}${String(totalFail).padStart(6)}${R}` : `${DIM}${'-'.padStart(6)}${R}`;
  const ts = totalSkip > 0 ? `${YLW}${String(totalSkip).padStart(6)}${R}` : `${DIM}${'-'.padStart(6)}${R}`;
  console.log(`  ${BOLD}${'Total'.padEnd(30)}${R}${tp}${tf}${ts}`);
}

async function main() {
  let config;
  try { config = loadConfig(configFile); }
  catch (e) { console.error(`Error loading config: ${e.message}`); process.exit(1); }

  const pkg       = require('../package.json');
  const startedAt = new Date();

  console.log(`\n${BOLD}api-security-probe${R} ${DIM}v${pkg.version}${R}`);
  console.log(`${DIM}Target:   ${config.target}${R}`);
  console.log(`${DIM}Started:  ${fmtTimestamp(startedAt)}${R}`);
  if (testsArg) console.log(`${DIM}Tests:    ${testsArg.join(', ')}${R}`);

  let results;
  try { results = await runProbe(config, { tests: testsArg }); }
  catch (e) { console.error(`Probe failed: ${e.message}`); process.exit(1); }

  const finishedAt  = new Date();
  const durationMs  = finishedAt - startedAt;
  const topFailed   = results.filter(r => r.status === 'FAIL').length;
  const topPassed   = results.filter(r => r.status === 'PASS').length;
  const topSkipped  = results.filter(r => r.status === 'SKIP').length;

  printGroup(results, 'FAIL');
  printGroup(results, 'PASS');
  printGroup(results, 'SKIP');

  console.log(`\n${DIM}${'─'.repeat(54)}${R}`);
  console.log(`  ${BOLD}Summary${R}\n`);
  printSummaryTable(results);

  console.log('');
  console.log(`  ${DIM}Duration: ${fmtDuration(durationMs)}  |  Finished: ${fmtTimestamp(finishedAt)}${R}`);
  console.log('');

  const verdict = topFailed > 0 ? `${RED}${BOLD}FAILED${R}` : `${GRN}${BOLD}PASSED${R}`;
  console.log(`  ${verdict}  ${GRN}${topPassed} passed${R} · ${RED}${topFailed} failed${R} · ${YLW}${topSkipped} skipped${R}\n`);

  if (outputFile) {
    const output = {
      target:       config.target,
      started_at:   startedAt.toISOString(),
      finished_at:  finishedAt.toISOString(),
      duration_ms:  durationMs,
      verdict:      topFailed > 0 ? 'FAILED' : 'PASSED',
      summary: {
        passed:  topPassed,
        failed:  topFailed,
        skipped: topSkipped,
        total:   results.length,
      },
      checks: results,
    };
    fs.writeFileSync(outputFile, JSON.stringify(output, null, 2));
    console.log(`  Results written to: ${path.resolve(outputFile)}\n`);
  }

  if (topFailed > 0) process.exit(1);
}

main();
