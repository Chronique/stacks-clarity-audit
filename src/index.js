#!/usr/bin/env node
'use strict';

/**
 * stacks-clarity-audit — CLI
 * ───────────────────────────────────────────────────────────────────────────
 * Security audit tool for Clarity smart contracts on Stacks / Bitcoin L2.
 * Scans .clar files for known vulnerability patterns and submits results
 * to the onchain audit registry (testnet or mainnet).
 *
 * Usage:
 *   npx stacks-clarity-audit scan <file.clar | dir> [--network testnet|mainnet]
 *   npx stacks-clarity-audit scan <file.clar | dir> --json
 *   npx stacks-clarity-audit push <contract-id> <score> [--network mainnet]
 *
 * Environment:
 *   STACKS_PRIVATE_KEY   Hex private key used to sign and broadcast transactions.
 *
 * Registry:
 *   testnet   ST3CM1955QMJ712DDV0C0F0KE205XQQT4CRZ3R3N2.audit-registry
 *   mainnet   SP3CM1955QMJ712DDV0C0F0KE205XQQT4CSAVV6W4.audit-registry2
 * ───────────────────────────────────────────────────────────────────────────
 */

const fs       = require('fs');
const path     = require('path');
const readline = require('readline');

// ── Security rules ──────────────────────────────────────────────────────────
// Each rule deducts `points` from the base score of 100.
// severity: 'critical' | 'warning' | 'info'
const RULES = [
  {
    id:       'CLA-001',
    severity: 'critical',
    points:   30,
    pattern:  /unwrap!/g,
    message:  'unwrap! panics on None/error — use match, try!, or unwrap-panic with care',
  },
  {
    id:       'CLA-002',
    severity: 'critical',
    points:   25,
    pattern:  /\(as-contract\s+\(contract-call\?/g,
    message:  'as-contract elevates privileges — validate caller before use',
  },
  {
    id:       'CLA-003',
    severity: 'warning',
    points:   15,
    pattern:  /\(as-contract\b/g,
    message:  'as-contract usage detected — review privilege escalation risk',
  },
  {
    id:       'CLA-004',
    severity: 'critical',
    points:   25,
    pattern:  /stx-transfer\?(?![^)]*\btx-sender\b)/g,
    message:  'stx-transfer? without tx-sender check — verify authorization',
  },
  {
    id:       'CLA-005',
    severity: 'info',
    points:   5,
    pattern:  /\(define-public\s+\([a-z-]+\s*\)\s*\(ok\b/g,
    message:  'Public getter should be define-read-only for gas-free off-chain calls',
  },
  {
    id:       'CLA-006',
    severity: 'critical',
    points:   20,
    pattern:  /ft-transfer\?(?![^)]*is-eq[^)]*tx-sender)/g,
    message:  'ft-transfer? without sender check — potential unauthorized transfer',
  },
  {
    id:       'CLA-007',
    severity: 'warning',
    points:   10,
    pattern:  /\(var-set\b/g,
    message:  'State mutation via var-set — ensure only authorized callers can mutate',
  },
];

// ── Registry config ─────────────────────────────────────────────────────────
const REGISTRY = {
  testnet: {
    contractAddress: 'ST3CM1955QMJ712DDV0C0F0KE205XQQT4CRZ3R3N2',
    contractName:    'audit-registry2',
    apiUrl:          'https://api.testnet.hiro.so',
    explorerQuery:   '?chain=testnet',
  },
  mainnet: {
    contractAddress: 'SP3CM1955QMJ712DDV0C0F0KE205XQQT4CSAVV6W4',   // UPDATE after deploy-mainnet.js
    contractName:    'audit-registry2',
    apiUrl:          'https://api.hiro.so',
    explorerQuery:   '',
  },
};

const TOOL_VERSION = '0.1.5';
const EXPLORER_BASE = 'https://explorer.hiro.so';

// ── Logger helpers ───────────────────────────────────────────────────────────
const c = {
  reset:  '\x1b[0m',
  bold:   '\x1b[1m',
  red:    '\x1b[31m',
  green:  '\x1b[32m',
  yellow: '\x1b[33m',
  blue:   '\x1b[34m',
  cyan:   '\x1b[36m',
};

const log   = (msg = '')  => console.log(`  ${msg}`);
const ok    = (msg)       => console.log(`  ${c.green}${msg}${c.reset}`);
const warn  = (msg)       => console.log(`  ${c.yellow}${msg}${c.reset}`);
const fail  = (msg)       => console.error(`  ${c.red}${msg}${c.reset}`);
const hr    = ()          => log('-'.repeat(50));

const severityIcon = (s) =>
  s === 'critical' ? `${c.red}[CRIT]${c.reset}` :
  s === 'warning'  ? `${c.yellow}[WARN]${c.reset}` :
                     `${c.blue}[INFO]${c.reset}`;

// ── Scanner ──────────────────────────────────────────────────────────────────
function scanFile(filePath) {
  const src      = fs.readFileSync(filePath, 'utf8');
  const findings = [];

  for (const rule of RULES) {
    const matches = src.match(rule.pattern);
    if (matches) findings.push({ ...rule, count: matches.length });
  }

  const deducted = findings.reduce((sum, f) => sum + f.points, 0);
  const score    = Math.max(0, 100 - deducted);

  return {
    score,
    critical: findings.filter(f => f.severity === 'critical').length,
    warning:  findings.filter(f => f.severity === 'warning').length,
    info:     findings.filter(f => f.severity === 'info').length,
    findings,
  };
}

function scanDir(dirPath) {
  // Collect all .clar files recursively
  const clarFiles = [];
  function walk(dir) {
    for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
      const fullPath = path.join(dir, entry.name);
      if (entry.isDirectory()) walk(fullPath);
      else if (entry.name.endsWith('.clar')) clarFiles.push(fullPath);
    }
  }
  walk(dirPath);

  if (!clarFiles.length) {
    fail(`No .clar files found in: ${dirPath}`);
    process.exit(1);
  }

  let allFindings  = [];
  let totalDeducted = 0;

  for (const file of clarFiles) {
    const rel    = path.relative(process.cwd(), file);
    const result = scanFile(file);

    log(`\n  ${c.bold}${rel}${c.reset}`);
    if (result.findings.length === 0) {
      ok('No issues found.');
    } else {
      result.findings.forEach(f => {
        log(`  ${severityIcon(f.severity)} ${f.id}  ${f.message}`);
      });
    }

    allFindings   = allFindings.concat(result.findings);
    totalDeducted += (100 - result.score);
  }

  const score = Math.max(0, 100 - Math.round(totalDeducted / clarFiles.length));

  return {
    score,
    critical: allFindings.filter(f => f.severity === 'critical').length,
    warning:  allFindings.filter(f => f.severity === 'warning').length,
    info:     allFindings.filter(f => f.severity === 'info').length,
    findings: allFindings,
    files:    clarFiles.length,
  };
}

// ── Report printer ───────────────────────────────────────────────────────────
function printReport(result, target) {
  const { score, critical, warning, info } = result;

  const scoreColor = score >= 70 ? c.green : score >= 40 ? c.yellow : c.red;
  const label      = score >= 90 ? 'EXCELLENT'
                   : score >= 70 ? 'CERTIFIED SAFE'
                   : score >= 40 ? 'MODERATE RISK'
                   :               'CRITICAL RISK';

  console.log(`\n  ${c.green}+--------------------------------+${c.reset}`);
  console.log(`  ${c.green}|${c.reset}  ${c.bold}Stacks Security Analyzer${c.reset}       ${c.green}|${c.reset}`);
  console.log(`  ${c.green}+--------------------------------+${c.reset}`);
  log();
  log(`Target : ${target}`);
  hr();
  log(`Score  : ${scoreColor}${score}/100${c.reset}  ${label}`);
  log(`Issues : ${c.red}${critical} critical${c.reset}  ${c.yellow}${warning} warning${c.reset}  ${c.blue}${info} info${c.reset}`);
  hr();

  return result;
}

// ── Push to onchain registry ─────────────────────────────────────────────────
async function pushToRegistry(contractId, result, network = 'testnet') {
  const cfg = REGISTRY[network];

  log();
  log(`Pushing to ${c.bold}${network.toUpperCase()}${c.reset} registry...`);

  // Load @stacks/transactions — install on demand if missing
  let stacks;
  try {
    stacks = require('@stacks/transactions');
  } catch {
    warn('@stacks/transactions not found — installing...');
    require('child_process').execSync(
      'npm install @stacks/transactions --save-optional',
      { stdio: 'inherit' }
    );
    stacks = require('@stacks/transactions');
  }

  const {
    makeContractCall,
    broadcastTransaction,
    AnchorMode,
    PostConditionMode,
    principalCV,
    uintCV,
    stringAsciiCV,
  } = stacks;

  // Get private key from env or interactive prompt
  let privateKey = process.env.STACKS_PRIVATE_KEY;
  if (!privateKey) {
    const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
    privateKey = await new Promise(resolve => {
      rl.question('  Private key (hex): ', ans => { rl.close(); resolve(ans.trim()); });
    });
  }

  const txOptions = {
    contractAddress:   cfg.contractAddress,
    contractName:      cfg.contractName,
    functionName:      'submit-audit',
    functionArgs: [
      principalCV(contractId),
      uintCV(result.score),
      uintCV(result.critical),
      uintCV(result.warning),
      uintCV(result.info),
      stringAsciiCV(TOOL_VERSION),
      stringAsciiCV(''),         // report hash — optional IPFS CID
    ],
    senderKey:         privateKey,
    network:           network,
    anchorMode:        AnchorMode.Any,
    postConditionMode: PostConditionMode.Deny,
  };

  try {
    const tx = await makeContractCall(txOptions);

    // Broadcast — compatible with both v6+ and legacy API signatures
    let response;
    try {
      response = await broadcastTransaction({ transaction: tx, url: cfg.apiUrl });
    } catch {
      response = await broadcastTransaction(tx, cfg.apiUrl);
    }

    if (response && response.error) {
      fail(`Broadcast failed: ${response.error}`);
      return false;
    }

    const txid = response.txid || response;

    ok(`Submitted to Stacks ${network}!`);
    log(`TxID     : ${c.cyan}${txid}${c.reset}`);
    log(`Explorer : ${EXPLORER_BASE}/txid/${txid}${cfg.explorerQuery}`);
    log();
    return true;

  } catch (err) {
    fail(`Error: ${err.message}`);
    return false;
  }
}

// ── CLI entry ────────────────────────────────────────────────────────────────
async function main() {
  const args = process.argv.slice(2);
  const cmd  = args[0];

  console.log(`\n  ${c.bold}${c.cyan}stacks-clarity-audit${c.reset} v${TOOL_VERSION}\n`);

  // Help
  if (!cmd || cmd === 'help' || cmd === '--help') {
    log('Usage:');
    log(`  scan <file.clar | dir>  [--network testnet|mainnet]  [--json]`);
    log(`  push <contract-id> <score> [--network testnet|mainnet]`);
    log();
    log('Options:');
    log('  --network   testnet (default) | mainnet');
    log('  --json      Output scan results as JSON and exit');
    log();
    log('Environment:');
    log('  STACKS_PRIVATE_KEY   Hex private key for signing transactions');
    log();
    log('Registry contracts:');
    log(`  testnet  ${REGISTRY.testnet.contractAddress}.audit-registry`);
    log(`  mainnet  ${REGISTRY.mainnet.contractAddress}.audit-registry`);
    log();
    process.exit(0);
  }

  const target  = args[1];
  const asJson  = args.includes('--json');
  const netIdx  = args.indexOf('--network');
  const network = netIdx !== -1 ? args[netIdx + 1] : 'testnet';

  if (!['testnet', 'mainnet'].includes(network)) {
    fail(`Invalid network "${network}". Use testnet or mainnet.`);
    process.exit(1);
  }

  // ── scan ──────────────────────────────────────────────────────────────────
  if (cmd === 'scan') {
    if (!target) { fail('Provide a .clar file or directory path.'); process.exit(1); }

    const stat   = fs.statSync(target);
    const result = stat.isDirectory() ? scanDir(target) : scanFile(target);

    // JSON output mode — used for CI/CD pipelines
    if (asJson) {
      console.log(JSON.stringify(result, null, 2));
      process.exit(result.critical > 0 ? 1 : 0);
    }

    printReport(result, target);

    // Ask whether to push to registry
    const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
    rl.question(`  Push to ${c.bold}${network}${c.reset} registry? [y/N] `, async answer => {
      rl.close();
      if (answer.toLowerCase() === 'y') {
        const rl2 = readline.createInterface({ input: process.stdin, output: process.stdout });
        rl2.question('  Contract principal (SP... or ST...): ', async cid => {
          rl2.close();
          await pushToRegistry(cid.trim(), result, network);
          process.exit(result.critical > 0 ? 1 : 0);
        });
      } else {
        process.exit(result.critical > 0 ? 1 : 0);
      }
    });

    return; // keep process alive for readline
  }

  // ── push (manual, bypasses scan) ─────────────────────────────────────────
  if (cmd === 'push') {
    if (!target) { fail('Provide a contract principal.'); process.exit(1); }
    await pushToRegistry(target, {
      score:    parseInt(args[2]) || 0,
      critical: parseInt(args[3]) || 0,
      warning:  parseInt(args[4]) || 0,
      info:     parseInt(args[5]) || 0,
    }, network);
    process.exit(0);
  }

  fail(`Unknown command: "${cmd}". Run with --help for usage.`);
  process.exit(1);
}

main().catch(err => {
  console.error(`\n  ${c.red}Fatal error:${c.reset} ${err.message}`);
  process.exit(1);
});