#!/usr/bin/env node
'use strict';

const fs       = require('fs');
const path     = require('path');
const readline = require('readline');

// ── Security rules ─────────────────────────────────────────────────────────
const RULES = [
  { id:'CLA-001', severity:'critical', points:30, pattern:/unwrap!/g,
    message:'unwrap! panics on None/error — use match, try!, or unwrap-panic with care' },
  { id:'CLA-002', severity:'critical', points:25, pattern:/\(as-contract\s+\(contract-call\?/g,
    message:'as-contract elevates privileges — validate caller before use' },
  { id:'CLA-003', severity:'warning',  points:15, pattern:/\(as-contract\b/g,
    message:'as-contract usage — review privilege escalation risk' },
  { id:'CLA-004', severity:'critical', points:25, pattern:/stx-transfer\?(?![^)]*\btx-sender\b)/g,
    message:'stx-transfer? without tx-sender check — verify authorization' },
  { id:'CLA-005', severity:'info',     points:5,  pattern:/\(define-public\s+\([a-z-]+\s*\)\s*\(ok\b/g,
    message:'Public getter should be define-read-only for gas-free off-chain calls' },
  { id:'CLA-006', severity:'critical', points:20, pattern:/ft-transfer\?(?![^)]*is-eq[^)]*tx-sender)/g,
    message:'ft-transfer? without sender check — potential unauthorized transfer' },
  { id:'CLA-007', severity:'warning',  points:10, pattern:/\(var-set\b/g,
    message:'State mutation via var-set — ensure only authorized callers can mutate' },
];

// ── Registry config (both networks) ────────────────────────────────────────
const REGISTRY = {
  testnet: {
    contractAddress: 'ST3CM1955QMJ712DDV0C0F0KE205XQQT4CRZ3R3N2',
    contractName:    'audit-registry',
    apiUrl:          'https://api.testnet.hiro.so',
  },
  mainnet: {
    contractAddress: 'SP3CM1955QMJ712DDV0C0F0KE205XQQT4CSAVV6W4',
    contractName:    'audit-registry',
    apiUrl:          'https://api.hiro.so',
  },
};

// ── Scanner ─────────────────────────────────────────────────────────────────
function scanFile(filePath) {
  const src      = fs.readFileSync(filePath, 'utf8');
  const findings = [];
  for (const rule of RULES) {
    const matches = src.match(rule.pattern);
    if (matches) findings.push({ ...rule, count: matches.length });
  }
  const deducted = findings.reduce((s, f) => s + f.points, 0);
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
  const clarFiles = [];
  function walk(dir) {
    for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
      const full = path.join(dir, entry.name);
      if (entry.isDirectory()) walk(full);
      else if (entry.name.endsWith('.clar')) clarFiles.push(full);
    }
  }
  walk(dirPath);
  if (!clarFiles.length) { console.log('  No .clar files found in', dirPath); process.exit(1); }

  let allFindings = [], totalDeducted = 0;
  for (const f of clarFiles) {
    const rel = path.relative(process.cwd(), f);
    const result = scanFile(f);
    console.log(`\n  File: ${rel}`);
    result.findings.forEach(fi => {
      const icon = fi.severity === 'critical' ? '\x1b[31m[CRIT]\x1b[0m'
                 : fi.severity === 'warning'  ? '\x1b[33m[WARN]\x1b[0m'
                 :                              '\x1b[34m[INFO]\x1b[0m';
      console.log(`  ${icon} ${fi.id} - ${fi.message}`);
    });
    allFindings = allFindings.concat(result.findings);
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

function printReport(result, target) {
  const { score, critical, warning, info } = result;
  const c   = score >= 70 ? '\x1b[32m' : score >= 40 ? '\x1b[33m' : '\x1b[31m';
  const lbl = score >= 90 ? 'EXCELLENT'
            : score >= 70 ? 'CERTIFIED SAFE'
            : score >= 40 ? 'MODERATE RISK'
            :               'CRITICAL RISK';
  console.log('\n  \x1b[32m+------------------------------+\x1b[0m');
  console.log('  \x1b[32m|\x1b[0m  \x1b[1mStacks Security Analyzer\x1b[0m     \x1b[32m|\x1b[0m');
  console.log('  \x1b[32m+------------------------------+\x1b[0m');
  console.log(`\n  Target : ${target}`);
  console.log('  --------------------------------');
  console.log(`  Score  : ${c}${score}/100\x1b[0m  ${lbl}`);
  console.log(`  Issues : \x1b[31m${critical} critical\x1b[0m  \x1b[33m${warning} warning\x1b[0m  \x1b[34m${info} info\x1b[0m`);
  console.log('  --------------------------------\n');
  return result;
}

// ── Push to blockchain (real tx) ────────────────────────────────────────────
async function pushToRegistry(contractId, result, network = 'testnet') {
  const cfg = REGISTRY[network];
  console.log(`\n  Pushing to \x1b[1m${network.toUpperCase()}\x1b[0m registry...`);

  let stacks;
  try {
    stacks = require('@stacks/transactions');
  } catch (e) {
    console.log('  Installing @stacks/transactions...');
    require('child_process').execSync('npm install @stacks/transactions --save-optional', { stdio: 'inherit' });
    stacks = require('@stacks/transactions');
  }

  const { makeContractCall, broadcastTransaction, AnchorMode, PostConditionMode,
          principalCV, uintCV, stringAsciiCV } = stacks;

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
      stringAsciiCV('0.1.5'),
      stringAsciiCV(''),
    ],
    senderKey:         privateKey,
    network:           network,
    anchorMode:        AnchorMode.Any,
    postConditionMode: PostConditionMode.Deny,
  };

  try {
    const tx = await makeContractCall(txOptions);
    let response;
    try {
      response = await broadcastTransaction({ transaction: tx, url: cfg.apiUrl });
    } catch (e) {
      response = await broadcastTransaction(tx, cfg.apiUrl);
    }

    if (response && response.error) {
      console.log(`  \x1b[31mBroadcast failed:\x1b[0m ${response.error}`);
      return false;
    }

    const txid    = response.txid || response;
    const qstr    = network === 'mainnet' ? '' : '?chain=testnet';
    console.log(`  \x1b[32mSubmitted to Stacks ${network}!\x1b[0m`);
    console.log(`  TxID    : \x1b[36m${txid}\x1b[0m`);
    console.log(`  Explorer: https://explorer.hiro.so/txid/${txid}${qstr}\n`);
    return true;
  } catch (err) {
    console.log(`  \x1b[31mError:\x1b[0m ${err.message}`);
    return false;
  }
}

// ── CLI entry ───────────────────────────────────────────────────────────────
async function main() {
  const args = process.argv.slice(2);
  const cmd  = args[0];

  console.log('\n  \x1b[1m\x1b[36mstacks-clarity-audit\x1b[0m v0.1.5\n');

  if (!cmd || cmd === 'help' || cmd === '--help') {
    console.log('  Usage:');
    console.log('    npx stacks-clarity-audit scan <file.clar|dir> [--network testnet|mainnet]');
    console.log('    npx stacks-clarity-audit scan <file.clar|dir> --json');
    console.log('    npx stacks-clarity-audit push <contract-id> <score> [--network mainnet]');
    console.log('\n  Env:');
    console.log('    STACKS_PRIVATE_KEY         wallet private key (hex)');
    console.log('\n  Registry contracts:');
    console.log('    testnet  ST3CM1955QMJ712DDV0C0F0KE205XQQT4CRZ3R3N2.audit-registry');
    console.log('    mainnet  SP3CM1955QMJ712DDV0C0F0KE205XQQT4CSAVV6W4.audit-registry\n');
    process.exit(0);
  }

  const target  = args[1];
  const asJson  = args.includes('--json');
  const netIdx  = args.indexOf('--network');
  const network = netIdx !== -1 ? args[netIdx + 1] : 'testnet';

  if (!['testnet','mainnet'].includes(network)) {
    console.log('  Invalid network. Use testnet or mainnet.\n');
    process.exit(1);
  }

  // -- scan
  if (cmd === 'scan') {
    if (!target) { console.log('  Provide a .clar file or directory\n'); process.exit(1); }
    const stat   = fs.statSync(target);
    const result = stat.isDirectory() ? scanDir(target) : scanFile(target);
    if (asJson) { console.log(JSON.stringify(result, null, 2)); process.exit(result.critical > 0 ? 1 : 0); }
    printReport(result, target);

    const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
    rl.question(`  Push to \x1b[1m${network}\x1b[0m registry? [y/N] `, async answer => {
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
    return;
  }

  // -- push
  if (cmd === 'push') {
    if (!target) { console.log('  Provide contract principal\n'); process.exit(1); }
    await pushToRegistry(target, {
      score:    parseInt(args[2]) || 0,
      critical: parseInt(args[3]) || 0,
      warning:  parseInt(args[4]) || 0,
      info:     parseInt(args[5]) || 0,
    }, network);
    process.exit(0);
  }

  console.log(`  Unknown command: ${cmd}\n`);
  process.exit(1);
}

main().catch(err => { console.error('\n  Fatal:', err.message); process.exit(1); });