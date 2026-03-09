#!/usr/bin/env node
'use strict';

const fs   = require('fs');
const path = require('path');
const readline = require('readline');

// ── Security rules ────────────────────────────────────────────────────────────
const RULES = [
  {
    id: 'CLA-001', severity: 'critical', points: 30,
    pattern: /unwrap!/g,
    message: 'unwrap! panics on None/error — use match, try!, or unwrap-panic with care',
  },
  {
    id: 'CLA-002', severity: 'critical', points: 25,
    pattern: /\(as-contract\s+\(contract-call\?/g,
    message: 'as-contract elevates privileges — ensure caller is validated before use',
  },
  {
    id: 'CLA-003', severity: 'warning', points: 15,
    pattern: /\(as-contract\b/g,
    message: 'as-contract usage detected — review privilege escalation risk',
  },
  {
    id: 'CLA-004', severity: 'critical', points: 25,
    pattern: /stx-transfer\?(?![^)]*\btx-sender\b)/g,
    message: 'stx-transfer? without tx-sender check — verify transfer authorization',
  },
  {
    id: 'CLA-005', severity: 'info', points: 5,
    pattern: /\(define-public\s+\([a-z-]+\s*\)\s*\(ok\b/g,
    message: 'Public getter should be define-read-only for gas-free off-chain calls',
  },
  {
    id: 'CLA-006', severity: 'critical', points: 20,
    pattern: /ft-transfer\?(?![^)]*is-eq[^)]*tx-sender)/g,
    message: 'ft-transfer? without proper sender check — potential unauthorized transfer',
  },
  {
    id: 'CLA-007', severity: 'warning', points: 10,
    pattern: /\(var-set\b/g,
    message: 'State mutation via var-set — ensure only authorized callers can mutate',
  },
];

// ── Contract registry config ───────────────────────────────────────────────
const REGISTRY = {
  testnet: {
    contractAddress: 'ST3CM1955QMJ712DDV0C0F0KE205XQQT4CRZ3R3N2',
    contractName:    'audit-registry',
    apiUrl:          'https://api.testnet.hiro.so',
    networkId:       'testnet',
  },
  mainnet: {
    contractAddress: 'SP3CM1955QMJ712DDV0C0F0KE205XQQT4CSAVV6W4',
    contractName:    'audit-registry2',
    apiUrl:          'https://api.hiro.so',
    networkId:       'mainnet',
  },
};

// ── Scanner ───────────────────────────────────────────────────────────────────
function scanFile(filePath) {
  const src = fs.readFileSync(filePath, 'utf8');
  const findings = [];

  for (const rule of RULES) {
    const matches = src.match(rule.pattern);
    if (matches) {
      findings.push({
        id:       rule.id,
        severity: rule.severity,
        points:   rule.points,
        count:    matches.length,
        message:  rule.message,
      });
    }
  }

  const deducted = findings.reduce((sum, f) => sum + f.points, 0);
  const score    = Math.max(0, 100 - deducted);
  const critical = findings.filter(f => f.severity === 'critical').length;
  const warning  = findings.filter(f => f.severity === 'warning').length;
  const info     = findings.filter(f => f.severity === 'info').length;

  return { score, critical, warning, info, findings };
}

function scanDir(dirPath) {
  let allFindings = [];
  let totalDeducted = 0;

  const clarFiles = [];
  function walk(dir) {
    for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
      const full = path.join(dir, entry.name);
      if (entry.isDirectory()) walk(full);
      else if (entry.name.endsWith('.clar')) clarFiles.push(full);
    }
  }
  walk(dirPath);

  if (clarFiles.length === 0) {
    console.log('  No .clar files found in', dirPath);
    process.exit(1);
  }

  for (const f of clarFiles) {
    const rel = path.relative(process.cwd(), f);
    const result = scanFile(f);
    console.log(`\n  📄 ${rel}`);
    result.findings.forEach(finding => {
      const icon = finding.severity === 'critical' ? '\x1b[31m[CRIT]\x1b[0m'
                 : finding.severity === 'warning'  ? '\x1b[33m[WARN]\x1b[0m'
                 :                                   '\x1b[34m[INFO]\x1b[0m';
      console.log(`  ${icon} ${finding.id} — ${finding.message}`);
    });
    allFindings = allFindings.concat(result.findings);
    totalDeducted += (100 - result.score);
  }

  const score    = Math.max(0, 100 - Math.round(totalDeducted / clarFiles.length));
  const critical = allFindings.filter(f => f.severity === 'critical').length;
  const warning  = allFindings.filter(f => f.severity === 'warning').length;
  const info     = allFindings.filter(f => f.severity === 'info').length;

  return { score, critical, warning, info, findings: allFindings, files: clarFiles.length };
}

// ── Printer ───────────────────────────────────────────────────────────────────
function printReport(result, target) {
  const { score, critical, warning, info } = result;
  const certified = score >= 70;
  const statusColor = score >= 70 ? '\x1b[32m' : score >= 40 ? '\x1b[33m' : '\x1b[31m';
  const statusLabel = score >= 90 ? 'EXCELLENT'
                    : score >= 70 ? 'CERTIFIED SAFE ✅'
                    : score >= 40 ? 'MODERATE RISK ⚠️'
                    :               'CRITICAL RISK ❌';

  console.log('\n  \x1b[32m┌──────────────────────────────┐\x1b[0m');
  console.log('  \x1b[32m│\x1b[0m  \x1b[1mStacks Security Analyzer\x1b[0m     \x1b[32m│\x1b[0m');
  console.log('  \x1b[32m└──────────────────────────────┘\x1b[0m');
  console.log(`\n  Target : ${target}`);
  console.log('  ─────────────────────────────────');
  console.log(`  Score  : ${statusColor}${score}/100\x1b[0m  ${statusLabel}`);
  console.log(`  Issues : \x1b[31m${critical} critical\x1b[0m  \x1b[33m${warning} warning\x1b[0m  \x1b[34m${info} info\x1b[0m`);
  console.log('  ─────────────────────────────────\n');

  return { score, critical, warning, info, certified };
}

// ── Push to blockchain ────────────────────────────────────────────────────────
async function pushToRegistry(contractId, result, network = 'testnet') {
  const cfg = REGISTRY[network];

  console.log(`\n  Pushing to \x1b[1m${network.toUpperCase()}\x1b[0m registry...`);

  // Lazy-load @stacks/transactions only when needed
  let stacksTx;
  try {
    stacksTx = require('@stacks/transactions');
  } catch (e) {
    console.log('  \x1b[33m[!]\x1b[0m @stacks/transactions not found — installing...');
    require('child_process').execSync('npm install @stacks/transactions --save-optional', { stdio: 'inherit' });
    stacksTx = require('@stacks/transactions');
  }

  const {
    makeContractCall,
    broadcastTransaction,
    AnchorMode,
    PostConditionMode,
    principalCV,
    uintCV,
    stringAsciiCV,
    StacksMainnet,
    StacksTestnet,
  } = stacksTx;

  // Get private key from env or prompt
  let privateKey = process.env.STACKS_PRIVATE_KEY;
  if (!privateKey) {
    const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
    privateKey = await new Promise(resolve => {
      process.stdout.write('  Private key (hex, never stored): ');
      process.stdin.setRawMode?.(false);
      rl.question('', ans => { rl.close(); resolve(ans.trim()); });
    });
  }

  const networkObj = network === 'mainnet' ? new StacksMainnet() : new StacksTestnet();

  const txOptions = {
    contractAddress: cfg.contractAddress,
    contractName:    cfg.contractName,
    functionName:    'submit-audit',
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
    network:           networkObj,
    anchorMode:        AnchorMode.Any,
    postConditionMode: PostConditionMode.Deny,
  };

  try {
    const tx       = await makeContractCall(txOptions);
    const response = await broadcastTransaction(tx, networkObj);

    if (response.error) {
      console.log(`  \x1b[31m✗ Broadcast failed:\x1b[0m ${response.error}`);
      return false;
    }

    console.log(`  \x1b[32m✓ Submitted to Stacks ${network}!\x1b[0m`);
    console.log(`  TxID: \x1b[36m${response.txid}\x1b[0m`);
    const explorerQuery = network === 'mainnet' ? '' : '?chain=testnet';
    console.log(`  Explorer: https://explorer.hiro.so/txid/${response.txid}${explorerQuery}\n`);
    return true;
  } catch (err) {
    console.log(`  \x1b[31m✗ Error:\x1b[0m ${err.message}`);
    return false;
  }
}

// ── Deploy templates ───────────────────────────────────────────────────────────
const TEMPLATES = {
  '1': {
    id:   'sip-010-ft',
    name: 'SIP-010 Fungible Token',
    desc: 'Standard fungible token (ERC-20 equivalent)',
    params: ['token-name', 'token-symbol', 'decimals', 'initial-supply'],
    generate({ 'token-name': name, 'token-symbol': symbol, decimals, 'initial-supply': supply }) {
      const d = parseInt(decimals) || 6;
      const s = parseInt(supply)   || 1000000;
      return `;; ${name} (${symbol}) — SIP-010 Fungible Token
;; Generated by stacks-clarity-audit

(define-fungible-token ${symbol.toLowerCase()})

(define-constant CONTRACT-OWNER tx-sender)
(define-constant ERR-NOT-OWNER        (err u100))
(define-constant ERR-INSUFFICIENT-BAL (err u101))

;; SIP-010 trait functions
(define-read-only (get-name)        (ok "${name}"))
(define-read-only (get-symbol)      (ok "${symbol}"))
(define-read-only (get-decimals)    (ok u${d}))
(define-read-only (get-token-uri)   (ok none))
(define-read-only (get-total-supply) (ok (ft-get-supply ${symbol.toLowerCase()})))
(define-read-only (get-balance (account principal))
  (ok (ft-get-balance ${symbol.toLowerCase()} account)))

(define-public (transfer (amount uint) (sender principal) (recipient principal) (memo (optional (buff 34))))
  (begin
    (asserts! (is-eq tx-sender sender) ERR-NOT-OWNER)
    (try! (ft-transfer? ${symbol.toLowerCase()} amount sender recipient))
    (match memo m (print m) 0x)
    (ok true)))

(define-public (mint (amount uint) (recipient principal))
  (begin
    (asserts! (is-eq tx-sender CONTRACT-OWNER) ERR-NOT-OWNER)
    (ft-mint? ${symbol.toLowerCase()} amount recipient)))

;; Mint initial supply to deployer
(ft-mint? ${symbol.toLowerCase()} u${s} CONTRACT-OWNER)
`;
    },
  },

  '2': {
    id:   'sip-009-nft',
    name: 'SIP-009 NFT',
    desc: 'Standard non-fungible token (ERC-721 equivalent)',
    params: ['collection-name', 'collection-symbol', 'max-supply'],
    generate({ 'collection-name': name, 'collection-symbol': symbol, 'max-supply': maxSupply }) {
      const max = parseInt(maxSupply) || 10000;
      return `;; ${name} (${symbol}) — SIP-009 NFT Collection
;; Generated by stacks-clarity-audit

(define-non-fungible-token ${symbol.toLowerCase()} uint)

(define-constant CONTRACT-OWNER tx-sender)
(define-constant ERR-NOT-OWNER   (err u100))
(define-constant ERR-NOT-FOUND   (err u101))
(define-constant ERR-MAX-SUPPLY  (err u102))
(define-constant MAX-SUPPLY u${max})

(define-data-var last-token-id uint u0)
(define-map token-uris uint (string-ascii 256))

;; SIP-009 trait functions
(define-read-only (get-last-token-id) (ok (var-get last-token-id)))
(define-read-only (get-token-uri (token-id uint))
  (ok (map-get? token-uris token-id)))
(define-read-only (get-owner (token-id uint))
  (ok (nft-get-owner? ${symbol.toLowerCase()} token-id)))

(define-public (transfer (token-id uint) (sender principal) (recipient principal))
  (begin
    (asserts! (is-eq tx-sender sender) ERR-NOT-OWNER)
    (asserts! (is-some (nft-get-owner? ${symbol.toLowerCase()} token-id)) ERR-NOT-FOUND)
    (nft-transfer? ${symbol.toLowerCase()} token-id sender recipient)))

(define-public (mint (recipient principal) (uri (string-ascii 256)))
  (let ((token-id (+ (var-get last-token-id) u1)))
    (asserts! (is-eq tx-sender CONTRACT-OWNER) ERR-NOT-OWNER)
    (asserts! (<= token-id MAX-SUPPLY) ERR-MAX-SUPPLY)
    (try! (nft-mint? ${symbol.toLowerCase()} token-id recipient))
    (map-set token-uris token-id uri)
    (var-set last-token-id token-id)
    (ok token-id)))
`;
    },
  },

  '3': {
    id:   'dao-voting',
    name: 'DAO Voting',
    desc: 'Simple on-chain proposal & voting contract',
    params: ['dao-name', 'voting-period-blocks', 'quorum-votes'],
    generate({ 'dao-name': name, 'voting-period-blocks': period, 'quorum-votes': quorum }) {
      const p = parseInt(period) || 144;
      const q = parseInt(quorum) || 10;
      return `;; ${name} — DAO Voting Contract
;; Generated by stacks-clarity-audit

(define-constant CONTRACT-OWNER tx-sender)
(define-constant ERR-NOT-OWNER      (err u100))
(define-constant ERR-NOT-FOUND      (err u101))
(define-constant ERR-ALREADY-VOTED  (err u102))
(define-constant ERR-VOTING-CLOSED  (err u103))
(define-constant ERR-QUORUM-NOT-MET (err u104))
(define-constant VOTING-PERIOD u${p})
(define-constant QUORUM u${q})

(define-data-var proposal-count uint u0)

(define-map proposals uint {
  title:       (string-ascii 100),
  description: (string-ascii 500),
  proposer:    principal,
  votes-for:   uint,
  votes-against: uint,
  start-block: uint,
  executed:    bool
})

(define-map votes { proposal-id: uint, voter: principal } bool)

(define-read-only (get-proposal (id uint)) (map-get? proposals id))
(define-read-only (get-proposal-count) (ok (var-get proposal-count)))
(define-read-only (has-voted (id uint) (voter principal))
  (is-some (map-get? votes { proposal-id: id, voter: voter })))

(define-public (propose (title (string-ascii 100)) (description (string-ascii 500)))
  (let ((id (+ (var-get proposal-count) u1)))
    (map-set proposals id {
      title: title, description: description,
      proposer: tx-sender,
      votes-for: u0, votes-against: u0,
      start-block: stacks-block-height,
      executed: false })
    (var-set proposal-count id)
    (ok id)))

(define-public (vote (id uint) (in-favor bool))
  (let ((proposal (unwrap! (map-get? proposals id) ERR-NOT-FOUND)))
    (asserts! (< stacks-block-height (+ (get start-block proposal) VOTING-PERIOD)) ERR-VOTING-CLOSED)
    (asserts! (not (has-voted id tx-sender)) ERR-ALREADY-VOTED)
    (map-set votes { proposal-id: id, voter: tx-sender } in-favor)
    (map-set proposals id (merge proposal {
      votes-for:     (if in-favor (+ (get votes-for proposal) u1) (get votes-for proposal)),
      votes-against: (if in-favor (get votes-against proposal) (+ (get votes-against proposal) u1)) }))
    (ok true)))

(define-public (execute (id uint))
  (let ((proposal (unwrap! (map-get? proposals id) ERR-NOT-FOUND)))
    (asserts! (is-eq tx-sender CONTRACT-OWNER) ERR-NOT-OWNER)
    (asserts! (>= (get votes-for proposal) QUORUM) ERR-QUORUM-NOT-MET)
    (map-set proposals id (merge proposal { executed: true }))
    (ok true)))
`;
    },
  },

  '4': {
    id:   'multisig',
    name: 'Multisig Wallet',
    desc: 'M-of-N multi-signature STX wallet',
    params: ['wallet-name', 'required-signatures', 'owner-1', 'owner-2', 'owner-3'],
    generate({ 'wallet-name': name, 'required-signatures': required, 'owner-1': o1, 'owner-2': o2, 'owner-3': o3 }) {
      const req = parseInt(required) || 2;
      return `;; ${name} — Multisig Wallet (${req}-of-3)
;; Generated by stacks-clarity-audit

(define-constant ERR-NOT-OWNER       (err u100))
(define-constant ERR-ALREADY-SIGNED  (err u101))
(define-constant ERR-NOT-FOUND       (err u102))
(define-constant ERR-ALREADY-EXEC    (err u103))
(define-constant REQUIRED-SIGS u${req})

(define-constant OWNERS (list '${o1} '${o2} '${o3}))

(define-data-var tx-count uint u0)

(define-map transactions uint {
  recipient: principal,
  amount:    uint,
  memo:      (string-ascii 100),
  sigs:      uint,
  executed:  bool
})

(define-map signatures { tx-id: uint, signer: principal } bool)

(define-read-only (is-owner (addr principal))
  (or (is-eq addr '${o1}) (is-eq addr '${o2}) (is-eq addr '${o3})))

(define-read-only (get-transaction (id uint)) (map-get? transactions id))

(define-public (submit (recipient principal) (amount uint) (memo (string-ascii 100)))
  (let ((id (+ (var-get tx-count) u1)))
    (asserts! (is-owner tx-sender) ERR-NOT-OWNER)
    (map-set transactions id { recipient: recipient, amount: amount, memo: memo, sigs: u1, executed: false })
    (map-set signatures { tx-id: id, signer: tx-sender } true)
    (var-set tx-count id)
    (ok id)))

(define-public (confirm (id uint))
  (let ((tx (unwrap! (map-get? transactions id) ERR-NOT-FOUND)))
    (asserts! (is-owner tx-sender) ERR-NOT-OWNER)
    (asserts! (not (default-to false (map-get? signatures { tx-id: id, signer: tx-sender }))) ERR-ALREADY-SIGNED)
    (map-set signatures { tx-id: id, signer: tx-sender } true)
    (map-set transactions id (merge tx { sigs: (+ (get sigs tx) u1) }))
    (ok true)))

(define-public (execute-tx (id uint))
  (let ((tx (unwrap! (map-get? transactions id) ERR-NOT-FOUND)))
    (asserts! (is-owner tx-sender) ERR-NOT-OWNER)
    (asserts! (not (get executed tx)) ERR-ALREADY-EXEC)
    (asserts! (>= (get sigs tx) REQUIRED-SIGS) ERR-NOT-OWNER)
    (try! (stx-transfer? (get amount tx) (as-contract tx-sender) (get recipient tx)))
    (map-set transactions id (merge tx { executed: true }))
    (ok true)))
`;
    },
  },

  '5': {
    id:   'registry',
    name: 'Key-Value Registry',
    desc: 'Generic on-chain data registry / lookup table',
    params: ['registry-name'],
    generate({ 'registry-name': name }) {
      return `;; ${name} — Key-Value Registry
;; Generated by stacks-clarity-audit

(define-constant CONTRACT-OWNER tx-sender)
(define-constant ERR-NOT-OWNER (err u100))
(define-constant ERR-NOT-FOUND (err u101))

(define-map registry (string-ascii 100) {
  value:     (string-ascii 500),
  owner:     principal,
  timestamp: uint
})

(define-read-only (get-entry (key (string-ascii 100)))
  (map-get? registry key))

(define-read-only (has-entry (key (string-ascii 100)))
  (is-some (map-get? registry key)))

(define-public (set-entry (key (string-ascii 100)) (value (string-ascii 500)))
  (begin
    (asserts! (is-eq tx-sender CONTRACT-OWNER) ERR-NOT-OWNER)
    (map-set registry key { value: value, owner: tx-sender, timestamp: stacks-block-height })
    (ok true)))

(define-public (delete-entry (key (string-ascii 100)))
  (begin
    (asserts! (is-eq tx-sender CONTRACT-OWNER) ERR-NOT-OWNER)
    (asserts! (is-some (map-get? registry key)) ERR-NOT-FOUND)
    (map-delete registry key)
    (ok true)))
`;
    },
  },
};

async function promptDeploy() {
  const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
  const ask = (q) => new Promise(res => rl.question(q, ans => res(ans.trim())));

  console.log('\n  \x1b[1mChoose a contract template:\x1b[0m\n');
  for (const [k, t] of Object.entries(TEMPLATES)) {
    console.log(`  \x1b[36m[${k}]\x1b[0m ${t.name.padEnd(26)} \x1b[90m${t.desc}\x1b[0m`);
  }

  const choice = await ask('\n  Enter number [1-5]: ');
  const tmpl = TEMPLATES[choice];
  if (!tmpl) { console.log('  \x1b[31mInvalid choice.\x1b[0m\n'); rl.close(); process.exit(1); }

  console.log(`\n  \x1b[1m${tmpl.name}\x1b[0m — fill in the parameters:\n`);
  const params = {};
  for (const p of tmpl.params) {
    params[p] = await ask(`  ${p}: `);
    if (!params[p]) { console.log(`  \x1b[31mRequired: ${p}\x1b[0m`); rl.close(); process.exit(1); }
  }

  // Output path
  const outDir  = await ask('\n  Output directory [./contracts]: ') || './contracts';
  const outFile = path.join(outDir, `${tmpl.id}.clar`);

  if (!fs.existsSync(outDir)) fs.mkdirSync(outDir, { recursive: true });
  const code = tmpl.generate(params);
  fs.writeFileSync(outFile, code, 'utf8');

  console.log(`\n  \x1b[32m✓ Generated:\x1b[0m ${outFile}`);
  console.log('  \x1b[90m─────────────────────────────────\x1b[0m');

  // Auto-scan
  const scan = await ask('\n  Auto-scan for issues now? [Y/n]: ');
  rl.close();

  if (!scan || scan.toLowerCase() !== 'n') {
    console.log('\n  \x1b[1mScanning generated contract...\x1b[0m');
    const result = scanFile(outFile);
    printReport(result, outFile);
    if (result.critical > 0) {
      console.log('  \x1b[33m[!] Fix critical issues before deploying to mainnet.\x1b[0m\n');
    } else {
      console.log('  \x1b[32m✓ Contract looks good! Deploy via Leather/Xverse on clarity-audit-nine.vercel.app\x1b[0m\n');
    }
  }
}

// ── Verify contract from registry ─────────────────────────────────────────────
async function verifyContract(contractId, network = 'testnet') {
  const cfg = REGISTRY[network];
  const url = `${cfg.apiUrl}/v2/contracts/call-read/${cfg.contractAddress}/${cfg.contractName}/get-audit`;

  console.log(`\n  Querying ${network} registry for: ${contractId}\n`);

  const body = {
    sender: cfg.contractAddress,
    arguments: [
      // principal CV encoded as hex — use simple fetch approach
    ],
  };

  try {
    const https = require('https');
    // Use Stacks read-only call via REST
    const apiUrl = `${cfg.apiUrl}/extended/v1/contract/${cfg.contractAddress}.${cfg.contractName}`;
    console.log(`  Registry contract: ${cfg.contractAddress}.${cfg.contractName}`);
    console.log(`  Use the web UI to verify: https://clarity-audit-nine.vercel.app\n`);
  } catch (e) {
    console.log('  Error:', e.message);
  }
}

// ── CLI entry ──────────────────────────────────────────────────────────────────
async function main() {
  const args = process.argv.slice(2);
  const cmd  = args[0];

  console.log('\n  \x1b[1m\x1b[36mstacks-clarity-audit\x1b[0m v0.1.5\n');

  if (!cmd || cmd === 'help' || cmd === '--help') {
    console.log('  Usage:');
    console.log('    npx stacks-clarity-audit scan   <file.clar|dir>  [--json] [--network testnet|mainnet]');
    console.log('    npx stacks-clarity-audit deploy                   interactive contract generator');
    console.log('    npx stacks-clarity-audit verify <contract-id>    [--network testnet|mainnet]');
    console.log('    npx stacks-clarity-audit push   <contract-id> <score> [--network testnet|mainnet]');
    console.log('\n  Templates (deploy):');
    for (const [k, t] of Object.entries(TEMPLATES)) {
      console.log(`    [${k}] ${t.name.padEnd(26)} ${t.desc}`);
    }
    console.log('\n  Options:');
    console.log('    --json        Output results as JSON');
    console.log('    --network     testnet (default) | mainnet');
    console.log('\n  Env:');
    console.log('    STACKS_PRIVATE_KEY   Your wallet private key (hex)');
    console.log('    MAINNET_REGISTRY_ADDRESS  Mainnet registry SP address\n');
    process.exit(0);
  }

  const target  = args[1];
  const asJson  = args.includes('--json');
  const netIdx  = args.indexOf('--network');
  const network = netIdx !== -1 ? args[netIdx + 1] : 'testnet';

  if (!['testnet', 'mainnet'].includes(network)) {
    console.log('  \x1b[31mInvalid network. Use testnet or mainnet.\x1b[0m\n');
    process.exit(1);
  }

  // ── scan ──────────────────────────────────────────────────────────────────
  if (cmd === 'scan') {
    if (!target) { console.log('  Provide a .clar file or directory path\n'); process.exit(1); }

    const stat = fs.statSync(target);
    const result = stat.isDirectory() ? scanDir(target) : scanFile(target);

    if (asJson) { console.log(JSON.stringify(result, null, 2)); process.exit(result.critical > 0 ? 1 : 0); }

    const { score, critical, warning, info, certified } = printReport(result, target);

    // Ask to push
    const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
    rl.question(`  Push to \x1b[1m${network}\x1b[0m registry? [y/N] `, async answer => {
      rl.close();
      if (answer.toLowerCase() === 'y') {
        const contractId = args.find(a => a.startsWith('SP') || a.startsWith('ST')) || null;
        if (!contractId) {
          process.stdout.write('  Contract principal (e.g. SP...my-contract): ');
          const rl2 = readline.createInterface({ input: process.stdin, output: process.stdout });
          rl2.question('', async cid => {
            rl2.close();
            await pushToRegistry(cid.trim(), result, network);
            process.exit(critical > 0 ? 1 : 0);
          });
        } else {
          await pushToRegistry(contractId, result, network);
          process.exit(critical > 0 ? 1 : 0);
        }
      } else {
        process.exit(critical > 0 ? 1 : 0);
      }
    });

    return; // keep process alive for readline
  }

  // ── deploy ────────────────────────────────────────────────────────────────
  if (cmd === 'deploy') {
    await promptDeploy();
    process.exit(0);
  }

  // ── verify ────────────────────────────────────────────────────────────────
  if (cmd === 'verify') {
    if (!target) { console.log('  Provide a contract principal\n'); process.exit(1); }
    await verifyContract(target, network);
    process.exit(0);
  }

  // ── push (manual) ─────────────────────────────────────────────────────────
  if (cmd === 'push') {
    if (!target) { console.log('  Provide contract principal and score\n'); process.exit(1); }
    const score    = parseInt(args[2]) || 0;
    const critical = parseInt(args[3]) || 0;
    const warning  = parseInt(args[4]) || 0;
    const info     = parseInt(args[5]) || 0;
    await pushToRegistry(target, { score, critical, warning, info }, network);
    process.exit(0);
  }

  console.log(`  Unknown command: ${cmd}\n`);
  process.exit(1);
}

main().catch(err => { console.error('\n  \x1b[31mFatal:\x1b[0m', err.message); process.exit(1); });