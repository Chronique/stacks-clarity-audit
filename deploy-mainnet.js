#!/usr/bin/env node
'use strict';

/**
 * deploy-mainnet.js
 * ───────────────────────────────────────────────────────────────────────────
 * One-time script to deploy audit-registry.clar to the Stacks mainnet.
 * Requires @stacks/transactions v6+ to be installed.
 *
 * Usage:
 *   Windows PowerShell:
 *     $env:STACKS_PRIVATE_KEY="<your-hex-private-key>"
 *     node deploy-mainnet.js
 *
 *   Linux / macOS:
 *     STACKS_PRIVATE_KEY=<your-hex-private-key> node deploy-mainnet.js
 *
 * Notes:
 *   - Contract source must exist at ./contracts/audit-registry.clar
 *   - Estimated gas cost: ~0.02 STX
 *   - Clarity version: 3 (Stacks 3.0+)
 * ───────────────────────────────────────────────────────────────────────────
 */

const fs   = require('fs');
const path = require('path');

// ── Config ──────────────────────────────────────────────────────────────────
const CONFIG = {
  contractName:   'audit-registry',
  contractSource: path.join(__dirname, 'contracts', 'audit-registry.clar'),
  clarityVersion: 3,
  network:        'mainnet',
  apiUrl:         'https://api.hiro.so',
  explorerBase:   'https://explorer.hiro.so',
};

// ── Logger helpers ───────────────────────────────────────────────────────────
const log  = (msg) => console.log(`  ${msg}`);
const info = (msg) => console.log(`  \x1b[36m${msg}\x1b[0m`);
const ok   = (msg) => console.log(`  \x1b[32m${msg}\x1b[0m`);
const fail = (msg) => console.error(`  \x1b[31m${msg}\x1b[0m`);
const hr   = ()    => log('-'.repeat(55));

// ── Main ─────────────────────────────────────────────────────────────────────
async function deploy() {
  console.log();
  info('stacks-clarity-audit -- Deploy to Mainnet');
  hr();

  // Validate environment variable
  const privateKey = process.env.STACKS_PRIVATE_KEY;
  if (!privateKey) {
    fail('STACKS_PRIVATE_KEY is not set.');
    log('Set it before running:');
    log('  PowerShell : $env:STACKS_PRIVATE_KEY="<hex-key>"');
    log('  bash/zsh   : export STACKS_PRIVATE_KEY="<hex-key>"');
    console.log();
    process.exit(1);
  }

  // Validate contract source file exists
  if (!fs.existsSync(CONFIG.contractSource)) {
    fail(`Contract source not found: ${CONFIG.contractSource}`);
    process.exit(1);
  }

  // Load @stacks/transactions
  const {
    makeContractDeploy,
    broadcastTransaction,
    AnchorMode,
    PostConditionMode,
    getAddressFromPrivateKey,
  } = require('@stacks/transactions');

  // Derive deployer address from private key
  const deployerAddress = getAddressFromPrivateKey(privateKey, CONFIG.network);
  const contractId      = `${deployerAddress}.${CONFIG.contractName}`;
  const contractSource  = fs.readFileSync(CONFIG.contractSource, 'utf8');

  // Print deployment summary
  log(`Contract  : ${CONFIG.contractName}`);
  log(`Clarity   : v${CONFIG.clarityVersion} (Stacks 3.0+)`);
  log(`Deployer  : ${deployerAddress}`);
  log(`Network   : ${CONFIG.network}`);
  log(`API       : ${CONFIG.apiUrl}`);
  hr();

  try {
    // Build the deployment transaction
    const tx = await makeContractDeploy({
      contractName:      CONFIG.contractName,
      codeBody:          contractSource,
      senderKey:         privateKey,
      network:           CONFIG.network,
      clarityVersion:    CONFIG.clarityVersion,
      anchorMode:        AnchorMode.Any,
      postConditionMode: PostConditionMode.Deny,
    });

    log('Broadcasting transaction...');

    // Broadcast — compatible with both v6+ and legacy API signatures
    let response;
    try {
      response = await broadcastTransaction({ transaction: tx, url: CONFIG.apiUrl });
    } catch (_) {
      response = await broadcastTransaction(tx, CONFIG.apiUrl);
    }

    // Handle broadcast-level errors
    if (response && response.error) {
      fail(`Broadcast failed: ${response.error}`);
      if (response.reason) fail(`Reason: ${response.reason}`);
      process.exit(1);
    }

    const txid = (response && response.txid) ? response.txid : response;

    // Success output
    console.log();
    ok('Contract deployed successfully!');
    hr();
    log(`TxID      : ${txid}`);
    log(`Address   : ${contractId}`);
    log(`Explorer  : ${CONFIG.explorerBase}/txid/${txid}`);
    hr();
    log('Next steps (after ~10 min confirmation):');
    log('');
    log('  1. Update src/index.js -> REGISTRY.mainnet.contractAddress:');
    info(`       "${deployerAddress}"`);
    log('');
    log('  2. Update index.html -> MAINNET_CONTRACT_ADDRESS:');
    info(`       "${contractId}"`);
    log('');
    log('  3. Commit and push:');
    log('       git add . && git commit -m "feat: mainnet registry" && git push');
    hr();
    console.log();

  } catch (err) {
    console.log();
    fail(`Deployment failed: ${err.message}`);

    // Helpful hints for common errors
    const HINTS = {
      NotEnoughFunds:        'Insufficient STX balance — top up your wallet and try again.',
      ContractAlreadyExists: 'A contract with this name already exists at this address.',
      BadNonce:              'Nonce conflict — wait 2-3 minutes and try again.',
    };

    const match = Object.entries(HINTS).find(([key]) => err.message.includes(key));
    if (match) fail(`Hint: ${match[1]}`);

    console.log();
    process.exit(1);
  }
}

deploy();