#!/usr/bin/env node
'use strict';

/**
 * deploy-mainnet.js
 * Deploys audit-registry2.clar to Stacks mainnet.
 * v2 introduces an auditor whitelist — only approved addresses can submit.
 *
 * Usage (PowerShell):
 *   $env:STACKS_PRIVATE_KEY="<hex-key>"
 *   node deploy-mainnet.js
 *
 * Usage (bash):
 *   STACKS_PRIVATE_KEY=<hex-key> node deploy-mainnet.js
 */

const fs   = require('fs');
const path = require('path');

const CONFIG = {
  contractName:   'audit-registry2',
  contractSource: path.join(__dirname, 'contracts', 'audit-registry2.clar'),
  clarityVersion: 3,
  network:        'mainnet',
  apiUrl:         'https://api.hiro.so',
  explorerBase:   'https://explorer.hiro.so',
};

const log  = (msg = '') => console.log(`  ${msg}`);
const info = (msg)      => console.log(`  \x1b[36m${msg}\x1b[0m`);
const ok   = (msg)      => console.log(`  \x1b[32m${msg}\x1b[0m`);
const fail = (msg)      => console.error(`  \x1b[31m${msg}\x1b[0m`);
const hr   = ()         => log('-'.repeat(55));

async function deploy() {
  console.log();
  info('stacks-clarity-audit -- Deploy audit-registry2 to Mainnet');
  hr();

  const privateKey = process.env.STACKS_PRIVATE_KEY;
  if (!privateKey) {
    fail('STACKS_PRIVATE_KEY is not set.');
    log('  PowerShell : $env:STACKS_PRIVATE_KEY="<hex-key>"');
    log('  bash/zsh   : export STACKS_PRIVATE_KEY="<hex-key>"');
    console.log(); process.exit(1);
  }

  if (!fs.existsSync(CONFIG.contractSource)) {
    fail(`Contract source not found: ${CONFIG.contractSource}`);
    log('Make sure audit-registry2.clar is in the contracts/ folder.');
    console.log(); process.exit(1);
  }

  const {
    makeContractDeploy,
    broadcastTransaction,
    AnchorMode,
    PostConditionMode,
    getAddressFromPrivateKey,
  } = require('@stacks/transactions');

  const deployerAddress = getAddressFromPrivateKey(privateKey, CONFIG.network);
  const contractId      = `${deployerAddress}.${CONFIG.contractName}`;

  // Normalize line endings — remove \r to avoid Stacks SIP-003 decode errors on Windows
  const contractSource  = fs.readFileSync(CONFIG.contractSource, 'utf8')
    .replace(/\r\n/g, '\n')
    .replace(/\r/g, '\n');

  log(`Contract  : ${CONFIG.contractName}`);
  log(`Clarity   : v${CONFIG.clarityVersion}`);
  log(`Deployer  : ${deployerAddress}`);
  log(`Network   : ${CONFIG.network}`);
  hr();

  log('Trust model (v2):');
  log('  - Only approved auditors can submit results');
  log('  - Deployer is automatically approved as the first auditor');
  log('  - Use add-auditor.js to approve additional addresses');
  hr();

  // Check balance before attempting deployment
  try {
    const balRes  = await fetch(`https://api.hiro.so/v2/accounts/${deployerAddress}?proof=0`);
    const balData = await balRes.json();
    const balance = parseInt(balData.balance || '0') / 1_000_000;
    const locked  = parseInt(balData.locked  || '0') / 1_000_000;

    log(`Balance   : ${balance.toFixed(6)} STX  (locked: ${locked.toFixed(6)} STX)`);

    if (balance < 0.5) {
      fail(`Balance is too low (${balance.toFixed(6)} STX). Minimum ~0.5 STX required for deployment.`);
      log('You can top up via: https://www.binance.com  or  https://www.okx.com');
      console.log(); process.exit(1);
    }

  } catch (_) {
    log('Warning: Could not fetch balance — continuing anyway...');
  }

  hr();

  try {
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

    let response;

    try {
      response = await broadcastTransaction({ transaction: tx, url: CONFIG.apiUrl });
    } catch (_) {
      response = await broadcastTransaction(tx, CONFIG.apiUrl);
    }

    if (response && response.error) {
      fail(`Broadcast failed: ${response.error}`);
      if (response.reason) fail(`Reason: ${response.reason}`);
      process.exit(1);
    }

    const txid = (response && response.txid) ? response.txid : response;

    console.log();
    ok('Contract deployed successfully!');
    hr();

    log(`TxID      : ${txid}`);
    log(`Address   : ${contractId}`);
    log(`Explorer  : ${CONFIG.explorerBase}/txid/${txid}`);

    hr();

    log('Next steps (after ~10 minutes confirmation):');
    log();

    log('  1. Update REGISTRY.mainnet in src/index.js:');
    info(`       contractAddress: '${deployerAddress}'`);
    info(`       contractName:    'audit-registry2'`);
    log();

    log('  2. Update MAINNET_CONTRACT_ADDRESS in index.html:');
    info(`       '${contractId}'`);
    log();

    log('  3. Approve additional auditors (optional):');
    info(`       node add-auditor.js <SP-address> --network mainnet`);
    log();

    log('  4. Push to git:');
    log('       git add . && git commit -m "feat: audit-registry2 whitelist" && git push');

    hr();
    console.log();

  } catch (err) {
    console.log();
    fail(`Deployment failed: ${err.message}`);

    const HINTS = {
      NotEnoughFunds:        'Insufficient STX — top up your wallet and try again.',
      ContractAlreadyExists: 'The contract name already exists. Change contractName in CONFIG.',
      BadNonce:              'Nonce conflict — wait 2-3 minutes and try again.',
    };

    const match = Object.entries(HINTS).find(([k]) => err.message.includes(k));
    if (match) fail(`Hint: ${match[1]}`);

    console.log(); 
    process.exit(1);
  }
}

deploy();