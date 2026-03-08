#!/usr/bin/env node
'use strict';

/**
 * add-auditor.js
 * Approve or remove an auditor in audit-registry2.
 * Only the contract owner (deployer) can call this.
 *
 * Usage:
 *   $env:STACKS_PRIVATE_KEY="<owner-key>"
 *   node add-auditor.js <SP-address> [--remove] [--network mainnet|testnet]
 *
 * Examples:
 *   node add-auditor.js SP2J6ZY48GV1EZ5V2V5RB9MP66SW86PYKKNRV9EJ7 --network mainnet
 *   node add-auditor.js SP2J6ZY48GV1EZ5V2V5RB9MP66SW86PYKKNRV9EJ7 --remove --network mainnet
 */

const REGISTRY = {
  testnet: {
    contractAddress: 'ST3CM1955QMJ712DDV0C0F0KE205XQQT4CRZ3R3N2',
    contractName:    'audit-registry2',
    apiUrl:          'https://api.testnet.hiro.so',
    explorerQuery:   '?chain=testnet',
  },
  mainnet: {
    contractAddress: 'SP3CM1955QMJ712DDV0C0F0KE205XQQT4CSAVV6W4',   // UPDATE after deploy
    contractName:    'audit-registry2',
    apiUrl:          'https://api.hiro.so',
    explorerQuery:   '',
  },
};

const EXPLORER_BASE = 'https://explorer.hiro.so';

const log  = (msg = '') => console.log(`  ${msg}`);
const ok   = (msg)      => console.log(`  \x1b[32m${msg}\x1b[0m`);
const fail = (msg)      => console.error(`  \x1b[31m${msg}\x1b[0m`);
const info = (msg)      => console.log(`  \x1b[36m${msg}\x1b[0m`);
const hr   = ()         => log('-'.repeat(55));

async function main() {
  const args    = process.argv.slice(2);
  const auditor = args[0];
  const remove  = args.includes('--remove');
  const netIdx  = args.indexOf('--network');
  const network = netIdx !== -1 ? args[netIdx + 1] : 'mainnet';

  console.log();
  info(`audit-registry2 -- ${remove ? 'Remove' : 'Add'} Auditor`);
  hr();

  if (!auditor || auditor.startsWith('--')) {
    fail('Provide an auditor address.');
    log('Usage: node add-auditor.js <SP-address> [--remove] [--network mainnet|testnet]');
    console.log(); process.exit(1);
  }

  if (!['testnet', 'mainnet'].includes(network)) {
    fail(`Invalid network: "${network}"`);
    process.exit(1);
  }

  const privateKey = process.env.STACKS_PRIVATE_KEY;
  if (!privateKey) {
    fail('STACKS_PRIVATE_KEY is not set.');
    process.exit(1);
  }

  const cfg = REGISTRY[network];
  const {
    makeContractCall,
    broadcastTransaction,
    AnchorMode,
    PostConditionMode,
    principalCV,
    getAddressFromPrivateKey,
  } = require('@stacks/transactions');

  const ownerAddress = getAddressFromPrivateKey(privateKey, network);
  const functionName = remove ? 'remove-auditor' : 'add-auditor';

  log(`Action    : ${remove ? 'remove' : 'approve'} auditor`);
  log(`Auditor   : ${auditor}`);
  log(`Owner     : ${ownerAddress}`);
  log(`Network   : ${network}`);
  log(`Contract  : ${cfg.contractAddress}.${cfg.contractName}`);
  hr();

  try {
    const tx = await makeContractCall({
      contractAddress:   cfg.contractAddress,
      contractName:      cfg.contractName,
      functionName,
      functionArgs:      [principalCV(auditor)],
      senderKey:         privateKey,
      network,
      anchorMode:        AnchorMode.Any,
      postConditionMode: PostConditionMode.Deny,
    });

    log('Broadcasting transaction...');

    let response;
    try {
      response = await broadcastTransaction({ transaction: tx, url: cfg.apiUrl });
    } catch (_) {
      response = await broadcastTransaction(tx, cfg.apiUrl);
    }

    if (response && response.error) {
      fail(`Broadcast failed: ${response.error}`);
      if (response.reason) fail(`Reason: ${response.reason}`);
      process.exit(1);
    }

    const txid = (response && response.txid) ? response.txid : response;

    console.log();
    ok(`Auditor ${remove ? 'removed' : 'approved'}!`);
    hr();
    log(`TxID     : ${txid}`);
    log(`Explorer : ${EXPLORER_BASE}/txid/${txid}${cfg.explorerQuery}`);
    hr();

    if (!remove) {
      log('Address ini sekarang bisa push audit ke registry:');
      info(`  npx stacks-clarity-audit scan ./contract.clar --network ${network}`);
    }
    console.log();

  } catch (err) {
    console.log();
    fail(`Failed: ${err.message}`);
    if (err.message.includes('u401')) fail('Hint: Only contract owner can manage auditors.');
    console.log(); process.exit(1);
  }
}

main().catch(err => {
  console.error(`\n  \x1b[31mFatal:\x1b[0m ${err.message}`);
  process.exit(1);
});