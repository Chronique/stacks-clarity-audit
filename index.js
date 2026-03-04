#!/usr/bin/env node
// index.js — CLI entry point for clarity-audit

const { parseContract, findClarityFiles } = require("./parser");
const { runAudit } = require("./auditor");
const { printBanner, printResult, printSummaryTable, printRules } = require("./reporter");
const { ALL_RULES } = require("./rules/index");
const fs = require("fs");
const path = require("path");

const args = process.argv.slice(2);
const command = args[0];
const target = args[1];
const flags = new Set(args.slice(2));

// ─── Help ────────────────────────────────────────────────────────────────────
function printHelp() {
  console.log(`
  \x1b[1mclarity-audit\x1b[0m — Security audit CLI for Clarity smart contracts

  \x1b[36mUsage:\x1b[0m
    clarity-audit scan <file.clar>       Scan a single contract
    clarity-audit scan <directory>       Scan all .clar files in directory
    clarity-audit rules                  List all available rules
    clarity-audit help                   Show this help

  \x1b[36mFlags:\x1b[0m
    --json          Output results as JSON (piping-friendly)
    --no-banner     Skip the ASCII banner

  \x1b[36mExamples:\x1b[0m
    clarity-audit scan ./contracts/token.clar
    clarity-audit scan ./contracts --json
    npx clarity-audit scan ./contracts

  \x1b[36mExit codes:\x1b[0m
    0  — No critical issues found
    1  — One or more critical issues found
  `);
}

// ─── Rules command ───────────────────────────────────────────────────────────
if (command === "rules") {
  printBanner();
  printRules(ALL_RULES);
  process.exit(0);
}

// ─── Help / no args ──────────────────────────────────────────────────────────
if (!command || command === "help" || command === "--help" || command === "-h") {
  printBanner();
  printHelp();
  process.exit(0);
}

// ─── Scan command ────────────────────────────────────────────────────────────
if (command === "scan") {
  if (!target) {
    console.error("\x1b[31mError: Please provide a file or directory to scan.\x1b[0m");
    console.error("  Usage: clarity-audit scan <file.clar|directory>");
    process.exit(1);
  }

  const targetPath = path.resolve(target);

  if (!fs.existsSync(targetPath)) {
    console.error(`\x1b[31mError: Path not found: ${targetPath}\x1b[0m`);
    process.exit(1);
  }

  const isJson = flags.has("--json");
  const noBanner = flags.has("--no-banner");

  if (!isJson && !noBanner) {
    printBanner();
  }

  // Collect files
  let files = [];
  const stat = fs.statSync(targetPath);

  if (stat.isDirectory()) {
    files = findClarityFiles(targetPath);
    if (files.length === 0) {
      console.error(`\x1b[33mNo .clar files found in: ${targetPath}\x1b[0m`);
      process.exit(0);
    }
    if (!isJson) {
      console.log(`  \x1b[2mFound ${files.length} contract(s) to scan...\x1b[0m\n`);
    }
  } else {
    files = [targetPath];
  }

  // Run audits
  const results = [];
  for (const file of files) {
    try {
      const contract = parseContract(file);
      const result = runAudit(contract);
      results.push(result);
      if (!isJson) {
        printResult(result);
      }
    } catch (err) {
      if (!isJson) {
        console.error(`\x1b[31mError scanning ${file}: ${err.message}\x1b[0m`);
      }
    }
  }

  // Output
  if (isJson) {
    console.log(JSON.stringify(results, null, 2));
  } else if (results.length > 1) {
    printSummaryTable(results);
  }

  // Exit code
  const hasCritical = results.some((r) => r.summary.critical > 0);
  process.exit(hasCritical ? 1 : 0);
}

// Unknown command
console.error(`\x1b[31mUnknown command: ${command}\x1b[0m`);
printHelp();
process.exit(1);
