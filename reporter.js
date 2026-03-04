// reporter.js — Format and print audit results to terminal

const c = {
  reset: "\x1b[0m",
  bold: "\x1b[1m",
  dim: "\x1b[2m",
  red: "\x1b[31m",
  yellow: "\x1b[33m",
  blue: "\x1b[34m",
  cyan: "\x1b[36m",
  green: "\x1b[32m",
  white: "\x1b[37m",
  bgRed: "\x1b[41m",
  bgYellow: "\x1b[43m",
  bgBlue: "\x1b[44m",
  bgGreen: "\x1b[42m",
};

function fmt(text, ...codes) {
  return codes.join("") + text + c.reset;
}

function severityBadge(severity) {
  switch (severity) {
    case "critical":
      return fmt(" CRITICAL ", c.bgRed, c.bold, c.white);
    case "warning":
      return fmt(" WARNING  ", c.bgYellow, c.bold, c.white);
    case "info":
      return fmt("  INFO    ", c.bgBlue, c.bold, c.white);
    default:
      return fmt(`  ${severity.toUpperCase()}  `, c.dim);
  }
}

function scoreDisplay(score) {
  const color = score >= 80 ? c.green : score >= 50 ? c.yellow : c.red;
  const label =
    score >= 90
      ? fmt("✓ SAFE", c.green, c.bold)
      : score >= 70
      ? fmt("⚠  MODERATE RISK", c.yellow, c.bold)
      : score >= 40
      ? fmt("✗ HIGH RISK", c.red, c.bold)
      : fmt("✗ CRITICAL RISK", c.red, c.bold);
  return { score: fmt(`${score}/100`, color, c.bold), label };
}

function printBanner() {
  console.log();
  console.log(fmt("  ┌──────────────────────────────────────────┐", c.cyan));
  console.log(fmt("  │   clarity-audit  ·  Stacks Security CLI  │", c.cyan, c.bold));
  console.log(fmt("  │   Bitcoin L2 Smart Contract Analyzer     │", c.cyan));
  console.log(fmt("  └──────────────────────────────────────────┘", c.cyan));
  console.log();
}

function printResult(result) {
  console.log(fmt(`📄  ${result.file}`, c.bold, c.white));
  console.log(fmt("  " + "─".repeat(48), c.dim));

  if (result.findings.length === 0) {
    console.log(fmt("  ✓ No issues found!", c.green, c.bold));
  } else {
    for (const finding of result.findings) {
      console.log();
      console.log(
        `  ${severityBadge(finding.severity)} ` +
          fmt(finding.ruleId, c.dim) +
          "  " +
          fmt(finding.ruleName, c.bold)
      );
      console.log(
        `  ${fmt(`Line ${finding.line}:${finding.column}`, c.dim)}  ${finding.message}`
      );
      console.log(
        `  ${fmt("›", c.cyan)} ${fmt(finding.snippet.slice(0, 72), c.dim)}`
      );
      // Suggestion — handle multi-line
      const suggLines = finding.suggestion.split("\n");
      console.log(`  ${fmt("💡", c.yellow)} ${fmt(suggLines[0], c.yellow)}`);
      for (let i = 1; i < suggLines.length; i++) {
        console.log(`     ${fmt(suggLines[i], c.yellow)}`);
      }
    }
  }

  console.log();
  const { score: scoreStr, label } = scoreDisplay(result.score);
  console.log(fmt("  " + "─".repeat(48), c.dim));
  console.log(`  Score   : ${scoreStr}  ${label}`);
  console.log(
    `  Issues  : ` +
      fmt(`${result.summary.critical} critical`, c.red) +
      `  ` +
      fmt(`${result.summary.warning} warning`, c.yellow) +
      `  ` +
      fmt(`${result.summary.info} info`, c.blue)
  );
  console.log();
}

function printSummaryTable(results) {
  const totalCritical = results.reduce((s, r) => s + r.summary.critical, 0);
  const totalWarning = results.reduce((s, r) => s + r.summary.warning, 0);
  const totalInfo = results.reduce((s, r) => s + r.summary.info, 0);
  const avgScore = Math.round(
    results.reduce((s, r) => s + r.score, 0) / results.length
  );

  const { score: scoreStr, label } = scoreDisplay(avgScore);

  console.log(fmt("  ══════════════════════════════════════════", c.cyan));
  console.log(fmt("  AUDIT COMPLETE", c.bold, c.cyan));
  console.log(fmt("  ══════════════════════════════════════════", c.cyan));
  console.log(`  Files scanned  : ${fmt(String(results.length), c.bold)}`);
  console.log(`  Average score  : ${scoreStr}  ${label}`);
  console.log(`  Total critical : ${fmt(String(totalCritical), c.red, c.bold)}`);
  console.log(`  Total warnings : ${fmt(String(totalWarning), c.yellow, c.bold)}`);
  console.log(`  Total info     : ${fmt(String(totalInfo), c.blue, c.bold)}`);
  console.log();
}

function printRules(rules) {
  console.log();
  console.log(fmt("  Available Rules", c.bold, c.white));
  console.log(fmt("  " + "─".repeat(48), c.dim));
  console.log();
  for (const rule of rules) {
    console.log(`  ${severityBadge(rule.severity)} ${fmt(rule.id, c.cyan, c.bold)}  ${fmt(rule.name, c.bold)}`);
    console.log(`  ${"".padStart(12)}${fmt(rule.description, c.dim)}`);
    console.log();
  }
}

module.exports = { printBanner, printResult, printSummaryTable, printRules };
