// auditor.js — Run all rules against a parsed contract
const { ALL_RULES } = require("./rules/index");

const SEVERITY_PENALTY = {
  critical: 25,
  warning: 10,
  info: 3,
};

function runAudit(contract, rules = ALL_RULES) {
  const findings = [];

  for (const rule of rules) {
    const ruleFindings = rule.check(contract.lines);
    for (const f of ruleFindings) {
      findings.push({
        ...f,
        ruleId: rule.id,
        ruleName: rule.name,
        severity: rule.severity,
      });
    }
  }

  // Sort by line number
  findings.sort((a, b) => a.line - b.line);

  // Calculate score (start at 100, deduct per finding)
  let penalty = 0;
  for (const f of findings) {
    penalty += SEVERITY_PENALTY[f.severity] || 0;
  }
  const score = Math.max(0, 100 - penalty);

  const summary = {
    critical: findings.filter((f) => f.severity === "critical").length,
    warning: findings.filter((f) => f.severity === "warning").length,
    info: findings.filter((f) => f.severity === "info").length,
    total: findings.length,
  };

  return {
    file: contract.fileName,
    filePath: contract.filePath,
    findings,
    score,
    summary,
  };
}

module.exports = { runAudit };
