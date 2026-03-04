# clarity-audit 🔍

> Security audit CLI for **Clarity smart contracts** on Stacks / Bitcoin L2

[![npm version](https://img.shields.io/npm/v/clarity-audit)](https://www.npmjs.com/package/clarity-audit)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

Scan your Clarity contracts for common security vulnerabilities and best practice violations — directly from your terminal.

```bash
npx clarity-audit scan ./contracts
```

---

## 🚀 Quick Start

```bash
# Scan a single contract
npx clarity-audit scan ./contracts/token.clar

# Scan all contracts in a directory
npx clarity-audit scan ./contracts

# Output as JSON (for CI/CD pipelines)
npx clarity-audit scan ./contracts --json

# List all available rules
npx clarity-audit rules
```

---

## 📋 Rules

| ID | Severity | Rule |
|---|---|---|
| CLA-001 | 🔴 Critical | `unwrap!` used without safe error-handling context |
| CLA-002 | 🔴 Critical | Admin-like public function missing authorization check |
| CLA-003 | 🟡 Warning | `as-contract` used without nearby authorization check |
| CLA-004 | 🟡 Warning | Hardcoded principal address |
| CLA-005 | 🔵 Info | Getter function should use `define-read-only` |

---

## 📊 Scoring

Each contract receives a score from **0 to 100**:

| Score | Label |
|---|---|
| 90–100 | ✅ Safe |
| 70–89 | ⚠️ Moderate Risk |
| 40–69 | ❌ High Risk |
| 0–39 | 🚨 Critical Risk |

Deductions: **-25** per critical · **-10** per warning · **-3** per info

---

## 🔧 Install Locally

```bash
npm install -g clarity-audit

# Then use anywhere:
clarity-audit scan ./contracts
```

---

## 🔌 CI/CD Integration

Add to your GitHub Actions workflow:

```yaml
- name: Audit Clarity contracts
  run: npx clarity-audit scan ./contracts --json > audit-report.json

- name: Fail on critical issues
  run: npx clarity-audit scan ./contracts
  # Exits with code 1 if any critical issues are found
```

---

## 🛠️ Project Structure

```
clarity-audit/
├── src/
│   ├── index.js          ← CLI entry point
│   ├── parser.js         ← .clar file reader
│   ├── auditor.js        ← Rule runner & scorer
│   ├── reporter.js       ← Terminal output formatter
│   └── rules/
│       └── index.js      ← All audit rules
├── examples/
│   ├── vulnerable-token.clar   ← Example with bugs
│   └── safe-token.clar         ← Clean reference
└── package.json
```

---

## 🤝 Contributing

New rules welcome! Each rule is a simple object:

```js
const myRule = {
  id: "CLA-006",
  name: "My rule name",
  severity: "warning",       // "critical" | "warning" | "info"
  description: "...",
  check(lines) {
    const findings = [];
    for (let i = 0; i < lines.length; i++) {
      // your detection logic
      if (/* issue found */) {
        findings.push({
          line: i + 1,
          column: 1,
          message: "What went wrong",
          snippet: lines[i].trim(),
          suggestion: "How to fix it",
        });
      }
    }
    return findings;
  },
};
```

---

## 📄 License

MIT — Built for the Stacks ecosystem 🟠
