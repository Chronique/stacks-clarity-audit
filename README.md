# stacks-clarity-audit 🔍

> Security audit CLI for **Clarity smart contracts** on Stacks / Bitcoin L2

[![npm version](https://img.shields.io/npm/v/stacks-clarity-audit)](https://www.npmjs.com/package/stacks-clarity-audit)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Clarity Audit](https://img.shields.io/badge/clarity--audit-91%2F100-green?style=flat-square&logo=bitcoin&logoColor=white)](https://clarity-audit-nine.vercel.app)
[![Stacks](https://img.shields.io/badge/Built%20on-Stacks-orange?style=flat-square)](https://stacks.co)

Scan your Clarity contracts for common security vulnerabilities and best practice violations — directly from your terminal. Publish audit results **onchain** to the Stacks blockchain for verifiable, permanent security transparency.

```bash
npx stacks-clarity-audit scan ./contracts
```

---

## 🌐 Onchain Registry

| | |
|---|---|
| **Dashboard** | https://clarity-audit-nine.vercel.app |
| **Contract** | `ST3CM1955QMJ712DDV0C0F0KE205XQQT4CRZ3R3N2.audit-registry` |
| **Network** | Stacks Testnet (mainnet coming soon) |
| **Explorer** | [View on Hiro Explorer ↗](https://explorer.hiro.so/address/ST3CM1955QMJ712DDV0C0F0KE205XQQT4CRZ3R3N2.audit-registry?chain=testnet) |

Audit results are stored permanently on the Bitcoin-anchored Stacks blockchain. Anyone can verify a contract's security status without trusting a centralized source.

---

## 🚀 Quick Start

```bash
# Scan a single contract
npx stacks-clarity-audit scan ./contracts/token.clar

# Scan all contracts in a directory
npx stacks-clarity-audit scan ./contracts

# Output as JSON (for CI/CD pipelines)
npx stacks-clarity-audit scan ./contracts --json

# List all available rules
npx stacks-clarity-audit rules
```

---

## 📋 Security Rules

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

| Score | Label | Registry Status |
|---|---|---|
| 90–100 | ✅ Excellent | Certified Safe |
| 70–89 | ✅ Safe | Certified Safe |
| 40–69 | ⚠️ Moderate Risk | Not Certified |
| 0–39 | 🚨 Critical Risk | Not Certified |

Deductions: **-25** per critical · **-10** per warning · **-3** per info

---

## 🔗 Submit to Onchain Registry

After scanning, publish your audit result to the Stacks blockchain:

1. Visit [clarity-audit-nine.vercel.app](https://clarity-audit-nine.vercel.app)
2. Connect your Hiro/Leather wallet
3. Go to **Submit Audit** tab
4. Enter contract address + score from CLI output
5. Confirm transaction → result is stored permanently onchain

Anyone can then verify your contract at:
```
https://clarity-audit-nine.vercel.app → Verify tab
```

---

## 🏅 Embed Your Badge

After submitting to the registry, add a badge to your README:

```markdown
[![Clarity Audit](https://img.shields.io/badge/clarity--audit-92%2F100-green?style=flat-square&logo=bitcoin&logoColor=white)](https://clarity-audit-nine.vercel.app)
```

---

## 🔧 Install Locally

```bash
npm install -g stacks-clarity-audit

# Then use anywhere:
stacks-clarity-audit scan ./contracts
```

---

## 🔌 CI/CD Integration

Add to your GitHub Actions workflow:

```yaml
- name: Audit Clarity contracts
  run: npx stacks-clarity-audit scan ./contracts --json > audit-report.json

- name: Fail on critical issues
  run: npx stacks-clarity-audit scan ./contracts
  # Exits with code 1 if any critical issues found — blocks merge
```

---

## 🛠️ Project Structure

```
stacks-clarity-audit/
├── contracts/
│   └── audit-registry.clar     ← Onchain registry contract (Stacks testnet)
├── src/
│   ├── index.js                ← CLI entry point
│   ├── parser.js               ← .clar file reader
│   ├── auditor.js              ← Rule runner & scorer
│   ├── reporter.js             ← Terminal output formatter
│   └── rules/
│       └── index.js            ← All audit rules (CLA-001 to CLA-005)
├── examples/
│   ├── vulnerable-token.clar   ← Example with intentional bugs (score: 19/100)
│   └── safe-token.clar         ← Clean reference contract (score: 100/100)
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

---

## 🔗 Links

- **Dashboard**: https://clarity-audit-nine.vercel.app
- **GitHub**: https://github.com/Chronique/stacks-clarity-audit
- **npm**: https://www.npmjs.com/package/stacks-clarity-audit
- **Contract**: [Hiro Explorer](https://explorer.hiro.so/address/ST3CM1955QMJ712DDV0C0F0KE205XQQT4CRZ3R3N2.audit-registry?chain=testnet)
- **Stacks**: https://stacks.co
