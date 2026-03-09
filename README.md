# stacks-clarity-audit 🔍

> Security audit CLI for **Clarity smart contracts** on Stacks / Bitcoin L2

[![npm version](https://img.shields.io/npm/v/stacks-clarity-audit)](https://www.npmjs.com/package/stacks-clarity-audit)
[![npm downloads](https://img.shields.io/npm/dw/stacks-clarity-audit)](https://www.npmjs.com/package/stacks-clarity-audit)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Clarity Audit](https://img.shields.io/badge/clarity--audit-91%2F100-green?style=flat-square&logo=bitcoin&logoColor=white)](https://clarity-audit-nine.vercel.app)
[![Stacks](https://img.shields.io/badge/Built%20on-Stacks-orange?style=flat-square)](https://stacks.co)

Scan your Clarity contracts for common security vulnerabilities and best practice violations — directly from your terminal. Generate boilerplate contracts from templates, then publish audit results **onchain** to the Stacks blockchain for verifiable, permanent security transparency.

```bash
npx stacks-clarity-audit scan ./contracts
```

---

## 🌐 Onchain Registry

| | |
|---|---|
| **Dashboard** | https://clarity-audit-nine.vercel.app |
| **Testnet** | `ST3CM1955QMJ712DDV0C0F0KE205XQQT4CRZ3R3N2.audit-registry` |
| **Mainnet** | `SP3CM1955QMJ712DDV0C0F0KE205XQQT4CSAVV6W4.audit-registry2` |
| **Explorer** | [View on Hiro Explorer ↗](https://explorer.hiro.so/address/SP3CM1955QMJ712DDV0C0F0KE205XQQT4CSAVV6W4.audit-registry2) |

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

# Generate a contract from template (interactive)
npx stacks-clarity-audit deploy

# List all available rules
npx stacks-clarity-audit rules
```

---

## 🏗️ Deploy — Contract Generator

Generate production-ready Clarity contracts from battle-tested templates:

```bash
npx stacks-clarity-audit deploy
```

```
  Choose a contract template:

  [1] SIP-010 Fungible Token      Standard fungible token (ERC-20 equivalent)
  [2] SIP-009 NFT                 Standard non-fungible token (ERC-721 equivalent)
  [3] DAO Voting                  Simple on-chain proposal & voting contract
  [4] Multisig Wallet             M-of-N multi-signature STX wallet
  [5] Key-Value Registry          Generic on-chain data registry / lookup table

  Enter number [1-5]:
```

Fill in the parameters → contract is generated as a `.clar` file → auto-scanned for issues before you deploy.

---

## 📋 Security Rules

| ID | Severity | Rule |
|---|---|---|
| CLA-001 | 🔴 Critical | `unwrap!` used without safe error-handling context |
| CLA-002 | 🔴 Critical | `as-contract` + `contract-call?` without authorization check |
| CLA-003 | 🟡 Warning | `as-contract` used without nearby authorization check |
| CLA-004 | 🔴 Critical | `stx-transfer?` without `tx-sender` check |
| CLA-005 | 🔵 Info | Getter function should use `define-read-only` |
| CLA-006 | 🔴 Critical | `ft-transfer?` without proper sender check |
| CLA-007 | 🟡 Warning | `var-set` state mutation — ensure only authorized callers |

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

> Score ≥ 70 = eligible to submit to the onchain registry and receive a certified badge.

---

## 🔗 Submit to Onchain Registry

After scanning, publish your audit result to the Stacks blockchain:

1. Visit [clarity-audit-nine.vercel.app](https://clarity-audit-nine.vercel.app)
2. Connect your Leather or Xverse wallet
3. Go to **Submit Audit** tab
4. Enter contract address + score from CLI output
5. Confirm transaction → result stored permanently onchain

Anyone can then verify your contract at:
```
https://clarity-audit-nine.vercel.app → Verify tab
```

> **Mainnet note:** `audit-registry2` uses an auditor whitelist. Contact the deployer to be approved before submitting on mainnet.

---

## 🏅 Embed Your Badge

After submitting to the registry, add a badge to your README:

```markdown
[![Clarity Audit](https://img.shields.io/badge/clarity--audit-91%2F100-green?style=flat-square&logo=bitcoin)](https://clarity-audit-nine.vercel.app)
```

> Badge is cosmetic. Real verification is onchain — anyone can check via the **Verify** tab.

---

## 🔧 Install Locally

```bash
npm install -g stacks-clarity-audit

# Then use anywhere:
stacks-clarity-audit scan ./contracts
stacks-clarity-audit deploy
```

---

## 🔌 CI/CD Integration

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
│   ├── audit-registry.clar      ← Testnet registry contract
│   └── audit-registry2.clar     ← Mainnet registry (auditor whitelist)
├── src/
│   ├── index.js                 ← CLI entry point (scan, deploy, push, verify)
│   ├── parser.js                ← .clar file reader
│   ├── auditor.js               ← Rule runner & scorer
│   └── reporter.js              ← Terminal output formatter
├── examples/
│   ├── vulnerable-token.clar    ← Example with intentional bugs (score: 19/100)
│   └── safe-token.clar          ← Clean reference contract (score: 100/100)
└── package.json
```

---

## 🤝 Contributing

New rules welcome! Each rule is a simple object:

```js
const myRule = {
  id: "CLA-008",
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
- **Mainnet Contract**: [Hiro Explorer](https://explorer.hiro.so/address/SP3CM1955QMJ712DDV0C0F0KE205XQQT4CSAVV6W4.audit-registry2)
- **Stacks**: https://stacks.co

---

## 📝 Changelog

### v0.1.6
- **New command**: `deploy` — interactive contract generator with 5 templates (SIP-010 FT, SIP-009 NFT, DAO Voting, Multisig, Registry)
- **Fix**: Mainnet registry address updated to `SP3CM...audit-registry2`
- **CLI**: `deploy` auto-scans generated contracts before deployment

### v0.1.5
- **Fix**: Score display now correctly shows 70+ as `✓ SAFE`
- **New rule**: CLA-006 — Unchecked return value from `stx-transfer?`, `ft-transfer?`, `nft-transfer?`
- **New rule**: CLA-007 — `tx-sender` used inside `as-contract` block
- **CLI**: Registry certification hint shown after each scan result
- **CLI**: Summary table shows certified/total count

### v0.1.4
- Initial release with 5 rules (CLA-001 to CLA-005)
- JSON output mode (`--json`)
- CI/CD exit code support