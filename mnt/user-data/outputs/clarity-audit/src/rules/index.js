// rules/index.js — All 5 audit rules for Clarity smart contracts

/**
 * CLA-001: Unsafe unwrap! usage
 * unwrap! will abort/panic if the value is none or err.
 */
const unwrapCheck = {
  id: "CLA-001",
  name: "Unsafe unwrap! usage",
  severity: "critical",
  description:
    "unwrap! panics and aborts the transaction if the value is none/err. " +
    "Use match or try! patterns instead.",
  check(lines) {
    const findings = [];
    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      const trimmed = line.trim();
      if (trimmed.startsWith(";")) continue;

      const idx = line.indexOf("unwrap!");
      if (idx === -1) continue;

      // Check surrounding context for safe patterns
      const context = lines
        .slice(Math.max(0, i - 3), i + 1)
        .join(" ")
        .toLowerCase();

      const safe =
        context.includes("(match ") ||
        context.includes("(if ") ||
        context.includes("try!");

      if (!safe) {
        findings.push({
          line: i + 1,
          column: idx + 1,
          message: "unwrap! used without safe error-handling context",
          snippet: trimmed,
          suggestion:
            "Replace with: (match <expr> val <ok-branch> <err-branch>)\n" +
            "         or: (try! <expr>) inside a public function returning response.",
        });
      }
    }
    return findings;
  },
};

/**
 * CLA-002: Admin function without authorization check
 */
const authCheck = {
  id: "CLA-002",
  name: "Public function missing authorization check",
  severity: "critical",
  description:
    "Public admin-like functions without tx-sender validation can be called by anyone.",
  check(lines) {
    const findings = [];
    const adminKeywords = [
      "set-", "update-", "admin", "owner", "mint", "burn",
      "withdraw", "pause", "upgrade", "transfer-ownership",
    ];

    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      const trimmed = line.trim();
      if (trimmed.startsWith(";")) continue;
      if (!trimmed.includes("(define-public")) continue;

      const funcNameLower = trimmed.toLowerCase();
      const looksAdmin = adminKeywords.some((k) => funcNameLower.includes(k));
      if (!looksAdmin) continue;

      // Collect function body (next 20 lines)
      const body = lines
        .slice(i, Math.min(lines.length, i + 20))
        .join("\n")
        .toLowerCase();

      const hasAuth =
        body.includes("tx-sender") ||
        body.includes("contract-caller") ||
        body.includes("asserts!") ||
        body.includes("is-eq");

      if (!hasAuth) {
        const funcName =
          trimmed.match(/\(define-public\s+\((\S+)/)?.[1] || "unknown";
        findings.push({
          line: i + 1,
          column: 1,
          message: `Admin-like function "${funcName}" has no authorization check`,
          snippet: trimmed,
          suggestion:
            "Add at top of function body:\n" +
            "  (asserts! (is-eq tx-sender CONTRACT-OWNER) (err u401))",
        });
      }
    }
    return findings;
  },
};

/**
 * CLA-003: as-contract without nearby auth check
 */
const asContractCheck = {
  id: "CLA-003",
  name: "Potentially unsafe as-contract usage",
  severity: "warning",
  description:
    "as-contract elevates to contract privileges. Without auth validation, " +
    "anyone can trigger privileged operations.",
  check(lines) {
    const findings = [];
    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      const trimmed = line.trim();
      if (trimmed.startsWith(";")) continue;

      const idx = line.indexOf("as-contract");
      if (idx === -1) continue;

      const contextBefore = lines
        .slice(Math.max(0, i - 5), i)
        .join(" ")
        .toLowerCase();

      const hasAuth =
        contextBefore.includes("asserts!") ||
        contextBefore.includes("is-eq tx-sender") ||
        contextBefore.includes("is-eq contract-caller");

      if (!hasAuth) {
        findings.push({
          line: i + 1,
          column: idx + 1,
          message: "as-contract used without nearby authorization check",
          snippet: trimmed,
          suggestion:
            "Validate tx-sender before using as-contract to prevent privilege escalation.",
        });
      }
    }
    return findings;
  },
};

/**
 * CLA-004: Hardcoded principal addresses
 */
const hardcodedPrincipalCheck = {
  id: "CLA-004",
  name: "Hardcoded principal address",
  severity: "warning",
  description:
    "Hardcoded addresses make contracts inflexible. If the key is compromised, contract cannot be updated.",
  check(lines) {
    const findings = [];
    const PRINCIPAL_RE = /\b(SP|ST)[A-Z0-9]{20,50}\b/g;

    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      const trimmed = line.trim();
      if (trimmed.startsWith(";")) continue;
      // Allow in define-constant (that's intentional)
      if (trimmed.startsWith("(define-constant")) continue;

      let match;
      PRINCIPAL_RE.lastIndex = 0;
      while ((match = PRINCIPAL_RE.exec(line)) !== null) {
        findings.push({
          line: i + 1,
          column: match.index + 1,
          message: `Hardcoded principal: ${match[0].slice(0, 12)}...`,
          snippet: trimmed,
          suggestion:
            "Use (define-constant OWNER 'SP...) at top level, or\n" +
            "    (define-data-var owner principal 'SP...) for upgradeability.",
        });
      }
    }
    return findings;
  },
};

/**
 * CLA-005: Getter using define-public instead of define-read-only
 */
const readOnlyCheck = {
  id: "CLA-005",
  name: "Getter function should use define-read-only",
  severity: "info",
  description:
    "Read-only getters should use define-read-only — they're free to call off-chain and signal intent clearly.",
  check(lines) {
    const findings = [];
    const getterKeywords = ["get-", "fetch-", "read-", "view-", "is-", "has-", "check-"];
    const writeFns = [
      "map-set", "map-insert", "map-delete",
      "var-set", "stx-transfer?", "ft-transfer?", "nft-transfer?",
    ];

    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      const trimmed = line.trim();
      if (trimmed.startsWith(";")) continue;
      if (!trimmed.includes("(define-public")) continue;

      const looksGetter = getterKeywords.some((k) =>
        trimmed.toLowerCase().includes(k)
      );
      if (!looksGetter) continue;

      const body = lines
        .slice(i, Math.min(lines.length, i + 15))
        .join("\n");

      const hasWrite = writeFns.some((fn) => body.includes(fn));
      if (!hasWrite) {
        const funcName =
          trimmed.match(/\(define-public\s+\((\S+)/)?.[1] || "unknown";
        findings.push({
          line: i + 1,
          column: 1,
          message: `Getter "${funcName}" should be define-read-only`,
          snippet: trimmed,
          suggestion:
            "Change (define-public ...) → (define-read-only ...)\n" +
            "Read-only calls are free and don't require a transaction.",
        });
      }
    }
    return findings;
  },
};

module.exports = {
  ALL_RULES: [
    unwrapCheck,
    authCheck,
    asContractCheck,
    hardcodedPrincipalCheck,
    readOnlyCheck,
  ],
};
