;; audit-registry.clar
;; ═══════════════════════════════════════════════════════════════
;; Stacks Clarity Audit Registry
;; Onchain registry of Clarity smart contract audit results.
;;
;; Deployed on Stacks Testnet by stacks-clarity-audit
;; Contract: ST3CM1955QMJ712DDV0C0F0KE205XQQT4CRZ3R3N2.audit-registry
;; Dashboard: https://clarity-audit-nine.vercel.app
;; CLI:       npx stacks-clarity-audit
;; ═══════════════════════════════════════════════════════════════

(define-constant CONTRACT-OWNER tx-sender)
(define-constant ERR-NOT-AUTHORIZED (err u401))
(define-constant ERR-ALREADY-EXISTS (err u409))
(define-constant ERR-NOT-FOUND (err u404))
(define-constant ERR-INVALID-SCORE (err u400))
(define-constant PASSING-SCORE u70)

;; Store audit results per contract address
(define-map audit-results
  principal
  {
    auditor: principal,
    score: uint,
    critical-count: uint,
    warning-count: uint,
    info-count: uint,
    passed: bool,
    audited-at: uint
  }
)

;; Safe contracts registry — score >= 70
(define-map safe-registry
  principal
  { score: uint, auditor: principal }
)

(define-data-var total-audits uint u0)

;; ── USE CASE 2: Auditor submits audit result ─────────────────
(define-public (submit-audit
    (contract-address principal)
    (score uint)
    (critical-count uint)
    (warning-count uint)
    (info-count uint)
  )
  (let ((passed (>= score PASSING-SCORE)))
    (begin
      (asserts! (<= score u100) ERR-INVALID-SCORE)
      (asserts! (is-none (map-get? audit-results contract-address)) ERR-ALREADY-EXISTS)

      (map-set audit-results contract-address {
        auditor:        tx-sender,
        score:          score,
        critical-count: critical-count,
        warning-count:  warning-count,
        info-count:     info-count,
        passed:         passed,
        audited-at:     stacks-block-height
      })

      ;; Score >= 70 → auto-certified safe
      (if passed
        (map-set safe-registry contract-address {
          score: score, auditor: tx-sender
        })
        false
      )

      (var-set total-audits (+ (var-get total-audits) u1))
      (ok passed)
    )
  )
)

;; Auditor can revoke their own audit result
(define-public (revoke-audit (contract-address principal))
  (let ((result (unwrap! (map-get? audit-results contract-address) ERR-NOT-FOUND)))
    (begin
      (asserts! (is-eq tx-sender (get auditor result)) ERR-NOT-AUTHORIZED)
      (map-delete audit-results contract-address)
      (map-delete safe-registry contract-address)
      (ok true)
    )
  )
)

;; ── USE CASE 3: Is this contract safe to interact with? ──────
(define-read-only (is-safe (contract-address principal))
  (is-some (map-get? safe-registry contract-address))
)

;; ── USE CASE 4: dApp integration — full audit detail ─────────
(define-read-only (get-audit (contract-address principal))
  (map-get? audit-results contract-address)
)

;; Get score only
(define-read-only (get-score (contract-address principal))
  (match (map-get? audit-results contract-address)
    result (ok (get score result))
    ERR-NOT-FOUND
  )
)

;; Check if passed
(define-read-only (is-audit-passed (contract-address principal))
  (match (map-get? audit-results contract-address)
    result (ok (get passed result))
    ERR-NOT-FOUND
  )
)

;; Total audits in registry
(define-read-only (get-total-audits)
  (ok (var-get total-audits))
)
