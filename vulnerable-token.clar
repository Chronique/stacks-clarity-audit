;; vulnerable-token.clar
;; ⚠  Example contract with INTENTIONAL vulnerabilities — for testing clarity-audit
;; Do NOT deploy this contract to mainnet!

(define-fungible-token my-token)

;; ────────────────────────────────────────────────────────
;; CLA-004 trigger: hardcoded principal address inline
;; (using define-constant would be fine, but not inline)
;; ────────────────────────────────────────────────────────
(define-data-var treasury-address principal 'SP2J6ZY48GV1EZ5V2V5RB9MP66SW86PYKKNRV9EJ7)

;; ────────────────────────────────────────────────────────
;; CLA-002 trigger: admin-like function with NO auth check
;; ────────────────────────────────────────────────────────
(define-public (mint-tokens (amount uint) (recipient principal))
  ;; BUG: Anyone can call this and mint unlimited tokens!
  ;; Fix: (asserts! (is-eq tx-sender CONTRACT-OWNER) (err u401))
  (ft-mint? my-token amount recipient)
)

;; ────────────────────────────────────────────────────────
;; CLA-002 trigger: withdraw without auth check
;; ────────────────────────────────────────────────────────
(define-public (withdraw (amount uint) (recipient principal))
  ;; BUG: Anyone can drain funds!
  (stx-transfer? amount (as-contract tx-sender) recipient)
)

;; ────────────────────────────────────────────────────────
;; CLA-001 trigger: unwrap! without safe error handling
;; ────────────────────────────────────────────────────────
(define-public (transfer (amount uint) (to principal))
  (let
    ;; BUG: If ft-get-balance returns none, contract will panic
    ((balance (unwrap! (ft-get-balance my-token tx-sender) (err u1))))
    (ft-transfer? my-token amount tx-sender to)
  )
)

;; ────────────────────────────────────────────────────────
;; CLA-003 trigger: as-contract without prior auth check
;; ────────────────────────────────────────────────────────
(define-public (sweep-funds (recipient principal))
  ;; BUG: No auth check before elevating to contract context
  (as-contract
    (stx-transfer?
      (stx-get-balance (as-contract tx-sender))
      (as-contract tx-sender)
      recipient
    )
  )
)

;; ────────────────────────────────────────────────────────
;; CLA-005 trigger: getter using define-public
;; ────────────────────────────────────────────────────────
(define-public (get-my-balance (address principal))
  ;; BUG: This only reads state — should be define-read-only
  (ok (ft-get-balance my-token address))
)

(define-public (get-treasury)
  ;; BUG: Same — pure getter should be read-only
  (ok (var-get treasury-address))
)

;; ────────────────────────────────────────────────────────
;; ✓ These are fine — no issues expected
;; ────────────────────────────────────────────────────────
(define-constant CONTRACT-OWNER tx-sender)

(define-read-only (get-token-name)
  (ok "my-token")
)

(define-read-only (get-total-supply)
  (ok (ft-get-supply my-token))
)
