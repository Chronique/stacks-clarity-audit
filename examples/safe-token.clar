;; safe-token.clar
;; ✓ Example of a well-written Clarity contract — should score 100/100

(define-fungible-token safe-token)

;; ────────────────────────────────────────────────────────
;; Constants & state
;; ────────────────────────────────────────────────────────
(define-constant CONTRACT-OWNER tx-sender)
(define-constant ERR-NOT-AUTHORIZED (err u401))
(define-constant ERR-INSUFFICIENT-BALANCE (err u402))
(define-constant ERR-INVALID-AMOUNT (err u403))

(define-data-var token-uri (optional (string-utf8 256)) none)

;; ────────────────────────────────────────────────────────
;; Authorization helper
;; ────────────────────────────────────────────────────────
(define-private (is-owner)
  (is-eq tx-sender CONTRACT-OWNER)
)

;; ────────────────────────────────────────────────────────
;; Admin functions — all protected
;; ────────────────────────────────────────────────────────
(define-public (mint-tokens (amount uint) (recipient principal))
  (begin
    (asserts! (is-owner) ERR-NOT-AUTHORIZED)
    (asserts! (> amount u0) ERR-INVALID-AMOUNT)
    (ft-mint? safe-token amount recipient)
  )
)

(define-public (burn-tokens (amount uint))
  (begin
    (asserts! (> amount u0) ERR-INVALID-AMOUNT)
    (ft-burn? safe-token amount tx-sender)
  )
)

(define-public (set-token-uri (uri (optional (string-utf8 256))))
  (begin
    (asserts! (is-owner) ERR-NOT-AUTHORIZED)
    (ok (var-set token-uri uri))
  )
)

;; ────────────────────────────────────────────────────────
;; Transfer — uses match instead of unwrap!
;; ────────────────────────────────────────────────────────
(define-public (transfer (amount uint) (to principal) (memo (optional (buff 34))))
  (begin
    (asserts! (> amount u0) ERR-INVALID-AMOUNT)
    (match (ft-transfer? safe-token amount tx-sender to)
      success (begin
        (match memo
          m (print m)
          true
        )
        (ok true)
      )
      error (err error)
    )
  )
)

;; ────────────────────────────────────────────────────────
;; Read-only getters — all correctly defined
;; ────────────────────────────────────────────────────────
(define-read-only (get-balance (address principal))
  (ok (ft-get-balance safe-token address))
)

(define-read-only (get-total-supply)
  (ok (ft-get-supply safe-token))
)

(define-read-only (get-token-uri)
  (ok (var-get token-uri))
)

(define-read-only (get-owner)
  (ok CONTRACT-OWNER)
)
