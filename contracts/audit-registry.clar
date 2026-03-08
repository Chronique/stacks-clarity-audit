;; audit-registry.clar
;; Onchain security registry for Clarity smart contracts
;; Clarity 3 / Stacks 3.0 compatible

;; --- Constants ---
(define-constant CONTRACT-OWNER tx-sender)
(define-constant ERR-NOT-AUTHORIZED (err u401))
(define-constant ERR-NOT-FOUND      (err u404))
(define-constant ERR-INVALID-SCORE  (err u400))

;; --- Data maps ---
(define-map audits
  { contract-id: principal }
  {
    score:        uint,
    critical:     uint,
    warning:      uint,
    info:         uint,
    version:      (string-ascii 16),
    report-hash:  (string-ascii 64),
    submitted-by: principal,
    block-height: uint,
    certified:    bool
  }
)

(define-data-var total-audits uint u0)
(define-map audit-index { idx: uint } { contract-id: principal })

;; --- Public functions ---

(define-public (submit-audit
    (contract-id    principal)
    (score          uint)
    (critical-count uint)
    (warning-count  uint)
    (info-count     uint)
    (tool-version   (string-ascii 16))
    (report-hash    (string-ascii 64)))
  (begin
    (asserts! (<= score u100) ERR-INVALID-SCORE)
    (let ((idx (var-get total-audits))
          (certified (>= score u70)))
      (map-set audits
        { contract-id: contract-id }
        {
          score:        score,
          critical:     critical-count,
          warning:      warning-count,
          info:         info-count,
          version:      tool-version,
          report-hash:  report-hash,
          submitted-by: tx-sender,
          block-height: stacks-block-height,
          certified:    certified
        }
      )
      (map-set audit-index { idx: idx } { contract-id: contract-id })
      (var-set total-audits (+ idx u1))
      (ok certified)
    )
  )
)

(define-public (update-audit
    (contract-id    principal)
    (score          uint)
    (critical-count uint)
    (warning-count  uint)
    (info-count     uint)
    (tool-version   (string-ascii 16))
    (report-hash    (string-ascii 64)))
  (let ((existing (unwrap! (map-get? audits { contract-id: contract-id }) ERR-NOT-FOUND)))
    (asserts! (is-eq tx-sender (get submitted-by existing)) ERR-NOT-AUTHORIZED)
    (asserts! (<= score u100) ERR-INVALID-SCORE)
    (map-set audits
      { contract-id: contract-id }
      (merge existing {
        score:        score,
        critical:     critical-count,
        warning:      warning-count,
        info:         info-count,
        version:      tool-version,
        report-hash:  report-hash,
        block-height: stacks-block-height,
        certified:    (>= score u70)
      })
    )
    (ok (>= score u70))
  )
)

;; --- Read-only functions ---

(define-read-only (get-audit (contract-id principal))
  (map-get? audits { contract-id: contract-id })
)

(define-read-only (is-certified (contract-id principal))
  (match (map-get? audits { contract-id: contract-id })
    entry (get certified entry)
    false
  )
)

(define-read-only (get-total-audits)
  (var-get total-audits)
)

(define-read-only (get-audit-by-index (idx uint))
  (match (map-get? audit-index { idx: idx })
    entry (map-get? audits { contract-id: (get contract-id entry) })
    none
  )
)
