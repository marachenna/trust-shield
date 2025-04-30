;; TrustShield Smart Contract

;; Error codes
(define-constant ERR_ACCESS_DENIED (err u100))
(define-constant ERR_DOMAIN_ALREADY_REGISTERED (err u101))
(define-constant ERR_DOMAIN_NOT_FOUND (err u102))
(define-constant ERR_SYSTEM_LOCKED (err u103))
(define-constant ERR_STAKE_TOO_LOW (err u104))
(define-constant ERR_WAITING_PERIOD (err u105))
(define-constant ERR_LIMIT_REACHED (err u106))
(define-constant ERR_TIMING_CONFLICT (err u107))
(define-constant ERR_INVALID_DOMAIN_FORMAT (err u400))
(define-constant ERR_INVALID_SECURITY_CERT (err u401))
(define-constant ERR_INSUFFICIENT_PROOF (err u402))
(define-constant ERR_INVALID_RISK_SCORE (err u403))
(define-constant ERR_INVALID_TRUST_TIER (err u404))
(define-constant ERR_INVALID_CONTROLLER_ADDRESS (err u405))

;; System constants
(define-constant WAITING_PERIOD_SECONDS u86400) ;; 24 hours in seconds
(define-constant MINIMUM_STAKE_AMOUNT u1000000) ;; in microSTX
(define-constant REQUIRED_GUARDIAN_SCORE u50)
(define-constant MAX_PROOF_STRING_LENGTH u500)

;; Input validation functions
(define-private (validate-domain-format (domain_name (string-ascii 255)))
    (begin
        (asserts! (>= (len domain_name) u3) (err "Domain name too short"))
        (asserts! (<= (len domain_name) u255) (err "Domain name too long"))
        (asserts! (is-eq (index-of domain_name ".") none) (err "Invalid character: ."))
        (asserts! (is-eq (index-of domain_name "/") none) (err "Invalid character: /"))
        (asserts! (is-eq (index-of domain_name " ") none) (err "Invalid character: space"))
        (ok true)))

(define-private (validate-security-cert (cert_code (string-ascii 50)))
    (begin
        (asserts! (>= (len cert_code) u5) (err "Certificate too short"))
        (asserts! (<= (len cert_code) u50) (err "Certificate too long"))
        (asserts! (is-eq (index-of cert_code "<") none) (err "Invalid character: <"))
        (asserts! (is-eq (index-of cert_code ">") none) (err "Invalid character: >"))
        (ok true)))

(define-private (validate-threat-proof (fraud_evidence (string-ascii 500)))
    (begin
        (asserts! (>= (len fraud_evidence) u10) (err "Evidence documentation too short"))
        (asserts! (<= (len fraud_evidence) u500) (err "Evidence documentation too long"))
        (asserts! (is-eq (index-of fraud_evidence "<") none) (err "Invalid character: <"))
        (asserts! (is-eq (index-of fraud_evidence ">") none) (err "Invalid character: >"))
        (ok true)))

(define-private (validate-risk-level (risk_level uint))
    (begin
        (asserts! (>= risk_level u1) (err "Risk level too low"))
        (asserts! (<= risk_level u100) (err "Risk level too high"))
        (ok true)))

(define-private (validate-trust-tier (trust_tier uint))
    (begin
        (asserts! (>= trust_tier u1) (err "Trust tier too low"))
        (asserts! (<= trust_tier u10) (err "Trust tier too high"))
        (ok true)))

;; Administrative state variables
(define-data-var system_controller principal tx-sender)
(define-data-var domain_registration_fee uint u100)
(define-data-var required_confirmations uint u5)
(define-data-var system_trust_tier uint u1)
(define-data-var system_locked bool false)

;; Primary data structures
(define-map verified_domains
    {domain_name: (string-ascii 255)}
    {
        domain_owner: principal,
        trust_tier: (string-ascii 20),
        registration_date: uint,
        risk_score: uint,
        total_fraud_incidents: uint,
        staked_amount: uint,
        last_audit_date: uint,
        security_cert: (string-ascii 50)
    })

(define-map fraud_reports
    {domain_name: (string-ascii 255)}
    {
        reporter_id: principal,
        report_timestamp: uint,
        fraud_evidence: (string-ascii 500),
        report_status: (string-ascii 20),
        severity_score: uint,
        affected_users: uint
    })

(define-map guardian_performance
    {guardian_id: principal, protected_domain: (string-ascii 255)}
    {
        reports_submitted: uint,
        last_activity_date: uint,
        credibility_score: uint,
        staked_tokens: uint,
        confirmed_reports: uint
    })

(define-map domain_audit_records
    {domain_name: (string-ascii 255)}
    {
        audit_frequency: uint,
        last_scan_date: uint,
        auditor_id: principal,
        security_score: uint,
        compliance_level: (string-ascii 50)
    })

(define-map guardian_profiles
    {guardian_id: principal}
    {
        staked_amount: uint,
        review_count: uint,
        trust_rating: uint,
        last_active_time: uint,
        status: (string-ascii 20)
    })

;; Query functions
(define-read-only (get-domain-security-info (domain_name (string-ascii 255)))
    (match (map-get? verified_domains {domain_name: domain_name})
        domain_data (ok domain_data)
        (err ERR_DOMAIN_NOT_FOUND)))

(define-read-only (has-active-reports (domain_name (string-ascii 255)))
    (is-some (map-get? fraud_reports {domain_name: domain_name})))

(define-read-only (get-guardian-reputation (guardian_id principal))
    (match (map-get? guardian_performance {guardian_id: guardian_id, protected_domain: ""})
        guardian_data (get credibility_score guardian_data)
        u0))

;; Core operations
(define-public (register-protected-domain 
    (domain_name (string-ascii 255))
    (security_cert (string-ascii 50)))
    (let (
        (current_time (unwrap-panic (get-block-info? time (- block-height u1))))
        (required_stake (* MINIMUM_STAKE_AMOUNT (var-get system_trust_tier))))
        
        ;; Input validation
        (asserts! (is-ok (validate-domain-format domain_name)) ERR_INVALID_DOMAIN_FORMAT)
        (asserts! (is-ok (validate-security-cert security_cert)) ERR_INVALID_SECURITY_CERT)
        (asserts! (is-eq tx-sender (var-get system_controller)) ERR_ACCESS_DENIED)
        (asserts! (>= (stx-get-balance tx-sender) required_stake) ERR_STAKE_TOO_LOW)
        
        (match (map-get? verified_domains {domain_name: domain_name})
            existing_domain ERR_DOMAIN_ALREADY_REGISTERED
            (begin
                (try! (stx-transfer? required_stake tx-sender (as-contract tx-sender)))
                (map-set verified_domains
                    {domain_name: domain_name}
                    {
                        domain_owner: tx-sender,
                        trust_tier: "verified",
                        registration_date: current_time,
                        risk_score: u0,
                        total_fraud_incidents: u0,
                        staked_amount: required_stake,
                        last_audit_date: current_time,
                        security_cert: security_cert
                    })
                (ok true)))))

(define-public (report-fraud 
    (domain_name (string-ascii 255)) 
    (fraud_evidence (string-ascii 500))
    (severity_score uint))
    (let (
        (current_time (unwrap-panic (get-block-info? time (- block-height u1))))
        (guardian_data (default-to 
            {reports_submitted: u0, last_activity_date: u0, credibility_score: u0, staked_tokens: u0, confirmed_reports: u0}
            (map-get? guardian_performance {guardian_id: tx-sender, protected_domain: domain_name}))))
        
        ;; Input validation
        (asserts! (is-ok (validate-domain-format domain_name)) ERR_INVALID_DOMAIN_FORMAT)
        (asserts! (is-ok (validate-threat-proof fraud_evidence)) ERR_INSUFFICIENT_PROOF)
        (asserts! (is-ok (validate-risk-level severity_score)) ERR_INVALID_RISK_SCORE)
        (asserts! (not (var-get system_locked)) ERR_SYSTEM_LOCKED)
        (asserts! (>= (get credibility_score guardian_data) REQUIRED_GUARDIAN_SCORE) ERR_STAKE_TOO_LOW)
        (asserts! (> (- current_time (get last_activity_date guardian_data)) WAITING_PERIOD_SECONDS) ERR_WAITING_PERIOD)
        
        (map-set fraud_reports
            {domain_name: domain_name}
            {
                reporter_id: tx-sender,
                report_timestamp: current_time,
                fraud_evidence: fraud_evidence,
                report_status: "pending",
                severity_score: severity_score,
                affected_users: u1
            })
        
        (map-set guardian_performance
            {guardian_id: tx-sender, protected_domain: domain_name}
            {
                reports_submitted: (+ (get reports_submitted guardian_data) u1),
                last_activity_date: current_time,
                credibility_score: (+ (get credibility_score guardian_data) u5),
                staked_tokens: (get staked_tokens guardian_data),
                confirmed_reports: (get confirmed_reports guardian_data)
            })
        (ok true)))

(define-private (update-domain-risk-score (domain_name (string-ascii 255)) (risk_change int))
    (begin 
        (asserts! (is-ok (validate-domain-format domain_name)) ERR_INVALID_DOMAIN_FORMAT)
        (match (map-get? verified_domains {domain_name: domain_name})
            domain_data 
                (begin
                    (map-set verified_domains
                        {domain_name: domain_name}
                        (merge domain_data {
                            risk_score: (+ (get risk_score domain_data) 
                                (if (> risk_change 0) 
                                    (to-uint risk_change)
                                    u0))
                        }))
                    (ok true))
            ERR_DOMAIN_NOT_FOUND)))

(define-public (verify-fraud-report 
    (domain_name (string-ascii 255))
    (is_confirmed bool))
    (let (
        (current_time (unwrap-panic (get-block-info? time (- block-height u1))))
        (guardian_profile (unwrap! (map-get? guardian_profiles {guardian_id: tx-sender}) ERR_ACCESS_DENIED)))
        
        (asserts! (is-ok (validate-domain-format domain_name)) ERR_INVALID_DOMAIN_FORMAT)
        (asserts! (>= (get staked_amount guardian_profile) MINIMUM_STAKE_AMOUNT) ERR_STAKE_TOO_LOW)
        
        (map-set guardian_profiles
            {guardian_id: tx-sender}
            (merge guardian_profile {
                review_count: (+ (get review_count guardian_profile) u1),
                last_active_time: current_time
            }))
        (if is_confirmed
            (update-domain-risk-score domain_name 10)
            (update-domain-risk-score domain_name -5))))

(define-public (register-as-guardian (stake_amount uint))
    (let (
        (current_time (unwrap-panic (get-block-info? time (- block-height u1)))))
        (asserts! (>= stake_amount MINIMUM_STAKE_AMOUNT) ERR_STAKE_TOO_LOW)
        (asserts! (>= (stx-get-balance tx-sender) stake_amount) ERR_STAKE_TOO_LOW)
        
        (map-set guardian_profiles
            {guardian_id: tx-sender}
            {
                staked_amount: stake_amount,
                review_count: u0,
                trust_rating: u100,
                last_active_time: current_time,
                status: "active"
            })
        (unwrap! (stx-transfer? stake_amount tx-sender (as-contract tx-sender))
                 ERR_STAKE_TOO_LOW)
        (ok true)))

;; System management functions
(define-public (update-trust-tier (new_trust_tier uint))
    (begin
        (asserts! (is-ok (validate-trust-tier new_trust_tier)) ERR_INVALID_TRUST_TIER)
        (asserts! (is-eq tx-sender (var-get system_controller)) ERR_ACCESS_DENIED)
        (var-set system_trust_tier new_trust_tier)
        (ok true)))

(define-public (set-emergency-lock (lock_state bool))
    (begin
        (asserts! (is-eq tx-sender (var-get system_controller)) ERR_ACCESS_DENIED)
        (var-set system_locked lock_state)
        (ok true)))

(define-public (transfer-system-control (new_controller principal))
    (begin
        (asserts! (is-eq tx-sender (var-get system_controller)) ERR_ACCESS_DENIED)
        (asserts! (not (is-eq new_controller 'SP000000000000000000002Q6VF78)) ERR_INVALID_CONTROLLER_ADDRESS)
        (var-set system_controller new_controller)
        (ok true)))

;; System initialization
(define-public (initialize-system (admin_address principal))
    (begin
        (asserts! (is-eq tx-sender (var-get system_controller)) ERR_ACCESS_DENIED)
        (asserts! (not (is-eq admin_address 'SP000000000000000000002Q6VF78)) ERR_INVALID_CONTROLLER_ADDRESS)
        (var-set system_controller admin_address)
        (var-set system_trust_tier u1)
        (var-set system_locked false)
        (ok true)))