-- ============================================================
-- SA-ID CITIZEN PLATFORM — PostgreSQL Schema
-- Version: 1.0.0
-- ============================================================

-- Enable UUID extension
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- ============================================================
-- CITIZENS TABLE — Core identity records
-- ============================================================
CREATE TABLE IF NOT EXISTS citizens (
    id                  UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    id_number           VARCHAR(13) UNIQUE NOT NULL,
    first_name          VARCHAR(100),
    last_name           VARCHAR(100),
    date_of_birth       DATE,
    gender              VARCHAR(10),
    province            VARCHAR(50),
    phone_number        VARCHAR(20),
    email               VARCHAR(150),
    pin_hash            TEXT,                          -- bcrypt hashed PIN
    biometric_enrolled  BOOLEAN DEFAULT FALSE,
    dha_verified        BOOLEAN DEFAULT FALSE,
    popia_consent       BOOLEAN DEFAULT FALSE,
    popia_consent_date  TIMESTAMP,
    is_active           BOOLEAN DEFAULT TRUE,
    created_at          TIMESTAMP DEFAULT NOW(),
    updated_at          TIMESTAMP DEFAULT NOW()
);

-- ============================================================
-- AUTH SESSIONS TABLE — Login tracking
-- ============================================================
CREATE TABLE IF NOT EXISTS auth_sessions (
    id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    citizen_id      UUID REFERENCES citizens(id) ON DELETE CASCADE,
    id_number       VARCHAR(13) NOT NULL,
    auth_method     VARCHAR(20) NOT NULL,  -- PIN, FACE, QR, FINGERPRINT
    ip_address      VARCHAR(45),
    user_agent      TEXT,
    success         BOOLEAN DEFAULT FALSE,
    failure_reason  TEXT,
    created_at      TIMESTAMP DEFAULT NOW()
);

-- ============================================================
-- BIOMETRIC RECORDS TABLE — Face / Fingerprint data
-- ============================================================
CREATE TABLE IF NOT EXISTS biometric_records (
    id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    citizen_id      UUID REFERENCES citizens(id) ON DELETE CASCADE,
    biometric_type  VARCHAR(20) NOT NULL,  -- FACE, FINGERPRINT
    template_hash   TEXT,                  -- hashed biometric template
    enrolled_at     TIMESTAMP DEFAULT NOW(),
    last_verified   TIMESTAMP,
    is_active       BOOLEAN DEFAULT TRUE
);

-- ============================================================
-- DOCUMENTS TABLE — Signed documents
-- ============================================================
CREATE TABLE IF NOT EXISTS signed_documents (
    id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    citizen_id      UUID REFERENCES citizens(id) ON DELETE CASCADE,
    id_number       VARCHAR(13) NOT NULL,
    document_name   VARCHAR(255) NOT NULL,
    document_hash   TEXT,                  -- SHA256 of document
    sign_method     VARCHAR(20) NOT NULL,  -- FACE, QR, PIN
    signature_data  TEXT,                  -- digital signature
    signed_at       TIMESTAMP DEFAULT NOW(),
    is_valid        BOOLEAN DEFAULT TRUE
);

-- ============================================================
-- GRANTS TABLE — SASSA grant records
-- ============================================================
CREATE TABLE IF NOT EXISTS grants (
    id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    citizen_id      UUID REFERENCES citizens(id) ON DELETE CASCADE,
    id_number       VARCHAR(13) NOT NULL,
    grant_type      VARCHAR(100) NOT NULL,  -- Social Relief, Child Support etc
    amount          DECIMAL(10,2) NOT NULL,
    status          VARCHAR(20) DEFAULT 'ACTIVE',  -- ACTIVE, PENDING, SUSPENDED
    start_date      DATE,
    next_payment    DATE,
    created_at      TIMESTAMP DEFAULT NOW(),
    updated_at      TIMESTAMP DEFAULT NOW()
);

-- ============================================================
-- PAYMENTS TABLE — Payment history
-- ============================================================
CREATE TABLE IF NOT EXISTS payments (
    id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    citizen_id      UUID REFERENCES citizens(id) ON DELETE CASCADE,
    grant_id        UUID REFERENCES grants(id),
    id_number       VARCHAR(13) NOT NULL,
    amount          DECIMAL(10,2) NOT NULL,
    payment_method  VARCHAR(50),           -- BANK_TRANSFER, CASH, POSTBANK
    reference       VARCHAR(100),
    status          VARCHAR(20) DEFAULT 'PENDING',  -- PENDING, PROCESSED, FAILED
    processed_at    TIMESTAMP,
    created_at      TIMESTAMP DEFAULT NOW()
);

-- ============================================================
-- NOTIFICATIONS TABLE — System notifications
-- ============================================================
CREATE TABLE IF NOT EXISTS notifications (
    id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    citizen_id      UUID REFERENCES citizens(id) ON DELETE CASCADE,
    id_number       VARCHAR(13),
    title           VARCHAR(200) NOT NULL,
    message         TEXT NOT NULL,
    notif_type      VARCHAR(30),           -- PAYMENT, IDENTITY, DOCUMENT, GRANT
    is_read         BOOLEAN DEFAULT FALSE,
    created_at      TIMESTAMP DEFAULT NOW()
);

-- ============================================================
-- AUDIT LOG TABLE — Full audit trail (raw SQL, no ORM)
-- ============================================================
CREATE TABLE IF NOT EXISTS audit_log (
    id              BIGSERIAL PRIMARY KEY,
    citizen_id      UUID,
    id_number       VARCHAR(13),
    action          VARCHAR(100) NOT NULL,
    table_affected  VARCHAR(50),
    record_id       UUID,
    old_values      JSONB,
    new_values      JSONB,
    ip_address      VARCHAR(45),
    performed_by    VARCHAR(100),
    created_at      TIMESTAMP DEFAULT NOW()
);

-- ============================================================
-- QR TOKENS TABLE — QR code authentication tokens
-- ============================================================
CREATE TABLE IF NOT EXISTS qr_tokens (
    id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    citizen_id      UUID REFERENCES citizens(id) ON DELETE CASCADE,
    id_number       VARCHAR(13) NOT NULL,
    token           TEXT UNIQUE NOT NULL,
    expires_at      TIMESTAMP NOT NULL,
    used            BOOLEAN DEFAULT FALSE,
    created_at      TIMESTAMP DEFAULT NOW()
);

-- ============================================================
-- INDEXES — For performance
-- ============================================================
CREATE INDEX idx_citizens_id_number ON citizens(id_number);
CREATE INDEX idx_auth_sessions_citizen ON auth_sessions(citizen_id);
CREATE INDEX idx_auth_sessions_id_number ON auth_sessions(id_number);
CREATE INDEX idx_documents_citizen ON signed_documents(citizen_id);
CREATE INDEX idx_grants_citizen ON grants(citizen_id);
CREATE INDEX idx_payments_citizen ON payments(citizen_id);
CREATE INDEX idx_notifications_citizen ON notifications(citizen_id);
CREATE INDEX idx_audit_log_citizen ON audit_log(citizen_id);
CREATE INDEX idx_audit_log_created ON audit_log(created_at);
CREATE INDEX idx_qr_tokens_token ON qr_tokens(token);

-- ============================================================
-- SEED DATA — Test citizen (ID: 8001015009087)
-- ============================================================
INSERT INTO citizens (
    id_number, first_name, last_name, date_of_birth,
    gender, province, dha_verified, popia_consent,
    popia_consent_date, biometric_enrolled
) VALUES (
    '8001015009087', 'Test', 'Citizen', '1980-01-01',
    'Male', 'Gauteng', TRUE, TRUE,
    NOW(), TRUE
) ON CONFLICT (id_number) DO NOTHING;

-- Seed grants for test citizen
INSERT INTO grants (citizen_id, id_number, grant_type, amount, status, start_date, next_payment)
SELECT id, id_number, 'SASSA Social Relief Grant', 350.00, 'ACTIVE', '2026-01-01', '2026-04-01'
FROM citizens WHERE id_number = '8001015009087'
ON CONFLICT DO NOTHING;

INSERT INTO grants (citizen_id, id_number, grant_type, amount, status, start_date, next_payment)
SELECT id, id_number, 'Child Support Grant', 480.00, 'ACTIVE', '2026-01-01', '2026-04-01'
FROM citizens WHERE id_number = '8001015009087'
ON CONFLICT DO NOTHING;

-- Seed notifications
INSERT INTO notifications (citizen_id, id_number, title, message, notif_type)
SELECT id, id_number, 'Welcome to SA-ID Platform', 'Your identity has been verified with DHA.', 'IDENTITY'
FROM citizens WHERE id_number = '8001015009087'
ON CONFLICT DO NOTHING;

COMMIT;
