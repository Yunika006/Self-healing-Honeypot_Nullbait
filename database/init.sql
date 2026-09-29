-- ═══════════════════════════════════════════════════════════
-- NullBait Database Schema
-- Runs once on first container startup via docker-entrypoint
-- ═══════════════════════════════════════════════════════════

-- Enable UUID generation (we use UUIDs as primary keys)
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- ─────────────────────────────────────────────────────────
-- TABLE: attack_events
-- Every interaction an attacker has with any honeypot service
-- gets one row here. This is the central log table.
-- ─────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS attack_events (
    id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    timestamp       TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    -- Who attacked
    attacker_ip     VARCHAR(45) NOT NULL,   -- supports IPv6
    attacker_port   INTEGER,
    country         VARCHAR(64),
    city            VARCHAR(64),
    isp             VARCHAR(128),

    -- Which service was hit
    service         VARCHAR(32) NOT NULL,   -- 'ssh', 'http', 'ftp', 'api'
    honeypot_port   INTEGER NOT NULL,

    -- What they did
    event_type      VARCHAR(64) NOT NULL,   -- 'login_attempt', 'command', 'payload', 'scan'
    raw_payload     TEXT,                   -- exactly what was sent
    username        VARCHAR(256),           -- if a login was attempted
    password        VARCHAR(256),           -- captured credential (it's fake, safe to store)
    command         TEXT,                   -- if a shell command was run

    -- How dangerous it was
    threat_score    INTEGER DEFAULT 0 CHECK (threat_score BETWEEN 0 AND 100),
    threat_level    VARCHAR(16) DEFAULT 'low',  -- 'low', 'medium', 'high', 'critical'

    -- Was it flagged by detection engine
    flagged         BOOLEAN DEFAULT FALSE,
    flag_reason     VARCHAR(256)
);

-- Index for fast lookups by IP (detection engine queries this constantly)
CREATE INDEX idx_attack_events_ip ON attack_events(attacker_ip);
CREATE INDEX idx_attack_events_timestamp ON attack_events(timestamp DESC);
CREATE INDEX idx_attack_events_service ON attack_events(service);


-- ─────────────────────────────────────────────────────────
-- TABLE: attacker_sessions
-- Tracks a full session from first contact to last activity.
-- One attacker IP gets one active session per service.
-- ─────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS attacker_sessions (
    id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    attacker_ip     VARCHAR(45) NOT NULL,
    service         VARCHAR(32) NOT NULL,
    started_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_seen_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    ended_at        TIMESTAMPTZ,
    is_active       BOOLEAN DEFAULT TRUE,

    -- Aggregated stats for this session
    total_events    INTEGER DEFAULT 0,
    login_attempts  INTEGER DEFAULT 0,
    commands_run    INTEGER DEFAULT 0,
    max_threat_score INTEGER DEFAULT 0,

    country         VARCHAR(64),
    city            VARCHAR(64),
    user_agent      VARCHAR(512)    -- for HTTP sessions
);

CREATE INDEX idx_sessions_ip ON attacker_sessions(attacker_ip);
CREATE INDEX idx_sessions_active ON attacker_sessions(is_active);


-- ─────────────────────────────────────────────────────────
-- TABLE: captured_credentials
-- Every username/password combo an attacker tried.
-- Useful for building wordlists and research.
-- ─────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS captured_credentials (
    id          UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    timestamp   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    attacker_ip VARCHAR(45) NOT NULL,
    service     VARCHAR(32) NOT NULL,
    username    VARCHAR(256),
    password    VARCHAR(256),
    -- How many times this exact combo was tried across all attackers
    attempt_count INTEGER DEFAULT 1
);

CREATE INDEX idx_creds_ip ON captured_credentials(attacker_ip);
-- Unique constraint so we can upsert and increment count
CREATE UNIQUE INDEX idx_creds_unique ON captured_credentials(service, username, password);


-- ─────────────────────────────────────────────────────────
-- TABLE: threat_scores
-- One row per unique attacker IP.
-- Updated by detection engine as more events come in.
-- ─────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS threat_scores (
    attacker_ip     VARCHAR(45) PRIMARY KEY,
    score           INTEGER DEFAULT 0 CHECK (score BETWEEN 0 AND 100),
    threat_level    VARCHAR(16) DEFAULT 'low',
    first_seen      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_seen       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    total_events    INTEGER DEFAULT 0,
    is_blocked      BOOLEAN DEFAULT FALSE,
    blocked_at      TIMESTAMPTZ,
    country         VARCHAR(64),

    -- What attack types this IP has performed
    brute_force     BOOLEAN DEFAULT FALSE,
    sql_injection   BOOLEAN DEFAULT FALSE,
    cmd_injection   BOOLEAN DEFAULT FALSE,
    port_scan       BOOLEAN DEFAULT FALSE
);


-- ─────────────────────────────────────────────────────────
-- TABLE: service_health
-- Records the health status of each honeypot service.
-- Recovery engine writes here when it detects issues.
-- ─────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS service_health (
    id          UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    timestamp   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    service     VARCHAR(32) NOT NULL,
    status      VARCHAR(16) NOT NULL,   -- 'healthy', 'degraded', 'down'
    cpu_percent FLOAT,
    mem_mb      FLOAT,
    uptime_secs INTEGER,
    note        TEXT
);

CREATE INDEX idx_health_service ON service_health(service, timestamp DESC);


-- ─────────────────────────────────────────────────────────
-- TABLE: recovery_history
-- Every time the self-healing engine took action,
-- it records what happened and why.
-- ─────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS recovery_history (
    id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    timestamp       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    service         VARCHAR(32) NOT NULL,
    action          VARCHAR(64) NOT NULL,  -- 'restart', 'isolate', 'rebuild', 'block_ip'
    trigger_reason  TEXT NOT NULL,          -- why was this action taken
    success         BOOLEAN NOT NULL,
    duration_ms     INTEGER,               -- how long the recovery took
    notes           TEXT
);


-- ─────────────────────────────────────────────────────────
-- TABLE: alerts
-- High-priority events surfaced to the dashboard
-- ─────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS alerts (
    id          UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    timestamp   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    severity    VARCHAR(16) NOT NULL,   -- 'info', 'warning', 'critical'
    title       VARCHAR(256) NOT NULL,
    message     TEXT NOT NULL,
    attacker_ip VARCHAR(45),
    service     VARCHAR(32),
    acknowledged BOOLEAN DEFAULT FALSE,
    ack_at      TIMESTAMPTZ
);

CREATE INDEX idx_alerts_unacked ON alerts(acknowledged, timestamp DESC);


-- ─────────────────────────────────────────────────────────
-- Seed: insert initial service health rows so dashboard
-- shows something immediately on first boot
-- ─────────────────────────────────────────────────────────
INSERT INTO service_health (service, status, note) VALUES
    ('ssh',  'healthy', 'Initial state'),
    ('http', 'healthy', 'Initial state'),
    ('ftp',  'healthy', 'Initial state'),
    ('api',  'healthy', 'Initial state');
