CREATE TABLE users (
  id SERIAL PRIMARY KEY,
  email VARCHAR(255) UNIQUE NOT NULL,
  hashed_password VARCHAR(255) NOT NULL,
  role VARCHAR(32) NOT NULL CHECK (role IN ('admin', 'analyst')),
  is_active BOOLEAN NOT NULL DEFAULT TRUE,
  created_at TIMESTAMP NOT NULL DEFAULT NOW()
);

CREATE TABLE scan_logs (
  id SERIAL PRIMARY KEY,
  provider VARCHAR(64) NOT NULL,
  model_name VARCHAR(128),
  prompt TEXT NOT NULL,
  response TEXT,
  risk_score INTEGER NOT NULL CHECK (risk_score BETWEEN 0 AND 100),
  severity VARCHAR(32) NOT NULL,
  findings JSONB NOT NULL,
  metadata JSONB,
  created_at TIMESTAMP NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_scan_logs_created_at ON scan_logs(created_at);
CREATE INDEX idx_scan_logs_provider ON scan_logs(provider);
CREATE INDEX idx_scan_logs_severity ON scan_logs(severity);
CREATE INDEX idx_scan_logs_findings_gin ON scan_logs USING GIN(findings);

CREATE TABLE audit_logs (
  id SERIAL PRIMARY KEY,
  event_type VARCHAR(64) NOT NULL,
  actor_user_id INTEGER REFERENCES users(id),
  scan_id INTEGER REFERENCES scan_logs(id),
  details JSONB NOT NULL,
  prev_hash VARCHAR(128),
  event_hash VARCHAR(128) NOT NULL,
  created_at TIMESTAMP NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_audit_logs_created_at ON audit_logs(created_at);
CREATE INDEX idx_audit_logs_scan_id ON audit_logs(scan_id);
