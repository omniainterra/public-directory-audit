-- Cloudflare D1 private ledger. Migration is NOT applied or deployed by public GitHub CI.
-- DO NOT store prospect URLs, business names, plaintext pages, credentials or messages.
-- D1 automatically enforces foreign keys on every query; this is not a mutable session setting.
CREATE TABLE IF NOT EXISTS audit_reservations (
  request_id TEXT PRIMARY KEY NOT NULL CHECK(length(request_id)=36),
  day_utc TEXT NOT NULL CHECK(length(day_utc)=10),
  created_at_utc TEXT NOT NULL CHECK(length(created_at_utc)<=30)
);
CREATE INDEX IF NOT EXISTS audit_reservations_day_idx ON audit_reservations(day_utc);
CREATE TABLE IF NOT EXISTS encrypted_reports (
  request_id TEXT PRIMARY KEY NOT NULL REFERENCES audit_reservations(request_id) ON DELETE RESTRICT,
  day_utc TEXT NOT NULL CHECK(length(day_utc)=10),
  payload_json TEXT NOT NULL CHECK(length(payload_json)<=15000),
  payload_sha256 TEXT NOT NULL CHECK(length(payload_sha256)=64),
  created_at_utc TEXT NOT NULL CHECK(length(created_at_utc)<=30)
);
CREATE INDEX IF NOT EXISTS encrypted_reports_day_idx ON encrypted_reports(day_utc);
