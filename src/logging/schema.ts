import Database from "better-sqlite3";
import { logger } from "../utils/logger.js";

const SCHEMA_SQL = `
CREATE TABLE IF NOT EXISTS audit_entries (
  id              TEXT PRIMARY KEY,
  sequence        INTEGER NOT NULL UNIQUE,
  timestamp       TEXT NOT NULL,
  prev_hash       TEXT NOT NULL,
  entry_hash      TEXT NOT NULL,

  request_body    TEXT NOT NULL,
  response_body   TEXT,

  provider        TEXT NOT NULL,
  model           TEXT,

  risk_score      REAL NOT NULL DEFAULT 0,
  risk_level      TEXT NOT NULL DEFAULT 'none',
  action_taken    TEXT NOT NULL DEFAULT 'pass',
  checks_json     TEXT NOT NULL DEFAULT '[]',
  domains         TEXT NOT NULL DEFAULT '[]',

  client_id       TEXT,
  metadata        TEXT
);

CREATE INDEX IF NOT EXISTS idx_timestamp ON audit_entries(timestamp);
CREATE INDEX IF NOT EXISTS idx_risk_level ON audit_entries(risk_level);
CREATE INDEX IF NOT EXISTS idx_action ON audit_entries(action_taken);
CREATE INDEX IF NOT EXISTS idx_sequence ON audit_entries(sequence);
CREATE INDEX IF NOT EXISTS idx_risk_score ON audit_entries(risk_score);
CREATE INDEX IF NOT EXISTS idx_provider_model ON audit_entries(provider, model);

-- Normalized check details for efficient dashboard queries
CREATE TABLE IF NOT EXISTS check_details (
  id              INTEGER PRIMARY KEY AUTOINCREMENT,
  audit_entry_id  TEXT NOT NULL,
  check_type      TEXT NOT NULL,
  category        TEXT NOT NULL,
  risk_score      REAL NOT NULL,
  article_ref     TEXT,
  flagged_content TEXT,
  FOREIGN KEY (audit_entry_id) REFERENCES audit_entries(id)
);

CREATE INDEX IF NOT EXISTS idx_check_entry ON check_details(audit_entry_id);
CREATE INDEX IF NOT EXISTS idx_check_category ON check_details(category);
CREATE INDEX IF NOT EXISTS idx_check_type ON check_details(check_type);
CREATE INDEX IF NOT EXISTS idx_check_score ON check_details(risk_score);

CREATE TABLE IF NOT EXISTS anchors (
  id                    TEXT PRIMARY KEY,
  created_at            TEXT NOT NULL,
  anchored_sequence     INTEGER NOT NULL,
  chain_head_hash       TEXT NOT NULL,
  artifact              TEXT NOT NULL,
  artifact_sha256       TEXT NOT NULL,
  signature             TEXT NOT NULL,
  public_key            TEXT NOT NULL,
  rekor_uuid            TEXT,
  rekor_log_index       INTEGER,
  rekor_integrated_time INTEGER,
  rekor_log_url         TEXT,
  inclusion_proof_json  TEXT,
  checkpoint            TEXT,
  signed_entry_timestamp TEXT,
  rekor_body            TEXT,
  status                TEXT NOT NULL DEFAULT 'pending'
);

CREATE INDEX IF NOT EXISTS idx_anchor_sequence ON anchors(anchored_sequence);
CREATE INDEX IF NOT EXISTS idx_anchor_status ON anchors(status);
`;

const MIGRATIONS = [
  "ALTER TABLE audit_entries ADD COLUMN domains TEXT NOT NULL DEFAULT '[]'",
  "ALTER TABLE anchors ADD COLUMN inclusion_proof_json TEXT",
  "ALTER TABLE anchors ADD COLUMN checkpoint TEXT",
  "ALTER TABLE anchors ADD COLUMN signed_entry_timestamp TEXT",
  "ALTER TABLE anchors ADD COLUMN rekor_body TEXT",
];

export function initDatabase(dbPath: string): Database.Database {
  const db = new Database(dbPath);

  db.pragma("journal_mode = WAL");
  db.pragma("synchronous = NORMAL");
  db.pragma("foreign_keys = ON");

  db.exec(SCHEMA_SQL);

  for (const sql of MIGRATIONS) {
    try {
      db.exec(sql);
    } catch {
      // Column/table already exists — ignore
    }
  }

  logger.debug("Database initialized", { path: dbPath });
  return db;
}
