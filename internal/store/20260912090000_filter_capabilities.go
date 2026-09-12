package store

import "gorm.io/gorm"

func init() {
	RegisterGORMMigration(func(db *gorm.DB) error {
		if db.Migrator().HasTable("filter_capabilities") {
			return nil
		}
		// Short-lived (30s) capabilities minted on the policy-filter hop.
		//
		// The row holds a token *hash*, never the token, and a non-secret
		// frozen-match snapshot — credential key names, never values.
		// source_session_hash is the sessions primary key (the SHA-256 of
		// the raw session token), so revoking the initiating session or
		// agent invalidates outstanding capabilities immediately without
		// this table ever storing a usable bearer credential.
		//
		// consumed_at is the single-use latch: the conditional UPDATE in
		// ConsumeFilterContinuation is what makes "first exact matching
		// request wins" hold across replicas.
		if db.Name() == "postgres" {
			if err := db.Exec(`CREATE TABLE filter_capabilities (
				id                  TEXT PRIMARY KEY,
				kind                TEXT NOT NULL,
				token_hash          TEXT NOT NULL UNIQUE,
				format_version      INTEGER NOT NULL,
				vault_id            TEXT NOT NULL REFERENCES vaults(id) ON DELETE CASCADE,
				policy_vault_id     TEXT REFERENCES vaults(id) ON DELETE CASCADE,
				actor_id            TEXT NOT NULL,
				source_session_hash TEXT NOT NULL,
				source_agent_id     TEXT NOT NULL DEFAULT '',
				service_name        TEXT NOT NULL DEFAULT '',
				bind_method         TEXT NOT NULL DEFAULT '',
				bind_scheme         TEXT NOT NULL DEFAULT '',
				bind_authority      TEXT NOT NULL DEFAULT '',
				bind_path           TEXT NOT NULL DEFAULT '',
				bind_query          TEXT NOT NULL DEFAULT '',
				match_snapshot      TEXT NOT NULL DEFAULT '',
				issued_at           TIMESTAMPTZ NOT NULL DEFAULT NOW(),
				expires_at          TIMESTAMPTZ NOT NULL,
				claimed_at          TIMESTAMPTZ,
				consumed_at         TIMESTAMPTZ
			)`).Error; err != nil {
				return err
			}
			return db.Exec(`CREATE INDEX idx_filter_capabilities_expires_at ON filter_capabilities(expires_at)`).Error
		}
		if err := db.Exec(`CREATE TABLE filter_capabilities (
			id                  TEXT PRIMARY KEY,
			kind                TEXT NOT NULL,
			token_hash          TEXT NOT NULL UNIQUE,
			format_version      INTEGER NOT NULL,
			vault_id            TEXT NOT NULL REFERENCES vaults(id) ON DELETE CASCADE,
			policy_vault_id     TEXT REFERENCES vaults(id) ON DELETE CASCADE,
			actor_id            TEXT NOT NULL,
			source_session_hash TEXT NOT NULL,
			source_agent_id     TEXT NOT NULL DEFAULT '',
			service_name        TEXT NOT NULL DEFAULT '',
			bind_method         TEXT NOT NULL DEFAULT '',
			bind_scheme         TEXT NOT NULL DEFAULT '',
			bind_authority      TEXT NOT NULL DEFAULT '',
			bind_path           TEXT NOT NULL DEFAULT '',
			bind_query          TEXT NOT NULL DEFAULT '',
			match_snapshot      TEXT NOT NULL DEFAULT '',
			issued_at           TEXT NOT NULL DEFAULT (datetime('now')),
			expires_at          TEXT NOT NULL,
			claimed_at          TEXT,
			consumed_at         TEXT
		)`).Error; err != nil {
			return err
		}
		return db.Exec(`CREATE INDEX idx_filter_capabilities_expires_at ON filter_capabilities(expires_at)`).Error
	})
}
