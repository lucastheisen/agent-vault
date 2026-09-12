package store

import "gorm.io/gorm"

func init() {
	RegisterGORMMigration(func(db *gorm.DB) error {
		if db.Migrator().HasTable("filter_capabilities") {
			return nil
		}

		timestamp := "TEXT"
		now := "(datetime('now'))"
		if db.Name() == "postgres" {
			timestamp = "TIMESTAMPTZ"
			now = "NOW()"
		}
		if err := db.Exec(`CREATE TABLE filter_capabilities (
			token_hash          TEXT PRIMARY KEY,
			kind                TEXT NOT NULL CHECK(kind IN ('continuation','policy')),
			state               TEXT NOT NULL DEFAULT 'issued' CHECK(state IN ('issued','claimed','consumed')),
			source_vault_id     TEXT NOT NULL REFERENCES vaults(id) ON DELETE CASCADE,
			source_session_hash TEXT NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
			source_actor_id     TEXT NOT NULL,
			source_actor_type   TEXT NOT NULL CHECK(source_actor_type IN ('user','agent')),
			source_agent_id     TEXT,
			target_vault_id     TEXT NOT NULL REFERENCES vaults(id) ON DELETE CASCADE,
			target_vault_name   TEXT NOT NULL,
			target_vault_role   TEXT NOT NULL,
			request_method      TEXT,
			request_scheme      TEXT,
			request_authority   TEXT,
			request_path        TEXT,
			request_query       TEXT,
			snapshot_version    INTEGER NOT NULL,
			snapshot_json       TEXT NOT NULL,
			expires_at          ` + timestamp + ` NOT NULL,
			created_at          ` + timestamp + ` NOT NULL DEFAULT ` + now + `,
			claimed_at          ` + timestamp + `,
			consumed_at         ` + timestamp + `
		)`).Error; err != nil {
			return err
		}
		if err := db.Exec(`CREATE INDEX idx_filter_capabilities_expires_at ON filter_capabilities(expires_at)`).Error; err != nil {
			return err
		}
		return db.Exec(`CREATE INDEX idx_filter_capabilities_source_session ON filter_capabilities(source_session_hash)`).Error
	})
}
