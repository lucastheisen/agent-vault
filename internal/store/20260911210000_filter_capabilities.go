package store

import "gorm.io/gorm"

func init() {
	RegisterGORMMigration(func(db *gorm.DB) error {
		if db.Migrator().HasTable("filter_capabilities") {
			return nil
		}
		if db.Name() == "postgres" {
			return db.Exec(`CREATE TABLE filter_capabilities (
				token_hash        TEXT PRIMARY KEY,
				kind              TEXT NOT NULL,
				source_vault_id   TEXT NOT NULL,
				policy_vault_id   TEXT NOT NULL DEFAULT '',
				policy_vault_name TEXT NOT NULL DEFAULT '',
				actor_user_id     TEXT NOT NULL DEFAULT '',
				actor_agent_id    TEXT NOT NULL DEFAULT '',
				source_sess_id    TEXT NOT NULL DEFAULT '',
				vault_role        TEXT NOT NULL DEFAULT '',
				vault_name        TEXT NOT NULL DEFAULT '',
				method            TEXT NOT NULL DEFAULT '',
				scheme            TEXT NOT NULL DEFAULT '',
				authority         TEXT NOT NULL DEFAULT '',
				escaped_path      TEXT NOT NULL DEFAULT '',
				query             TEXT NOT NULL DEFAULT '',
				snapshot          TEXT NOT NULL DEFAULT '',
				expires_at        TIMESTAMPTZ NOT NULL,
				consumed          BOOLEAN NOT NULL DEFAULT FALSE,
				created_at        TIMESTAMPTZ NOT NULL DEFAULT NOW()
			)`).Error
		}
		return db.Exec(`CREATE TABLE filter_capabilities (
			token_hash        TEXT PRIMARY KEY,
			kind              TEXT NOT NULL,
			source_vault_id   TEXT NOT NULL,
			policy_vault_id   TEXT NOT NULL DEFAULT '',
			policy_vault_name TEXT NOT NULL DEFAULT '',
			actor_user_id     TEXT NOT NULL DEFAULT '',
			actor_agent_id    TEXT NOT NULL DEFAULT '',
			source_sess_id    TEXT NOT NULL DEFAULT '',
			vault_role        TEXT NOT NULL DEFAULT '',
			vault_name        TEXT NOT NULL DEFAULT '',
			method            TEXT NOT NULL DEFAULT '',
			scheme            TEXT NOT NULL DEFAULT '',
			authority         TEXT NOT NULL DEFAULT '',
			escaped_path      TEXT NOT NULL DEFAULT '',
			query             TEXT NOT NULL DEFAULT '',
			snapshot          TEXT NOT NULL DEFAULT '',
			expires_at        TEXT NOT NULL,
			consumed          INTEGER NOT NULL DEFAULT 0,
			created_at        TEXT NOT NULL DEFAULT (datetime('now'))
		)`).Error
	})
}
