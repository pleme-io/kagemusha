//! SeaORM persistence layer for kagemusha Tor network analysis data.
//!
//! Feature-gated behind `persistence`. Provides SQLite-backed stores for
//! relay snapshots and exit node snapshots.

use sea_orm::entity::prelude::*;
use sea_orm::{
    ActiveModelTrait, ColumnTrait, Database, DatabaseConnection, EntityTrait, QueryFilter, Set,
};

use kagemusha_core::{ExitNode, RelayEntry};

// ---------------------------------------------------------------------------
// Entity: relay_snapshots
// ---------------------------------------------------------------------------

/// SeaORM entity for persisted relay snapshots.
pub mod relay_snapshot {
    use sea_orm::entity::prelude::*;

    #[derive(Clone, Debug, PartialEq, DeriveEntityModel)]
    #[sea_orm(table_name = "relay_snapshots")]
    pub struct Model {
        #[sea_orm(primary_key, auto_increment = true)]
        pub id: i64,
        pub fingerprint: String,
        pub nickname: String,
        pub address: String,
        pub or_port: i32,
        pub dir_port: i32,
        pub flags: String,
        pub bandwidth: i64,
        pub country: Option<String>,
        pub captured_at: String,
    }

    #[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
    pub enum Relation {}

    impl ActiveModelBehavior for ActiveModel {}
}

// ---------------------------------------------------------------------------
// Entity: exit_snapshots
// ---------------------------------------------------------------------------

/// SeaORM entity for persisted exit node snapshots.
pub mod exit_snapshot {
    use sea_orm::entity::prelude::*;

    #[derive(Clone, Debug, PartialEq, DeriveEntityModel)]
    #[sea_orm(table_name = "exit_snapshots")]
    pub struct Model {
        #[sea_orm(primary_key, auto_increment = true)]
        pub id: i64,
        pub fingerprint: String,
        pub address: String,
        pub exit_policy: String,
        pub country: Option<String>,
        pub bandwidth: i64,
        pub captured_at: String,
    }

    #[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
    pub enum Relation {}

    impl ActiveModelBehavior for ActiveModel {}
}

// ---------------------------------------------------------------------------
// SqliteRelayStore
// ---------------------------------------------------------------------------

/// SQLite-backed store for relay and exit node snapshots.
pub struct SqliteRelayStore {
    db: DatabaseConnection,
}

impl SqliteRelayStore {
    /// Connect to the given SQLite database URL.
    ///
    /// Use `"sqlite::memory:"` for an ephemeral in-memory database.
    pub async fn new(db_url: &str) -> Result<Self, DbErr> {
        let db = Database::connect(db_url).await?;
        Ok(Self { db })
    }

    /// Create the `relay_snapshots` and `exit_snapshots` tables if they do not exist.
    pub async fn init_tables(&self) -> Result<(), DbErr> {
        let relay_sql = r"
            CREATE TABLE IF NOT EXISTS relay_snapshots (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                fingerprint TEXT    NOT NULL,
                nickname    TEXT    NOT NULL,
                address     TEXT    NOT NULL,
                or_port     INTEGER NOT NULL,
                dir_port    INTEGER NOT NULL,
                flags       TEXT    NOT NULL,
                bandwidth   INTEGER NOT NULL,
                country     TEXT,
                captured_at TEXT    NOT NULL
            )
        ";
        self.db
            .execute(sea_orm::Statement::from_string(
                sea_orm::DatabaseBackend::Sqlite,
                relay_sql,
            ))
            .await?;

        let exit_sql = r"
            CREATE TABLE IF NOT EXISTS exit_snapshots (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                fingerprint TEXT    NOT NULL,
                address     TEXT    NOT NULL,
                exit_policy TEXT    NOT NULL,
                country     TEXT,
                bandwidth   INTEGER NOT NULL,
                captured_at TEXT    NOT NULL
            )
        ";
        self.db
            .execute(sea_orm::Statement::from_string(
                sea_orm::DatabaseBackend::Sqlite,
                exit_sql,
            ))
            .await?;

        Ok(())
    }

    /// Persist a [`RelayEntry`] snapshot.
    pub async fn save_relay(
        &self,
        relay: &RelayEntry,
        captured_at: &str,
    ) -> Result<(), DbErr> {
        let flags_json =
            serde_json::to_string(&relay.flags).unwrap_or_else(|_| "[]".to_string());

        let model = relay_snapshot::ActiveModel {
            id: sea_orm::ActiveValue::NotSet,
            fingerprint: Set(relay.fingerprint.clone()),
            nickname: Set(relay.nickname.clone()),
            address: Set(relay.address.to_string()),
            or_port: Set(i32::from(relay.or_port)),
            dir_port: Set(i32::from(relay.dir_port)),
            flags: Set(flags_json),
            bandwidth: Set(relay.bandwidth as i64),
            country: Set(None),
            captured_at: Set(captured_at.to_string()),
        };
        model.insert(&self.db).await?;
        Ok(())
    }

    /// Query relay snapshots by fingerprint.
    pub async fn query_by_fingerprint(
        &self,
        fingerprint: &str,
    ) -> Result<Vec<relay_snapshot::Model>, DbErr> {
        relay_snapshot::Entity::find()
            .filter(relay_snapshot::Column::Fingerprint.eq(fingerprint))
            .all(&self.db)
            .await
    }

    /// Persist an [`ExitNode`] snapshot.
    pub async fn save_exit(
        &self,
        exit: &ExitNode,
        captured_at: &str,
    ) -> Result<(), DbErr> {
        let model = exit_snapshot::ActiveModel {
            id: sea_orm::ActiveValue::NotSet,
            fingerprint: Set(exit.fingerprint.clone()),
            address: Set(exit.address.to_string()),
            exit_policy: Set(exit.exit_policy_summary.clone()),
            country: Set(exit.country.clone()),
            bandwidth: Set(exit.bandwidth as i64),
            captured_at: Set(captured_at.to_string()),
        };
        model.insert(&self.db).await?;
        Ok(())
    }

    /// Return the total number of stored relay snapshots.
    pub async fn count_relays(&self) -> Result<u64, DbErr> {
        relay_snapshot::Entity::find().count(&self.db).await
    }

    /// Return the total number of stored exit snapshots.
    pub async fn count_exits(&self) -> Result<u64, DbErr> {
        exit_snapshot::Entity::find().count(&self.db).await
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use std::net::IpAddr;

    use kagemusha_core::RelayFlag;

    use super::*;

    fn sample_relay() -> RelayEntry {
        RelayEntry {
            fingerprint: "AAAA1234BBBB5678".into(),
            nickname: "TestRelay".into(),
            address: "1.2.3.4".parse::<IpAddr>().unwrap(),
            or_port: 9001,
            dir_port: 0,
            flags: vec![RelayFlag::Exit, RelayFlag::Running, RelayFlag::Valid],
            bandwidth: 100_000,
        }
    }

    fn sample_exit() -> ExitNode {
        ExitNode {
            fingerprint: "EXIT_FP_001".into(),
            nickname: "FastExit".into(),
            address: "5.6.7.8".parse::<IpAddr>().unwrap(),
            exit_policy_summary: "accept 80,443".into(),
            country: Some("de".into()),
            bandwidth: 500_000,
        }
    }

    #[tokio::test]
    async fn store_relay_snapshot() {
        let store = SqliteRelayStore::new("sqlite::memory:").await.unwrap();
        store.init_tables().await.unwrap();

        let relay = sample_relay();
        store
            .save_relay(&relay, "2025-06-01T00:00:00Z")
            .await
            .unwrap();

        let count = store.count_relays().await.unwrap();
        assert_eq!(count, 1);
    }

    #[tokio::test]
    async fn query_relay_by_fingerprint() {
        let store = SqliteRelayStore::new("sqlite::memory:").await.unwrap();
        store.init_tables().await.unwrap();

        let relay = sample_relay();
        store
            .save_relay(&relay, "2025-06-01T00:00:00Z")
            .await
            .unwrap();

        let results = store
            .query_by_fingerprint("AAAA1234BBBB5678")
            .await
            .unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].nickname, "TestRelay");
        assert_eq!(results[0].address, "1.2.3.4");
        assert_eq!(results[0].or_port, 9001);
        assert_eq!(results[0].bandwidth, 100_000);

        let empty = store
            .query_by_fingerprint("NONEXISTENT")
            .await
            .unwrap();
        assert!(empty.is_empty());
    }

    #[tokio::test]
    async fn store_exit_snapshot() {
        let store = SqliteRelayStore::new("sqlite::memory:").await.unwrap();
        store.init_tables().await.unwrap();

        let exit = sample_exit();
        store
            .save_exit(&exit, "2025-06-01T12:00:00Z")
            .await
            .unwrap();

        let count = store.count_exits().await.unwrap();
        assert_eq!(count, 1);
    }

    #[tokio::test]
    async fn multiple_snapshots_same_relay() {
        let store = SqliteRelayStore::new("sqlite::memory:").await.unwrap();
        store.init_tables().await.unwrap();

        let relay = sample_relay();
        store
            .save_relay(&relay, "2025-06-01T00:00:00Z")
            .await
            .unwrap();
        store
            .save_relay(&relay, "2025-06-02T00:00:00Z")
            .await
            .unwrap();

        let results = store
            .query_by_fingerprint("AAAA1234BBBB5678")
            .await
            .unwrap();
        assert_eq!(results.len(), 2);
        assert_eq!(results[0].captured_at, "2025-06-01T00:00:00Z");
        assert_eq!(results[1].captured_at, "2025-06-02T00:00:00Z");
    }
}
