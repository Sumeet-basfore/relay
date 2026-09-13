//! Asynchronous SQLite Ledger implementing the `relay_domain::Ledger` trait.
//!
//! Complies with A006 §5.3:
//! Dedicated single-writer actor thread with bounded mpsc channel queue (1024 capacity).

use async_trait::async_trait;
use relay_domain::{
    ActionReceipt, Digest, Ledger, LedgerEntry, LedgerError, ReceiptId, SequenceNumber,
};
use std::path::Path;
use tokio::sync::{mpsc, oneshot};

use crate::engine::SqliteStorageEngine;
use crate::models::NodeIdentityRecord;
use crate::verifier::{LedgerVerificationReport, LedgerVerifier};

enum LedgerCommand {
    Append {
        receipt: Box<ActionReceipt>,
        reply: oneshot::Sender<Result<LedgerEntry, LedgerError>>,
    },
    GetBySequence {
        seq: SequenceNumber,
        reply: oneshot::Sender<Result<Option<LedgerEntry>, LedgerError>>,
    },
    GetByReceiptId {
        id: ReceiptId,
        reply: oneshot::Sender<Result<Option<LedgerEntry>, LedgerError>>,
    },
    GetReceiptById {
        id: ReceiptId,
        reply: oneshot::Sender<Result<Option<ActionReceipt>, LedgerError>>,
    },
    GetLatestReceiptHash {
        reply: oneshot::Sender<Result<Digest, LedgerError>>,
    },
    GetLatestEntryHash {
        reply: oneshot::Sender<Result<Digest, LedgerError>>,
    },
    VerifyChain {
        reply: oneshot::Sender<Result<bool, LedgerError>>,
    },
    Verify {
        public_key: Option<[u8; 32]>,
        from_seq: Option<u64>,
        reply: oneshot::Sender<Result<LedgerVerificationReport, LedgerError>>,
    },
    Count {
        reply: oneshot::Sender<Result<u64, LedgerError>>,
    },
    ListRecent {
        limit: usize,
        reply: oneshot::Sender<Result<Vec<LedgerEntry>, LedgerError>>,
    },
    InitializeGenesis {
        node_id: String,
        public_key_hex: String,
        reply: oneshot::Sender<Result<LedgerEntry, LedgerError>>,
    },
    GetNodeIdentity {
        reply: oneshot::Sender<Result<Option<NodeIdentityRecord>, LedgerError>>,
    },
}

/// Asynchronous SQLite Ledger adapter wrapping the single-writer storage actor
#[derive(Clone)]
pub struct SqliteLedger {
    tx: mpsc::Sender<LedgerCommand>,
}

impl SqliteLedger {
    /// Opens or creates a SQLite ledger database at the given filesystem path
    pub fn open(path: impl AsRef<Path>) -> Result<Self, LedgerError> {
        let engine = SqliteStorageEngine::open(path)?;
        Ok(Self::spawn_actor(engine))
    }

    /// Creates an in-memory SQLite ledger database (ideal for tests)
    pub fn in_memory() -> Result<Self, LedgerError> {
        let engine = SqliteStorageEngine::in_memory()?;
        Ok(Self::spawn_actor(engine))
    }

    /// Spawns the dedicated storage actor thread pinned to the SQLite connection
    fn spawn_actor(mut engine: SqliteStorageEngine) -> Self {
        let (tx, mut rx) = mpsc::channel::<LedgerCommand>(1024);

        std::thread::Builder::new()
            .name("relay-sqlite-ledger-writer".to_string())
            .spawn(move || {
                while let Some(cmd) = rx.blocking_recv() {
                    match cmd {
                        LedgerCommand::Append { receipt, reply } => {
                            let res = engine.append(&receipt);
                            let _ = reply.send(res);
                        }
                        LedgerCommand::GetBySequence { seq, reply } => {
                            let res = engine.get_by_sequence(seq);
                            let _ = reply.send(res);
                        }
                        LedgerCommand::GetByReceiptId { id, reply } => {
                            let res = engine.get_by_receipt_id(&id);
                            let _ = reply.send(res);
                        }
                        LedgerCommand::GetReceiptById { id, reply } => {
                            let res = engine.get_receipt_by_id(&id);
                            let _ = reply.send(res);
                        }
                        LedgerCommand::GetLatestReceiptHash { reply } => {
                            let res = engine.get_latest_receipt_hash();
                            let _ = reply.send(res);
                        }
                        LedgerCommand::GetLatestEntryHash { reply } => {
                            let res = engine.get_latest_entry_hash();
                            let _ = reply.send(res);
                        }
                        LedgerCommand::VerifyChain { reply } => {
                            let report = LedgerVerifier::verify_connection(
                                engine.raw_connection(),
                                None,
                                None,
                            );
                            let res = match report {
                                Ok(rep) => {
                                    if rep.status.is_valid() {
                                        Ok(true)
                                    } else {
                                        Err(LedgerError::Corruption(format!(
                                            "Ledger verification failed: {:?}",
                                            rep.status
                                        )))
                                    }
                                }
                                Err(e) => Err(e),
                            };
                            let _ = reply.send(res);
                        }
                        LedgerCommand::Verify {
                            public_key,
                            from_seq,
                            reply,
                        } => {
                            let res = LedgerVerifier::verify_connection(
                                engine.raw_connection(),
                                public_key.as_ref(),
                                from_seq,
                            );
                            let _ = reply.send(res);
                        }
                        LedgerCommand::Count { reply } => {
                            let res = engine.count();
                            let _ = reply.send(res);
                        }
                        LedgerCommand::ListRecent { limit, reply } => {
                            let res = engine.list_recent(limit);
                            let _ = reply.send(res);
                        }
                        LedgerCommand::InitializeGenesis {
                            node_id,
                            public_key_hex,
                            reply,
                        } => {
                            let res = engine.initialize_genesis(&node_id, &public_key_hex);
                            let _ = reply.send(res);
                        }
                        LedgerCommand::GetNodeIdentity { reply } => {
                            let res = engine.get_node_identity();
                            let _ = reply.send(res);
                        }
                    }
                }
            })
            .expect("Failed to spawn SQLite ledger writer thread");

        Self { tx }
    }

    /// Initializes genesis block with node identity
    pub async fn initialize_genesis(
        &self,
        node_id: &str,
        public_key_hex: &str,
    ) -> Result<LedgerEntry, LedgerError> {
        let (reply_tx, reply_rx) = oneshot::channel();
        self.tx
            .send(LedgerCommand::InitializeGenesis {
                node_id: node_id.to_string(),
                public_key_hex: public_key_hex.to_string(),
                reply: reply_tx,
            })
            .await
            .map_err(|_| LedgerError::ConnectionFailed("Storage actor terminated".to_string()))?;

        reply_rx.await.map_err(|_| {
            LedgerError::ConnectionFailed("Storage actor dropped response".to_string())
        })?
    }

    /// Retrieves an entry by receipt ID
    pub async fn get_by_receipt_id(
        &self,
        id: &ReceiptId,
    ) -> Result<Option<LedgerEntry>, LedgerError> {
        let (reply_tx, reply_rx) = oneshot::channel();
        self.tx
            .send(LedgerCommand::GetByReceiptId {
                id: *id,
                reply: reply_tx,
            })
            .await
            .map_err(|_| LedgerError::ConnectionFailed("Storage actor terminated".to_string()))?;

        reply_rx.await.map_err(|_| {
            LedgerError::ConnectionFailed("Storage actor dropped response".to_string())
        })?
    }

    /// Retrieves an ActionReceipt by receipt ID
    pub async fn get_receipt_by_id(
        &self,
        id: &ReceiptId,
    ) -> Result<Option<ActionReceipt>, LedgerError> {
        let (reply_tx, reply_rx) = oneshot::channel();
        self.tx
            .send(LedgerCommand::GetReceiptById {
                id: *id,
                reply: reply_tx,
            })
            .await
            .map_err(|_| LedgerError::ConnectionFailed("Storage actor terminated".to_string()))?;

        reply_rx.await.map_err(|_| {
            LedgerError::ConnectionFailed("Storage actor dropped response".to_string())
        })?
    }

    /// Returns the latest entry hash
    pub async fn get_latest_entry_hash(&self) -> Result<Digest, LedgerError> {
        let (reply_tx, reply_rx) = oneshot::channel();
        self.tx
            .send(LedgerCommand::GetLatestEntryHash { reply: reply_tx })
            .await
            .map_err(|_| LedgerError::ConnectionFailed("Storage actor terminated".to_string()))?;

        reply_rx.await.map_err(|_| {
            LedgerError::ConnectionFailed("Storage actor dropped response".to_string())
        })?
    }

    /// Returns total count of entries
    pub async fn count(&self) -> Result<u64, LedgerError> {
        let (reply_tx, reply_rx) = oneshot::channel();
        self.tx
            .send(LedgerCommand::Count { reply: reply_tx })
            .await
            .map_err(|_| LedgerError::ConnectionFailed("Storage actor terminated".to_string()))?;

        reply_rx.await.map_err(|_| {
            LedgerError::ConnectionFailed("Storage actor dropped response".to_string())
        })?
    }

    /// Lists the most recent N entries
    pub async fn list_recent(&self, limit: usize) -> Result<Vec<LedgerEntry>, LedgerError> {
        let (reply_tx, reply_rx) = oneshot::channel();
        self.tx
            .send(LedgerCommand::ListRecent {
                limit,
                reply: reply_tx,
            })
            .await
            .map_err(|_| LedgerError::ConnectionFailed("Storage actor terminated".to_string()))?;

        reply_rx.await.map_err(|_| {
            LedgerError::ConnectionFailed("Storage actor dropped response".to_string())
        })?
    }

    /// Retrieves node identity
    pub async fn get_node_identity(&self) -> Result<Option<NodeIdentityRecord>, LedgerError> {
        let (reply_tx, reply_rx) = oneshot::channel();
        self.tx
            .send(LedgerCommand::GetNodeIdentity { reply: reply_tx })
            .await
            .map_err(|_| LedgerError::ConnectionFailed("Storage actor terminated".to_string()))?;

        reply_rx.await.map_err(|_| {
            LedgerError::ConnectionFailed("Storage actor dropped response".to_string())
        })?
    }

    /// Verifies the full cryptographic ledger and returns a detailed report
    pub async fn verify(
        &self,
        public_key: Option<&[u8; 32]>,
    ) -> Result<LedgerVerificationReport, LedgerError> {
        let (reply_tx, reply_rx) = oneshot::channel();
        self.tx
            .send(LedgerCommand::Verify {
                public_key: public_key.copied(),
                from_seq: None,
                reply: reply_tx,
            })
            .await
            .map_err(|_| LedgerError::ConnectionFailed("Storage actor terminated".to_string()))?;

        reply_rx.await.map_err(|_| {
            LedgerError::ConnectionFailed("Storage actor dropped response".to_string())
        })?
    }

    /// Verifies the ledger from a specific sequence number
    pub async fn verify_from_seq(
        &self,
        from_seq: u64,
        public_key: Option<&[u8; 32]>,
    ) -> Result<LedgerVerificationReport, LedgerError> {
        let (reply_tx, reply_rx) = oneshot::channel();
        self.tx
            .send(LedgerCommand::Verify {
                public_key: public_key.copied(),
                from_seq: Some(from_seq),
                reply: reply_tx,
            })
            .await
            .map_err(|_| LedgerError::ConnectionFailed("Storage actor terminated".to_string()))?;

        reply_rx.await.map_err(|_| {
            LedgerError::ConnectionFailed("Storage actor dropped response".to_string())
        })?
    }
}

#[async_trait]
impl Ledger for SqliteLedger {
    async fn append(&self, receipt: &ActionReceipt) -> Result<LedgerEntry, LedgerError> {
        let (reply_tx, reply_rx) = oneshot::channel();
        self.tx
            .send(LedgerCommand::Append {
                receipt: Box::new(receipt.clone()),
                reply: reply_tx,
            })
            .await
            .map_err(|_| LedgerError::ConnectionFailed("Storage actor terminated".to_string()))?;

        reply_rx.await.map_err(|_| {
            LedgerError::ConnectionFailed("Storage actor dropped response".to_string())
        })?
    }

    async fn get_by_sequence(
        &self,
        seq: SequenceNumber,
    ) -> Result<Option<LedgerEntry>, LedgerError> {
        let (reply_tx, reply_rx) = oneshot::channel();
        self.tx
            .send(LedgerCommand::GetBySequence {
                seq,
                reply: reply_tx,
            })
            .await
            .map_err(|_| LedgerError::ConnectionFailed("Storage actor terminated".to_string()))?;

        reply_rx.await.map_err(|_| {
            LedgerError::ConnectionFailed("Storage actor dropped response".to_string())
        })?
    }

    async fn verify_chain(&self) -> Result<bool, LedgerError> {
        let (reply_tx, reply_rx) = oneshot::channel();
        self.tx
            .send(LedgerCommand::VerifyChain { reply: reply_tx })
            .await
            .map_err(|_| LedgerError::ConnectionFailed("Storage actor terminated".to_string()))?;

        reply_rx.await.map_err(|_| {
            LedgerError::ConnectionFailed("Storage actor dropped response".to_string())
        })?
    }

    async fn get_latest_receipt_hash(&self) -> Result<Digest, LedgerError> {
        let (reply_tx, reply_rx) = oneshot::channel();
        self.tx
            .send(LedgerCommand::GetLatestReceiptHash { reply: reply_tx })
            .await
            .map_err(|_| LedgerError::ConnectionFailed("Storage actor terminated".to_string()))?;

        reply_rx.await.map_err(|_| {
            LedgerError::ConnectionFailed("Storage actor dropped response".to_string())
        })?
    }
}
