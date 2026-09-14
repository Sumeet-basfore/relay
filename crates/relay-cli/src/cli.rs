use clap::{Args, Parser, Subcommand};
use std::path::PathBuf;

/// Relay — Local-first zero-trust security gateway and credential broker for AI agents
#[derive(Parser, Debug)]
#[command(
    name = "relay",
    version,
    about = "Zero-trust MCP security gateway and credential broker for AI agents",
    long_about = "Relay is a local-first security control plane interposed between AI agents and sensitive tools. It evaluates deterministic Cedar policies, injects vaulted credentials just-in-time, and produces tamper-evident in-toto Action Receipts in an append-only SQLite ledger."
)]
pub struct Cli {
    /// Path to Relay configuration file [default: ~/.config/relay/relay.toml]
    #[arg(short = 'c', long = "config", global = true)]
    pub config: Option<PathBuf>,

    /// Increase diagnostic logging verbosity (-v: DEBUG, -vv: TRACE)
    #[arg(short = 'v', long = "verbose", action = clap::ArgAction::Count, global = true)]
    pub verbose: u8,

    /// Silence all diagnostic logging to stderr
    #[arg(short = 'q', long = "quiet", global = true)]
    pub quiet: bool,

    /// Format diagnostic output as JSON
    #[arg(long = "json", global = true)]
    pub json: bool,

    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand, Debug)]
pub enum Commands {
    /// Wrap and govern an MCP server over stdio
    Run(RunArgs),

    /// Validate, test, and inspect Cedar security policies
    Policy(PolicyArgs),

    /// Manage vaulted credentials in the OS secure keyring
    Secret(SecretArgs),

    /// Cryptographically verify action receipts and audit chains
    #[command(alias = "verify-ledger")]
    Verify(VerifyArgs),

    /// Query and inspect local ledger action receipts
    Receipt(ReceiptArgs),

    /// Diagnose system health, keyring access, keys, and permissions
    Doctor,

    /// Launch the local security console web UI
    Ui(UiArgs),
}

#[derive(Args, Debug)]
pub struct RunArgs {
    /// The MCP server command and arguments to launch and govern
    #[arg(required = true, last = true)]
    pub server_command: Vec<String>,

    /// Fail-closed on approvals; do not prompt on /dev/tty
    #[arg(long = "non-interactive")]
    pub non_interactive: bool,

    /// Path to custom Cedar policy directory
    #[arg(long = "policy")]
    pub policy_dir: Option<PathBuf>,

    /// Dynamic secret interpolation (e.g. DATABASE_URL=vault:pg_prod)
    #[arg(long = "env")]
    pub env: Vec<String>,
}

#[derive(Args, Debug)]
pub struct PolicyArgs {
    #[command(subcommand)]
    pub command: PolicySubcommands,
}

#[derive(Subcommand, Debug)]
pub enum PolicySubcommands {
    /// Validate Cedar policy syntax and schema consistency
    Validate {
        /// Path to policy file or directory
        #[arg(short, long)]
        path: Option<PathBuf>,
    },
    /// Test Cedar policies against test fixtures
    Test {
        /// Path to test fixtures directory
        #[arg(short, long)]
        fixtures: Option<PathBuf>,
    },
}

#[derive(Args, Debug)]
pub struct SecretArgs {
    #[command(subcommand)]
    pub command: SecretSubcommands,
}

#[derive(Subcommand, Debug)]
pub enum SecretSubcommands {
    /// Store a secret in the OS secure keyring
    Set {
        /// Key identifier alias (e.g. github_token, pg_password)
        key: String,
        /// Secret value to store
        value: String,
    },
    /// Inspect secret metadata (masked value)
    Get {
        /// Key identifier alias
        key: String,
    },
    /// List configured secret key aliases
    List,
    /// Purge a secret from the keyring
    Delete {
        /// Key identifier alias
        key: String,
    },
}

#[derive(Args, Debug)]
pub struct VerifyArgs {
    /// Path to SQLite ledger database file [default: config storage.ledger_path]
    #[arg(long = "db-path", alias = "ledger", alias = "ledger-path")]
    pub db_path: Option<PathBuf>,

    /// Start verification from specific sequence number
    #[arg(long = "from", alias = "from-seq")]
    pub from_seq: Option<u64>,

    /// Path to Ed25519 public key for verification
    #[arg(long = "pubkey")]
    pub pubkey_path: Option<PathBuf>,

    /// Specific receipt ID to target for verification
    #[arg(long = "target-receipt-id")]
    pub target_receipt_id: Option<String>,
}

#[derive(Args, Debug)]
pub struct ReceiptArgs {
    /// Path to SQLite ledger database file [default: config storage.ledger_path]
    #[arg(
        long = "db-path",
        alias = "ledger",
        alias = "ledger-path",
        global = true
    )]
    pub db_path: Option<PathBuf>,

    #[command(subcommand)]
    pub command: ReceiptSubcommands,
}

#[derive(Subcommand, Debug)]
pub enum ReceiptSubcommands {
    /// Fetch and display a receipt by UUIDv7 ID or hash
    Get {
        /// Receipt ID or SHA-256 hash
        id: String,
    },
    /// List recent receipts from the local ledger
    List {
        /// Maximum number of receipts to list
        #[arg(short, long, default_value = "20")]
        limit: usize,
    },
}

#[derive(Args, Debug, Clone)]
pub struct UiArgs {
    /// Port to bind the local UI server [default: 8765]
    #[arg(short = 'p', long = "port", default_value_t = 8765)]
    pub port: u16,

    /// Host address to bind [default: 127.0.0.1; MUST be loopback]
    #[arg(long = "host", default_value = "127.0.0.1")]
    pub host: String,

    /// Do not automatically open default web browser
    #[arg(long = "no-browser")]
    pub no_browser: bool,

    /// Specific session auth token to use instead of generating an ephemeral token
    #[arg(long = "token")]
    pub token: Option<String>,
}
