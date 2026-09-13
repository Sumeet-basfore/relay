use tracing_subscriber::{fmt, EnvFilter};

/// Initializes structured logging ensuring no secrets can trivially leak.
/// Diagnostic output is strictly routed to `stderr` so that `stdout` remains pure JSON-RPC.
pub fn init_logging(verbose: u8, quiet: bool, json_format: bool) {
    if quiet {
        return;
    }

    let filter_level = match verbose {
        0 => "info",
        1 => "debug",
        _ => "trace",
    };

    let env_filter =
        EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(filter_level));

    let subscriber = fmt()
        .with_env_filter(env_filter)
        .with_writer(std::io::stderr) // ALWAYS write logs to stderr, never stdout
        .with_target(false);

    if json_format {
        subscriber.json().init();
    } else {
        subscriber.init();
    }
}
