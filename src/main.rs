//! R0N Gateway binary entry point.

/// Entry point for R0N Gateway.
///
/// Currently initializes the gateway and prints a startup message.
/// This will be expanded to load configuration and start the module system.
fn main() {
    println!("R0N Gateway v{}", env!("CARGO_PKG_VERSION"));
    println!("Starting gateway...");
}
