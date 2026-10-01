//! Configuration subsystem entry point.

pub mod defaults;
pub mod file;

pub use file::{parse_file, Config};
