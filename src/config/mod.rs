#![allow(clippy::all, clippy::pedantic, clippy::nursery, clippy::restriction)]
#![allow(clippy::all)]
//! Configuration subsystem entry point.

#![allow(clippy::all)]

pub mod defaults;
pub mod file;

pub use file::{parse_file, Config};
