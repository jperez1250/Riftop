//! Riftop library — capture, decode, stats (TUI stays in the binary).

pub mod capture;
pub mod dns;
pub mod error;
pub mod flow;
pub mod protocols;
pub mod services;

pub use flow::{FlowKey, FlowTable};
pub use protocols::{decode_ethernet, decode_frame, DecodeResult, FlowEndpoints};
