//! AI / inference runtime attributes
//!
//! One module per managed AI runtime: `ollama.rs` manages the Ollama
//! inference engine (install, service, models, API config), `onnx.rs`
//! manages ONNX Runtime installations in Python environments.

pub mod ollama;
pub mod onnx;

pub use ollama::{OllamaApiCall, OllamaExpectedState};
pub use onnx::{OnnxApiCall, OnnxExpectedState};
