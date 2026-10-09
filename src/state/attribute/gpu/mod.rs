//! GPU attributes: the NVIDIA driver and container toolkit on Linux hosts,
//! the Apple MPS (Metal) prerequisites on macOS hosts

pub mod apple_mps;
pub mod nvidia_container_toolkit;
pub mod nvidia_driver;
pub mod platform;
