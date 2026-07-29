//! State management module
//!
//! This module provides the core state management functionality for Regent SDK.
//! It includes types and traits for defining expected states, assessing compliance,
//! and performing remediation.
//!
//! ## Architecture
//!
//! The state management system is built around several key concepts:
//!
//! - **[`ExpectedState`]**: The root container for infrastructure definitions
//! - **[`Attribute`]**: Individual resource definitions (packages, services, files, etc.)
//! - **[`attribute::AttributeDetail`]**: Enum of all supported resource types
//! - **[`compliance`]**: Types for compliance assessment and status reporting
//!
//! ## Quick Start
//!
//! ```no_run
//! use regent_sdk::state::{ExpectedState, Attribute};
//! use regent_sdk::attribute::system::service::{ServiceBlockExpectedState, ServiceExpectedState};
//! use regent_sdk::Privilege;
//!
//! // Create a service attribute
//! let nginx_service = ServiceBlockExpectedState::builder("nginx")
//!     .with_state(ServiceExpectedState::Started)
//!     .with_enabled(true)
//!     .build()
//!     .unwrap();
//!
//! // Create expected state with the attribute
//! let expected_state = ExpectedState::new()
//!     .with_attribute(Attribute::service(
//!         nginx_service,
//!         Privilege::WithSudo,
//!         Some("Ensure nginx is running".to_string()),
//!     ))
//!     .build();
//! ```

pub mod attribute;
pub mod compliance;
pub mod expected_state;

use crate::error::RegentError;
pub use expected_state::ExpectedState;

/// Trait for types that can validate themselves.
///
/// This trait is used throughout the SDK to ensure that configurations
/// are valid before they are used.
pub trait Check {
    /// Validate this item.
    ///
    /// # Returns
    ///
    /// `Ok(())` if validation passed, or a [`RegentError`] if validation failed.
    fn check(&self) -> Result<(), RegentError>;
}
