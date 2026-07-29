//! # Regent SDK
//!
//! A **multi-paradigm configuration management system as a library**.
//!
//! Regent SDK provides an Ansible-like engine for declarative infrastructure management,
//! allowing you to define expected system states and automatically assess/remedy compliance.
//!
//! ## Features
//!
//! - **Declarative State Management**: Define infrastructure as code using `ExpectedState` and `Attribute`
//! - **Multi-Protocol Host Management**: Connect to hosts via SSH (`Ssh2HostHandler`) or local execution (`LocalHostHandler`)
//! - **Comprehensive Resource Modules**: Manage packages, services, users, groups, cron jobs, files, iptables, and more
//! - **Secret Management**: Secure secret retrieval from multiple providers (AWS Secrets Manager, GCP Secret Manager, Hashicorp Vault, Infisical, files, environment variables)
//! - **Task Distribution**: Serializable tasks for distributed workload execution
//! - **Compliance Engine**: Automatic assessment and remediation of system state
//! - **Idempotent Operations**: All operations are designed to be idempotent
//! - **Templating Support**: Variable substitution using Tera templates
//!
//! ## Quick Start
//!
//! Add Regent SDK to your `Cargo.toml`:
//!
//! ```toml
//! [dependencies]
//! regent-sdk = "0.6"
//! tokio = { version = "1", features = ["full"] }
//! ```
//!
//! ### Basic Usage
//!
//! ```no_run
//! use regent_sdk::{Attribute, ExpectedState, Privilege};
//! use regent_sdk::attribute::system::service::{ServiceBlockExpectedState, ServiceExpectedState};
//! use regent_sdk::hosts::handlers::{ConnectionMethod, TargetUser};
//! use regent_sdk::hosts::managed_host::ManagedHostBuilder;
//! use regent_sdk::secrets::{SecretProvider, SecretProvidersPoolBuilder};
//!
//! #[tokio::main]
//! async fn main() {
//!     // Create a secret providers pool
//!     let secrets_pool = SecretProvidersPoolBuilder::new()
//!         .add_default_provider("files", SecretProvider::files())
//!         .build()
//!         .unwrap();
//!
//!     // Define the target host
//!     let mut managed_host = ManagedHostBuilder::new(
//!         "web-server-01",
//!         "192.168.1.100:22",
//!         Some(ConnectionMethod::Localhost(TargetUser::CurrentUser)),
//!     )
//!     .build(Some(secrets_pool))
//!     .await
//!     .unwrap();
//!
//!     // Connect to the host
//!     managed_host.connect().unwrap();
//!
//!     // Define the expected state: nginx should be installed and running
//!     let nginx_service = ServiceBlockExpectedState::builder("nginx")
//!         .with_state(ServiceExpectedState::Started)
//!         .with_enabled(true)
//!         .build()
//!         .unwrap();
//!
//!     let expected_state = ExpectedState::new()
//!         .with_attribute(Attribute::service(
//!             nginx_service,
//!             Privilege::WithSudo,
//!             Some("Ensure nginx is running".to_string()),
//!         ))
//!         .build();
//!
//!     // Assess compliance
//!     let status = managed_host
//!         .assess_compliance(&expected_state)
//!         .await
//!         .unwrap();
//!
//!     if status.is_already_compliant() {
//!         println!("Host is already compliant!");
//!     } else {
//!         println!("Host needs remediation:");
//!         for remediation in status.all_remediations() {
//!             println!("  - {:?}", remediation);
//!         }
//!     }
//!
//!     // Or automatically reach compliance
//!     let result = managed_host
//!         .reach_compliance(&expected_state)
//!         .await
//!         .unwrap();
//!
//!     if result.is_reach_compliance_success() {
//!         println!("Compliance successfully reached!");
//!     }
//! }
//! ```
//!
//! ## Architecture Overview
//!
//! The library is organized around several key concepts:
//!
//! - **[`ExpectedState`]**: The root container for your infrastructure definition
//! - **[`Attribute`]**: Individual resource definitions (packages, services, files, etc.)
//! - **[`ManagedHost`]**: Represents a target host with connection capabilities
//! - **[`RegentTask`]**: A serializable unit of work for distributed execution
//! - **[`SecretProvidersPool`]**: Manages access to various secret backends
//!
//! ## Available Attribute Types
//!
//! Regent SDK provides a rich set of resource types through the [`attribute`] module:
//!
//! ### System Resources
//! - [`attribute::system::Service`] - Manage system services
//! - [`attribute::system::User`] - Manage user accounts
//! - [`attribute::system::Group`] - Manage user groups
//! - [`attribute::system::Cron`] - Manage cron jobs
//! - [`attribute::system::Hostname`] - Manage hostname
//!
//! ### Package Management
//! - [`attribute::package::Apt`] - Debian/Ubuntu package management
//! - [`attribute::package::YumDnf`] - RHEL/CentOS package management
//! - [`attribute::package::Pacman`] - Arch Linux package management
//! - [`attribute::package::AptRepo`] - APT repository management
//! - [`attribute::package::DnfRepo`] - DNF repository management
//!
//! ### Network Configuration
//! - [`attribute::network::Iptables`] - Firewall rule management
//!
//! ### Shell & Commands
//! - [`attribute::shell::Command`] - Execute arbitrary commands
//!
//! ### File Operations
//! - [`attribute::utilities::LineInFile`] - Manage lines in files
//! - [`attribute::utilities::Debug`] - Debugging utilities
//! - [`attribute::utilities::Ping`] - Connectivity testing
//!
//! ### AI Integration
//! - [`attribute::ai::Ollama`] - Ollama API integration
//!
//! ## Connection Methods
//!
//! Connect to hosts using different methods:
//!
//! - **Localhost**: Execute on the local machine
//!   - [`hosts::handlers::localhost::LocalHostHandler`]
//!   - [`hosts::handlers::TargetUser`] for specifying user context
//!
//! - **SSH**: Connect to remote hosts via SSH2
//!   - [`hosts::handlers::ssh2::Ssh2HostHandler`]
//!   - [`hosts::handlers::ssh2::Ssh2AuthMethod`] for authentication (password, key, agent)
//!
//! ## Secret Providers
//!
//! Securely manage secrets from various sources:
//!
//! - **Local**: Files and environment variables
//! - **Cloud**: AWS Secrets Manager, Google Cloud Secret Manager
//! - **Vault**: Hashicorp Vault (planned)
//! - **Other**: Delinea Secret Server (planned), Infisical (planned)
//!
//! Enable cloud providers with features:
//!
//! ```toml
//! [dependencies]
//! regent-sdk = { version = "0.6", features = ["aws-secretsmanager"] }
//! regent-sdk = { version = "0.6", features = ["gcp-secretmanager"] }
//! ```
//!
//! ## Task Distribution
//!
//! Regent SDK supports distributed workload execution through serializable tasks:
//!
//! ```no_run
//! use regent_sdk::task::{RegentTask, Job};
//! use regent_sdk::hosts::handlers::ConnectionMethod;
//!
//! // Create a task
//! let task = RegentTask::from(
//!     managed_host_builder,
//!     expected_state,
//!     Job::Assess, // or Job::Reach for remediation
//! );
//!
//! // Serialize for network transport
//! let serialized = serde_json::to_string(&task).unwrap();
//!
//! // Deserialize and execute on worker
//! let mut task: RegentTask = serde_json::from_str(&serialized).unwrap();
//! let result = task.run(Some(secrets_pool)).await.unwrap();
//! ```
//!
//! ## Error Handling
//!
//! All operations return [`RegentError`] for consistent error handling:
//!
//! ```no_run
//! use regent_sdk::RegentError;
//!
//! match some_operation().await {
//!     Ok(result) => { /* success */ }
//!     Err(RegentError::NotConnectedToHost) => { /* handle connection error */ }
//!     Err(RegentError::TimeOutReached(msg)) => { /* handle timeout */ }
//!     Err(e) => { /* handle other errors */ }
//! }
//! ```
//!
//! ## Logging
//!
//! Regent SDK uses the `tracing` crate for logging. Enable it in your application:
//!
//! ```toml
//! [dependencies]
//! tracing = "0.1"
//! tracing-subscriber = "0.3"
//! ```
//!
//! ```no_run
//! use tracing_subscriber;
//!
//! fn main() {
//!     tracing_subscriber::fmt()
//!         .with_max_level(tracing::Level::INFO)
//!         .init();
//!     // Your code here
//! }
//! ```

pub mod command;
pub mod error;
pub mod hosts;
pub mod secrets;
pub mod state;
pub mod task;

pub use error::RegentError;
pub use hosts::handlers::localhost::{LocalHostHandler, WhichUser};
pub use hosts::handlers::ssh2::{Ssh2AuthMethod, Ssh2HostHandler};
pub use hosts::managed_host::ManagedHost;
pub use hosts::privilege::Privilege;
pub use state::ExpectedState;
pub use state::attribute;
pub use state::attribute::Attribute;
