//! # Regent SDK
//!
//! A **multi-paradigm configuration management system as a library**.
//!
//! Regent SDK provides an Ansible-like engine for declarative infrastructure management,
//! allowing you to define expected system states and automatically assess/remedy compliance.
//!
//! *Note: While inspired by Ansible, Regent does not aim to reproduce its API or behaviors.
//! Also, as a multi-paradigm library, you're free to implement agent/agent-less,
//! autonomous/centralized, push/pull models — whatever fits your use case.*
//!
//! ## Core Concepts
//!
//! Regent is built around three key concepts:
//!
//! - **Expected State**: The desired configuration of your system, defined via [`ExpectedState`]
//! - **Attributes**: Building blocks that describe that state (see [`attribute`] module)
//! - **Compliance**: Whether a host matches its expected state, with methods to **assess** or **enforce** it
//!
//! ## Features
//!
//! Enable the following Cargo features for additional capabilities:
//!
//! - `aws-secretsmanager`: Enable AWS Secrets Manager support via [`SecretProvider::aws_secretsmanager`]
//! - `gcp-secretmanager`: Enable Google Cloud Secret Manager support via [`SecretProvider::gcp_secretmanager`]
//! - `windows`: Enable Windows support, including Windows OS detection, command execution, and service management
//!
//! ## Capabilities
//!
//! - **Declarative State Management**: Define infrastructure as code using [`ExpectedState`] and [`Attribute`]
//! - **Multi-Protocol Host Management**: Connect to hosts via [`Ssh2HostHandler`] or [`LocalHostHandler`]
//! - **Comprehensive Resource Modules**: Manage packages, services, users, groups, cron jobs, files, iptables, and more
//! - **Secret Management**: Secure secret retrieval from multiple providers using [`SecretProvidersPoolBuilder`]
//! - **Task Distribution**: Serializable tasks for distributed workload execution using [`RegentTask`]
//! - **Compliance Engine**: Automatic assessment and remediation via [`assess_compliance`] and [`reach_compliance`]
//! - **Idempotent Operations**: All operations are designed to be idempotent
//! - **Templating Support**: Variable substitution using Tera templates
//!
//! ## Usage
//!
//! The primary workflow with Regent's Rust API:
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
//!     // 1. Create a secret providers pool
//!     let secrets_pool = SecretProvidersPoolBuilder::new()
//!         .add_default_provider("files", SecretProvider::files())
//!         .build()
//!         .unwrap();
//!
//!     // 2. Define and connect to the target host
//!     let mut managed_host = ManagedHostBuilder::new(
//!         "web-server-01",
//!         "192.168.1.100:22",
//!         Some(ConnectionMethod::Localhost(TargetUser::CurrentUser)),
//!     )
//!     .build(Some(secrets_pool))
//!     .await
//!     .unwrap();
//!
//!     managed_host.connect().unwrap();
//!
//!     // 3. Define the expected state using attributes
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
//!     // 4. Assess compliance
//!     let status = managed_host
//!         .assess_compliance(&expected_state)
//!         .await
//!         .unwrap();
//!
//!     if !status.is_already_compliant() {
//!         // 5. Or enforce it directly
//!         managed_host.reach_compliance(&expected_state).await.unwrap();
//!     }
//! }
//! ```
//!
//! For YAML-based configuration, see [`ExpectedState::from_raw_yaml`] and [`Inventory`].
//!
//! ## Attribute Categories
//!
//! Available attribute modules for defining expected state:
//!
//! - **[`attribute::system`]**: System resources (services, users, groups, cron, hostname)
//! - **[`attribute::package`]**: Package management (apt, yum/dnf, pacman, repositories)
//! - **[`attribute::network`]**: Network configuration (iptables)
//! - **[`attribute::shell`]**: Shell commands
//! - **[`attribute::utilities`]**: Utilities (line in file, debug, ping)
//! - **[`attribute::ai`]**: AI integration (Ollama)
//!
//! ## Connection Methods
//!
//! Connect to hosts using:
//!
//! - **[`hosts::handlers::localhost::LocalHostHandler`]**: Execute on the local machine
//! - **[`hosts::handlers::ssh2::Ssh2HostHandler`]**: Connect to remote hosts via SSH2
//!
//! ## Secret Management
//!
//! Securely retrieve secrets from:
//!
//! - **Local**: Files and environment variables
//! - **Cloud**: AWS Secrets Manager, Google Cloud Secret Manager (enable via features)
//!
//! See [`SecretProvidersPoolBuilder`] for configuration.
//!
//! ## Task Distribution
//!
//! Create serializable tasks for distributed execution:
//!
//! ```no_run
//! use regent_sdk::task::{RegentTask, Job};
//!
//! let task = RegentTask::from(managed_host_builder, expected_state, Job::Assess);
//! let serialized = serde_json::to_string(&task).unwrap();
//! let mut task: RegentTask = serde_json::from_str(&serialized).unwrap();
//! let result = task.run(Some(secrets_pool)).await.unwrap();
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
pub use hosts::inventory::Inventory;
pub use hosts::managed_host::ManagedHost;
pub use hosts::privilege::Privilege;
pub use state::ExpectedState;
pub use state::attribute;
pub use state::attribute::Attribute;
