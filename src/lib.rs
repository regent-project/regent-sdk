//! # Regent SDK
//!
//! A **multi-paradigm configuration management system as a library**.
//!
//! Regent SDK provides an engine for declarative configuration management, allowing you to define expected system states and automatically assess or remedy compliance. Because it's an engine, you embed it in your own solution — an all-in-one CLI tool, a distributed system with control nodes and workers, a monitoring system feeding a web interface, or an agent fetching remote configuration — whatever suits you !
//!
//! ## Core principles
//! 
//! Regent is built around three key concepts:
//! 
//! - **Expected State**: The desired configuration of your system, defined via [`ExpectedState`](https://docs.rs/regent-sdk/latest/regent_sdk/struct.ExpectedState.html)
//! - **Attributes**: Building blocks that describe that state (see [`attribute`](https://docs.rs/regent-sdk/latest/regent_sdk/state/attribute/index.html) module)
//! - **Compliance**: Whether a host matches its expected state, with methods to **assess** or **enforce** it
//! 
//! On top of these concepts, Regent is developped with the following goals in mind :
//! - **Declarative State Management**: Describe the expected state of a host using [`ExpectedState`](https://docs.rs/regent-sdk/latest/regent_sdk/struct.ExpectedState.html) and [`Attribute`](https://docs.rs/regent-sdk/latest/regent_sdk/state/attribute/index.html). Regent is not a scripting tool.
//! - **Idempotency when possible**: All operations are designed to be idempotent, meaning a strong focus on the initial assessment of the host's state. However some operations can't be idempotent by nature (a shell command).
//! - **Multi-Protocol Host Connection**: Regent can connect to hosts using SSH2 or direct access (localhost) so nothing new for now but we abstracted away the connection protocol and we intend to add more protocols and ways to connect to hosts (like this [cool project](https://github.com/h4sh5/sshoq))
//! - **Secret Management**: For secrets, we rely on modern specialized platforms instead. Regent has the [`SecretProvider`](https://docs.rs/regent-sdk/latest/regent_sdk/secrets/enum.SecretProvider.html) abstraction for this.
//! - **Task Distribution**: Workload can be sent through the wire (serialized/deserialized) using the [`RegentTask`](https://docs.rs/regent-sdk/latest/regent_sdk/task/struct.RegentTask.html) type. Build a RegentTask, send it to someone else to be executed then get back the outcome. Lots of possibilities here !
//! - **Templating Support**: Variable substitution using [Tera](https://docs.rs/tera/latest/tera/) templates
//! 
//! ## Available crate features
//! 
//! - `aws-secretsmanager`: dynamically retrieve secrets from AWS Secrets Manager
//! - `gcp-secretmanager`: dynamically retrieve secrets from Google Cloud Secret Manager
//! - `windows`: Enable Windows support (not every attribute will be compatible, see [Usage](#usage))
//! 
//!
//! ## Usage
//!
//! The primary workflow with Regent's Rust API:
//!
//! ```no_run
//! use regent_sdk::{Attribute, ConnectionMethod, ExpectedState, ManagedHostBuilder, Privilege};
//! use regent_sdk::{SecretProvider, SecretProvidersPoolBuilder, TargetUser};
//! use regent_sdk::attribute::system::service::{ServiceBlockExpectedState, ServiceExpectedState};
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
//!         Some(ConnectionMethod::Localhost(TargetUser::current_user())),
//!     )
//!     .build(Some(secrets_pool))
//!     .await
//!     .unwrap();
//!
//!     managed_host.connect().unwrap();
//!
//!     // 3. Define the expected state using attributes
//!     let nginx_service = ServiceBlockExpectedState::state("nginx", ServiceExpectedState::Started, true);
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

pub mod error;
pub mod hosts;
pub mod secrets;
pub mod state;
pub mod task;

pub use error::RegentError;
pub use hosts::handlers::localhost::{LocalHostHandler, WhichUser};
pub use hosts::handlers::ssh2::{Ssh2AuthMethod, Ssh2HostHandler};
pub use hosts::handlers::{ConnectionMethod, TargetUser};
pub use hosts::inventory::Inventory;
pub use hosts::managed_host::{ManagedHost, ManagedHostBuilder};
pub use hosts::privilege::Privilege;
pub use secrets::{SecretProvider, SecretProvidersPoolBuilder};
pub use state::ExpectedState;
pub use state::attribute;
pub use state::attribute::Attribute;
pub use task::{Job, RegentTask};
