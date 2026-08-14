<div align="center">
  <img src="regent-logo.png" alt="Regent" width="200" />
  <h1>Regent</h1>
  <p><em>Shape the tool for the job</em></p>

  [![Crates.io](https://img.shields.io/crates/v/regent-sdk.svg)](https://crates.io/crates/regent-sdk)
  [![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)
  [![Rust](https://img.shields.io/badge/rust-2024%20Edition-green.svg)](https://www.rust-lang.org/)
  [![Docs.rs](https://docs.rs/regent-sdk/badge.svg)](https://docs.rs/regent-sdk)
  [![Discord](https://img.shields.io/badge/Discord-Join%20our%20server-5865F2?logo=discord&logoColor=white)](https://discord.gg/2gxAW7uzsx)
  
  <p><strong>Multi-paradigm configuration management library for Rust</strong></p>
</div>

---

## Table of Contents

- [What is Regent?](#what-is-regent)
- [Core Concepts](#core-concepts)
- [Features](#features)
- [Capabilities](#capabilities)
- [Quick Start](#quick-start)
- [Installation](#installation)
- [Usage](#usage)
  - [YAML API](#yaml-api)
  - [Rust API](#rust-api)
- [Attribute Categories](#attribute-categories)
- [Connection Methods](#connection-methods)
- [Use Cases](#use-cases)
- [Secret Management](#secret-management)
- [Task Distribution](#task-distribution)
- [Contributing](#contributing)
- [License](#license)

---

## What is Regent?

A **multi-paradigm configuration management system as a library**.

Regent SDK provides an engine for declarative configuration management, allowing you to define expected system states and automatically assess or remedy compliance. Because it's an engine, you embed it in your own solution — whether that's an all-in-one CLI tool, a distributed system with control nodes and workers, a monitoring system feeding a web interface, or an agent fetching remote configuration — whatever suits your needs and constraints.

> **Note:** While inspired by Ansible in several ways, Regent does not aim to reproduce its API or behaviors.

## Core Concepts

Regent is built around three key concepts:

- **Expected State**: The desired configuration of your system, defined via [`ExpectedState`](https://docs.rs/regent-sdk/latest/regent_sdk/struct.ExpectedState.html)
- **Attributes**: Building blocks that describe that state (see [`attribute`](https://docs.rs/regent-sdk/latest/regent_sdk/state/attribute/index.html) module)
- **Compliance**: Whether a host matches its expected state, with methods to **assess** or **enforce** it
---

## Features

Enable the following Cargo features for additional capabilities:

- `aws-secretsmanager`: Enable AWS Secrets Manager support via `SecretProvider::aws_secretsmanager`
- `gcp-secretmanager`: Enable Google Cloud Secret Manager support via `SecretProvider::gcp_secretmanager`
- `windows`: Enable Windows support, including Windows OS detection, command execution, and service management

## Capabilities

- **Declarative State Management**: Define infrastructure as code using [`ExpectedState`](https://docs.rs/regent-sdk/latest/regent_sdk/struct.ExpectedState.html) and [`Attribute`](https://docs.rs/regent-sdk/latest/regent_sdk/state/attribute/index.html)
- **Multi-Protocol Host Management**: Connect to hosts via [`Ssh2HostHandler`](https://docs.rs/regent-sdk/latest/regent_sdk/hosts/handlers/ssh2/struct.Ssh2HostHandler.html) or [`LocalHostHandler`](https://docs.rs/regent-sdk/latest/regent_sdk/hosts/handlers/localhost/struct.LocalHostHandler.html)
- **Comprehensive Resource Modules**: Manage packages, services, users, groups, cron jobs, files, iptables, and more
- **Secret Management**: Secure secret retrieval from multiple providers using [`SecretProvidersPoolBuilder`](https://docs.rs/regent-sdk/latest/regent_sdk/struct.SecretProvidersPoolBuilder.html)
- **Task Distribution**: Serializable tasks for distributed workload execution using [`RegentTask`](https://docs.rs/regent-sdk/latest/regent_sdk/task/struct.RegentTask.html) and [`Job`](https://docs.rs/regent-sdk/latest/regent_sdk/task/enum.Job.html)
- **Compliance Engine**: Automatic assessment and remediation via [`ManagedHost::assess_compliance`](https://docs.rs/regent-sdk/latest/regent_sdk/hosts/managed_host/struct.ManagedHost.html#method.assess_compliance) and [`ManagedHost::reach_compliance`](https://docs.rs/regent-sdk/latest/regent_sdk/hosts/managed_host/struct.ManagedHost.html#method.reach_compliance)
- **Idempotent Operations**: All operations are designed to be idempotent
- **Templating Support**: Variable substitution using Tera templates

---

## Quick Start

Ready to try Regent? With the core concepts of **expected state**, **attributes**, and **compliance**, you can assess or enforce configuration across your infrastructure in minutes.

---

## Installation

Add Regent to your `Cargo.toml`:

```toml
[dependencies]
regent-sdk = "0.8.3"
```

Enable features for secret providers as needed:

```toml
[dependencies]
regent-sdk = { version = "0.8.3", features = ["aws-secretsmanager", "gcp-secretmanager"] }
```

---

## Usage

### YAML API

Define your infrastructure declaratively with YAML:

```rust
#[tokio::main]
async fn main() {
    tracing_subscriber::fmt().init();

    // Define inventory
    let yaml_inventory = r#"---
DefaultConnectionMethod: !Localhost
    UserKind: !CurrentUser
Hosts:
  - Id: my_managed_host
    Endpoint: localhost
"#;

    let mut inventory = Inventory::from_raw_yaml(yaml_inventory).unwrap();

    // Define expected state
    let expected_state = r#"---
Attributes:
  - Name: token value set in conf file
    Privilege: !None
    Detail: !LineInFile
      FilePath: ~/my_token
      Line: !Raw !Secret arn:aws:secretsmanager:eu-central-1:658712556498:secret:MY_TOKEN_CONTENT-xyz
      State: !Present
        Position: !InsertBefore BOF
"#;

    let expected_state = ExpectedState::from_raw_yaml(expected_state).unwrap();

    // Build secret providers pool
    let config_aws = aws_config::load_from_env().await;
    let secrets_providers_pool = SecretProvidersPoolBuilder::new()
        .add_default_provider("aws", SecretProvider::aws_secretsmanager(config_aws))
        .build()
        .unwrap();

    // Initialize and reach compliance
    let mut living_inventory = inventory.init(Some(secrets_providers_pool)).await.unwrap();
    living_inventory.reach_compliance(&expected_state).await.unwrap();
}
```

### Rust API

Build your infrastructure programmatically:

```rust
#[tokio::main]
async fn main() {
    // Build managed host
    let mut managed_host = ManagedHostBuilder::new(
        "<host-id>",
        "<host-endpoint>:<port>",
        Some(ConnectionMethod::Localhost(TargetUser::current_user())),
    )
    .build(None)
    .await
    .unwrap();

    managed_host.connect().await.unwrap();

    // Define expected state programmatically
    let apache_expected_state = AptBlockExpectedState::package_state(
        "apache2", 
        PackageExpectedState::Present
    );

    let expected_state = ExpectedState::new()
        .with_attribute(Attribute::apt(
            apache_expected_state,
            Privilege::WithSudo,
            None,
        ))
        .build();

    // Assess and reach compliance
    if let Ok(compliance_status) = managed_host.assess_compliance(&expected_state).await {
        if !compliance_status.is_already_compliant() {
            managed_host.reach_compliance(&expected_state).await.unwrap();
        }
    }
}
```

---

## Attribute Categories

Available attribute modules for defining expected state:

- **[`attribute::system`](https://docs.rs/regent-sdk/latest/regent_sdk/state/attribute/system/index.html)**: System resources (services, users, groups, cron, hostname)
- **[`attribute::package`](https://docs.rs/regent-sdk/latest/regent_sdk/state/attribute/package/index.html)**: Package management (apt, yum/dnf, pacman, repositories)
- **[`attribute::network`](https://docs.rs/regent-sdk/latest/regent_sdk/state/attribute/network/index.html)**: Network configuration (iptables)
- **[`attribute::shell`](https://docs.rs/regent-sdk/latest/regent_sdk/state/attribute/shell/index.html)**: Shell commands
- **[`attribute::utilities`](https://docs.rs/regent-sdk/latest/regent_sdk/state/attribute/utilities/index.html)**: Utilities (line in file, debug, ping)
- **[`attribute::ai`](https://docs.rs/regent-sdk/latest/regent_sdk/state/attribute/ai/index.html)**: AI integration (Ollama)

## Connection Methods

Connect to hosts using:

- **[`hosts::handlers::localhost::LocalHostHandler`](https://docs.rs/regent-sdk/latest/regent_sdk/hosts/handlers/localhost/struct.LocalHostHandler.html)**: Execute on the local machine
- **[`hosts::handlers::ssh2::Ssh2HostHandler`](https://docs.rs/regent-sdk/latest/regent_sdk/hosts/handlers/ssh2/struct.Ssh2HostHandler.html)**: Connect to remote hosts via SSH2

---

## Use Cases

Regent integrates seamlessly with the Rust ecosystem:

- **CLI Tools** - Wrap with [clap](https://docs.rs/clap) for configuration management commands
- **Massive Scale** - Use tokio to handle thousands of hosts concurrently
- **Distributed Systems** - Serialize tasks, send via HTTP/gRPC/RabbitMQ, execute on worker nodes
- **Observability** - Run compliance checks in [axum](https://docs.rs/axum) health endpoints
- **Monitoring Integration** - Plug into Centreon, Nagios, Zabbix for regular health checks

---

## Secret Management

Securely retrieve secrets from:

- **Local**: Files and environment variables
- **Cloud**: AWS Secrets Manager, Google Cloud Secret Manager (enable via features)

See [`SecretProvidersPoolBuilder`](https://docs.rs/regent-sdk/latest/regent_sdk/struct.SecretProvidersPoolBuilder.html) for configuration options.

## Task Distribution

Create serializable tasks for distributed execution:

```rust
use regent_sdk::{Job, RegentTask};

let task = RegentTask::from(managed_host_builder, expected_state, Job::Assess);
let serialized = serde_json::to_string(&task).unwrap();
let mut task: RegentTask = serde_json::from_str(&serialized).unwrap();
let result = task.run(Some(secrets_pool)).await.unwrap();
```

---

## Contributing

We welcome contributions! The project needs help with:

- **New Secret Providers**: Hashicorp Vault, Delinea SecretServer, Azure Key Vault, or any other secure backend
- **New Attributes**: Expand coverage for network management (nftables, firewalld), additional package managers, container orchestration, or cloud resource management
- **Documentation**: Tutorials, real-world examples, and deeper API documentation
- **Testing**: More comprehensive test coverage, especially for edge cases and multi-host scenarios
- **Performance**: Benchmarks, optimizations for large-scale deployments

**Join our community:** [Regent Discord](https://discord.gg/2gxAW7uzsx)

---

## License

Regent is licensed under the [Apache License, Version 2.0](LICENSE).

