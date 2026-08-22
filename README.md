<div align="center">
  <img src="regent-logo.png" alt="Regent" width="200" />
  <h1>Regent</h1>
  <p><em>Where configuration management meets Rust's type system</em></p>

  [![Crates.io](https://img.shields.io/crates/v/regent-sdk.svg)](https://crates.io/crates/regent-sdk)
  [![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)
  [![Rust](https://img.shields.io/badge/rust-2024%20Edition-green.svg)](https://www.rust-lang.org/)
  [![Discord](https://img.shields.io/badge/Discord-Join%20our%20server-5865F2?logo=discord&logoColor=white)](https://discord.gg/2gxAW7uzsx)

</div>


## Table of Contents

- [What is Regent?](#what-is-regent)
- [Core principles](#core-principles)
- [Available crate features](#available-crate-features)
- [Usage](#usage)
  - [YAML API](#yaml-api)
  - [Rust API](#rust-api)
- [Attribute Categories](#attribute-categories)
- [Use Cases](#use-cases)
- [Task Distribution](#task-distribution)
- [Contributing](#contributing)
- [License](#license)


## What is Regent?

A **multi-paradigm configuration management system as a library**.

Regent SDK provides an engine for declarative configuration management, allowing you to define expected system states and automatically assess or remedy compliance. Because it's an engine, you embed it in your own solution — an all-in-one CLI tool, a distributed system with control nodes and workers, a monitoring system feeding a web interface, or an agent fetching remote configuration — whatever suits you !


## Core principles

Regent is built around three key concepts:

- **Expected State**: The desired configuration of your system, defined via [`ExpectedState`](https://docs.rs/regent-sdk/latest/regent_sdk/struct.ExpectedState.html)
- **Attributes**: Building blocks that describe that state (see [`attribute`](https://docs.rs/regent-sdk/latest/regent_sdk/state/attribute/index.html) module)
- **Compliance**: Whether a host matches its expected state, with methods to **assess** or **enforce** it

On top of these concepts, Regent is developped with the following goals in mind :
- **Declarative State Management**: Describe the expected state of a host using [`ExpectedState`](https://docs.rs/regent-sdk/latest/regent_sdk/struct.ExpectedState.html) and [`Attribute`](https://docs.rs/regent-sdk/latest/regent_sdk/state/attribute/index.html). Regent is not a scripting tool.
- **Idempotency when possible**: All operations are designed to be idempotent, meaning a strong focus on the initial assessment of the host's state. However some operations can't be idempotent by nature (a shell command).
- **Multi-Protocol Host Connection**: Regent can connect to hosts using SSH2 or direct access (localhost) so nothing new for now but we abstracted away the connection protocol and we intend to add more protocols and ways to connect to hosts (like this [cool project](https://github.com/h4sh5/sshoq))
- **Secret Management**: For secrets, we rely on modern specialized platforms instead. Regent has the [`SecretProvider`](https://docs.rs/regent-sdk/latest/regent_sdk/secrets/enum.SecretProvider.html) abstraction for this.
- **Task Distribution**: Workload can be sent through the wire (serialized/deserialized) using the [`RegentTask`](https://docs.rs/regent-sdk/latest/regent_sdk/task/struct.RegentTask.html) type. Build a RegentTask, send it to someone else to be executed then get back the outcome. Lots of possibilities here !
- **Templating Support**: Variable substitution using [Tera](https://docs.rs/tera/latest/tera/) templates


## Available crate features
Enable the following Cargo features for additional capabilities: `cargo add regent-sdk -F <feature>`

- `aws-secretsmanager`: dynamically retrieve secrets from AWS Secrets Manager
- `gcp-secretmanager`: dynamically retrieve secrets from Google Cloud Secret Manager
- `windows`: Enable Windows support (not every attribute will be compatible, see [Usage](#usage))


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

## Attribute Categories

Available attribute modules for defining expected state:

- **[`system`](https://docs.rs/regent-sdk/latest/regent_sdk/state/attribute/system/index.html)**: System resources (services, users, groups, cron, hostname)
- **[`package`](https://docs.rs/regent-sdk/latest/regent_sdk/state/attribute/package/index.html)**: Package management (apt, yum/dnf, pacman, repositories)
- **[`network`](https://docs.rs/regent-sdk/latest/regent_sdk/state/attribute/network/index.html)**: Network configuration (iptables)
- **[`shell`](https://docs.rs/regent-sdk/latest/regent_sdk/state/attribute/shell/index.html)**: Shell commands
- **[`utilities`](https://docs.rs/regent-sdk/latest/regent_sdk/state/attribute/utilities/index.html)**: Utilities (line in file, debug, ping)
- **[`ai`](https://docs.rs/regent-sdk/latest/regent_sdk/state/attribute/ai/index.html)**: AI integration (Ollama)


## Use Cases

Regent integrates seamlessly with the Rust ecosystem:

- **CLI Tools** - Wrap with [clap](https://docs.rs/clap) for configuration management commands
- **Massive Scale** - Use tokio to handle thousands of hosts concurrently
- **Distributed Systems** - Serialize tasks, send via HTTP/gRPC/RabbitMQ, execute on worker nodes
- **Observability** - Run compliance checks in [axum](https://docs.rs/axum) health endpoints
- **Monitoring Integration** - Plug into Centreon, Nagios, Zabbix for regular health checks


## Contributing

We welcome contributions! The project needs help with:

- **New Secret Providers**: Hashicorp Vault, Delinea SecretServer, Azure Key Vault, or any other secure backend
- **New Attributes**: Expand coverage for network management (nftables, firewalld), additional package managers, container orchestration, or cloud resource management
- **Documentation**: Tutorials, real-world examples, and deeper API documentation
- **Testing**: More comprehensive test coverage, especially for edge cases and multi-host scenarios
- **Performance**: Benchmarks, optimizations for large-scale deployments

**Join the conversation** [Regent Discord](https://discord.gg/2gxAW7uzsx)


## License

Regent is licensed under the [Apache License, Version 2.0](LICENSE).

