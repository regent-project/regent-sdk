<div style="display: flex; align-items: center; gap: 30px;">
  <img src="regent-logo.png" alt="Regent" width="200" style="margin-bottom: 10px;" />
  <div>
    <h1>Regent</h1>
    <p><em>Shape the tool for the job</em></p>
  </div>
</div>

***Regent*** is a multi-paradigm configuration management library for Rust. By embedding a generic automation engine in your codebase, you leverage Rust's type system, fearless concurrency, and rich ecosystem to industrialize automation, configuration management, and self-remediation at scale.

*Note: While inspired by Ansible, Regent does not aim to reproduce its API or behaviors. Also, as a multi-paradigm library, you're free to implement agent/agent-less, autonomous/centralized, push/pull models — whatever fits your use case.*

## Key Regent Principles

At its core, Regent is built around a very straightforward approach: **expected state** (the desired configuration of your system), **attributes** (the building blocks that describe that state), and **compliance** (whether a host matches its expected state or not). When you use Regent, you can **assess** if a host is compliant or you can **enforce** it.

Available attributes :
| Category | Attribute | Description |
|---|---|---|
| **Package Management** | [Apt](https://docs.rs/regent-sdk/latest/regent_sdk/state/attribute/package/apt/index.html) | Debian/Ubuntu package management |
| | [YumDnf](https://docs.rs/regent-sdk/latest/regent_sdk/state/attribute/package/yumdnf/index.html) | RHEL/CentOS package management |
| | [Pacman](https://docs.rs/regent-sdk/latest/regent_sdk/state/attribute/package/pacman/index.html) | Arch Linux package management |
| | [AptRepo](https://docs.rs/regent-sdk/latest/regent_sdk/state/attribute/package/apt_repo/index.html) | APT repository configuration |
| | [DnfRepo](https://docs.rs/regent-sdk/latest/regent_sdk/state/attribute/package/dnf_repo/index.html) | DNF repository configuration |
| **System** | [Service](https://docs.rs/regent-sdk/latest/regent_sdk/state/attribute/system/service/index.html) | System service management (start/stop/enable/disable) |
| | [User](https://docs.rs/regent-sdk/latest/regent_sdk/state/attribute/system/user/index.html) | User account management |
| | [Group](https://docs.rs/regent-sdk/latest/regent_sdk/state/attribute/system/group/index.html) | Group management |
| | [Cron](https://docs.rs/regent-sdk/latest/regent_sdk/state/attribute/system/cron/index.html) | Cron job management |
| | [Hostname](https://docs.rs/regent-sdk/latest/regent_sdk/state/attribute/system/hostname/index.html) | Hostname configuration |
| **Network** | [Iptables](https://docs.rs/regent-sdk/latest/regent_sdk/state/attribute/network/iptables/index.html) | Firewall rule management |
| **Shell** | [Command](https://docs.rs/regent-sdk/latest/regent_sdk/state/attribute/shell/command/index.html) | Arbitrary command execution |
| **Utilities** | [LineInFile](https://docs.rs/regent-sdk/latest/regent_sdk/state/attribute/utilities/lineinfile/index.html) | Line insertion/removal in files |
| | [Ping](https://docs.rs/regent-sdk/latest/regent_sdk/state/attribute/utilities/ping/index.html) | Connectivity checks between Regent and hosts (network, authentication) |
| | [Debug](https://docs.rs/regent-sdk/latest/regent_sdk/state/attribute/utilities/debug/index.html) | Debug message output |
| **AI** | [Ollama](https://docs.rs/regent-sdk/latest/regent_sdk/state/attribute/ai/ollama/index.html) | Ollama API integration for AI model management |

## Why Regent?

**Type Safety Meets System Management**
Regent puts Rust's powerful type system to work in infrastructure automation. Define your expected state with compile-time guarantees, eliminating entire classes of configuration errors before they reach production.

**Async by Default**
Built on tokio, Regent executes operations in parallel when possible. Handle thousands of hosts concurrently without fighting with threads or callbacks.

**Observable by Design**
Full tracing instrumentation means every operation, every connection, and every state change is observable. Integrate seamlessly with your existing monitoring and logging infrastructure.

**Secure Secret Management**
Never hardcode secrets. Regent's SecretProvider abstraction dynamically retrieves credentials at runtime from environment variables, files, AWS Secrets Manager, GCP Secret Manager, with more providers coming soon.

**Flexible as Your Use Case**
As a library, not a framework, Regent adapts to you. Need a CLI tool? Wrap it with clap. Distributing work? Serialize your tasks and ship them anywhere. Making hosts observable? Put a compliance check behind an axum endpoint.

## Two Ways to Use Regent
### The YAML API

```rust
#[tokio::main]
async fn main() {
    tracing_subscriber::fmt().init();

    // Define your inventory
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

    // Build your secret providers pool
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
### The Rusty API
```rust
#[tokio::main]
async fn main() {
    // Build your managed host
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
    let apache_expected_state = AptBlockExpectedState::package_state("apache2", PackageExpectedState::Present);

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

## Use Cases

Regent integrates with the Rust ecosystem you already know:

- **CLI Tools**: Wrap with [clap](https://docs.rs/clap) for configuration management commands
- **Massive Scale**: Use tokio to handle thousands of hosts concurrently
- **Distributed Systems**: Serialize tasks, send via HTTP/gRPC/RabbitMQ, execute on worker nodes
- **Observability**: Run compliance checks in [axum](https://docs.rs/axum) health endpoints
- **Monitoring Integration**: Plug into Centreon, Nagios, Zabbix for regular health checks

## Secret Providers

Regent never hardcodes secrets. The SecretProvider abstraction dynamically retrieves credentials at runtime from:
- [x] Environment variables
- [x] Files
- [x] AWS Secrets Manager
- [x] GCP Secret Manager
- [ ] Hashicorp Vault
- [ ] Delinea SecretServer (Thycotic)

## Contributing

We welcome contributions! The project needs help with:
- **New secret providers**: Hashicorp Vault, Delinea SecretServer, Azure Key Vault, or any other secure backend
- **New attributes**: Expand coverage for network management (nftables, firewalld), additional package managers, container orchestration, or cloud resource management
- **Documentation**: Tutorials, real-world examples, and deeper API documentation
- **Testing**: More comprehensive test coverage, especially for edge cases and multi-host scenarios
- **Performance**: Benchmarks, optimizations for large-scale deployments



Join our Discord: [Regent project](https://discord.gg/2gxAW7uzsx)

