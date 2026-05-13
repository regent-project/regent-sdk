# Regent
*Adapt the tool to the job*

***Regent*** is a multi-paradigm configuration management system released as a library. It lets you embed a generic automation engine in any codebase that fits your use case. By leveraging Rust's powerful type system, fearless concurrency and rich ecosystem, ***regent*** allows you to industrialize automation, configuration management, and self-remediation systems at scale.

## A few use cases

***Regent*** integrates nicely with the rest of the ecosystem and with crates you already know.

- *Need a small CLI tool to run some configuration changes on a group of hosts?* Wrap **regent** with [clap](https://docs.rs/clap/latest/clap/).
- *Thousands of hosts to handle ?* Leverage [tokio](https://docs.rs/tokio/latest/tokio/) and work concurrently or in parallel.
- *You want to distribute work?* [Serialize](https://docs.rs/serde/latest/serde/index.html) your **RegentTasks**, send them across a wire (http, gRPC, RabbitMQ...), and have them run by some worker node.
- *Make any host observable?* Have some [axum](https://docs.rs/axum/latest/axum/) handler behind a `/health` route run a ***regent*** compliance assessment on localhost and respond accordingly. Then have this host regularly checked by your external monitoring service (Centreon, Nagios, Zabbix...).


## 2 ways to use regent
### The YAML API

```rust
#[tokio::main]
async fn main() {
    tracing_subscriber::fmt().init();

    // Inventory as a raw YAML content
    let yaml_inventory_builder = r#"---
DefaultConnectionMethod: !Localhost
    UserKind: !CurrentUser

Hosts:
  - Id: my_managed_host
    Endpoint: localhost
"#;

    // Deserialize and check inventory coherence
    let mut inventory = Inventory::from_raw_yaml(yaml_inventory_builder).unwrap();

    // Expected state of the hosts
    let expected_state_description = r#"---
Attributes:
  - Name: token value set in conf file
    Privilege: !None
    Detail: !LineInFile
      FilePath: ~/my_token
      Line:
        SecRef: arn:aws:secretsmanager:eu-central-1:658712556498:secret:MY_TOKEN_CONTENT-xyz
      State: !Present
      Position: !Top
"#;

    // Deserialize and check expected state coherence
    let expected_state = ExpectedState::from_raw_yaml(expected_state_description).unwrap();

    // In many cases, we need a SecretProvider to retrieve secrets from (secrets to connect to managed hosts and secrets as part of the expected state). Here we are connecting to AWS Secretsmanager.
    let config_aws = aws_config::load_from_env().await;
    let secret_provider = SecretProvider::aws_secretsmanager(config_aws);

    // Now, out of the inventory (which is serializable), we actually do something. A "LivingInventory" is sensitive. It holds secrets, connections and progression. This is why it is distinct from the Inventory which is a static object.
    // First we initialize connections to hosts...
    let mut living_inventory = inventory.init(Some(secret_provider)).await.unwrap();

    // ... then we make hosts reach the expected state described earlier.
    living_inventory
        .reach_compliance(&expected_state)
        .await
        .unwrap();
}
```
### The Rusty API
```rust
#[tokio::main]
async fn main() {
    // Describe the ManagedHost
    let mut managed_host = ManagedHostBuilder::new(
        "<host-id>",
        "<host-endpoint>:<port>",
        Some(ConnectionMethod::Localhost(TargetUser::current_user())),
    )
    .build(None)
    .await
    .unwrap();

    // Open connection with this ManageHost
    assert!(managed_host.connect().is_ok());

    // Describe the expected state
    let apache_expected_state = AptBlockExpectedState::builder()
        .with_package_state("apache2", PackageExpectedState::Present)
        .build()
        .unwrap();

    let expected_state = ExpectedState::new()
        .with_attribute(Attribute::apt(
            apache_expected_state,
            Privilege::WithSudo,
            None,
        ))
        .build();

    // Assess whether the host is compliant or not
    match managed_host.assess_compliance(&expected_state).await {
        Ok(compliance_status) => {
            if compliance_status.is_already_compliant() {
                println!("Congratulations, host is already compliant !");
            } else {
                // If not, try once to reach compliance
                match managed_host.reach_compliance(&expected_state).await {
                    Ok(outcome) => {
                        println!(
                            "Try reach compliance outcome : {:#?}",
                            outcome.actions_taken()
                        );
                    }
                    Err(error_detail) => {
                        println!("Unable to try to reach compliance : {:#?}", error_detail);
                    }
                }
            }
        }
        Err(error_detail) => {
            println!("Failed to assess compliance : {:?}", error_detail);
        }
    }
}
```

## Why
Very often, automation frameworks will impose their architecture on you and thus limit their scope. You will end up accepting blind spots and manual interventions at scale, adapting your infrastructure to meet the tool's requirements or finding "workarounds" which will become the norm over time (a cron job which runs a bash script which runs an ansible playbook which connects to...). And very often, you have to assemble a solution to your specific use case with a mixture of official tooling, custom scripting, creativity and a little bit of trickery. With ***regent***, we are not even trying to build another unicorn. Instead, we acknowledge that your use case is unique to you, so must be your solution. No more mixture and trickery - you build what you need, nothing more, nothing less.

## Secrets management
As any other automation framework, regent will have to handle secrets. We don't try to store and manage secrets ourselves. We prefer to rely on the concept of *SecretProvider*. Regent will dynamically bind to an external source and retrieve secrets at runtime whenever needed. For the sake of abstraction, files and environment variables are considered external sources.

Secrets can be retrieved from :
- [x] Environment variables
- [x] Files
- [x] AWS Secretsmanager
- [x] GCP Secret Manager
- [ ] Hashicorp Vault
- [ ] Delinea SecretServer (Thycotic)


## Contributing

We welcome contributions from the community! Whether it's bug fixes, new features, or documentation improvements, feel free to submit a pull request.

Join our Discord server to chat with other contributors: [Regent project](https://discord.gg/2gxAW7uzsx)