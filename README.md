# Regent
*Adapt the tool to the job*

***Regent*** is a multi-paradigm configuration management system released as a library. It lets you embed a generic automation engine in any codebase that fits your use case. By leveraging Rust's powerful type system, fearless concurrency and rich ecosystem, ***regent*** allows you to industrialize automation, configuration management, and self-remediation systems at scale.

## A couple use cases

***Regent*** integrates nicely with the rest of the ecosystem and with crates you already know.

- *Need a small CLI tool to run some configuration changes on a group of hosts?* Wrap **regent** with [clap](https://docs.rs/clap/latest/clap/).
- *Thousands of hosts to handle at once, no async allowed?* Build a Vec of **RegentTasks** and unleash [rayon](https://docs.rs/rayon/latest/rayon/) on it.
- *You want to distribute work?* [Serialize](https://docs.rs/serde/latest/serde/index.html) your **RegentTasks**, send them across a wire (http, gRPC, RabbitMQ...), and have them run by some worker node.
- *Make any host observable?* Have some [axum](https://docs.rs/axum/latest/axum/) handler behind a `/health` route run a ***regent*** compliance assessment on localhost and respond accordingly. Then have this host regularly checked by your external monitoring service (Centreon, Nagios, Zabbix...).


## 2 ways to use regent
### The YAML API

```rust
let yaml_inventory_builder = r#"---
ConnectionMethod: !Ssh2
  AuthMethod: !Key
    Username: regenter
    Key:
      SecRef: /path/to/ssh/private.key

Hosts:
- Id: my_first_host
  Endpoint: <address:port>

- Id: my_second_host
  Endpoint: <address:port>
  ConnectionMethod: !Ssh2
    AuthMethod: !UsernamePassword
      SecRef: /path/to/credentials/secret
"#;

let inventory_builder = InventoryBuilder::from_raw_yaml(yaml_inventory_builder).unwrap();

let mut inventory = inventory_builder
    .build(&Some(SecretProvider::files()))
    .unwrap();

// Describe the expected state
let httpd_service_active_and_enabled = ServiceBlockExpectedState::builder("httpd")
    .with_service_state(ServiceExpectedStatus::Active)
    .with_autostart_state(ServiceExpectedAutoStart::Enabled)
    .build()
    .unwrap();

let localhost_expected_state = ExpectedState::new()
    .with_attribute(Attribute::service(
        httpd_service_active_and_enabled,
        Privilege::None,
    ))
    .build();

// Open connections within this Inventory
if let Err(details) = inventory.connect() {
    println!("Failed to connect to hosts : {:?}", details);
    std::process::exit(1);
}

// Assess whether the host is compliant or not
match inventory.reach_compliance(&localhost_expected_state) {
    Ok(inventory_comliance) => {
        for (host_id, compliance_status) in inventory_comliance {
            if compliance_status.is_already_compliant() {
                println!("Congratulations, {} is already compliant !", host_id);
            } else {
                println!(
                    "Oups ! {} is not compliant. Here is the list of required remediations :",
                    host_id
                );

                for remediation in compliance_status.all_remediations() {
                    println!("*** {:?}", remediation);
                }
            }
        }
    }
    Err(error_detail) => {
        println!("Failed to assess compliance : {:?}", error_detail);
    }
}
```
### The Rusty API
```rust
let secret_provider = SecretProvider::files();

// Describe the ManagedHost
let mut managed_host = ManagedHostBuilder::new("<host-id>", "<address:port>", Some(ConnectionMethod::Ssh2(Ssh2Auth::username_password(
        "/path/to/credentials/secret",
    ))))
    .build(&Some(secret_provider))
    .unwrap();

// Open connection with this ManageHost
assert!(managed_host.connect().is_ok());

// Describe the expected state
let httpd_service_active_and_enabled = ServiceBlockExpectedState::builder("httpd")
    .with_service_state(ServiceExpectedStatus::Active)
    .with_autostart_state(ServiceExpectedAutoStart::Enabled)
    .build()
    .unwrap();

let localhost_expected_state = ExpectedState::new()
    .with_attribute(Attribute::service(
        httpd_service_active_and_enabled,
        Privilege::None,
    ))
    .build();

// Assess whether the host is compliant or not
match managed_host.assess_compliance(&localhost_expected_state) {
    Ok(compliance_status) => {
        if compliance_status.is_already_compliant() {
            println!("Congratulations, host is already compliant !");
        } else {
            println!(
                "Oups ! Host is not compliant. Here is the list of required remediations :"
            );

            for remediation in compliance_status.all_remediations() {
                println!("*** {:?}", remediation);
            }
        }
    }
    Err(error_detail) => {
        println!("Failed to assess compliance : {:?}", error_detail);
    }
}
```

## Why
Very often, automation frameworks will impose their architecture on you and thus limit their scope. You will end up accepting blind spots and manual interventions at scale, adapting your infrastructure to meet the tool's requirements or finding "workarounds" which will become the norm over time (a cron job which runs a bash script which runs an ansible playbook which connects to...). And very often, you have to assemble a solution to your specific use case with a mixture of official tooling, custom scripting, creativity and a little bit of trickery. With ***regent***, we are not even trying to build another unicorn. Instead, we acknowledge that your use case is unique to you, so must be your solution. No more mixture and trickery - you build what you need, nothing more, nothing less.

## Secrets management
As any other automation framework, regent will have to handle secrets. For this part, regent doesn't try to store and manage secrets itself but relies on the concept of *SecretProvider*. This object is regent's binding with any external secrets management solution which implements the *SecretProvidingSolution* trait. That way, you can pass your credentials, keys, and any other kind of secrets to regent as environment variables or files, but you can also store all your secrets in solutions like AWS Secrets Manager, GCP Secret Manager, Hashicorp Vault or even inside the Linux Kernel Key Retention Service and have regent retrieve them dynamically when needed ! (these bindings are still to be implemented)


## Contributing

We welcome contributions from the community! Whether it's bug fixes, new features, or documentation improvements, feel free to submit a pull request.

Join our Discord server to chat with other contributors: [Regent project](https://discord.gg/2gxAW7uzsx)