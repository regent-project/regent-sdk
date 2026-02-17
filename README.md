# Regent
*Adapt the tool to the job*

***Regent*** is a multi-paradigm configuration management system released as a library. It lets you embed a generic automation engine in any codebase that fits your use case. By leveraging Rust's powerful type system, fearless concurrency and rich ecosystem, ***regent*** allows you to industrialize automation, configuration management, and self-remediation systems at scale.

## Why
Very often, automation frameworks will impose their architecture on you and thus limit their scope. You will end up accepting blind spots and manual interventions at scale, adapting your infrastructure to meet the tool's requirements or finding "workarounds" which will become the norm over time (a cron job which runs a bash script which runs an ansible playbook which connects to...). And very often, you have to assemble a solution to your specific use case with a mixture of official tooling, custom scripting, creativity and a little bit of trickery. With ***regent***, we are not even trying to build another unicorn. Instead, we acknowledge that your use case is unique to you, so must be your solution. No more mixture and trickery - you build what you need, nothing more, nothing less.

## A couple use cases

***Regent*** integrates nicely with the rest of the ecosystem and with crates you already know.

- *Need a small CLI tool to run some configuration changes on a group of hosts?* Wrap **regent** with [clap](https://docs.rs/clap/latest/clap/).
- *Thousands of hosts to handle at once, no async allowed?* Build a Vec of **RegentTasks** and unleash [rayon](https://docs.rs/rayon/latest/rayon/) on it.
- *You want to distribute work?* [Serialize](https://docs.rs/serde/latest/serde/index.html) your **RegentTasks**, send them across a wire (http, gRPC, RabbitMQ...), and have them run by some worker node.
- *Make any host observable?* Have some [axum](https://docs.rs/axum/latest/axum/) handler behind a `/health` route run a ***regent*** compliance assessment on localhost and respond accordingly. Then have this host regularly checked by your external monitoring service (Centreon, Nagios, Zabbix...).


## Getting Started

Import ***regent*** to your Rust project
```bash
cargo add regent-sdk
```
Then start using it. The usual example: let's make sure a web server is running!
```rust
use regent_sdk::{ManagedHost, Privilege, Ssh2HostHandler};
use regent_sdk::{ExpectedState, Attribute};
use regent_sdk::attribute::system::service::{
    ServiceBlockExpectedState, ServiceExpectedAutoStart, ServiceExpectedStatus,
};

fn main() {
    // Describe the ManagedHost and how to connect to it
    let mut managed_host = ManagedHost::new(
        "<host-endpoint>:<port>",
        Ssh2HostHandler::key_file("regent-user", "<path/to/private/key>"),
    );

    // Open connection with this ManagedHost
    managed_host.connect().unwrap();

    // Describe the expected state of this host
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

    // Assess whether the host is compliant or not with this expected state
    match managed_host.assess_compliance(&expected_state) {
        Ok(compliance_status) => {
            if compliance_status.is_already_compliant() {
                println!("Congratulations, host is already compliant!");
            } else {
                println!(
                    "Oops! Host is not compliant. Here is the list of required remediations: {:#?}",
                    compliance_status.all_remediations()
                );

                // If not, try once to reach compliance
                match managed_host.reach_compliance(&expected_state) {
                    Ok(outcome) => {
                        println!(
                            "Try reach compliance outcome: {:#?}",
                            outcome.actions_taken()
                        );
                    }
                    Err(error_detail) => {
                        println!("Unable to try to reach compliance: {:#?}", error_detail);
                    }
                }
            }
        }
        Err(error_detail) => {
            println!("Failed to assess compliance: {:?}", error_detail);
        }
    }
}
```

## Contributing

We welcome contributions from the community! Whether it's bug fixes, new features, or documentation improvements, feel free to submit a pull request.

Join our Discord server to chat with other contributors: [Regent project](https://discord.gg/2gxAW7uzsx)