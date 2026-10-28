//! Grafana Alloy attribute
//!
//! This module provides the `AlloyExpectedState` type for installing
//! [Grafana Alloy](https://grafana.com/docs/alloy/) (Grafana's OpenTelemetry Collector
//! distribution, successor of Grafana Agent and Promtail) from Grafana's package repositories
//! and managing its configuration.
//!
//! **Compatible OS:** Linux distributions based on `apt-get`, `dnf` or `zypper` (detected from
//! `/etc/os-release` at assessment time).
//!
//! **Privilege:** installing packages and writing to `/etc` needs root, use `!WithSudo`.
//!
//! # How compliance is assessed
//!
//! 1. Grafana's repository must be configured (`https://apt.grafana.com` with its signing key
//!    for apt, `https://rpm.grafana.com` for dnf and zypper). It is never removed by this
//!    attribute.
//! 2. The `alloy` package must be installed. With `Version`, in that version (upgraded or
//!    downgraded). Without it, it is installed once and not upgraded afterwards.
//! 3. `Config`, if set, is the whole content of `/etc/alloy/config.alloy`. A running service is
//!    reloaded when it changes.
//! 4. `CustomArgs`, if set, are the command line flags of Alloy (e.g.
//!    `--server.http.listen-addr=0.0.0.0:12345` to expose its UI and metrics), written to its
//!    environment file (`/etc/default/alloy` for apt, `/etc/sysconfig/alloy` for dnf and zypper)
//!    along with `CONFIG_FILE="/etc/alloy/config.alloy"`. A running service is restarted when it
//!    changes.
//!
//! `Absent` removes the package, but keeps the repository.
//!
//! Whether Alloy runs is managed by the `Service` attribute (unit `alloy`).
//!
//! **Prerequisites:** `curl` (or `wget`) for apt, to download the repository key.
//!
//! # Examples
//!
//! ## Rust API
//!
//! ```no_run
//! use regent_sdk::state::attribute::observability::alloy::AlloyExpectedState;
//! use regent_sdk::state::attribute::system::service::ServiceExpectedState;
//! use regent_sdk::{Attribute, ExpectedState, Privilege, RegentError};
//!
//! fn grafana_agent() -> Result<ExpectedState, RegentError> {
//!     let alloy = AlloyExpectedState::present()
//!         .with_version("1.10.2".parse()?)
//!         .with_config(
//!             r#"prometheus.exporter.unix "host" { }
//!
//! prometheus.scrape "host" {
//!   targets    = prometheus.exporter.unix.host.targets
//!   forward_to = [prometheus.remote_write.mimir.receiver]
//! }
//!
//! prometheus.remote_write "mimir" {
//!   endpoint {
//!     url = "https://mimir.example.com/api/v1/push"
//!   }
//! }
//! "#,
//!         )
//!         .with_custom_args(&["--server.http.listen-addr=0.0.0.0:12345"]);
//!
//!     Ok(ExpectedState::new()
//!         .with_attribute(Attribute::alloy(alloy, Privilege::WithSudo, None))
//!         .with_attribute(Attribute::service(
//!             ServiceExpectedState::started_and_enabled("alloy"),
//!             Privilege::WithSudo,
//!             None,
//!         ))
//!         .build())
//! }
//! ```
//!
//! ## YAML API
//!
//! ```yaml
//! Attributes:
//!   - Name: Alloy sends the host metrics to Mimir
//!     Privilege: !WithSudo
//!     Detail: !Alloy
//!       State: Present
//!       Version: '1.10.2'          # optional, pins the alloy package
//!       CustomArgs:                # optional, the environment file is left alone without it
//!         - --server.http.listen-addr=0.0.0.0:12345
//!       Config: |                  # optional, the configuration is left alone without it
//!         prometheus.exporter.unix "host" { }
//!
//!         prometheus.scrape "host" {
//!           targets    = prometheus.exporter.unix.host.targets
//!           forward_to = [prometheus.remote_write.mimir.receiver]
//!         }
//!
//!         prometheus.remote_write "mimir" {
//!           endpoint {
//!             url = "https://mimir.example.com/api/v1/push"
//!           }
//!         }
//!   - Name: Alloy runs
//!     Privilege: !WithSudo
//!     Detail: !Service
//!       Name: alloy
//!       State: Started
//!       Enabled: true
//! ```
//!
//! To remove Alloy:
//!
//! ```yaml
//! Attributes:
//!   - Name: Alloy must be removed
//!     Privilege: !WithSudo
//!     Detail: !Alloy
//!       State: Absent
//! ```

use crate::error::RegentError;
use crate::hosts::managed_host::InternalApiCallOutcome;
use crate::hosts::managed_host::{AssessCompliance, ReachCompliance, Timeout};
use crate::hosts::properties::HostProperties;
use crate::secrets::SecretProvidersPool;
use crate::state::Check;
use crate::state::attribute::HostHandler;
use crate::state::attribute::Privilege;
use crate::state::attribute::Remediation;
use crate::state::attribute::RemediationsList;
use crate::state::attribute::observability::{
    AgentRepository, AgentVersion, VersionChange, as_remediation_error, check_config_content,
    check_linux_host, file_content, install_package, version_change, with_trailing_newline,
    write_unit_files,
};
use crate::state::attribute::shared::{
    PackageFamily, host_package_family, installed_packages, is_repository_configured, is_success,
    run_step,
};
use crate::state::compliance::AttributeComplianceAssessment;
use serde::{Deserialize, Serialize};
use std::time::Duration;

const ATTRIBUTE: &str = "Alloy";
const PACKAGE: &str = "alloy";
const UNIT: &str = "alloy";
const CONFIG_FILE: &str = "/etc/alloy/config.alloy";
const APT_REPOSITORY_URL_FRAGMENT: &str = "apt.grafana.com";
const RPM_REPOSITORY_URL_FRAGMENT: &str = "rpm.grafana.com";
const APT_KEY_URL: &str = "https://apt.grafana.com/gpg-full.key";
const APT_KEYRING: &str = "/etc/apt/keyrings/grafana.asc";
const APT_LIST: &str = "/etc/apt/sources.list.d/grafana.list";
const RPM_REPOSITORY_URL: &str = "https://rpm.grafana.com";
const RPM_KEY_URL: &str = "https://rpm.grafana.com/gpg.key";
const RPM_REPO_FILE: &str = "/etc/yum.repos.d/grafana.repo";
const ZYPPER_ALIAS: &str = "grafana";

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(
    tag = "State",
    rename_all = "PascalCase",
    rename_all_fields = "PascalCase",
    deny_unknown_fields
)]
pub enum AlloyExpectedState {
    Present {
        version: Option<AgentVersion>,
        /// Whole content of `/etc/alloy/config.alloy`
        config: Option<String>,
        /// Command line flags, written to `CUSTOM_ARGS` in the environment file
        custom_args: Option<Vec<String>>,
    },
    Absent,
}

impl Timeout for AlloyExpectedState {
    fn default_timeout(&self) -> Duration {
        Duration::from_secs(600)
    }
}

impl AlloyExpectedState {
    /// Alloy installed, in any version, with its configuration left alone
    pub fn present() -> Self {
        AlloyExpectedState::Present {
            version: None,
            config: None,
            custom_args: None,
        }
    }

    pub fn absent() -> Self {
        AlloyExpectedState::Absent
    }

    /// Pin the `alloy` package to a version (no effect on `Absent`)
    pub fn with_version(mut self, expected_version: AgentVersion) -> Self {
        if let AlloyExpectedState::Present { version, .. } = &mut self {
            *version = Some(expected_version);
        }
        self
    }

    /// Manage `/etc/alloy/config.alloy` (no effect on `Absent`)
    pub fn with_config(mut self, content: &str) -> Self {
        if let AlloyExpectedState::Present { config, .. } = &mut self {
            *config = Some(content.to_string());
        }
        self
    }

    /// Manage the command line flags of Alloy (no effect on `Absent`)
    pub fn with_custom_args(mut self, args: &[&str]) -> Self {
        if let AlloyExpectedState::Present { custom_args, .. } = &mut self {
            *custom_args = Some(args.iter().map(|arg| arg.to_string()).collect());
        }
        self
    }
}

fn repository(family: PackageFamily) -> AgentRepository {
    match family {
        PackageFamily::Apt => AgentRepository::Apt {
            key_url: APT_KEY_URL.to_string(),
            keyring: APT_KEYRING.to_string(),
            dearmor: false,
            list_file: APT_LIST.to_string(),
            source_line: format!(
                "deb [signed-by={}] https://apt.grafana.com stable main",
                APT_KEYRING
            ),
        },
        PackageFamily::Dnf => AgentRepository::RpmFile {
            repo_file: RPM_REPO_FILE.to_string(),
            content: format!(
                "[grafana]\nname=grafana\nbaseurl={}\nrepo_gpgcheck=1\nenabled=1\ngpgcheck=1\ngpgkey={}\nsslverify=1\n",
                RPM_REPOSITORY_URL, RPM_KEY_URL
            ),
        },
        PackageFamily::Zypper => AgentRepository::Zypper {
            url: RPM_REPOSITORY_URL.to_string(),
            alias: ZYPPER_ALIAS.to_string(),
        },
    }
}

fn repository_url_fragment(family: PackageFamily) -> &'static str {
    match family {
        PackageFamily::Apt => APT_REPOSITORY_URL_FRAGMENT,
        PackageFamily::Dnf | PackageFamily::Zypper => RPM_REPOSITORY_URL_FRAGMENT,
    }
}

fn environment_file(family: PackageFamily) -> &'static str {
    match family {
        PackageFamily::Apt => "/etc/default/alloy",
        PackageFamily::Dnf | PackageFamily::Zypper => "/etc/sysconfig/alloy",
    }
}

/// The packaged unit runs `alloy run $CUSTOM_ARGS ... $CONFIG_FILE`
fn environment_content(custom_args: &[String]) -> String {
    format!(
        "CONFIG_FILE=\"{}\"\nCUSTOM_ARGS=\"{}\"\nRESTART_ON_UPGRADE=true\n",
        CONFIG_FILE,
        custom_args.join(" ")
    )
}

impl Check for AlloyExpectedState {
    fn check(&self) -> Result<(), RegentError> {
        let AlloyExpectedState::Present {
            config,
            custom_args,
            ..
        } = self
        else {
            return Ok(());
        };
        if let Some(config) = config {
            check_config_content(ATTRIBUTE, config)?;
        }
        // CUSTOM_ARGS is split on whitespace by systemd and sits in a double-quoted value
        let invalid_arg = custom_args.iter().flatten().find(|arg| {
            arg.is_empty()
                || arg
                    .chars()
                    .any(|c| c.is_whitespace() || matches!(c, '"' | '\\' | '$' | '`'))
        });
        match invalid_arg {
            Some(arg) => Err(RegentError::IncoherentExpectedState(format!(
                "Alloy: invalid custom argument {:?}, an argument can't be empty nor contain whitespace, quotes, backslashes, $ or `",
                arg
            ))),
            None => Ok(()),
        }
    }

    fn check_host_compatibility(
        &self,
        host_properties: &HostProperties,
    ) -> Result<(), RegentError> {
        check_linux_host(host_properties, ATTRIBUTE)
    }
}

impl<Handler: HostHandler> AssessCompliance<Handler> for AlloyExpectedState {
    async fn assess_compliance(
        &self,
        host_handler: &mut Handler,
        host_properties: &Option<HostProperties>,
        privilege: &Privilege,
        _optional_secret_provider: &Option<SecretProvidersPool>,
    ) -> Result<AttributeComplianceAssessment, RegentError> {
        if let Some(props) = host_properties {
            self.check_host_compatibility(props)?;
        }

        let Some(family) = host_package_family(host_handler, privilege).await? else {
            return Ok(AttributeComplianceAssessment::NonCompliantFatal(
                "the distribution (/etc/os-release) is not based on apt-get, dnf or zypper: Alloy can't be installed".to_string(),
            ));
        };
        let installed = installed_packages(host_handler, family, &[PACKAGE], privilege).await?;

        let mut api_calls = Vec::new();
        match self {
            AlloyExpectedState::Absent => {
                if installed.contains_key(PACKAGE) {
                    api_calls.push(AlloyInternalApiCall::Remove { family });
                }
            }
            AlloyExpectedState::Present {
                version,
                config,
                custom_args,
            } => {
                if !is_repository_configured(
                    host_handler,
                    family,
                    repository_url_fragment(family),
                    privilege,
                )
                .await?
                {
                    api_calls.push(AlloyInternalApiCall::AddRepository(repository(family)));
                }

                if let Some(change) =
                    version_change(installed.get(PACKAGE).map(String::as_str), version.as_ref())
                {
                    api_calls.push(AlloyInternalApiCall::Install {
                        family,
                        version: version.clone(),
                        change,
                    });
                }

                if let Some(custom_args) = custom_args {
                    let path = environment_file(family);
                    let expected = environment_content(custom_args);
                    if file_content(host_handler, path, privilege)
                        .await?
                        .as_deref()
                        != Some(expected.as_str())
                    {
                        api_calls.push(AlloyInternalApiCall::WriteEnvironment {
                            path: path.to_string(),
                            content: expected,
                        });
                    }
                }

                if let Some(config) = config {
                    let expected = with_trailing_newline(config);
                    if file_content(host_handler, CONFIG_FILE, privilege)
                        .await?
                        .as_deref()
                        != Some(expected.as_str())
                    {
                        api_calls.push(AlloyInternalApiCall::WriteConfig { content: expected });
                    }
                }
            }
        }

        if api_calls.is_empty() {
            return Ok(AttributeComplianceAssessment::Compliant);
        }
        let remediations = api_calls
            .into_iter()
            .map(|api_call| Remediation::Alloy(AlloyApiCall::from(api_call, privilege.clone())))
            .collect();
        Ok(AttributeComplianceAssessment::NonCompliant(
            RemediationsList::from(remediations)?,
        ))
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase", rename_all_fields = "PascalCase")]
pub enum AlloyInternalApiCall {
    AddRepository(AgentRepository),
    /// Install, upgrade or downgrade the `alloy` package
    Install {
        family: PackageFamily,
        version: Option<AgentVersion>,
        change: VersionChange,
    },
    /// Write the environment file, restart the service if running
    WriteEnvironment {
        path: String,
        content: String,
    },
    /// Write `/etc/alloy/config.alloy`, reload the service if running
    WriteConfig {
        content: String,
    },
    Remove {
        family: PackageFamily,
    },
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AlloyApiCall {
    pub api_call: AlloyInternalApiCall,
    privilege: Privilege,
}

impl AlloyApiCall {
    pub fn display(&self) -> String {
        match &self.api_call {
            AlloyInternalApiCall::AddRepository(repository) => {
                format!("Add the Grafana repository ({})", repository)
            }
            AlloyInternalApiCall::Install {
                version: Some(version),
                change,
                ..
            } => format!("{} Alloy {}", change, version),
            AlloyInternalApiCall::Install { version: None, .. } => "Install Alloy".to_string(),
            AlloyInternalApiCall::WriteEnvironment { path, .. } => format!(
                "Write the Alloy command line flags to {} and restart it if running",
                path
            ),
            AlloyInternalApiCall::WriteConfig { .. } => format!(
                "Write the Alloy configuration {} and reload it if running",
                CONFIG_FILE
            ),
            AlloyInternalApiCall::Remove { .. } => "Remove Alloy".to_string(),
        }
    }

    fn from(api_call: AlloyInternalApiCall, privilege: Privilege) -> AlloyApiCall {
        AlloyApiCall {
            api_call,
            privilege,
        }
    }
}

impl Check for AlloyApiCall {
    fn check(&self) -> Result<(), RegentError> {
        Ok(())
    }

    fn check_host_compatibility(
        &self,
        host_properties: &HostProperties,
    ) -> Result<(), RegentError> {
        check_linux_host(host_properties, ATTRIBUTE)
    }
}

impl<Handler: HostHandler> ReachCompliance<Handler> for AlloyApiCall {
    async fn call(
        &self,
        host_handler: &mut Handler,
        host_properties: &Option<HostProperties>,
        _optional_secret_provider: &Option<SecretProvidersPool>,
    ) -> Result<InternalApiCallOutcome, RegentError> {
        if let Some(props) = host_properties {
            self.check_host_compatibility(props)?;
        }

        let privilege = &self.privilege;
        match &self.api_call {
            AlloyInternalApiCall::AddRepository(repository) => {
                repository.setup(host_handler, privilege).await
            }
            AlloyInternalApiCall::Install {
                family,
                version,
                change,
            } => {
                install_package(
                    host_handler,
                    *family,
                    PACKAGE,
                    version.as_ref(),
                    *change,
                    privilege,
                )
                .await
            }
            AlloyInternalApiCall::WriteEnvironment { path, content } => {
                write_unit_files(host_handler, &[(path, content)], UNIT, "restart", privilege).await
            }
            AlloyInternalApiCall::WriteConfig { content } => {
                write_unit_files(
                    host_handler,
                    &[(CONFIG_FILE, content)],
                    UNIT,
                    "reload",
                    privilege,
                )
                .await
            }
            AlloyInternalApiCall::Remove { family } => {
                let outcome = run_step(
                    host_handler,
                    &family.remove_command(&[PACKAGE.to_string()]),
                    privilege,
                )
                .await;
                if !is_success(&outcome) {
                    return Ok(outcome);
                }
                let installed = installed_packages(host_handler, *family, &[PACKAGE], privilege)
                    .await
                    .map_err(as_remediation_error)?;
                if installed.contains_key(PACKAGE) {
                    Ok(InternalApiCallOutcome::Failure(format!(
                        "{} is still installed after its removal",
                        PACKAGE
                    )))
                } else {
                    Ok(outcome)
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::attribute::Attribute;

    #[test]
    fn parsing_alloy_module_block_from_yaml_str() {
        let raw = "---
State: Present
Version: '1.10.2'
CustomArgs:
  - --server.http.listen-addr=0.0.0.0:12345
  - --stability.level=public-preview
Config: |
  prometheus.exporter.unix \"host\" { }
";
        let block: AlloyExpectedState = yaml_serde::from_str(raw).unwrap();
        assert!(block.check().is_ok());
        assert_eq!(
            block,
            AlloyExpectedState::present()
                .with_version("1.10.2".parse().unwrap())
                .with_config("prometheus.exporter.unix \"host\" { }\n")
                .with_custom_args(&[
                    "--server.http.listen-addr=0.0.0.0:12345",
                    "--stability.level=public-preview",
                ])
        );

        let block: AlloyExpectedState = yaml_serde::from_str("---\nState: Absent\n").unwrap();
        assert_eq!(block, AlloyExpectedState::absent());
    }

    #[test]
    fn rejecting_incorrect_alloy_module_block_from_yaml_str() {
        for raw in [
            "---\nState: Running\n",
            "---\nState: Present\nVersion: '1'\n",
            "---\nState: Present\nCustomArg: []\n",
            "---\nState: Present\nCustomArgs: --flag\n",
        ] {
            assert!(
                yaml_serde::from_str::<AlloyExpectedState>(raw).is_err(),
                "{raw}"
            );
        }

        for invalid_args in [&["--a b"][..], &["--a=\"b\""], &["--a=$HOME"], &[""]] {
            assert!(
                AlloyExpectedState::present()
                    .with_custom_args(invalid_args)
                    .check()
                    .is_err(),
                "{invalid_args:?}"
            );
        }
        assert!(
            AlloyExpectedState::present()
                .with_config("\n")
                .check()
                .is_err()
        );
    }

    #[test]
    fn parsing_full_alloy_attribute_envelope_from_yaml_str() {
        let raw_attribute = "---
Name: Alloy must be installed
Privilege: !WithSudo
Detail: !Alloy
  State: Present
  Config: |
    logging {
      level = \"info\"
    }
";
        let attribute: Attribute = yaml_serde::from_str(raw_attribute).unwrap();
        assert!(attribute.check().is_ok());
    }

    #[test]
    fn the_configuration_survives_templating() {
        let attribute = Attribute::alloy(
            AlloyExpectedState::present().with_config(
                "loki.source.journal \"journal\" {\n  labels = { job = \"journal\" }\n}\n",
            ),
            Privilege::WithSudo,
            None,
        );
        let rendered = attribute.consider_context(&tera::Context::new()).unwrap();
        assert_eq!(
            serde_json::to_string(&rendered).unwrap(),
            serde_json::to_string(&attribute).unwrap()
        );
    }

    #[test]
    fn the_environment_file_holds_the_custom_args() {
        assert_eq!(
            environment_content(&[
                "--server.http.listen-addr=0.0.0.0:12345".to_string(),
                "--disable-reporting".to_string(),
            ]),
            "CONFIG_FILE=\"/etc/alloy/config.alloy\"\nCUSTOM_ARGS=\"--server.http.listen-addr=0.0.0.0:12345 --disable-reporting\"\nRESTART_ON_UPGRADE=true\n"
        );
        assert_eq!(environment_file(PackageFamily::Apt), "/etc/default/alloy");
        assert_eq!(environment_file(PackageFamily::Dnf), "/etc/sysconfig/alloy");
    }
}
