//! Fluent Bit attribute
//!
//! This module provides the `FluentBitExpectedState` type for installing the
//! [Fluent Bit](https://docs.fluentbit.io) log collector and forwarder from its official package
//! repository (`https://packages.fluentbit.io`) and managing its configuration.
//!
//! **Compatible OS:** Linux distributions with an official Fluent Bit repository: Debian,
//! Ubuntu (and derivatives), CentOS, Rocky Linux, AlmaLinux, RHEL and Oracle Linux (through the
//! Rocky Linux packages) and Amazon Linux. The repository is picked from `/etc/os-release` at
//! assessment time.
//!
//! **Privilege:** installing packages and writing to `/etc` needs root, use `!WithSudo`.
//!
//! # How compliance is assessed
//!
//! 1. The Fluent Bit repository must be configured (`/etc/apt/sources.list.d/fluent-bit.list`
//!    and its signing key for apt, `/etc/yum.repos.d/fluent-bit.repo` for dnf). It is never
//!    removed by this attribute.
//! 2. The `fluent-bit` package must be installed. With `Version`, in that version (upgraded or
//!    downgraded). Without it, it is installed once and not upgraded afterwards.
//! 3. `Config`, if set, is the whole main configuration file, in the classic format
//!    (`/etc/fluent-bit/fluent-bit.conf`) or the YAML one (`/etc/fluent-bit/fluent-bit.yaml`).
//!    A systemd drop-in (`/etc/systemd/system/fluent-bit.service.d/regent.conf`) makes the
//!    service read that file. A running service is restarted when either changes. Other files
//!    (parsers, Lua scripts...) can be managed with the `Template` or `LineInFile` attributes.
//!
//! `Absent` removes the package and the drop-in, but keeps the repository.
//!
//! Whether Fluent Bit runs is managed by the `Service` attribute (unit `fluent-bit`).
//!
//! **Prerequisites:** `curl` (or `wget`) and, for apt, `gpg` to install the repository key.
//!
//! # Examples
//!
//! ## Rust API
//!
//! ```no_run
//! use regent_sdk::state::attribute::observability::fluentbit::{
//!     FluentBitConfig, FluentBitExpectedState,
//! };
//! use regent_sdk::state::attribute::system::service::ServiceExpectedState;
//! use regent_sdk::{Attribute, ExpectedState, Privilege, RegentError};
//!
//! fn log_shipping() -> Result<ExpectedState, RegentError> {
//!     let fluentbit = FluentBitExpectedState::present()
//!         .with_version("4.0.3".parse()?)
//!         .with_config(FluentBitConfig::yaml(
//!             r#"service:
//!   flush: 1
//! pipeline:
//!   inputs:
//!     - name: systemd
//!       tag: host.*
//!   outputs:
//!     - name: loki
//!       match: '*'
//!       host: loki.example.com
//!       port: 3100
//!       labels: job=fluentbit
//! "#,
//!         ));
//!
//!     Ok(ExpectedState::new()
//!         .with_attribute(Attribute::fluentbit(fluentbit, Privilege::WithSudo, None))
//!         .with_attribute(Attribute::service(
//!             ServiceExpectedState::started_and_enabled("fluent-bit"),
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
//!   - Name: Fluent Bit ships the journal to Loki
//!     Privilege: !WithSudo
//!     Detail: !FluentBit
//!       State: Present
//!       Version: '4.0.3'           # optional, pins the fluent-bit package
//!       Config:                    # optional, the configuration is left alone without it
//!         Format: Yaml             # Classic | Yaml
//!         Content: |
//!           service:
//!             flush: 1
//!           pipeline:
//!             inputs:
//!               - name: systemd
//!                 tag: host.*
//!             outputs:
//!               - name: loki
//!                 match: '*'
//!                 host: loki.example.com
//!                 port: 3100
//!   - Name: Fluent Bit runs
//!     Privilege: !WithSudo
//!     Detail: !Service
//!       Name: fluent-bit
//!       State: Started
//!       Enabled: true
//! ```
//!
//! To remove Fluent Bit:
//!
//! ```yaml
//! Attributes:
//!   - Name: Fluent Bit must be removed
//!     Privilege: !WithSudo
//!     Detail: !FluentBit
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
use crate::state::attribute::container::container_spec::quoted_command;
use crate::state::attribute::observability::{
    AgentRepository, AgentVersion, VersionChange, as_remediation_error, check_config_content,
    check_linux_host, file_content, install_package, systemctl, version_change,
    with_trailing_newline, write_unit_files,
};
use crate::state::attribute::shared::{
    OsRelease, PackageFamily, host_os_release, installed_packages, is_repository_configured,
    is_success, package_family, run_steps,
};
use crate::state::compliance::AttributeComplianceAssessment;
use serde::{Deserialize, Serialize};
use std::time::Duration;

const ATTRIBUTE: &str = "FluentBit";
const PACKAGE: &str = "fluent-bit";
const UNIT: &str = "fluent-bit";
const BINARY: &str = "/opt/fluent-bit/bin/fluent-bit";
const REPOSITORY_URL_FRAGMENT: &str = "packages.fluentbit.io";
const REPOSITORY_BASE_URL: &str = "https://packages.fluentbit.io";
const GPG_KEY_URL: &str = "https://packages.fluentbit.io/fluentbit.key";
const APT_KEYRING: &str = "/usr/share/keyrings/fluentbit-keyring.gpg";
const APT_LIST: &str = "/etc/apt/sources.list.d/fluent-bit.list";
const RPM_REPO_FILE: &str = "/etc/yum.repos.d/fluent-bit.repo";
const CLASSIC_CONFIG_FILE: &str = "/etc/fluent-bit/fluent-bit.conf";
const YAML_CONFIG_FILE: &str = "/etc/fluent-bit/fluent-bit.yaml";
const DROP_IN_FILE: &str = "/etc/systemd/system/fluent-bit.service.d/regent.conf";

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(
    tag = "State",
    rename_all = "PascalCase",
    rename_all_fields = "PascalCase",
    deny_unknown_fields
)]
pub enum FluentBitExpectedState {
    Present {
        version: Option<AgentVersion>,
        config: Option<FluentBitConfig>,
    },
    Absent,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub enum FluentBitConfigFormat {
    /// `[SERVICE]` / `[INPUT]` / `[OUTPUT]` sections
    Classic,
    Yaml,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[serde(rename_all = "PascalCase")]
pub struct FluentBitConfig {
    format: FluentBitConfigFormat,
    /// The whole main configuration file
    content: String,
}

impl FluentBitConfig {
    pub fn classic(content: &str) -> Self {
        Self {
            format: FluentBitConfigFormat::Classic,
            content: content.to_string(),
        }
    }

    pub fn yaml(content: &str) -> Self {
        Self {
            format: FluentBitConfigFormat::Yaml,
            content: content.to_string(),
        }
    }

    fn path(&self) -> &'static str {
        match self.format {
            FluentBitConfigFormat::Classic => CLASSIC_CONFIG_FILE,
            FluentBitConfigFormat::Yaml => YAML_CONFIG_FILE,
        }
    }

    fn file_content(&self) -> String {
        with_trailing_newline(&self.content)
    }

    /// The packaged unit reads `fluent-bit.conf`: the drop-in points it to the managed file
    fn drop_in_content(&self) -> String {
        format!(
            "[Service]\nExecStart=\nExecStart={} -c {}\n",
            BINARY,
            self.path()
        )
    }
}

impl Timeout for FluentBitExpectedState {
    fn default_timeout(&self) -> Duration {
        Duration::from_secs(600)
    }
}

impl FluentBitExpectedState {
    /// Fluent Bit installed, in any version, with its configuration left alone
    pub fn present() -> Self {
        FluentBitExpectedState::Present {
            version: None,
            config: None,
        }
    }

    pub fn absent() -> Self {
        FluentBitExpectedState::Absent
    }

    /// Pin the `fluent-bit` package to a version (no effect on `Absent`)
    pub fn with_version(mut self, expected_version: AgentVersion) -> Self {
        if let FluentBitExpectedState::Present { version, .. } = &mut self {
            *version = Some(expected_version);
        }
        self
    }

    /// Manage the main configuration file (no effect on `Absent`)
    pub fn with_config(mut self, expected_config: FluentBitConfig) -> Self {
        if let FluentBitExpectedState::Present { config, .. } = &mut self {
            *config = Some(expected_config);
        }
        self
    }
}

/// Official repository of the distribution, or why there is none
fn repository(os_release: &OsRelease, family: PackageFamily) -> Result<AgentRepository, String> {
    let ids: Vec<&str> = std::iter::once(os_release.id.as_str())
        .chain(os_release.id_like.iter().map(String::as_str))
        .collect();
    let unsupported = || {
        format!(
            "Fluent Bit publishes no package repository for {} {}",
            os_release.id, os_release.version_id
        )
    };
    match family {
        PackageFamily::Apt => {
            let (distribution, codename) = if ids.contains(&"ubuntu") {
                let codename = if os_release.ubuntu_codename.is_empty() {
                    &os_release.version_codename
                } else {
                    &os_release.ubuntu_codename
                };
                ("ubuntu", codename)
            } else if ids.contains(&"debian") {
                ("debian", &os_release.version_codename)
            } else {
                return Err(unsupported());
            };
            if codename.is_empty() {
                return Err(format!(
                    "{} has no VERSION_CODENAME in /etc/os-release: the Fluent Bit repository can't be picked",
                    os_release.id
                ));
            }
            Ok(AgentRepository::Apt {
                key_url: GPG_KEY_URL.to_string(),
                keyring: APT_KEYRING.to_string(),
                dearmor: true,
                list_file: APT_LIST.to_string(),
                source_line: format!(
                    "deb [signed-by={}] {}/{}/{} {} main",
                    APT_KEYRING, REPOSITORY_BASE_URL, distribution, codename, codename
                ),
            })
        }
        PackageFamily::Dnf => {
            // RHEL builds are not published: the binary compatible Rocky Linux ones are used
            let distribution = ids.iter().find_map(|id| match *id {
                "centos" => Some("centos"),
                "rocky" | "rhel" | "ol" => Some("rockylinux"),
                "almalinux" => Some("almalinux"),
                "amzn" => Some("amazonlinux"),
                _ => None,
            });
            let Some(distribution) = distribution else {
                return Err(unsupported());
            };
            // $releasever is not always the major version (e.g. 7Server): it is written out
            Ok(AgentRepository::RpmFile {
                repo_file: RPM_REPO_FILE.to_string(),
                content: format!(
                    "[fluent-bit]\nname=Fluent Bit\nbaseurl={}/{}/{}/\ngpgcheck=1\ngpgkey={}\nrepo_gpgcheck=1\nenabled=1\n",
                    REPOSITORY_BASE_URL,
                    distribution,
                    os_release.major_version(),
                    GPG_KEY_URL
                ),
            })
        }
        PackageFamily::Zypper => Err(unsupported()),
    }
}

impl Check for FluentBitExpectedState {
    fn check(&self) -> Result<(), RegentError> {
        match self {
            FluentBitExpectedState::Present {
                config: Some(config),
                ..
            } => check_config_content(ATTRIBUTE, &config.content),
            _ => Ok(()),
        }
    }

    fn check_host_compatibility(
        &self,
        host_properties: &HostProperties,
    ) -> Result<(), RegentError> {
        check_linux_host(host_properties, ATTRIBUTE)
    }
}

impl<Handler: HostHandler> AssessCompliance<Handler> for FluentBitExpectedState {
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

        let os_release = host_os_release(host_handler, privilege).await?;
        let Some(family) = package_family(&os_release) else {
            return Ok(AttributeComplianceAssessment::NonCompliantFatal(
                "the distribution (/etc/os-release) is not based on apt-get, dnf or zypper: Fluent Bit can't be installed".to_string(),
            ));
        };
        let installed = installed_packages(host_handler, family, &[PACKAGE], privilege).await?;

        let mut api_calls = Vec::new();
        match self {
            FluentBitExpectedState::Absent => {
                if installed.contains_key(PACKAGE) {
                    api_calls.push(FluentBitInternalApiCall::Remove { family });
                }
            }
            FluentBitExpectedState::Present { version, config } => {
                if !is_repository_configured(
                    host_handler,
                    family,
                    REPOSITORY_URL_FRAGMENT,
                    privilege,
                )
                .await?
                {
                    match repository(&os_release, family) {
                        Ok(repository) => {
                            api_calls.push(FluentBitInternalApiCall::AddRepository(repository))
                        }
                        Err(reason) => {
                            return Ok(AttributeComplianceAssessment::NonCompliantFatal(reason));
                        }
                    }
                }

                if let Some(change) =
                    version_change(installed.get(PACKAGE).map(String::as_str), version.as_ref())
                {
                    api_calls.push(FluentBitInternalApiCall::Install {
                        family,
                        version: version.clone(),
                        change,
                    });
                }

                if let Some(config) = config {
                    let current_config =
                        file_content(host_handler, config.path(), privilege).await?;
                    let current_drop_in =
                        file_content(host_handler, DROP_IN_FILE, privilege).await?;
                    if current_config.as_deref() != Some(config.file_content().as_str())
                        || current_drop_in.as_deref() != Some(config.drop_in_content().as_str())
                    {
                        api_calls.push(FluentBitInternalApiCall::WriteConfig(config.clone()));
                    }
                }
            }
        }

        if api_calls.is_empty() {
            return Ok(AttributeComplianceAssessment::Compliant);
        }
        let remediations = api_calls
            .into_iter()
            .map(|api_call| {
                Remediation::FluentBit(FluentBitApiCall::from(api_call, privilege.clone()))
            })
            .collect();
        Ok(AttributeComplianceAssessment::NonCompliant(
            RemediationsList::from(remediations)?,
        ))
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase", rename_all_fields = "PascalCase")]
pub enum FluentBitInternalApiCall {
    AddRepository(AgentRepository),
    /// Install, upgrade or downgrade the `fluent-bit` package
    Install {
        family: PackageFamily,
        version: Option<AgentVersion>,
        change: VersionChange,
    },
    /// Write the configuration file and the systemd drop-in, restart the service if running
    WriteConfig(FluentBitConfig),
    Remove {
        family: PackageFamily,
    },
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct FluentBitApiCall {
    pub api_call: FluentBitInternalApiCall,
    privilege: Privilege,
}

impl FluentBitApiCall {
    pub fn display(&self) -> String {
        match &self.api_call {
            FluentBitInternalApiCall::AddRepository(repository) => {
                format!("Add the Fluent Bit repository ({})", repository)
            }
            FluentBitInternalApiCall::Install {
                version: Some(version),
                change,
                ..
            } => format!("{} Fluent Bit {}", change, version),
            FluentBitInternalApiCall::Install { version: None, .. } => {
                "Install Fluent Bit".to_string()
            }
            FluentBitInternalApiCall::WriteConfig(config) => format!(
                "Write the Fluent Bit configuration {} and restart it if running",
                config.path()
            ),
            FluentBitInternalApiCall::Remove { .. } => "Remove Fluent Bit".to_string(),
        }
    }

    fn from(api_call: FluentBitInternalApiCall, privilege: Privilege) -> FluentBitApiCall {
        FluentBitApiCall {
            api_call,
            privilege,
        }
    }
}

impl Check for FluentBitApiCall {
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

impl<Handler: HostHandler> ReachCompliance<Handler> for FluentBitApiCall {
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
            FluentBitInternalApiCall::AddRepository(repository) => {
                repository.setup(host_handler, privilege).await
            }
            FluentBitInternalApiCall::Install {
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
            FluentBitInternalApiCall::WriteConfig(config) => {
                write_unit_files(
                    host_handler,
                    &[
                        (config.path(), &config.file_content()),
                        (DROP_IN_FILE, &config.drop_in_content()),
                    ],
                    UNIT,
                    "restart",
                    privilege,
                )
                .await
            }
            FluentBitInternalApiCall::Remove { family } => {
                let outcome = run_steps(
                    host_handler,
                    &[
                        family.remove_command(&[PACKAGE.to_string()]),
                        quoted_command(&["rm", "-f", DROP_IN_FILE]),
                        systemctl(&["daemon-reload"]),
                    ],
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
    use crate::state::attribute::shared::parse_os_release;

    #[test]
    fn parsing_fluentbit_module_block_from_yaml_str() {
        let raw = "---
State: Present
Version: '4.0.3'
Config:
  Format: Classic
  Content: |
    [INPUT]
        Name cpu
";
        let block: FluentBitExpectedState = yaml_serde::from_str(raw).unwrap();
        assert!(block.check().is_ok());
        assert_eq!(
            block,
            FluentBitExpectedState::present()
                .with_version("4.0.3".parse().unwrap())
                .with_config(FluentBitConfig::classic("[INPUT]\n    Name cpu\n"))
        );

        let block: FluentBitExpectedState = yaml_serde::from_str("---\nState: Present\n").unwrap();
        assert_eq!(block, FluentBitExpectedState::present());

        let block: FluentBitExpectedState = yaml_serde::from_str("---\nState: Absent\n").unwrap();
        assert_eq!(block, FluentBitExpectedState::absent());
    }

    #[test]
    fn rejecting_incorrect_fluentbit_module_block_from_yaml_str() {
        for raw in [
            "---\nState: Installed\n",
            "---\nState: Present\nVersion: latest\n",
            "---\nState: Present\nVersoin: '4.0.3'\n",
            "---\nState: Present\nConfig:\n  Format: Json\n  Content: x\n",
            "---\nState: Present\nConfig:\n  Content: x\n",
        ] {
            assert!(
                yaml_serde::from_str::<FluentBitExpectedState>(raw).is_err(),
                "{raw}"
            );
        }

        let empty_config: FluentBitExpectedState =
            yaml_serde::from_str("---\nState: Present\nConfig:\n  Format: Yaml\n  Content: '  '\n")
                .unwrap();
        assert!(empty_config.check().is_err());
    }

    #[test]
    fn parsing_full_fluentbit_attribute_envelope_from_yaml_str() {
        let raw_attribute = "---
Name: Fluent Bit ships logs
Privilege: !WithSudo
Detail: !FluentBit
  State: Present
  Config:
    Format: Yaml
    Content: |
      pipeline:
        inputs:
          - name: cpu
";
        let attribute: Attribute = yaml_serde::from_str(raw_attribute).unwrap();
        assert!(attribute.check().is_ok());
        assert_eq!(attribute.name(), "Fluent Bit ships logs");
    }

    #[test]
    fn serialization_round_trip_preserves_state() {
        let state = FluentBitExpectedState::present()
            .with_version("4.0.3".parse().unwrap())
            .with_config(FluentBitConfig::yaml("pipeline: {}\n"));
        let json = serde_json::to_string(&state).unwrap();
        assert_eq!(
            serde_json::from_str::<FluentBitExpectedState>(&json).unwrap(),
            state
        );
    }

    #[test]
    fn the_drop_in_points_the_service_to_the_managed_file() {
        assert_eq!(
            FluentBitConfig::yaml("x").drop_in_content(),
            "[Service]\nExecStart=\nExecStart=/opt/fluent-bit/bin/fluent-bit -c /etc/fluent-bit/fluent-bit.yaml\n"
        );
        assert_eq!(FluentBitConfig::classic("x").file_content(), "x\n");
    }

    #[test]
    fn repositories_follow_the_distribution() {
        let noble = parse_os_release(
            "ID=ubuntu\nID_LIKE=debian\nVERSION_ID=\"24.04\"\nVERSION_CODENAME=noble\n",
        );
        let AgentRepository::Apt { source_line, .. } =
            repository(&noble, PackageFamily::Apt).unwrap()
        else {
            panic!("expected an apt repository");
        };
        assert_eq!(
            source_line,
            "deb [signed-by=/usr/share/keyrings/fluentbit-keyring.gpg] https://packages.fluentbit.io/ubuntu/noble noble main"
        );

        let mint = parse_os_release(
            "ID=linuxmint\nID_LIKE=\"ubuntu debian\"\nVERSION_CODENAME=wilma\nUBUNTU_CODENAME=noble\n",
        );
        let AgentRepository::Apt { source_line, .. } =
            repository(&mint, PackageFamily::Apt).unwrap()
        else {
            panic!("expected an apt repository");
        };
        assert!(source_line.ends_with("/ubuntu/noble noble main"));

        let rhel = parse_os_release("ID=\"rhel\"\nID_LIKE=\"fedora\"\nVERSION_ID=\"9.4\"\n");
        let AgentRepository::RpmFile { content, .. } =
            repository(&rhel, PackageFamily::Dnf).unwrap()
        else {
            panic!("expected a .repo file");
        };
        assert!(content.contains("baseurl=https://packages.fluentbit.io/rockylinux/9/\n"));

        let fedora = parse_os_release("ID=fedora\nVERSION_ID=40\n");
        assert!(repository(&fedora, PackageFamily::Dnf).is_err());
        let sles = parse_os_release("ID=\"sles\"\nVERSION_ID=\"15.6\"\n");
        assert!(repository(&sles, PackageFamily::Zypper).is_err());
    }
}
