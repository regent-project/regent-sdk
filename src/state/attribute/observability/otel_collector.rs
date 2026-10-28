//! OpenTelemetry Collector attribute
//!
//! This module provides the `OtelCollectorExpectedState` type for installing the
//! [OpenTelemetry Collector](https://opentelemetry.io/docs/collector/) from the packages of its
//! [GitHub releases](https://github.com/open-telemetry/opentelemetry-collector-releases/releases)
//! and managing its configuration.
//!
//! Two distributions are managed: `Core` (`otelcol`, the components maintained by the
//! OpenTelemetry project) and `Contrib` (`otelcol-contrib`, with the vendor and community
//! components, e.g. the `filelog`, `hostmetrics` or `prometheus` receivers).
//!
//! **Compatible OS:** Linux distributions based on `apt-get` (`.deb`), `dnf` or `zypper`
//! (`.rpm`), on x86_64 or aarch64.
//!
//! **Privilege:** installing packages and writing to `/etc` needs root, use `!WithSudo`.
//!
//! # How compliance is assessed
//!
//! 1. The package of the distribution (`otelcol` or `otelcol-contrib`) must be installed in
//!    `Version` (the collector has no package repository: a release is always pinned). Another
//!    version is upgraded or downgraded with the package downloaded from GitHub.
//! 2. `Config`, if set, is the whole content of `/etc/<package>/config.yaml`. A running service
//!    is restarted when it changes.
//!
//! `Absent` removes both distributions.
//!
//! Whether the collector runs is managed by the `Service` attribute (unit `otelcol` or
//! `otelcol-contrib`).
//!
//! **Prerequisites:** `curl` (or `wget`) and access to `github.com`.
//!
//! # Examples
//!
//! ## Rust API
//!
//! ```no_run
//! use regent_sdk::state::attribute::observability::otel_collector::{
//!     OtelCollectorDistribution, OtelCollectorExpectedState,
//! };
//! use regent_sdk::state::attribute::system::service::ServiceExpectedState;
//! use regent_sdk::{Attribute, ExpectedState, Privilege, RegentError};
//!
//! fn telemetry_pipeline() -> Result<ExpectedState, RegentError> {
//!     let collector =
//!         OtelCollectorExpectedState::present(OtelCollectorDistribution::Contrib, "0.164.0".parse()?)
//!             .with_config(
//!                 r#"receivers:
//!   otlp:
//!     protocols:
//!       grpc:
//!         endpoint: 0.0.0.0:4317
//!   hostmetrics:
//!     scrapers:
//!       cpu:
//!       memory:
//! exporters:
//!   otlphttp:
//!     endpoint: https://otel-gateway.example.com
//! service:
//!   pipelines:
//!     traces:
//!       receivers: [otlp]
//!       exporters: [otlphttp]
//!     metrics:
//!       receivers: [otlp, hostmetrics]
//!       exporters: [otlphttp]
//! "#,
//!             );
//!
//!     Ok(ExpectedState::new()
//!         .with_attribute(Attribute::otel_collector(collector, Privilege::WithSudo, None))
//!         .with_attribute(Attribute::service(
//!             ServiceExpectedState::started_and_enabled("otelcol-contrib"),
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
//!   - Name: OpenTelemetry Collector forwards traces and metrics
//!     Privilege: !WithSudo
//!     Detail: !OtelCollector
//!       State: Present
//!       Distribution: Contrib      # Core | Contrib
//!       Version: '0.164.0'
//!       Config: |                  # optional, the configuration is left alone without it
//!         receivers:
//!           otlp:
//!             protocols:
//!               grpc:
//!                 endpoint: 0.0.0.0:4317
//!         exporters:
//!           otlphttp:
//!             endpoint: https://otel-gateway.example.com
//!         service:
//!           pipelines:
//!             traces:
//!               receivers: [otlp]
//!               exporters: [otlphttp]
//!   - Name: OpenTelemetry Collector runs
//!     Privilege: !WithSudo
//!     Detail: !Service
//!       Name: otelcol-contrib
//!       State: Started
//!       Enabled: true
//! ```
//!
//! To remove the collector:
//!
//! ```yaml
//! Attributes:
//!   - Name: OpenTelemetry Collector must be removed
//!     Privilege: !WithSudo
//!     Detail: !OtelCollector
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
    AgentVersion, ReleaseArch, VersionChange, apply_to_running_unit, as_remediation_error,
    check_config_content, check_linux_host, file_content, host_release_arch,
    install_package_file_command, verify_installed_package, version_change, with_trailing_newline,
    write_unit_files,
};
use crate::state::attribute::shared::{
    PackageFamily, download, host_package_family, installed_packages, is_success, make_temp_dir,
    remove_temp_dir, run_step,
};
use crate::state::compliance::AttributeComplianceAssessment;
use serde::{Deserialize, Serialize};
use std::fmt;
use std::time::Duration;

const ATTRIBUTE: &str = "OtelCollector";
const RELEASES_URL: &str =
    "https://github.com/open-telemetry/opentelemetry-collector-releases/releases/download";

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(
    tag = "State",
    rename_all = "PascalCase",
    rename_all_fields = "PascalCase",
    deny_unknown_fields
)]
pub enum OtelCollectorExpectedState {
    Present {
        distribution: OtelCollectorDistribution,
        version: AgentVersion,
        /// Whole content of `/etc/<package>/config.yaml`
        config: Option<String>,
    },
    Absent,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub enum OtelCollectorDistribution {
    /// `otelcol`
    Core,
    /// `otelcol-contrib`
    Contrib,
}

impl fmt::Display for OtelCollectorDistribution {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.package())
    }
}

impl OtelCollectorDistribution {
    /// Also the name of the systemd unit and of the configuration directory
    pub fn package(&self) -> &'static str {
        match self {
            OtelCollectorDistribution::Core => "otelcol",
            OtelCollectorDistribution::Contrib => "otelcol-contrib",
        }
    }

    fn config_file(&self) -> String {
        format!("/etc/{}/config.yaml", self.package())
    }

    fn package_url(
        &self,
        version: &AgentVersion,
        arch: ReleaseArch,
        family: PackageFamily,
    ) -> String {
        let extension = match family {
            PackageFamily::Apt => "deb",
            PackageFamily::Dnf | PackageFamily::Zypper => "rpm",
        };
        format!(
            "{}/v{}/{}_{}_linux_{}.{}",
            RELEASES_URL,
            version,
            self.package(),
            version,
            arch,
            extension
        )
    }
}

const DISTRIBUTIONS: [OtelCollectorDistribution; 2] = [
    OtelCollectorDistribution::Core,
    OtelCollectorDistribution::Contrib,
];

impl Timeout for OtelCollectorExpectedState {
    fn default_timeout(&self) -> Duration {
        Duration::from_secs(600)
    }
}

impl OtelCollectorExpectedState {
    /// Collector installed in `version`, with its configuration left alone
    pub fn present(distribution: OtelCollectorDistribution, version: AgentVersion) -> Self {
        OtelCollectorExpectedState::Present {
            distribution,
            version,
            config: None,
        }
    }

    pub fn absent() -> Self {
        OtelCollectorExpectedState::Absent
    }

    /// Manage `/etc/<package>/config.yaml` (no effect on `Absent`)
    pub fn with_config(mut self, content: &str) -> Self {
        if let OtelCollectorExpectedState::Present { config, .. } = &mut self {
            *config = Some(content.to_string());
        }
        self
    }
}

impl Check for OtelCollectorExpectedState {
    fn check(&self) -> Result<(), RegentError> {
        match self {
            OtelCollectorExpectedState::Present {
                config: Some(config),
                ..
            } => check_config_content(ATTRIBUTE, config),
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

impl<Handler: HostHandler> AssessCompliance<Handler> for OtelCollectorExpectedState {
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
                "the distribution (/etc/os-release) is not based on apt-get, dnf or zypper: the OpenTelemetry Collector packages can't be installed".to_string(),
            ));
        };
        let packages = DISTRIBUTIONS.map(|distribution| distribution.package());
        let installed = installed_packages(host_handler, family, &packages, privilege).await?;

        let mut api_calls = Vec::new();
        match self {
            OtelCollectorExpectedState::Absent => {
                if !installed.is_empty() {
                    api_calls.push(OtelCollectorInternalApiCall::Remove {
                        family,
                        packages: installed.into_keys().collect(),
                    });
                }
            }
            OtelCollectorExpectedState::Present {
                distribution,
                version,
                config,
            } => {
                if let Some(change) = version_change(
                    installed.get(distribution.package()).map(String::as_str),
                    Some(version),
                ) {
                    let arch = match host_release_arch(host_handler, privilege).await? {
                        Ok(arch) => arch,
                        Err(reason) => {
                            return Ok(AttributeComplianceAssessment::NonCompliantFatal(reason));
                        }
                    };
                    api_calls.push(OtelCollectorInternalApiCall::Install {
                        family,
                        distribution: *distribution,
                        version: version.clone(),
                        arch,
                        change,
                    });
                }

                if let Some(config) = config {
                    let expected = with_trailing_newline(config);
                    if file_content(host_handler, &distribution.config_file(), privilege)
                        .await?
                        .as_deref()
                        != Some(expected.as_str())
                    {
                        api_calls.push(OtelCollectorInternalApiCall::WriteConfig {
                            distribution: *distribution,
                            content: expected,
                        });
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
                Remediation::OtelCollector(OtelCollectorApiCall::from(api_call, privilege.clone()))
            })
            .collect();
        Ok(AttributeComplianceAssessment::NonCompliant(
            RemediationsList::from(remediations)?,
        ))
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase", rename_all_fields = "PascalCase")]
pub enum OtelCollectorInternalApiCall {
    /// Install, upgrade or downgrade the package downloaded from the GitHub release, restart the
    /// service if running
    Install {
        family: PackageFamily,
        distribution: OtelCollectorDistribution,
        version: AgentVersion,
        arch: ReleaseArch,
        change: VersionChange,
    },
    /// Write `/etc/<package>/config.yaml`, restart the service if running
    WriteConfig {
        distribution: OtelCollectorDistribution,
        content: String,
    },
    Remove {
        family: PackageFamily,
        packages: Vec<String>,
    },
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct OtelCollectorApiCall {
    pub api_call: OtelCollectorInternalApiCall,
    privilege: Privilege,
}

impl OtelCollectorApiCall {
    pub fn display(&self) -> String {
        match &self.api_call {
            OtelCollectorInternalApiCall::Install {
                distribution,
                version,
                arch,
                change,
                ..
            } => format!("{} {} {} ({})", change, distribution, version, arch),
            OtelCollectorInternalApiCall::WriteConfig { distribution, .. } => format!(
                "Write the {} configuration {} and restart it if running",
                distribution,
                distribution.config_file()
            ),
            OtelCollectorInternalApiCall::Remove { packages, .. } => {
                format!("Remove {}", packages.join(", "))
            }
        }
    }

    fn from(api_call: OtelCollectorInternalApiCall, privilege: Privilege) -> OtelCollectorApiCall {
        OtelCollectorApiCall {
            api_call,
            privilege,
        }
    }
}

impl Check for OtelCollectorApiCall {
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

impl<Handler: HostHandler> ReachCompliance<Handler> for OtelCollectorApiCall {
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
            OtelCollectorInternalApiCall::Install {
                family,
                distribution,
                version,
                arch,
                ..
            } => {
                let tmp = match make_temp_dir(host_handler, privilege)
                    .await
                    .map_err(as_remediation_error)?
                {
                    Ok(tmp) => tmp,
                    Err(failure) => return Ok(failure),
                };
                let url = distribution.package_url(version, *arch, *family);
                let file = format!("{}/{}", tmp, url.rsplit('/').next().unwrap_or_default());
                let mut outcome = download(host_handler, &url, &file, privilege).await;
                if is_success(&outcome) {
                    outcome = run_step(
                        host_handler,
                        &install_package_file_command(*family, &file),
                        privilege,
                    )
                    .await;
                }
                remove_temp_dir(host_handler, &tmp, privilege).await;
                if !is_success(&outcome) {
                    return Ok(outcome);
                }
                let outcome = verify_installed_package(
                    host_handler,
                    *family,
                    distribution.package(),
                    Some(version),
                    privilege,
                )
                .await?;
                if !is_success(&outcome) {
                    return Ok(outcome);
                }
                let restart = apply_to_running_unit(
                    host_handler,
                    distribution.package(),
                    "restart",
                    privilege,
                )
                .await?;
                Ok(if is_success(&restart) {
                    outcome
                } else {
                    restart
                })
            }
            OtelCollectorInternalApiCall::WriteConfig {
                distribution,
                content,
            } => {
                write_unit_files(
                    host_handler,
                    &[(&distribution.config_file(), content)],
                    distribution.package(),
                    "restart",
                    privilege,
                )
                .await
            }
            OtelCollectorInternalApiCall::Remove { family, packages } => {
                let outcome =
                    run_step(host_handler, &family.remove_command(packages), privilege).await;
                if !is_success(&outcome) {
                    return Ok(outcome);
                }
                let patterns: Vec<&str> = packages.iter().map(String::as_str).collect();
                let installed = installed_packages(host_handler, *family, &patterns, privilege)
                    .await
                    .map_err(as_remediation_error)?;
                if installed.is_empty() {
                    Ok(outcome)
                } else {
                    Ok(InternalApiCallOutcome::Failure(format!(
                        "{} still installed after their removal",
                        installed.into_keys().collect::<Vec<_>>().join(", ")
                    )))
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
    fn parsing_otel_collector_module_block_from_yaml_str() {
        let raw = "---
State: Present
Distribution: Contrib
Version: '0.164.0'
Config: |
  receivers:
    otlp:
";
        let block: OtelCollectorExpectedState = yaml_serde::from_str(raw).unwrap();
        assert!(block.check().is_ok());
        assert_eq!(
            block,
            OtelCollectorExpectedState::present(
                OtelCollectorDistribution::Contrib,
                "0.164.0".parse().unwrap()
            )
            .with_config("receivers:\n  otlp:\n")
        );

        let block: OtelCollectorExpectedState =
            yaml_serde::from_str("---\nState: Absent\n").unwrap();
        assert_eq!(block, OtelCollectorExpectedState::absent());
    }

    #[test]
    fn rejecting_incorrect_otel_collector_module_block_from_yaml_str() {
        for raw in [
            "---\nState: Present\nDistribution: Contrib\n",
            "---\nState: Present\nVersion: '0.164.0'\n",
            "---\nState: Present\nDistribution: K8s\nVersion: '0.164.0'\n",
            "---\nState: Present\nDistribution: Core\nVersion: '0.164.0'\nConfigFile: x\n",
        ] {
            assert!(
                yaml_serde::from_str::<OtelCollectorExpectedState>(raw).is_err(),
                "{raw}"
            );
        }
    }

    #[test]
    fn parsing_full_otel_collector_attribute_envelope_from_yaml_str() {
        let raw_attribute = "---
Name: OpenTelemetry Collector must be installed
Privilege: !WithSudo
Timeout: 15m
Detail: !OtelCollector
  State: Present
  Distribution: Core
  Version: '0.164.0'
";
        let attribute: Attribute = yaml_serde::from_str(raw_attribute).unwrap();
        assert!(attribute.check().is_ok());
        assert_eq!(attribute.timeout(), Duration::from_secs(900));
    }

    #[test]
    fn release_packages_are_located_on_github() {
        let version: AgentVersion = "0.164.0".parse().unwrap();
        assert_eq!(
            OtelCollectorDistribution::Contrib.package_url(
                &version,
                ReleaseArch::Amd64,
                PackageFamily::Apt
            ),
            "https://github.com/open-telemetry/opentelemetry-collector-releases/releases/download/v0.164.0/otelcol-contrib_0.164.0_linux_amd64.deb"
        );
        assert_eq!(
            OtelCollectorDistribution::Core.package_url(
                &version,
                ReleaseArch::Arm64,
                PackageFamily::Dnf
            ),
            "https://github.com/open-telemetry/opentelemetry-collector-releases/releases/download/v0.164.0/otelcol_0.164.0_linux_arm64.rpm"
        );
        assert_eq!(
            OtelCollectorDistribution::Core.config_file(),
            "/etc/otelcol/config.yaml"
        );
    }
}
