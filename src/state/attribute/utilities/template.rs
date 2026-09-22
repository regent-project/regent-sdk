//! Template file management attribute
//!
//! This module provides the `TemplateExpectedState` type for rendering a
//! [Tera](https://docs.rs/tera/latest/tera/) template and writing the result to a
//! destination file on the managed host. The template source can be a file path
//! (`TemplateOrigin::File`) or an inline string (`TemplateOrigin::InLine`), and
//! can be combined with an optional context map of variables.
//!
//! **Compatible OS:** Linux
//!
//! # Examples
//!
//! ## Rust API
//!
//! ```no_run
//! use std::path::PathBuf;
//! use std::collections::HashMap;
//! use regent_sdk::state::attribute::utilities::template::TemplateExpectedState;
//! use regent_sdk::{Attribute, ExpectedState, Privilege};
//!
//! // Render a template file to /etc/nginx/nginx.conf
//! let nginx = TemplateExpectedState::from_file(
//!     PathBuf::from("/etc/regent/templates/nginx.conf.j2"),
//!     PathBuf::from("/etc/nginx/nginx.conf"),
//! );
//!
//! // Render an inline template with a context map
//! let mut context = HashMap::from(vec![("port".to_string(), "8080".to_string()]);
//!
//! let server_block = TemplateExpectedState::from_inline_with_additional_context(
//!     "server { listen {{ port }}; }".to_string(),
//!     PathBuf::from("/etc/nginx/conf.d/default.conf"),
//!     context,
//! );
//!
//! let expected_state = ExpectedState::new()
//!     .with_attribute(Attribute::template(nginx, Privilege::WithSudo, None))
//!     .with_attribute(Attribute::template(server_block, Privilege::WithSudo, None))
//!     .build();
//! ```
//!
//! ## YAML API
//!
//! ```yaml
//! Attributes:
//!   - Name: Render nginx config from template file
//!     Privilege: !WithSudo
//!     Detail: !Template
//!       Template: !File /etc/regent/templates/nginx.conf.template
//!       Destination: /etc/nginx/nginx.conf
//!       Context:
//!         server_name: example.com
//!         port: 8080
//! ```
//!
//! For an inline template:
//!
//! ```yaml
//! Attributes:
//!   - Name: Render server block inline
//!     Privilege: !WithSudo
//!     Detail: !Template
//!       Template: !InLine |
//!         [Server]
//!         host = {{ host }}
//!         port = {{ port }}
//!         timeout = {{ 2 * 50 }}
//!       Destination: /etc/myapp/config.toml
//!       Context:
//!         host: srv.mydomain.com
//!         port: 443
//! ```

use crate::error::RegentError;
use crate::hosts::managed_host::InternalApiCallOutcome;
use crate::hosts::managed_host::{AssessCompliance, ReachCompliance, Timeout};
use crate::hosts::properties::{HostProperties, OsKind};
use crate::secrets::SecretProvidersPool;
use crate::state::Check;
use crate::state::attribute::HostHandler;
use crate::state::attribute::Privilege;
use crate::state::attribute::Remediation;
use crate::state::attribute::RemediationsList;
use crate::state::compliance::AttributeComplianceAssessment;
use serde::{Deserialize, Serialize};
use std::time::Duration;
use std::{collections::HashMap, path::PathBuf};

#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub enum TemplateOrigin {
    File(PathBuf),
    InLine(String),
}

/// Manual `Serialize` implementation, required to escape the in-line tera template
/// when rendering tera at Attribute level (normal process, not specific to this Template attribute).
/// If not escaped, the Inline content will get prematurely rendered with wrong tera context
/// when attribute level "consider_context" method is called.
impl Serialize for TemplateOrigin {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        match self {
            TemplateOrigin::File(path) => {
                serializer.serialize_newtype_variant("TemplateOrigin", 0, "File", path)
            }
            TemplateOrigin::InLine(content) => {
                let wrapped = format!("{{% raw %}}{}{{% endraw %}}", content);
                serializer.serialize_newtype_variant("TemplateOrigin", 1, "InLine", &wrapped)
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[serde(rename_all = "PascalCase")]
pub struct TemplateExpectedState {
    pub template: TemplateOrigin,
    pub destination: PathBuf,
    pub context: Option<HashMap<String, String>>,
}

impl Timeout for TemplateExpectedState {
    fn default_timeout(&self) -> Duration {
        Duration::from_secs(2)
    }
}

impl TemplateExpectedState {
    pub fn from_file(file: PathBuf, destination: PathBuf) -> TemplateExpectedState {
        TemplateExpectedState {
            template: TemplateOrigin::File(file),
            destination,
            context: None,
        }
    }

    pub fn from_file_with_additional_context(
        file: PathBuf,
        destination: PathBuf,
        context: HashMap<String, String>,
    ) -> TemplateExpectedState {
        TemplateExpectedState {
            template: TemplateOrigin::File(file),
            destination,
            context: Some(context),
        }
    }

    pub fn from_inline(inline: String, destination: PathBuf) -> TemplateExpectedState {
        TemplateExpectedState {
            template: TemplateOrigin::InLine(inline),
            destination,
            context: None,
        }
    }

    pub fn from_inline_with_additional_context(
        inline: String,
        destination: PathBuf,
        context: HashMap<String, String>,
    ) -> TemplateExpectedState {
        TemplateExpectedState {
            template: TemplateOrigin::InLine(inline),
            destination,
            context: Some(context),
        }
    }
}

impl Check for TemplateExpectedState {
    fn check(&self) -> Result<(), RegentError> {
        Ok(())
    }

    fn check_host_compatibility(
        &self,
        host_properties: &HostProperties,
    ) -> Result<(), RegentError> {
        match host_properties.os_kind() {
            OsKind::Linux(_) => Ok(()),
            incompatible_os_kind => Err(RegentError::IncompatibleHost(format!(
                "Host is {:?} but APT is only supported on Linux distributions",
                incompatible_os_kind
            ))),
        }
    }
}

impl<Handler: HostHandler> AssessCompliance<Handler> for TemplateExpectedState {
    async fn assess_compliance(
        &self,
        host_handler: &mut Handler,
        host_properties: &Option<HostProperties>,
        privilege: &Privilege,
        _optional_secret_provider: &Option<SecretProvidersPool>,
    ) -> Result<AttributeComplianceAssessment, RegentError> {
        // Early check: verify we're on a compatible host
        if let Some(props) = host_properties {
            self.check_host_compatibility(props)?;
        }

        let expected_content = render_template_content(&self.template, &self.context)?;

        let destination = self.destination.to_string_lossy();

        // Check whether the destination file already exists on the host.
        let file_exists = host_handler
            .run_command(&format!("test -f {}", destination), &privilege)
            .await
            .map_err(|details| {
                RegentError::FailedDryRunEvaluation(format!(
                    "Unable to check existence of destination file {}: {:?}",
                    destination, details
                ))
            })?
            .return_code
            == 0;

        if !file_exists {
            return Ok(AttributeComplianceAssessment::NonCompliant(
                RemediationsList::from(vec![Remediation::Template(TemplateApiCall {
                    template: self.template.clone(),
                    destination: self.destination.clone(),
                    destination_action: DestinationFileAction::CreateFile,
                    context: self.context.clone(),
                    privilege: privilege.clone(),
                })])?,
            ));
        }

        let current_content = host_handler
            .run_command(&format!("cat {}", destination), &privilege)
            .await
            .map_err(|details| {
                RegentError::FailedDryRunEvaluation(format!(
                    "Unable to read destination file {}: {:?}",
                    destination, details
                ))
            })?
            .stdout;

        if current_content.trim_end_matches('\n') == expected_content.trim_end_matches('\n') {
            Ok(AttributeComplianceAssessment::Compliant)
        } else {
            // Content differs: remediation is a full content replacement.
            Ok(AttributeComplianceAssessment::NonCompliant(
                RemediationsList::from(vec![Remediation::Template(TemplateApiCall {
                    template: self.template.clone(),
                    destination: self.destination.clone(),
                    destination_action: DestinationFileAction::WrongContent,
                    context: self.context.clone(),
                    privilege: privilege.clone(),
                })])?,
            ))
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
enum DestinationFileAction {
    WrongContent,
    CreateFile,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TemplateApiCall {
    template: TemplateOrigin,
    destination: PathBuf,
    destination_action: DestinationFileAction,
    context: Option<HashMap<String, String>>,
    privilege: Privilege,
}

impl Check for TemplateApiCall {
    fn check(&self) -> Result<(), RegentError> {
        Ok(())
    }

    fn check_host_compatibility(
        &self,
        host_properties: &HostProperties,
    ) -> Result<(), RegentError> {
        match host_properties.os_kind() {
            OsKind::Linux(_) => Ok(()),
            incompatible_os_kind => Err(RegentError::IncompatibleHost(format!(
                "Host is {:?} but APT is only supported on Linux distributions",
                incompatible_os_kind
            ))),
        }
    }
}

impl TemplateApiCall {
    pub fn display(&self) -> String {
        match &self.destination_action {
            DestinationFileAction::WrongContent => format!("Destination file content is wrong"),
            DestinationFileAction::CreateFile => format!("Destination file does not exist"),
        }
    }
}

impl<Handler: HostHandler> ReachCompliance<Handler> for TemplateApiCall {
    async fn call(
        &self,
        host_handler: &mut Handler,
        host_properties: &Option<HostProperties>,
        _optional_secret_provider: &Option<SecretProvidersPool>,
    ) -> Result<InternalApiCallOutcome, RegentError> {
        if let Some(props) = host_properties {
            self.check_host_compatibility(props)?;
        }

        let expected_content = render_template_content(&self.template, &self.context)?;

        let destination = self.destination.to_string_lossy();

        // Overwrite the destination file if it exists, or create it otherwise.
        // "printf ... > file" handles both cases: it truncates an existing file
        // and creates a new one when the file is absent. DestinationFileAction is
        // only used at assessment step to distinguish reasons for non-compliance.
        // Remediation is the same anyway.
        let cmd = format!(
            "printf '{}' > {}",
            escape_for_printf(&expected_content),
            destination
        );

        let cmd_result = host_handler
            .run_command(cmd.as_str(), &self.privilege)
            .await
            .map_err(|details| {
                RegentError::FailureToRunCommand(format!(
                    "Unable to write rendered template to {}: {:?}",
                    destination, details
                ))
            })?;

        if cmd_result.return_code != 0 {
            return Ok(InternalApiCallOutcome::Failure(format!(
                "RC: {}, STDOUT: {}, STDERR: {}",
                cmd_result.return_code, cmd_result.stdout, cmd_result.stderr
            )));
        }

        let verification = host_handler
            .run_command(&format!("cat {}", destination), &self.privilege)
            .await
            .map_err(|details| {
                RegentError::FailedDryRunEvaluation(format!(
                    "Unable to read destination file {} for verification: {:?}",
                    destination, details
                ))
            })?
            .stdout;

        if verification.trim_end_matches('\n') == expected_content.trim_end_matches('\n') {
            Ok(InternalApiCallOutcome::Success(None))
        } else {
            Ok(InternalApiCallOutcome::Failure(format!(
                "Command succeeded but post-verification failed (expected : {:?}, real : {:?}",
                expected_content, verification
            )))
        }
    }
}

fn render_template_content(
    template: &TemplateOrigin,
    context: &Option<HashMap<String, String>>,
) -> Result<String, RegentError> {
    let template_str = match template {
        TemplateOrigin::File(path) => std::fs::read_to_string(path).map_err(|details| {
            RegentError::FailedDryRunEvaluation(format!(
                "Unable to read template file {:?}: {}",
                path, details
            ))
        })?,
        TemplateOrigin::InLine(content) => content.clone(),
    };

    let tera_context = match context {
        Some(variables) => tera::Context::from_serialize(variables).map_err(|details| {
            RegentError::FailureToConsiderContext(format!(
                "Failed to build template context: {}",
                details
            ))
        })?,
        None => tera::Context::new(),
    };

    tera::Tera::one_off(&template_str, &tera_context, true).map_err(|details| {
        RegentError::FailureToConsiderContext(format!("Failed to render template: {}", details))
    })
}

fn escape_for_printf(content: &str) -> String {
    content
        .replace('\\', "\\\\")
        .replace('%', "%%")
        .replace('\n', "\\n")
        .replace('\'', "'\\''")
}
