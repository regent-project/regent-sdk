use crate::error::RegentError;
use crate::hosts::managed_host::InternalApiCallOutcome;
use crate::hosts::managed_host::{AssessCompliance, ReachCompliance};
use crate::hosts::properties::HostProperties;
use crate::secrets::SecretProvider;
use crate::state::attribute::HostHandler;
use crate::state::attribute::Privilege;
use crate::state::attribute::Remediation;
use crate::state::compliance::AttributeComplianceAssessment;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub enum ServiceModuleInternalApiCall {
    Start(String),
    Stop(String),
    Enable(String),
    Disable(String),
}

impl std::fmt::Display for ServiceModuleInternalApiCall {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ServiceModuleInternalApiCall::Start(service) => write!(f, "start {}", service),
            ServiceModuleInternalApiCall::Stop(service) => write!(f, "stop {}", service),
            ServiceModuleInternalApiCall::Enable(service) => write!(f, "enable {}", service),
            ServiceModuleInternalApiCall::Disable(service) => write!(f, "disable {}", service),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub enum ServiceExpectedStatus {
    Active,
    Inactive,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub enum ServiceExpectedAutoStart {
    Enabled,
    Disabled,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[serde(rename_all = "PascalCase")]
pub struct ServiceBlockExpectedState {
    name: String,
    current_status: Option<ServiceExpectedStatus>,
    auto_start: Option<ServiceExpectedAutoStart>,
    exists: Option<bool>, // None treated as Some(true)
}

// Chained methods to allow building an ServiceBlockExpectedState as follows :
// let apt_block = ServiceBlockExpectedState::builder()
//     .with_service_state("apache2", ServiceExpectedStatus::Active)
//     .with_autostart_state(ServiceExpectedAutoStart::Enabled)
//     .build();
impl ServiceBlockExpectedState {
    pub fn builder(service_name: &str) -> ServiceBlockExpectedState {
        ServiceBlockExpectedState {
            name: service_name.to_string(),
            current_status: None,
            auto_start: None,
            exists: None,
        }
    }

    pub fn with_service_state(
        &mut self,
        expected_current_status: ServiceExpectedStatus,
    ) -> &mut Self {
        self.current_status = Some(expected_current_status);
        self
    }

    pub fn with_autostart_state(
        &mut self,
        expected_autostart_state: ServiceExpectedAutoStart,
    ) -> &mut Self {
        self.auto_start = Some(expected_autostart_state);
        self
    }

    pub fn exists(&mut self, setting: bool) -> &mut Self {
        self.exists = Some(setting);
        self
    }

    pub fn build(&self) -> Result<ServiceBlockExpectedState, RegentError> {
        // if let Err(RegentError_detail) = self.check() {
        //     return Err(RegentError_detail);
        // }
        Ok(self.clone())
    }
}

// impl Check for ServiceBlockExpectedState {
//     fn check(&self) -> Result<(), RegentError> {
//         if let (None, None) = (&self.current_status, &self.auto_start) {
//             return Err(RegentError::IncoherentExpectedState(format!(
//                 "Incomplete minimal description of the expected state of the service."
//             )));
//         }
//         if let Some(false) = self.exists {
//             if let Some(ServiceExpectedStatus::Active) = self.current_status {
//                 return Err(RegentError::IncoherentExpectedState(format!(
//                     "Service cannot be both active and non-existing."
//                 )));
//             }
//             if let Some(ServiceExpectedAutoStart::Enabled) = self.auto_start {
//                 return Err(RegentError::IncoherentExpectedState(format!(
//                     "Service cannot be both enabled and non-existing."
//                 )));
//             }
//         }
//         Ok(())
//     }
// }

impl<Handler: HostHandler> AssessCompliance<Handler> for ServiceBlockExpectedState {
    fn assess_compliance(
        &self,
        host_handler: &mut Handler,
        _host_properties: &Option<HostProperties>,
        privilege: &Privilege,
        _optional_secret_provider: &Option<SecretProvider>,
    ) -> Result<AttributeComplianceAssessment, RegentError> {
        // Prechecks

        if !host_handler
            .is_this_command_available("systemctl", &privilege)
            .unwrap()
        {
            return Err(RegentError::FailedDryRunEvaluation(
                "SYSTEMCTL not available on this host".to_string(),
            ));
        }

        let must_exists = match self.exists {
            Some(value) => value,
            None => true,
        };

        let service_is_active = match service_is_active(host_handler, &self.name, must_exists) {
            Ok(active_state) => active_state,
            Err(e) => return Err(RegentError::FailedDryRunEvaluation(e)),
        };

        let service_is_enabled = match service_is_enabled(host_handler, &self.name, must_exists) {
            Ok(enabled_state) => enabled_state,
            Err(e) => return Err(RegentError::FailedDryRunEvaluation(e)),
        };

        // Changes assessment
        let mut remediations: Vec<Remediation> = Vec::new();

        // State or enabled :
        // - one of them is required
        if let (None, None) = (&self.current_status, &self.auto_start) {
            // PROBLEM : both 'state' and 'enabled' are empty
            return Err(RegentError::FailedDryRunEvaluation(
                "STATE and ENABLED fields are both empty in provided Task List".to_string(),
            ));
        } else if let Some(false) = self.exists {
            if let Some(ServiceExpectedStatus::Active) = self.current_status {
                return Err(RegentError::IncoherentExpectedState(format!(
                    "Service cannot be both active and non-existing."
                )));
            }
            if let Some(ServiceExpectedAutoStart::Enabled) = self.auto_start {
                return Err(RegentError::IncoherentExpectedState(format!(
                    "Service cannot be both enabled and non-existing."
                )));
            }
        } else {
            match &self.current_status {
                Some(state_content) => {
                    match state_content {
                        ServiceExpectedStatus::Active => {
                            if service_is_active {
                                remediations.push(Remediation::None(format!(
                                    "{} already Active",
                                    &self.name
                                )));
                            } else {
                                // Service needs to be Active
                                remediations.push(Remediation::Service(ServiceApiCall::from(
                                    ServiceModuleInternalApiCall::Start(self.name.clone()),
                                    privilege.clone(),
                                )));
                            }
                        }
                        ServiceExpectedStatus::Inactive => {
                            if service_is_active {
                                // Service needs to be Inactive
                                remediations.push(Remediation::Service(ServiceApiCall::from(
                                    ServiceModuleInternalApiCall::Stop(self.name.clone()),
                                    privilege.clone(),
                                )));
                            } else {
                                remediations.push(Remediation::None(format!(
                                    "{} already Inactive",
                                    &self.name
                                )));
                            }
                        }
                    }
                }
                None => {}
            }

            if let Some(service_auto_start_expected_state) = &self.auto_start {
                match service_auto_start_expected_state {
                    ServiceExpectedAutoStart::Enabled => {
                        if service_is_enabled {
                            remediations
                                .push(Remediation::None(format!("{} already enabled", &self.name)));
                        } else {
                            // SERVICE MUST BE ENABLED
                            remediations.push(Remediation::Service(ServiceApiCall::from(
                                ServiceModuleInternalApiCall::Enable(self.name.clone()),
                                privilege.clone(),
                            )));
                        }
                    }
                    ServiceExpectedAutoStart::Disabled => {
                        if service_is_enabled {
                            // SERVICE MUST BE DISABLED
                            remediations.push(Remediation::Service(ServiceApiCall::from(
                                ServiceModuleInternalApiCall::Disable(self.name.clone()),
                                privilege.clone(),
                            )));
                        } else {
                            remediations.push(Remediation::None(format!(
                                "{} already disabled",
                                &self.name
                            )));
                        }
                    }
                }
            }
        }

        // If remediations are only None, it means a Match. If only one change is not a None, return the whole list.
        for change in remediations.iter() {
            match change {
                Remediation::None(_) => {}
                _ => {
                    return Ok(AttributeComplianceAssessment::NonCompliant(remediations));
                }
            }
        }
        return Ok(AttributeComplianceAssessment::Compliant);
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ServiceApiCall {
    pub api_call: ServiceModuleInternalApiCall,
    privilege: Privilege,
}

impl ServiceApiCall {
    pub fn display(&self) -> String {
        match &self.api_call {
            ServiceModuleInternalApiCall::Start(service_name) => {
                return format!("Start service {}", service_name);
            }
            ServiceModuleInternalApiCall::Stop(service_name) => {
                return format!("Stop service {}", service_name);
            }
            ServiceModuleInternalApiCall::Enable(service_name) => {
                return format!("Enable service {}", service_name);
            }
            ServiceModuleInternalApiCall::Disable(service_name) => {
                return format!("Disable service {}", service_name);
            }
        }
    }
}

impl<Handler: HostHandler> ReachCompliance<Handler> for ServiceApiCall {
    fn call(
        &self,
        host_handler: &mut Handler,
        _host_properties: &Option<HostProperties>,
        _optional_secret_provider: &Option<SecretProvider>,
    ) -> Result<InternalApiCallOutcome, RegentError> {
        let (cmd, privilege) = match &self.api_call {
            ServiceModuleInternalApiCall::Start(service_name) => {
                (format!("systemctl start {}", service_name), &self.privilege)
            }
            ServiceModuleInternalApiCall::Stop(service_name) => {
                (format!("systemctl stop {}", service_name), &self.privilege)
            }
            ServiceModuleInternalApiCall::Enable(service_name) => (
                format!("systemctl enable {}", service_name),
                &self.privilege,
            ),
            ServiceModuleInternalApiCall::Disable(service_name) => (
                format!("systemctl disable {}", service_name),
                &self.privilege,
            ),
        };

        let cmd_result = host_handler.run_command(cmd.as_str(), privilege).unwrap();

        if cmd_result.return_code == 0 {
            Ok(InternalApiCallOutcome::Success(None))
        } else {
            Ok(InternalApiCallOutcome::Failure(format!(
                "RC : {}, STDOUT : {}, STDERR : {}",
                cmd_result.return_code, cmd_result.stdout, cmd_result.stderr
            )))
        }
    }
}

impl ServiceApiCall {
    fn from(api_call: ServiceModuleInternalApiCall, privilege: Privilege) -> ServiceApiCall {
        ServiceApiCall {
            api_call,
            privilege,
        }
    }
}

fn service_is_active<Handler: HostHandler>(
    host_handler: &mut Handler,
    service_name: &String,
    must_exists: bool,
) -> Result<bool, String> {
    match host_handler.run_command(
        format!("systemctl is-active {}", service_name).as_str(),
        &Privilege::None,
    ) {
        Ok(test_result) => match test_result.return_code {
            0 => Ok(true),
            1 => Err(format!("Unit not failed : {}", service_name)),
            3 => Ok(false),
            4 => {
                if must_exists {
                    Err(format!("No such service : {}", service_name))
                } else {
                    Ok(false)
                }
            }
            _ => Err(format!(
                "Unknown return code : RC : {}, STDOUT : {}, STDERR : {}",
                test_result.return_code, test_result.stdout, test_result.stderr
            )),
        },
        Err(e) => Err(format!("Unable to check service status : {:?}", e)),
    }
}

fn service_is_enabled<Handler: HostHandler>(
    host_handler: &mut Handler,
    service_name: &String,
    must_exists: bool,
) -> Result<bool, String> {
    match host_handler.run_command(
        format!("systemctl is-enabled {}", service_name).as_str(),
        &Privilege::None,
    ) {
        Ok(test_result) => {
            match test_result.return_code {
                0 => Ok(true),
                1 => Ok(false),
                // 3 => Ok(false),
                4 => {
                    if must_exists {
                        Err(format!("No such service : {}", service_name))
                    } else {
                        Ok(false)
                    }
                }
                _ => Err(format!(
                    "Unknown return code : RC : {}, STDOUT : {}, STDERR : {}",
                    test_result.return_code, test_result.stdout, test_result.stderr
                )),
            }
        }
        Err(e) => Err(format!("Unable to check service status : {:?}", e)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parsing_service_module_block_from_yaml_str() {
        let raw_attributes = "---
- Name: apache2
  CurrentStatus: !Active
  AutoStart: !Enabled

- Name: apache2
  CurrentStatus: !Inactive
  AutoStart: !Disabled
        ";

        let _attributes: Vec<ServiceBlockExpectedState> =
            yaml_serde::from_str(raw_attributes).unwrap();
    }
}
