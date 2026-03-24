use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use crate::LocalHostHandler;
use crate::Ssh2AuthMethod;
use crate::Ssh2HostHandler;
use crate::WhichUser;
use crate::error::Error;
use crate::hosts::handlers::ConnectionMethod;
use crate::hosts::handlers::Handler;
use crate::hosts::handlers::HostHandler;
use crate::hosts::handlers::TargetUserKind;
use crate::hosts::handlers::ssh2::Ssh2AuthReference;
use crate::hosts::privilege::Credentials;
use crate::hosts::privilege::LoginKeyPath;
use crate::hosts::privilege::Privilege;
use crate::hosts::properties::HostProperties;
use crate::secrets::SecretsManagementSolution;
use crate::state::ExpectedState;
use crate::state::attribute::Remediation;
use crate::state::compliance::Action;
use crate::state::compliance::AttributeComplianceAssessment;
use crate::state::compliance::HostStatus;
use crate::state::compliance::ManagedHostStatus;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct ManagedHostBuilder {
    endpoint: String,
    connection_method: Option<ConnectionMethod>,
    host_properties: Option<HostProperties>,
    vars: Option<HashMap<String, String>>,
}

impl ManagedHostBuilder {
    pub fn new(endpoint: &str) -> Self {
        Self {
            endpoint: endpoint.to_string(),
            connection_method: None,
            host_properties: None,
            vars: None,
        }
    }

    pub fn connection_method(mut self, connection_method: ConnectionMethod) -> Self {
        self.connection_method = Some(connection_method);
        self
    }

    pub fn from_raw_yaml(raw_yaml: &str) -> Result<Self, Error> {
        match yaml_serde::from_str::<Self>(raw_yaml) {
            Ok(managed_host_builder) => Ok(managed_host_builder),
            Err(error_detail) => Err(Error::FailureToParseContent(format!("{:?}", error_detail))),
        }
    }

    pub fn from_raw_json(raw_json: &str) -> Result<Self, Error> {
        match serde_json::from_str::<Self>(raw_json) {
            Ok(managed_host_builder) => Ok(managed_host_builder),
            Err(error_detail) => Err(Error::FailureToParseContent(format!("{:?}", error_detail))),
        }
    }

    pub fn build(
        self,
        secret_provider: &Option<SecretsManagementSolution>,
    ) -> Result<ManagedHost, Error> {
        // Check that each required field is set
        if let None = self.connection_method {
            return Err(Error::WrongInitialization(format!(
                "connection method unset"
            )));
        }

        // Retrieve connection secrets when needed
        match self.connection_method {
            Some(connection) => {
                match connection {
                    ConnectionMethod::Localhost(target_user) => {
                        match target_user.user_kind {
                            TargetUserKind::CurrentUser => {
                                // No secret required
                                Ok(ManagedHost::new(
                                    &self.endpoint,
                                    Handler::localhost(LocalHostHandler::from(
                                        WhichUser::CurrentUser,
                                    )),
                                    self.vars,
                                    self.host_properties,
                                    secret_provider.clone(),
                                ))
                            }
                            TargetUserKind::User(secret_reference) => match secret_provider {
                                Some(secret_provider) => {
                                    match secret_provider
                                        .get_secret::<Credentials>(secret_reference.sec_ref())
                                    {
                                        Ok(secret) => Ok(ManagedHost::new(
                                            &self.endpoint,
                                            Handler::localhost(LocalHostHandler::from(
                                                WhichUser::UsernamePassword(secret.inner()),
                                            )),
                                            self.vars,
                                            self.host_properties,
                                            Some(secret_provider.clone()),
                                        )),
                                        Err(error_detail) => Err(error_detail),
                                    }
                                }
                                None => Err(Error::WrongInitialization(format!(
                                    "secret required to connect to host but secret_provider unset"
                                ))),
                            },
                        }
                    }
                    ConnectionMethod::Ssh2(ssh2_auth_reference) => {
                        match ssh2_auth_reference.auth_method {
                            Ssh2AuthReference::UsernamePassword(secret_reference) => {
                                match secret_provider {
                                    Some(secret_provider) => {
                                        match secret_provider
                                            .get_secret::<Credentials>(secret_reference.sec_ref())
                                        {
                                            Ok(secret) => Ok(ManagedHost::new(
                                                &self.endpoint,
                                                Handler::ss2(Ssh2HostHandler::from(
                                                    Ssh2AuthMethod::UsernamePassword(
                                                        secret.inner(),
                                                    ),
                                                )),
                                                self.vars,
                                                self.host_properties,
                                                Some(secret_provider.clone()),
                                            )),
                                            Err(error_detail) => Err(error_detail),
                                        }
                                    }
                                    None => Err(Error::WrongInitialization(format!(
                                        "secret required to connect to host but secret_provider unset"
                                    ))),
                                }
                            }
                            Ssh2AuthReference::KeyFile(secret_reference) => match secret_provider {
                                Some(secret_provider) => {
                                    match secret_provider
                                        .get_secret::<LoginKeyPath>(secret_reference.sec_ref())
                                    {
                                        Ok(secret) => Ok(ManagedHost::new(
                                            &self.endpoint,
                                            Handler::ss2(Ssh2HostHandler::from(
                                                Ssh2AuthMethod::KeyFile(secret.inner()),
                                            )),
                                            self.vars,
                                            self.host_properties,
                                            Some(secret_provider.clone()),
                                        )),
                                        Err(error_detail) => Err(error_detail),
                                    }
                                }
                                None => Err(Error::WrongInitialization(format!(
                                    "secret required to connect to host but secret_provider unset"
                                ))),
                            },
                            Ssh2AuthReference::Agent(agent_name) => {
                                // No secret required
                                Ok(ManagedHost::new(
                                    &self.endpoint,
                                    Handler::ss2(Ssh2HostHandler::from(
                                        crate::Ssh2AuthMethod::Agent(agent_name),
                                    )),
                                    self.vars,
                                    self.host_properties,
                                    secret_provider.clone(),
                                ))
                            }
                        }
                    }
                }
            }
            None => Err(Error::WrongInitialization(format!(
                "connection_method unset"
            ))),
        }
    }
}

#[derive(Clone)]
pub struct ManagedHost {
    endpoint: String,
    pub handler: Handler,
    vars: Option<HashMap<String, String>>,
    host_properties: Option<HostProperties>,
    secret_provider: Option<SecretsManagementSolution>,
}

impl ManagedHost {
    pub fn new(
        endpoint: &str,
        handler: Handler,
        vars: Option<HashMap<String, String>>,
        host_properties: Option<HostProperties>,
        secret_provider: Option<SecretsManagementSolution>,
    ) -> ManagedHost {
        ManagedHost {
            endpoint: endpoint.to_string(),
            handler,
            vars,
            host_properties,
            secret_provider,
        }
    }

    pub fn from(
        endpoint: &str,
        handler: Handler,
        vars: Option<impl IntoIterator<Item = (String, String)>>,
        host_properties: Option<HostProperties>,
        secret_provider: SecretsManagementSolution,
    ) -> ManagedHost {
        let final_vars = match vars {
            Some(vars_list) => {
                let mut final_vars: HashMap<String, String> = HashMap::new();

                for (key, value) in vars_list.into_iter() {
                    final_vars.insert(key, value);
                }

                Some(final_vars)
            }
            None => None,
        };

        ManagedHost {
            endpoint: endpoint.to_string(),
            handler,
            vars: final_vars,
            host_properties,
            secret_provider: Some(secret_provider),
        }
    }

    pub fn add_var(&mut self, key: String, value: String) {
        match &mut self.vars {
            Some(vars_list) => {
                vars_list.insert(key, value);
            }
            None => {
                let mut new_vars_list: HashMap<String, String> = HashMap::new();
                new_vars_list.insert(key, value);
                self.vars = Some(new_vars_list);
            }
        }
    }

    pub fn set_host_properties(&mut self, host_properties: Option<HostProperties>) {
        self.host_properties = host_properties;
    }

    pub fn collect_properties(&mut self) -> Result<(), Error> {
        match HostProperties::collect_dynamically(&mut self.handler) {
            Ok(host_properties) => {
                self.host_properties = Some(host_properties);
                Ok(())
            }
            Err(error_detail) => Err(error_detail),
        }
    }

    pub fn get_host_properties(&self) -> &Option<HostProperties> {
        &self.host_properties
    }

    pub fn connect(&mut self) -> Result<(), Error> {
        self.handler
            .connect(&self.endpoint, &self.secret_provider.clone().unwrap())
    }

    pub fn is_connected(&mut self) -> bool {
        self.handler.is_connected()
    }

    pub fn disconnect(&mut self) -> Result<(), Error> {
        self.handler.disconnect()
    }

    // Defaults to sequential assessment
    pub fn assess_compliance(
        &mut self,
        expected_state: &ExpectedState,
    ) -> Result<ManagedHostStatus, Error> {
        if !self.is_connected() {
            return Err(Error::NotConnectedToHost);
        }

        let mut already_compliant = true;
        let mut final_remediations_list: Vec<Remediation> = Vec::new();

        for attribute in &expected_state.attributes {
            match attribute.assess(&mut self.handler, &self.host_properties) {
                Ok(attribute_compliance) => {
                    if let AttributeComplianceAssessment::NonCompliant(remediations) =
                        attribute_compliance
                    {
                        already_compliant = false;
                        final_remediations_list.extend(remediations);
                    }
                }
                Err(error_detail) => {
                    return Err(error_detail);
                }
            }
        }

        if already_compliant {
            Ok(ManagedHostStatus::already_compliant())
        } else {
            Ok(ManagedHostStatus::not_compliant(final_remediations_list))
        }
    }

    pub fn assess_compliance_in_parallel(
        &mut self,
        expected_state: &ExpectedState,
    ) -> Result<ManagedHostStatus, Error> {
        if !self.is_connected() {
            return Err(Error::NotConnectedToHost);
        }

        let mut already_compliant = true;
        let mut final_remediations_list: Vec<Remediation> = Vec::new();

        let (sender, receiver) =
            std::sync::mpsc::channel::<Result<AttributeComplianceAssessment, Error>>();

        for attribute in &expected_state.attributes {
            let attribute_clone = attribute.clone();
            let sender_clone = sender.clone();
            std::thread::spawn({
                let mut host_handler = self.handler.clone();
                let host_properties = self.host_properties.clone();
                move || {
                    let result = attribute_clone.assess(&mut host_handler, &host_properties);
                    let _ = sender_clone.send(result);
                }
            });
        }

        for _ in 0..expected_state.attributes.len() {
            match receiver.recv() {
                Ok(result_dry_run_attribute) => match result_dry_run_attribute {
                    Ok(attribute_compliance) => {
                        if let AttributeComplianceAssessment::NonCompliant(remediations) =
                            attribute_compliance
                        {
                            already_compliant = false;
                            final_remediations_list.extend(remediations);
                        }
                    }
                    Err(error_detail) => {
                        return Err(error_detail);
                    }
                },
                Err(error_detail) => {
                    return Err(Error::FailedDryRunEvaluation(format!("{}", error_detail)));
                }
            }
        }

        if already_compliant {
            Ok(ManagedHostStatus::already_compliant())
        } else {
            Ok(ManagedHostStatus::not_compliant(final_remediations_list))
        }
    }

    pub fn reach_compliance(
        &mut self,
        expected_state: &ExpectedState,
    ) -> Result<ManagedHostStatus, Error> {
        if !self.is_connected() {
            return Err(Error::NotConnectedToHost);
        }

        let mut final_host_status = HostStatus::AlreadyCompliant;
        let mut reaching_compliance_failed = false;
        let mut actions_taken: Vec<Action> = Vec::new();

        for attribute in &expected_state.attributes {
            match attribute.assess(&mut self.handler, &self.host_properties) {
                Ok(attribute_compliance) => {
                    match attribute_compliance {
                        AttributeComplianceAssessment::Compliant => {
                            // Nothing to do
                        }
                        AttributeComplianceAssessment::NonCompliant(remediations) => {
                            // Host is not compliant as there are remediations to perform
                            // Host status switches from AlreadyCompliant to ReachComplianceSuccess by default
                            final_host_status = HostStatus::ReachComplianceSuccess;

                            // Try to remedy

                            for remediation in remediations {
                                match remediation
                                    .reach_compliance(&mut self.handler, &self.host_properties)
                                {
                                    Ok(internal_api_call_outcome) => {
                                        actions_taken.push(Action::from(
                                            remediation,
                                            Some(internal_api_call_outcome.clone()),
                                        ));

                                        if let InternalApiCallOutcome::Failure(_details) =
                                            internal_api_call_outcome
                                        {
                                            reaching_compliance_failed = true;
                                            final_host_status = HostStatus::ReachComplianceFailed;

                                            // Stop processing more mediations for this attribute
                                            break;
                                        }
                                    }
                                    Err(error_detail) => {
                                        // TODO : return the whole automation up to this point, and not just an error without context like this
                                        return Err(error_detail);
                                    }
                                }
                            }

                            if reaching_compliance_failed {
                                // Stop processing more attributes
                                break;
                            }
                        }
                    }
                }
                Err(error_detail) => {
                    return Err(error_detail);
                }
            }
        }

        if let HostStatus::ReachComplianceFailed = final_host_status {
            Ok(ManagedHostStatus::reach_compliance_failed(actions_taken))
        } else {
            Ok(ManagedHostStatus::reach_compliance_success(actions_taken))
        }
    }
}

pub trait AssessCompliance<Handler: HostHandler> {
    fn assess_compliance(
        &self,
        host_handler: &mut Handler,
        host_properties: &Option<HostProperties>,
        privilege: &Privilege,
    ) -> Result<AttributeComplianceAssessment, Error>;
}

pub trait ReachCompliance<Handler: HostHandler> {
    fn call(
        &self,
        host_handler: &mut Handler,
        host_properties: &Option<HostProperties>,
    ) -> Result<InternalApiCallOutcome, Error>;
}

#[derive(Serialize, Deserialize)]
pub enum AttributeLevelOperationOutcome {
    AlreadyCompliant,
    NotCompliant(Vec<Remediation>),
    ReachComplianceFailed(InternalApiCallOutcome),
    ComplianceReachedWithAllowedFailure(InternalApiCallOutcome),
    ComplianceReached(Vec<(Remediation, InternalApiCallOutcome)>),
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub enum InternalApiCallOutcome {
    Success,
    Failure(String),
    AllowedFailure(String),
}

// #[derive(Clone, Serialize, Deserialize, Debug)]
// pub struct ManagedHostIntermediateRepresentation {
//     alias: String,
//     endpoint: String,
//     connection_type: ConnectionType,
//     #[serde(skip_serializing)]
//     connection_secrets_ref: String,
//     vars: Option<HashMap<String, String>>,
// }

// impl ManagedHostIntermediateRepresentation {
//     pub fn to_managed_host<Handler: HostHandler + Clone + Send + 'static>(
//         self
//     ) -> ManagedHost {

//         let endpoint: String = self.endpoint;

//         let mut vars: HashMap<String, String> = HashMap::new();
//         if let Some(vars_list) = self.vars {
//             vars.extend(vars_list);
//         }

//         match self.connection.kind {
//             HandlerKind::Localhost(local_host_handler) => {
//                 ManagedHost::from(endpoint, handler, vars) { endpoint, handler: local_host_handler, vars }

//             }
//             HandlerKind::Ssh2(ssh2_auth_method) => {
//                 Ssh2HostHandler::from(ssh2_auth_method)
//             }
//         }
//     }
// }

// #[derive(Clone, Serialize, Deserialize, Debug)]
// pub enum ConnectionType {
//     Localhost,
//     Ssh2,
// }

// #[cfg(test)]
// mod tests {
//     use crate::{LocalHostHandler, secrets::local::environment_variables::EnvVarSecretProvider};

//     use super::*;

//     #[test]
//     fn test_deserialize_localhost_managed_host_from_yaml() {
//         let yaml_content = r#"
// endpoint: "localhost"
// handler:
//     user: CurrentUser
// vars: {}
// secret_provider: !EnvironmentVariable
// "#; // EnvVarSecretProvider

//         let managed_host: ManagedHost<LocalHostHandler> =
//             yaml_serde::from_str(yaml_content).unwrap();
//         assert_eq!(managed_host.endpoint, "localhost");
//     }
// }
