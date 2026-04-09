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
use crate::hosts::privilege::LoginKey;
use crate::hosts::privilege::Privilege;
use crate::hosts::properties::HostProperties;
use crate::secrets::SecretProvider;
use crate::state::ExpectedState;
use crate::state::attribute::Remediation;
use crate::state::compliance::Action;
use crate::state::compliance::AttributeComplianceAssessment;
use crate::state::compliance::HostStatus;
use crate::state::compliance::ManagedHostStatus;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
#[serde(deny_unknown_fields)]
pub struct ManagedHostBuilder {
    pub id: String,
    endpoint: String,
    pub host_connection_method: Option<ConnectionMethod>,
    host_properties: Option<HostProperties>,
    pub host_vars: Option<HashMap<String, String>>,
}

impl ManagedHostBuilder {
    pub fn new(id: &str, endpoint: &str, connection_method: Option<ConnectionMethod>) -> Self {
        Self {
            id: id.to_string(),
            endpoint: endpoint.to_string(),
            host_connection_method: connection_method,
            host_properties: None,
            host_vars: None,
        }
    }

    pub fn set_connection_method(&mut self, connection_method: ConnectionMethod) {
        self.host_connection_method = Some(connection_method);
    }

    pub fn set_host_vars(&mut self, host_vars: Option<HashMap<String, String>>) {
        self.host_vars = host_vars;
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

    pub fn build(self, secret_provider: &Option<SecretProvider>) -> Result<ManagedHost, Error> {
        // Check that each required field is set
        if let None = self.host_connection_method {
            return Err(Error::WrongInitialization(format!(
                "connection method unset"
            )));
        }

        // Retrieve connection secrets when needed
        match self.host_connection_method {
            Some(connection) => {
                match connection {
                    ConnectionMethod::Localhost(target_user) => {
                        match target_user.user_kind {
                            TargetUserKind::CurrentUser => {
                                // No secret required
                                Ok(ManagedHost::new(
                                    self.id,
                                    &self.endpoint,
                                    Handler::localhost(LocalHostHandler::from(
                                        WhichUser::CurrentUser,
                                    )),
                                    self.host_vars,
                                    self.host_properties,
                                    secret_provider.clone(),
                                ))
                            }
                            TargetUserKind::User(secret_reference) => match secret_provider {
                                Some(secret_provider) => {
                                    match secret_provider
                                        .get_secret_typed::<Credentials>(secret_reference.sec_ref())
                                    {
                                        Ok(secret) => Ok(ManagedHost::new(
                                            self.id,
                                            &self.endpoint,
                                            Handler::localhost(LocalHostHandler::from(
                                                WhichUser::UsernamePassword(secret.inner()),
                                            )),
                                            self.host_vars,
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
                                        match secret_provider.get_secret_typed::<Credentials>(
                                            secret_reference.sec_ref(),
                                        ) {
                                            Ok(secret) => Ok(ManagedHost::new(
                                                self.id,
                                                &self.endpoint,
                                                Handler::ss2(Ssh2HostHandler::from(
                                                    Ssh2AuthMethod::UsernamePassword(
                                                        secret.inner(),
                                                    ),
                                                )),
                                                self.host_vars,
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
                            Ssh2AuthReference::Key(login_key_ref) => match secret_provider {
                                Some(secret_provider) => {
                                    match secret_provider.get_secret_raw(login_key_ref.key_ref()) {
                                        Ok(secret) => Ok(ManagedHost::new(
                                            self.id,
                                            &self.endpoint,
                                            Handler::ss2(Ssh2HostHandler::from(
                                                Ssh2AuthMethod::Key(LoginKey::from(
                                                    login_key_ref.username().to_string(),
                                                    secret.inner(),
                                                )),
                                            )),
                                            self.host_vars,
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
                                    self.id,
                                    &self.endpoint,
                                    Handler::ss2(Ssh2HostHandler::from(
                                        crate::Ssh2AuthMethod::Agent(agent_name),
                                    )),
                                    self.host_vars,
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
    id: String,
    endpoint: String,
    pub handler: Handler,
    context: tera::Context,
    host_properties: Option<HostProperties>,
    secret_provider: Option<SecretProvider>,
}

impl ManagedHost {
    pub fn new(
        id: String,
        endpoint: &str,
        handler: Handler,
        host_vars: Option<HashMap<String, String>>,
        host_properties: Option<HostProperties>,
        secret_provider: Option<SecretProvider>,
    ) -> ManagedHost {
        ManagedHost {
            id,
            endpoint: endpoint.to_string(),
            handler,
            context: tera::Context::from_serialize(host_vars).unwrap(),
            host_properties,
            secret_provider,
        }
    }

    pub fn from(
        id: String,
        endpoint: &str,
        handler: Handler,
        vars: Option<impl IntoIterator<Item = (String, String)>>,
        host_properties: Option<HostProperties>,
        secret_provider: SecretProvider,
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
            id,
            endpoint: endpoint.to_string(),
            handler,
            context: tera::Context::from_serialize(final_vars).unwrap(),
            host_properties,
            secret_provider: Some(secret_provider),
        }
    }

    pub fn id(&self) -> &str {
        &self.id
    }

    pub fn add_var(&mut self, key: String, value: String) {
        self.context.insert(key, &value);
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

        for attribute in expected_state.attributes.clone().iter_mut() {
            // Taking context into account before working on the Attribute
            match attribute.consider_context(&self.context) {
                Ok(context_aware_attribute) => {
                    match context_aware_attribute.assess(&mut self.handler, &self.host_properties) {
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
            // Taking context into account before working on the Attribute

            match attribute.consider_context(&self.context) {
                Ok(context_aware_attribute) => {
                    let sender_clone = sender.clone();
                    std::thread::spawn({
                        let mut host_handler = self.handler.clone();
                        let host_properties = self.host_properties.clone();
                        move || {
                            let result =
                                context_aware_attribute.assess(&mut host_handler, &host_properties);
                            let _ = sender_clone.send(result);
                        }
                    });
                }
                Err(error_detail) => {
                    return Err(error_detail);
                }
            }
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
            match attribute.consider_context(&self.context) {
                Ok(context_aware_attribute) => {
                    match context_aware_attribute.assess(&mut self.handler, &self.host_properties) {
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
                                        match remediation.reach_compliance(
                                            &mut self.handler,
                                            &self.host_properties,
                                        ) {
                                            Ok(internal_api_call_outcome) => {
                                                actions_taken.push(Action::from(
                                                    remediation,
                                                    Some(internal_api_call_outcome.clone()),
                                                ));

                                                if let InternalApiCallOutcome::Failure(_details) =
                                                    internal_api_call_outcome
                                                {
                                                    reaching_compliance_failed = true;
                                                    final_host_status =
                                                        HostStatus::ReachComplianceFailed;

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
//         if let Some(vars_list) = self.host_vars {
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
