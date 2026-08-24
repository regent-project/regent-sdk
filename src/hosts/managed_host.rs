//! Managed host and builder
//!
//! This module provides the [`ManagedHost`] and [`ManagedHostBuilder`] types for
//! managing connections to target hosts and executing compliance operations.

use serde::{Deserialize, Serialize};
use tracing::Instrument;
use std::collections::HashMap;
use std::time::Duration;
use tracing::Level;
use tracing::span;
#[allow(unused)]
use tracing::{debug, error, info, trace, warn};

use crate::LocalHostHandler;
use crate::Ssh2AuthMethod;
use crate::Ssh2HostHandler;
use crate::WhichUser;
use crate::error::RegentError;
use crate::hosts::handlers::ConnectionMethod;
use crate::hosts::handlers::Handler;
use crate::hosts::handlers::HostHandler;
use crate::hosts::handlers::TargetUserKind;
use crate::hosts::handlers::ssh2::Ssh2AuthReference;
use crate::hosts::privilege::Credentials;
use crate::hosts::privilege::LoginKey;
use crate::hosts::privilege::Privilege;
use crate::hosts::properties::HostProperties;
use crate::secrets::SecretProvidersPool;
use crate::state::ExpectedState;
use crate::state::attribute::Remediation;
use crate::state::compliance::Action;
use crate::state::compliance::AttributeComplianceAssessment;
use crate::state::compliance::HostStatus;
use crate::state::compliance::ManagedHostStatus;

/// Represents the connection state of a managed host.
///
/// This enum tracks whether a host is currently connected, disconnected, or in an error state,
/// enabling proper state management and preventing issues like double-connection or
/// reconnection failures due to stale state.
#[derive(Clone, Serialize, Deserialize, Debug, PartialEq)]
pub enum ConnectionState {
    /// The host is currently disconnected.
    Disconnected,
    /// The host is currently connected and ready for operations.
    Connected,
    /// The host connection state is unknown (e.g., after a failed connection attempt).
    Unknown,
}

impl Default for ConnectionState {
    fn default() -> Self {
        ConnectionState::Disconnected
    }
}

/// Builder for creating [`ManagedHost`] instances.
///
/// This struct is used to configure a managed host before it's built and connected.
/// It holds all the configuration needed to establish a connection and manage the host.
///
/// # Serialization
///
/// `ManagedHostBuilder` can be serialized and deserialized as JSON or YAML:
///
/// ```no_run
/// use regent_sdk::hosts::managed_host::ManagedHostBuilder;
/// use regent_sdk::hosts::handlers::{ConnectionMethod, TargetUser};
///
/// let builder = ManagedHostBuilder::new(
///     "web-server-01",
///     "192.168.1.100:22",
///     Some(ConnectionMethod::Localhost(TargetUser::current_user())),
/// );
///
/// let yaml = serde_yaml::to_string(&builder).unwrap();
/// let json = serde_json::to_string(&builder).unwrap();
/// ```
///
/// # Example
///
/// ```no_run
/// use regent_sdk::hosts::managed_host::ManagedHostBuilder;
/// use regent_sdk::hosts::handlers::{ConnectionMethod, TargetUser};
/// use regent_sdk::secrets::{SecretProvider, SecretProvidersPoolBuilder};
///
/// let builder = ManagedHostBuilder::new(
///     "web-server-01",
///     "192.168.1.100:22",
///     Some(ConnectionMethod::Localhost(TargetUser::current_user())),
/// );
///
/// let secrets_pool = SecretProvidersPoolBuilder::new()
///     .add_default_provider("files", SecretProvider::files())
///     .build()
///     .unwrap();
///
/// let managed_host = builder.build(Some(secrets_pool)).await.unwrap();
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
#[serde(deny_unknown_fields)]
pub struct ManagedHostBuilder {
    /// Unique identifier for this managed host.
    ///
    /// Used for tracking and logging purposes.
    pub id: String,
    /// The network endpoint for the host (e.g., "192.168.1.100:22" or "localhost").
    endpoint: String,
    /// The connection method to use for connecting to the host.
    pub host_connection_method: Option<ConnectionMethod>,
    /// Optional host properties that have been collected.
    host_properties: Option<HostProperties>,
    /// Optional host-specific variables for templating.
    ///
    /// These variables are available during template rendering and can be used
    /// to customize attribute behavior per host.
    pub host_vars: Option<HashMap<String, String>>,
}

impl ManagedHostBuilder {
    /// Create a new managed host builder.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use regent_sdk::hosts::managed_host::ManagedHostBuilder;
    /// use regent_sdk::hosts::handlers::{ConnectionMethod, TargetUser};
    ///
    /// let builder = ManagedHostBuilder::new(
    ///     "web-server-01",
    ///     "192.168.1.100:22",
    ///     Some(ConnectionMethod::Localhost(TargetUser::current_user())),
    /// );
    /// ```
    pub fn new(id: &str, endpoint: &str, connection_method: Option<ConnectionMethod>) -> Self {
        Self {
            id: id.to_string(),
            endpoint: endpoint.to_string(),
            host_connection_method: connection_method,
            host_properties: None,
            host_vars: None,
        }
    }

    pub fn id(&self) -> &str {
        &self.id
    }

    /// Set the connection method for this host.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use regent_sdk::hosts::managed_host::ManagedHostBuilder;
    /// use regent_sdk::hosts::handlers::{ConnectionMethod, TargetUser};
    ///
    /// let mut builder = ManagedHostBuilder::new("host-01", "localhost", None);
    /// builder.set_connection_method(ConnectionMethod::Localhost(TargetUser::current_user()));
    /// ```
    pub fn set_connection_method(&mut self, connection_method: ConnectionMethod) {
        self.host_connection_method = Some(connection_method);
    }

    /// Set the host variables for templating.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use regent_sdk::hosts::managed_host::ManagedHostBuilder;
    /// use std::collections::HashMap;
    ///
    /// let mut builder = ManagedHostBuilder::new("host-01", "localhost", None);
    ///
    /// let mut vars = HashMap::new();
    /// vars.insert("env".to_string(), "production".to_string());
    /// vars.insert("region".to_string(), "us-east-1".to_string());
    ///
    /// builder.set_host_vars(Some(vars));
    /// ```
    pub fn set_host_vars(&mut self, host_vars: Option<HashMap<String, String>>) {
        self.host_vars = host_vars;
    }

    /// Parse a managed host builder from raw YAML content.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use regent_sdk::hosts::managed_host::ManagedHostBuilder;
    ///
    /// let yaml = r#"
    /// Id: web-server-01
    /// Endpoint: 192.168.1.100:22
    /// HostConnectionMethod:
    ///   Localhost:
    ///     UserKind: CurrentUser
    /// "#;
    ///
    /// let builder = ManagedHostBuilder::from_raw_yaml(yaml).unwrap();
    /// ```
    pub fn from_raw_yaml(raw_yaml: &str) -> Result<Self, RegentError> {
        match yaml_serde::from_str::<Self>(raw_yaml) {
            Ok(managed_host_builder) => Ok(managed_host_builder),
            Err(details) => Err(RegentError::FailureToParseContent(format!("{:?}", details))),
        }
    }

    /// Parse a managed host builder from raw JSON content.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use regent_sdk::hosts::managed_host::ManagedHostBuilder;
    ///
    /// let json = r#"{"Id":"web-server-01","Endpoint":"192.168.1.100:22"}"#;
    /// let builder = ManagedHostBuilder::from_raw_json(json).unwrap();
    /// ```
    pub fn from_raw_json(raw_json: &str) -> Result<Self, RegentError> {
        match serde_json::from_str::<Self>(raw_json) {
            Ok(managed_host_builder) => Ok(managed_host_builder),
            Err(details) => Err(RegentError::FailureToParseContent(format!("{:?}", details))),
        }
    }

    pub async fn build(
        self,
        optional_secret_provider: Option<SecretProvidersPool>,
    ) -> Result<ManagedHost, RegentError> {
        // Check that each required field is set
        if let None = self.host_connection_method {
            return Err(RegentError::WrongInitialization(format!(
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
                                    optional_secret_provider,
                                ))
                            }
                            TargetUserKind::User(secret_reference) => {
                                match &optional_secret_provider {
                                    Some(secret_provider) => {
                                        match secret_provider
                                            .get_secret_typed::<Credentials>(&secret_reference)
                                            .await
                                        {
                                            Ok(secret) => Ok(ManagedHost::new(
                                                self.id,
                                                &self.endpoint,
                                                Handler::localhost(LocalHostHandler::from(
                                                    WhichUser::UsernamePassword(secret.inner()),
                                                )),
                                                self.host_vars,
                                                self.host_properties,
                                                optional_secret_provider,
                                            )),
                                            Err(details) => Err(details),
                                        }
                                    }
                                    None => Err(RegentError::WrongInitialization(format!(
                                        "secret required to connect to host but secret_provider unset"
                                    ))),
                                }
                            }
                        }
                    }
                    ConnectionMethod::Ssh2(ssh2_auth_reference) => {
                        match ssh2_auth_reference.auth_method {
                            Ssh2AuthReference::UsernamePassword(secret_reference) => {
                                match &optional_secret_provider {
                                    Some(secret_provider) => {
                                        match secret_provider
                                            .get_secret_typed::<Credentials>(&secret_reference)
                                            .await
                                        {
                                            Ok(secret) => Ok(ManagedHost::new(
                                                self.id,
                                                &self.endpoint,
                                                Handler::ss2(Ssh2HostHandler::NotConnected(
                                                    Ssh2AuthMethod::UsernamePassword(
                                                        secret.inner(),
                                                    ),
                                                )),
                                                self.host_vars,
                                                self.host_properties,
                                                optional_secret_provider,
                                            )),
                                            Err(details) => Err(details),
                                        }
                                    }
                                    None => Err(RegentError::WrongInitialization(format!(
                                        "secret required to connect to host but secret_provider unset"
                                    ))),
                                }
                            }
                            Ssh2AuthReference::Key(login_key_ref) => {
                                match &optional_secret_provider {
                                    Some(secret_provider) => {
                                        match secret_provider
                                            .get_secret_raw(login_key_ref.key_ref())
                                            .await
                                        {
                                            Ok(secret) => Ok(ManagedHost::new(
                                                self.id,
                                                &self.endpoint,
                                                Handler::ss2(Ssh2HostHandler::NotConnected(
                                                    Ssh2AuthMethod::Key(LoginKey::from(
                                                        login_key_ref.username().to_string(),
                                                        secret.inner(),
                                                    )),
                                                )),
                                                self.host_vars,
                                                self.host_properties,
                                                optional_secret_provider,
                                            )),
                                            Err(details) => Err(details),
                                        }
                                    }
                                    None => Err(RegentError::WrongInitialization(format!(
                                        "secret required to connect to host but secret_provider unset"
                                    ))),
                                }
                            }
                        }
                    }
                }
            }
            None => Err(RegentError::WrongInitialization(format!(
                "connection_method unset"
            ))),
        }
    }
}

/// A managed host that can execute compliance operations.
///
/// `ManagedHost` represents a target system that can be connected to and managed.
/// It provides methods for assessing and reaching compliance with expected states.
///
/// # Lifecycle
///
/// 1. Create using [`ManagedHostBuilder::build()`]
/// 2. Connect using [`ManagedHost::connect()`]
/// 3. Execute operations (assess/reach compliance)
/// 4. Disconnect using [`ManagedHost::disconnect()`]
///
/// # Example
///
/// ```no_run
/// use regent_sdk::hosts::managed_host::{ManagedHost, ManagedHostBuilder};
/// use regent_sdk::hosts::handlers::{ConnectionMethod, TargetUser};
/// use regent_sdk::state::ExpectedState;
///
/// let builder = ManagedHostBuilder::new(
///     "web-server-01",
///     "192.168.1.100:22",
///     Some(ConnectionMethod::Localhost(TargetUser::current_user())),
/// );
///
/// let mut host = builder.build(None).await.unwrap();
/// host.connect().unwrap();
///
/// let expected_state = ExpectedState::new();
/// let status = host.assess_compliance(&expected_state).await.unwrap();
///
/// host.disconnect().unwrap();
/// ```
// #[derive(Clone)]
pub struct ManagedHost {
    /// Unique identifier for this managed host.
    id: String,
    /// The network endpoint for the host.
    endpoint: String,
    /// The handler used for connecting and executing commands on the host.
    pub handler: Handler,
    /// Tera context for template rendering with host variables.
    context: tera::Context,
    /// Cached host properties (OS, architecture, etc.).
    host_properties: Option<HostProperties>,
    /// Secret providers pool for retrieving secrets.
    // TODO : how to avoid cloning the whole Pool for each Host ? Is it worth introducting Arc<Mutex<T>> ?
    secret_providers: Option<SecretProvidersPool>,
    /// The current connection state of this host.
    ///
    /// This tracks whether the host is connected, disconnected, or in an unknown state,
    /// enabling proper idempotency for connection/disconnection operations.
    connection_state: ConnectionState,
}

impl Clone for ManagedHost {
    fn clone(&self) -> Self {
        Self {
            id: self.id.clone(),
            endpoint: self.endpoint.clone(),
            handler: self.handler.clone(),
            context: self.context.clone(),
            host_properties: self.host_properties.clone(),
            secret_providers: self.secret_providers.clone(),
            connection_state: self.connection_state.clone(),
        }
    }
}

impl ManagedHost {
    /// Create a new managed host.
    pub fn new(
        id: String,
        endpoint: &str,
        handler: Handler,
        host_vars: Option<HashMap<String, String>>,
        host_properties: Option<HostProperties>,
        secret_providers: Option<SecretProvidersPool>,
    ) -> ManagedHost {
        let context = match host_vars {
            Some(content) => match tera::Context::from_serialize(&content) {
                Ok(context) => context,
                Err(details) => {
                    error!("Failed to create Tera context : {:?}", details);
                    // TODO : turn this into an Err -> return type of this function -> Result
                    tera::Context::new()
                }
            },
            None => tera::Context::new(),
        };
        ManagedHost {
            id,
            endpoint: endpoint.to_string(),
            handler,
            context,
            host_properties,
            secret_providers: secret_providers.clone(),
            connection_state: ConnectionState::Disconnected,
        }
    }

    /// Create a new managed host from an iterator of variables.
    ///
    /// This is a convenience constructor that accepts variables as an iterator.
    ///
    pub fn from(
        id: String,
        endpoint: &str,
        handler: Handler,
        vars: Option<impl IntoIterator<Item = (String, String)>>,
        host_properties: Option<HostProperties>,
        secret_providers: Option<SecretProvidersPool>,
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
            context: tera::Context::from_serialize(&final_vars).unwrap(),
            host_properties,
            secret_providers: secret_providers.clone(),
            connection_state: ConnectionState::Disconnected,
        }
    }

    /// Get the unique identifier for this managed host.
    pub fn id(&self) -> &str {
        &self.id
    }

    /// Add a variable to the host's template context.
    ///
    /// This variable will be available during template rendering for attributes.
    pub fn add_var(&mut self, key: String, value: String) {
        if self.context.contains_key(&key) {
            warn!(
                key,
                "Writing an already-existing variable to context. Is this expected ?"
            );
        }
        self.context.insert(key, &value);
    }

    /// Set the host properties.
    ///
    /// This replaces any existing host properties with the provided value.
    pub fn set_host_properties(&mut self, host_properties: Option<HostProperties>) {
        self.host_properties = host_properties;
    }

    /// Enable secret caching for this managed host.
    ///
    /// This ensures that secrets retrieved during assessment and enforcement
    /// phases are the same, even if the underlying secrets are rotated.
    /// This is crucial for idempotency in compliance operations.
    pub fn enable_secret_caching(&mut self) {
        if let Some(secret_providers) = &mut self.secret_providers {
            secret_providers.enable_caching();
        }
    }

    /// Disable secret caching for this managed host.
    pub fn disable_secret_caching(&mut self) {
        if let Some(secret_providers) = &mut self.secret_providers {
            secret_providers.disable_caching();
        }
    }

    /// Collect host properties dynamically from the host.
    ///
    /// This method connects to the host and collects information about its
    /// operating system, architecture, and other properties.
    ///
    pub async fn collect_properties(&mut self) -> Result<(), RegentError> {
        if matches!(self.host_properties, None) {
            match HostProperties::collect_dynamically(&mut self.handler).await {
                Ok(host_properties) => {
                    self.host_properties = Some(host_properties);
                }
                Err(details) => {
                    return Err(details);
                }
            }
        } else {
            warn!("HostProperties already collected. Logic error ?");
        }
        Ok(())
    }

    /// Get the host properties.
    pub fn get_host_properties(&self) -> &Option<HostProperties> {
        &self.host_properties
    }

    /// Connect to the host.
    ///
    /// This method establishes a connection to the host using the configured handler.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use regent_sdk::hosts::managed_host::ManagedHost;
    ///
    /// let mut host = /* create host */;
    /// host.connect().unwrap();
    /// assert!(host.is_connected());
    /// ```
    pub async fn connect(&mut self) -> Result<(), RegentError> {
        let result = self.handler.connect(&self.endpoint).await;
        if result.is_ok() {
            self.connection_state = ConnectionState::Connected;
        } else {
            self.connection_state = ConnectionState::Unknown;
        }
        result
    }

    /// Check if the host is currently connected.
    pub async fn is_connected(&mut self) -> bool {
        self.handler.is_connected().await
    }

    /// Check the tracked connection state of this host.
    ///
    /// Unlike `is_connected()`, which queries the underlying handler,
    /// this returns the tracked state that was last set by `connect()` or `disconnect()`.
    ///
    pub fn connection_state(&self) -> &ConnectionState {
        &self.connection_state
    }

    /// Check if the host is in a tracked connected state.
    ///
    /// This returns `true` if the tracked state is `Connected`, regardless of
    /// the actual underlying handler state. Use `is_connected()` to check
    /// the actual connection status.
    ///
    pub fn is_tracked_connected(&self) -> bool {
        matches!(self.connection_state, ConnectionState::Connected)
    }

    /// Check if the host is in a tracked disconnected state.
    ///
    /// This returns `true` if the tracked state is `Disconnected`.
    ///
    pub fn is_tracked_disconnected(&self) -> bool {
        matches!(self.connection_state, ConnectionState::Disconnected)
    }

    /// Disconnect from the host.
    ///
    pub async fn disconnect(&mut self) -> Result<(), RegentError> {
        let result = self.handler.disconnect().await;
        if result.is_ok() {
            self.connection_state = ConnectionState::Disconnected;
        } else {
            self.connection_state = ConnectionState::Unknown;
        }
        result
    }

    /// Assess compliance of the host with the expected state.
    ///
    /// This method checks each attribute in the expected state and determines
    /// whether the host is compliant. It does not make any changes to the host.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use regent_sdk::hosts::managed_host::ManagedHost;
    /// use regent_sdk::state::{ExpectedState, Attribute};
    ///
    /// let mut host = /* create and connect host */;
    /// let expected_state = ExpectedState::new()
    ///     .with_attribute(Attribute::service(/* ... */))
    ///     .build();
    ///
    /// let status = host.assess_compliance(&expected_state).await.unwrap();
    ///
    /// if status.is_already_compliant() {
    ///     println!("Host is compliant!");
    /// } else {
    ///     println!("Host needs remediation");
    /// }
    /// ```
    // Defaults to sequential assessment
    pub async fn assess_compliance(
        &mut self,
        expected_state: &ExpectedState,
        logging: bool
    ) -> Result<ManagedHostStatus, RegentError> {
        if !self.is_connected().await {
            return Err(RegentError::NotConnectedToHost);
        }
        
        // Enable secret caching to ensure idempotency
        self.enable_secret_caching();
        
        let mut already_compliant = true;
        let mut final_remediations_list: Vec<Remediation> = Vec::new();
        
        for attribute in expected_state.attributes.clone().iter_mut() {
            let attribute_span = span!(Level::INFO, "attribute", name = attribute.name());

            // We execute the entire loop iteration inside an instrumented async block for tracing consistency
            let iteration_result = async {
                // Taking context into account before working on the Attribute
                match attribute.consider_context(&self.context) {
                    Ok(context_aware_attribute) => {
                        match context_aware_attribute
                            .assess(
                                &mut self.handler,
                                &self.host_properties,
                                &self.secret_providers,
                            )
                            .await
                        {
                            Ok(attribute_compliance_assessment) => {
                                match attribute_compliance_assessment {
                                    AttributeComplianceAssessment::Compliant => {
                                        if logging {
                                            info!(target: "run", "Compliant");
                                        }
                                        Ok(Some(Vec::new())) // Compliant, no remediations
                                    }
                                    AttributeComplianceAssessment::NonCompliant(remediations) => {
                                        if logging {
                                            warn!(target: "run", remediations = ?remediations.remediations(), "Not compliant");
                                        }
                                        Ok(Some(remediations.into_inner()))
                                    }
                                    AttributeComplianceAssessment::NonCompliantFatal(details) => {
                                        if logging {
                                            error!(target: "run", details, "Not compliant and no remediation possible");
                                        }
                                        Ok(None) // Non-compliant fatal, can't remediate
                                    }
                                }
                            }
                            Err(details) => Err(details),
                        }
                    }
                    Err(details) => {
                        let content = match &details {
                            RegentError::FailureToConsiderContext(content) => content,
                            _ => &format!("{:?}", details),
                        };
                        error!("{}", content);
                        Err(details)
                    }
                }
            }
            .instrument(attribute_span) // <-- Captures EVERYTHING inside the async block
            .await;

            // Process the control-flow state safely outside the span tracking lifecycle
            match iteration_result {
                Ok(Some(remediations)) => {
                    if !remediations.is_empty() {
                        already_compliant = false;
                        final_remediations_list.extend(remediations);
                    }
                }
                Ok(None) => {
                    already_compliant = false;
                }
                Err(details) => {
                    return Err(details);
                }
            }
        }

        if already_compliant {
            Ok(ManagedHostStatus::already_compliant())
        } else {
            Ok(ManagedHostStatus::not_compliant(final_remediations_list))
        }
    }

    /// Automatically reach compliance with the expected state.
    ///
    /// This method assesses compliance and then automatically performs the necessary
    /// remediations to bring the host into the expected state. It will stop at the
    /// first failure unless all remediations are marked as allowed to fail.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use regent_sdk::hosts::managed_host::ManagedHost;
    /// use regent_sdk::state::{ExpectedState, Attribute};
    ///
    /// let mut host = /* create and connect host */;
    /// let expected_state = ExpectedState::new()
    ///     .with_attribute(Attribute::service(/* ... */))
    ///     .build();
    ///
    /// let result = host.reach_compliance(&expected_state).await.unwrap();
    ///
    /// if result.is_reach_compliance_success() {
    ///     println!("Compliance reached successfully!");
    /// } else if result.is_reach_compliance_failed() {
    ///     println!("Failed to reach compliance");
    /// }
    /// ```
    pub async fn reach_compliance(
        &mut self,
        expected_state: &ExpectedState,
    ) -> Result<ManagedHostStatus, RegentError> {
        if !self.is_connected().await {
            return Err(RegentError::NotConnectedToHost);
        }

        // Enable secret caching to ensure idempotency
        self.enable_secret_caching();

        let mut final_host_status = HostStatus::AlreadyCompliant;
        let mut reaching_compliance_failed = false;
        let mut actions_taken: Vec<Action> = Vec::new();

        for attribute in &expected_state.attributes {
            let attribute_span = span!(Level::INFO, "attribute", name = attribute.name());

            // Wrap the logic into an instrumented async block to facilitate tracing
            let iteration_result = async {
                match attribute.consider_context(&self.context) {
                    Ok(context_aware_attribute) => {
                        let timeout_duration = context_aware_attribute.timeout()?;

                        match context_aware_attribute
                            .assess(
                                &mut self.handler,
                                &self.host_properties,
                                &self.secret_providers,
                            )
                            .await
                        {
                            Ok(attribute_compliance) => {
                                match attribute_compliance {
                                    AttributeComplianceAssessment::Compliant => {
                                        info!(target: "run", "Compliant");
                                        // Return progress updates back to the parent collector
                                        Ok(LoopControl::Continue)
                                    }
                                    AttributeComplianceAssessment::NonCompliant(remediations) => {
                                        warn!(target: "run", remediations = ?remediations.remediations(), "Not compliant");

                                        let mut local_failed = false;
                                        let mut local_actions = Vec::new();

                                        for remediation in remediations.iter() {
                                            match remediation
                                                .reach_compliance(
                                                    &mut self.handler,
                                                    &self.host_properties,
                                                    &self.secret_providers,
                                                    timeout_duration,
                                                )
                                                .await
                                            {
                                                Ok(internal_api_call_outcome) => {
                                                    local_actions.push(Action::from(
                                                        remediation.clone(),
                                                        Some(internal_api_call_outcome.clone()),
                                                    ));

                                                    match &internal_api_call_outcome {
                                                        InternalApiCallOutcome::Success(details) => {
                                                            info!(target: "run", remediation_outcome = "Success", "{:?} : {}", remediation, details.clone().unwrap_or("no details".to_string()));
                                                        }
                                                        InternalApiCallOutcome::AllowedFailure(details) => {
                                                            info!(target: "run", remediation_outcome = "AllowedFailure", "Allowed failure occured : {}", details);
                                                        }
                                                        InternalApiCallOutcome::Failure(details) => {
                                                            local_failed = true;
                                                            warn!(remediation_outcome = "Failure", "Attribute not met : {}", details);
                                                            // Break the local remediation sub-loop
                                                            break;
                                                        }
                                                    }
                                                }
                                                Err(details) => {
                                                    warn!("Failed to apply remediation");
                                                    return Err(details);
                                                }
                                            }
                                        }

                                        Ok(LoopControl::Remediated { 
                                            failed: local_failed, 
                                            actions: local_actions 
                                        })
                                    }
                                    AttributeComplianceAssessment::NonCompliantFatal(details) => {
                                        error!(target: "run", details, "Not compliant and no remediation possible");
                                        Ok(LoopControl::Fatal)
                                    }
                                }
                            }
                            Err(details) => {
                                warn!(reason = ?details, "Failed assessment");
                                Err(details)
                            }
                        }
                    }
                    Err(details) => {
                        let content = match &details {
                            RegentError::FailureToConsiderContext(content) => content,
                            _ => &format!("{:?}", details),
                        };
                        error!("{}", content);
                        Err(details)
                    }
                }
            }
            .instrument(attribute_span) // <-- Seamlessly maintains 'attribute' tracing span across everything
            .await;

            // Process loop control and state changes outside of the tracing block context
            match iteration_result {
                Ok(LoopControl::Continue) => {}
                Ok(LoopControl::Fatal) => {
                    final_host_status = HostStatus::ReachComplianceFailed;
                }
                Ok(LoopControl::Remediated { failed, actions }) => {
                    actions_taken.extend(actions);
                    if failed {
                        // reaching_compliance_failed = true;
                        final_host_status = HostStatus::ReachComplianceFailed;
                        break; // Stop processing further attributes due to failure
                    } else {
                        final_host_status = HostStatus::ReachComplianceSuccess;
                    }
                }
                Err(details) => {
                    return Err(details);
                }
            }
        }

        match final_host_status {
            HostStatus::AlreadyCompliant => Ok(ManagedHostStatus::already_compliant()),
            HostStatus::ReachComplianceFailed => {
                Ok(ManagedHostStatus::reach_compliance_failed(actions_taken))
            }
            _ => Ok(ManagedHostStatus::reach_compliance_success(actions_taken)),
        }
    }
}

/// Trait for types that can assess compliance of a host.
///
/// Implement this trait for custom attribute types that need to check
/// whether a host is compliant with a specific configuration.
///
/// # Type Parameters
///
/// * `Handler` - The type of host handler
pub trait AssessCompliance<Handler: HostHandler> {
    /// Assess whether the host is compliant.
    async fn assess_compliance(
        &self,
        host_handler: &mut Handler,
        host_properties: &Option<HostProperties>,
        privilege: &Privilege,
        optional_secret_provider: &Option<SecretProvidersPool>,
    ) -> Result<AttributeComplianceAssessment, RegentError>;
}

/// Trait for types that can perform remediation to reach compliance.
///
/// Implement this trait for custom remediation types that need to make
/// changes to a host to bring it into compliance.
///
/// # Type Parameters
///
/// * `Handler` - The type of host handler
pub trait ReachCompliance<Handler: HostHandler> {
    /// Perform remediation on the host.
    async fn call(
        &self,
        host_handler: &mut Handler,
        host_properties: &Option<HostProperties>,
        optional_secret_provider: &Option<SecretProvidersPool>,
    ) -> Result<InternalApiCallOutcome, RegentError>;
}

/// Trait for types that have a default timeout.
///
/// Implement this trait for operations that should have a configurable timeout.
pub trait Timeout {
    /// Get the default timeout for this operation.
    fn default_timeout(&self) -> Duration;
}

/// Outcome of an attribute-level operation.
///
/// This enum represents the possible results of assessing and/or remediating
/// a single attribute on a host.
///
/// # Variants
///
/// - `AlreadyCompliant`: The attribute was already compliant
/// - `NotCompliant`: The attribute was not compliant, with list of required remediations
/// - `ReachComplianceFailed`: Attempt to reach compliance failed
/// - `ComplianceReachedWithAllowedFailure`: Compliance reached but with allowed failures
/// - `ComplianceReached`: Compliance successfully reached with list of actions taken
#[derive(Serialize, Deserialize)]
pub enum AttributeLevelOperationOutcome {
    /// The attribute was already compliant.
    AlreadyCompliant,
    /// The attribute was not compliant.
    ///
    /// Contains the list of remediations that would be needed to reach compliance.
    NotCompliant(Vec<Remediation>),
    /// Attempt to reach compliance failed.
    ///
    /// Contains the failure outcome.
    ReachComplianceFailed(InternalApiCallOutcome),
    /// Compliance reached but with allowed failures.
    ///
    /// Some remediations failed but were marked as allowed to fail.
    ComplianceReachedWithAllowedFailure(InternalApiCallOutcome),
    /// Compliance successfully reached.
    ///
    /// Contains the list of remediations performed and their outcomes.
    ComplianceReached(Vec<(Remediation, InternalApiCallOutcome)>),
}

/// Outcome of an internal API call (remediation execution).
///
/// This enum represents the result of executing a single remediation action.
///
/// # Variants
///
/// - `Success`: The remediation succeeded, with optional details
/// - `Failure`: The remediation failed, with error details
/// - `AllowedFailure`: The remediation failed but was allowed to fail
#[derive(Debug, Serialize, Deserialize, Clone)]
pub enum InternalApiCallOutcome {
    /// The remediation succeeded.
    ///
    /// Contains optional details about the success.
    Success(Option<String>),
    /// The remediation failed.
    ///
    /// Contains error details.
    Failure(String),
    /// The remediation failed but was marked as allowed to fail.
    ///
    /// This allows for "best effort" compliance where some failures are acceptable.
    AllowedFailure(String),
}


// Internal state tracking helper for out-of-span control flow
enum LoopControl {
    Continue,
    Remediated { failed: bool, actions: Vec<Action> },
    Fatal,
}