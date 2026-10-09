//! Apptainer service attribute
//!
//! This module provides the "ApptainerExpectedState" type for running an
//! [Apptainer](https://apptainer.org) container (Apptainer 1.x) as a long-running service, such
//! as an inference server.
//!
//! **Compatible OS:** Linux with systemd
//!
//! Apptainer has no daemon keeping containers alive across reboots: the container runs in the
//! foreground of a **systemd service unit** ("regent-apptainer-<name>.service"), which brings the
//! restart policy, the start at boot and the logs ("journalctl -u regent-apptainer-<name>").
//!
//! **System or user unit:** the attribute's "Privilege" decides. When it runs commands as root
//! ("!WithSudo", or connected as root), a system unit is installed in "/etc/systemd/system".
//! Otherwise ("!None" as a regular user), a user unit is installed in
//! "~/.config/systemd/user" and lingering is enabled for the user, so that the service runs
//! without an open session and starts at boot.
//!
//! # How compliance is assessed
//!
//! - "apptainer" must be available ("FailedDryRunEvaluation" otherwise), except to remove a
//!   service. Its absolute path is written in the unit.
//! - A "Local" image must exist ("NonCompliantFatal" otherwise). A "Pulled" image is pulled
//!   ("apptainer pull <path> <source>") **only if its file is missing**: SIF files are
//!   immutable, so to change the image, change "Path" too (put the version in the file name,
//!   e.g. "/opt/images/triton-24.08.sif"). Pulling a large image can be long: the default
//!   timeouts are generous, set "Timeout" on the attribute if needed.
//! - The unit file and the environment file are rendered and compared with the files on the
//!   host: if they differ, they are rewritten, and the service is restarted if it must run.
//! - The service is then enabled and started ("Running") or disabled and stopped ("Stopped").
//! - "Absent" stops and disables the service and deletes its files. The image file is kept.
//!
//! "Env" values can be secrets. They are written in an environment file only readable by its
//! owner (mode 0600), as "APPTAINERENV_<NAME>", so they reach the container even with
//! "CleanEnv" or "Isolation: ContainAll". They never appear in the unit file nor in remediation
//! messages, but they are on the command line writing the environment file.
//!
//! "Memory" and "Cpus" rely on cgroups: in a user unit, they require cgroups v2 with delegation
//! to the user's systemd instance.
//!
//! # Examples
//!
//! ## Rust API
//!
//! ```no_run
//! use regent_sdk::state::attribute::container::apptainer::{
//!     ApptainerExpectedState, ApptainerGpu, ApptainerImage, ApptainerProcess,
//!     ApptainerServiceConfig, ApptainerIsolation,
//! };
//! use regent_sdk::state::attribute::container::container_spec::ContainerCommand;
//! use regent_sdk::state::expected_state::Parameter;
//! use regent_sdk::secrets::SecretReference;
//! use regent_sdk::{Attribute, ExpectedState, Privilege, RegentError};
//!
//! fn inference_server() -> Result<ExpectedState, RegentError> {
//!     let config = ApptainerServiceConfig::new(ApptainerImage::pulled(
//!         "docker://vllm/vllm-openai:v0.6.3".parse()?,
//!         "/opt/images/vllm-0.6.3.sif".parse()?,
//!     ))
//!     .with_process(ApptainerProcess::Exec(ContainerCommand::new(&[
//!         "vllm", "serve", "meta-llama/Llama-3.1-8B-Instruct", "--port", "8000",
//!     ])?))
//!     .with_gpu(ApptainerGpu::Nvidia)
//!     .with_binds(vec!["/srv/models:/root/.cache/huggingface".parse()?])
//!     .with_env(
//!         "HF_TOKEN".parse()?,
//!         Parameter::Secret(SecretReference::from("hf_token", Some("files".to_string()))),
//!     )
//!     .with_isolation(ApptainerIsolation::ContainAll);
//!
//!     let vllm = ApptainerExpectedState::running("vllm".parse()?, config);
//!
//!     Ok(ExpectedState::new()
//!         .with_attribute(Attribute::apptainer(vllm, Privilege::WithSudo, None))
//!         .build())
//! }
//! ```
//!
//! ## YAML API
//!
//! ```yaml
//! Attributes:
//!   - Name: Triton inference server must be running
//!     Privilege: !WithSudo          # system unit (root); !None for a user unit
//!     Detail: !Apptainer
//!       Name: triton
//!       State: !Running             # !Running | !Stopped (same configuration) | Absent
//!         Image: !Pulled            # !Local /opt/images/app.sif | !Pulled
//!           Source: docker://nvcr.io/nvidia/tritonserver:24.08-py3
//!           Path: /opt/images/triton-24.08.sif
//!         Process: !Exec            # !RunScript [args...] (default: run script, no args) | !Exec [command, args...]
//!           - tritonserver
//!           - --model-repository=/models
//!         Gpu: Nvidia               # Nvidia (--nv) | NvidiaContainerCli (--nv --nvccli) | Rocm (--rocm)
//!         Binds:                    # source[:target[:ro|rw]]
//!           - /srv/triton/models:/models:ro
//!         Env:
//!           TZ: Europe/Paris
//!           NGC_API_KEY:            # secret retrieved from a secret provider
//!             SecRef: ngc_api_key
//!             Provider: files
//!         CleanEnv: true            # --cleanenv
//!         Isolation: Contain        # Contain (--contain) | ContainAll (--containall)
//!         WritableTmpfs: false      # --writable-tmpfs
//!         Fakeroot: false           # --fakeroot
//!         WorkingDir: /models       # --pwd
//!         Memory: 32g               # --memory
//!         Cpus: 8                   # --cpus
//!         RestartPolicy: OnFailure  # No | OnFailure (default) | Always
//! ```
//!
//! To make sure a service does not exist:
//!
//! ```yaml
//! Attributes:
//!   - Name: Old inference server must be removed
//!     Privilege: !WithSudo
//!     Detail: !Apptainer
//!       Name: legacy-llm
//!       State: Absent
//! ```

use crate::error::RegentError;
use crate::hosts::handlers::shell_quote;
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
use crate::state::expected_state::Parameter;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fmt;
use std::str::FromStr;
use std::time::Duration;

use super::container_spec::{ContainerCommand, ContainerName, CpuCount, MemorySize, invalid};
use super::service_unit::{
    AbsolutePath, BindMount, ServiceEngine, ServiceEnvVarName, ServiceStep, ServiceUnitAction,
    ServiceUnitId, UnitRestartPolicy, UnitSpec, file_exists, needs_removal, observe_service,
    plan_service, render_env_file, render_unit, resolve_executable, run_action, run_remediation,
    write_files,
};

/// Prefix of the variables Apptainer passes into the container, even with `--cleanenv`
const APPTAINER_ENV_PREFIX: &str = "APPTAINERENV_";

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[serde(rename_all = "PascalCase")]
pub struct ApptainerExpectedState {
    /// The unit is `regent-apptainer-<name>.service`
    name: ContainerName,
    state: ApptainerServiceState,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub enum ApptainerServiceState {
    Running(Box<ApptainerServiceConfig>),
    Stopped(Box<ApptainerServiceConfig>),
    Absent,
}

impl ApptainerExpectedState {
    pub fn running(name: ContainerName, config: ApptainerServiceConfig) -> Self {
        Self {
            name,
            state: ApptainerServiceState::Running(Box::new(config)),
        }
    }

    pub fn stopped(name: ContainerName, config: ApptainerServiceConfig) -> Self {
        Self {
            name,
            state: ApptainerServiceState::Stopped(Box::new(config)),
        }
    }

    pub fn absent(name: ContainerName) -> Self {
        Self {
            name,
            state: ApptainerServiceState::Absent,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub enum ApptainerImage {
    /// Not managed: the file must be present
    Local(AbsolutePath),
    Pulled(ApptainerPulledImage),
}

impl ApptainerImage {
    pub fn pulled(source: ApptainerImageUri, path: AbsolutePath) -> Self {
        ApptainerImage::Pulled(ApptainerPulledImage { source, path })
    }

    pub fn path(&self) -> &AbsolutePath {
        match self {
            ApptainerImage::Local(path) => path,
            ApptainerImage::Pulled(pulled) => &pulled.path,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[serde(rename_all = "PascalCase")]
pub struct ApptainerPulledImage {
    source: ApptainerImageUri,
    /// SIF file to create (include the version in the file name: an existing file is never
    /// pulled again)
    path: AbsolutePath,
}

/// Source of `apptainer pull`: `docker://`, `oras://`, `library://`, `shub://`, `http://`,
/// `https://`, `docker-archive:`, `docker-daemon:` or `oci-archive:`
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct ApptainerImageUri(String);

const APPTAINER_URI_SCHEMES: [&str; 9] = [
    "docker://",
    "oras://",
    "library://",
    "shub://",
    "http://",
    "https://",
    "docker-archive:",
    "docker-daemon:",
    "oci-archive:",
];

impl TryFrom<String> for ApptainerImageUri {
    type Error = RegentError;

    fn try_from(uri: String) -> Result<Self, Self::Error> {
        let rest = APPTAINER_URI_SCHEMES
            .iter()
            .find_map(|scheme| uri.strip_prefix(scheme));
        match rest {
            None => Err(invalid(
                "image URI",
                &uri,
                &format!("supported schemes are {}", APPTAINER_URI_SCHEMES.join(", ")),
            )),
            Some(rest) if rest.is_empty() || uri.chars().any(char::is_whitespace) => Err(invalid(
                "image URI",
                &uri,
                "must name an image, without whitespace",
            )),
            Some(_) => Ok(Self(uri)),
        }
    }
}

impl FromStr for ApptainerImageUri {
    type Err = RegentError;

    fn from_str(uri: &str) -> Result<Self, Self::Err> {
        Self::try_from(uri.to_string())
    }
}

impl From<ApptainerImageUri> for String {
    fn from(uri: ApptainerImageUri) -> String {
        uri.0
    }
}

impl fmt::Display for ApptainerImageUri {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl ApptainerImageUri {
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub enum ApptainerProcess {
    /// `apptainer run`: the image's run script, with these arguments. For an image built from
    /// a Docker image, the run script is `ENTRYPOINT` + `CMD`, and arguments replace `CMD`.
    RunScript(Vec<String>),
    /// `apptainer exec`: this command, with its arguments
    Exec(ContainerCommand),
}

impl Default for ApptainerProcess {
    fn default() -> Self {
        ApptainerProcess::RunScript(Vec::new())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub enum ApptainerGpu {
    /// NVIDIA GPUs, host libraries bound into the container (`--nv`)
    Nvidia,
    /// NVIDIA GPUs set up by `nvidia-container-cli` (`--nv --nvccli`, implies `--writable-tmpfs`)
    NvidiaContainerCli,
    /// AMD GPUs (`--rocm`)
    Rocm,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub enum ApptainerIsolation {
    /// Minimal `/dev`, empty `/tmp` and home directory (`--contain`)
    Contain,
    /// Same, plus separate PID and IPC namespaces and a clean environment (`--containall`)
    ContainAll,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[serde(rename_all = "PascalCase")]
pub struct ApptainerServiceConfig {
    image: ApptainerImage,
    #[serde(default)]
    process: ApptainerProcess,
    gpu: Option<ApptainerGpu>,
    binds: Option<Vec<BindMount>>,
    /// Environment variables of the container (values can be secrets)
    env: Option<BTreeMap<ServiceEnvVarName, Parameter<String>>>,
    /// Don't pass the host environment to the container (`--cleanenv`)
    #[serde(default)]
    clean_env: bool,
    isolation: Option<ApptainerIsolation>,
    /// Writable, non-persistent root filesystem (`--writable-tmpfs`)
    #[serde(default)]
    writable_tmpfs: bool,
    /// Appear as root inside the container (`--fakeroot`)
    #[serde(default)]
    fakeroot: bool,
    /// Working directory inside the container (`--pwd`)
    working_dir: Option<AbsolutePath>,
    /// Memory limit (`--memory`)
    memory: Option<MemorySize>,
    /// Number of CPUs (`--cpus`)
    cpus: Option<CpuCount>,
    #[serde(default)]
    restart_policy: UnitRestartPolicy,
}

impl ApptainerServiceConfig {
    pub fn new(image: ApptainerImage) -> Self {
        Self {
            image,
            process: ApptainerProcess::default(),
            gpu: None,
            binds: None,
            env: None,
            clean_env: false,
            isolation: None,
            writable_tmpfs: false,
            fakeroot: false,
            working_dir: None,
            memory: None,
            cpus: None,
            restart_policy: UnitRestartPolicy::default(),
        }
    }

    pub fn with_process(mut self, process: ApptainerProcess) -> Self {
        self.process = process;
        self
    }

    pub fn with_gpu(mut self, gpu: ApptainerGpu) -> Self {
        self.gpu = Some(gpu);
        self
    }

    pub fn with_binds(mut self, binds: Vec<BindMount>) -> Self {
        self.binds = Some(binds);
        self
    }

    /// Add an environment variable (the value may be a secret reference)
    pub fn with_env(mut self, key: ServiceEnvVarName, value: Parameter<String>) -> Self {
        self.env
            .get_or_insert_with(BTreeMap::new)
            .insert(key, value);
        self
    }

    pub fn with_clean_env(mut self, clean_env: bool) -> Self {
        self.clean_env = clean_env;
        self
    }

    pub fn with_isolation(mut self, isolation: ApptainerIsolation) -> Self {
        self.isolation = Some(isolation);
        self
    }

    pub fn with_writable_tmpfs(mut self, writable_tmpfs: bool) -> Self {
        self.writable_tmpfs = writable_tmpfs;
        self
    }

    pub fn with_fakeroot(mut self, fakeroot: bool) -> Self {
        self.fakeroot = fakeroot;
        self
    }

    pub fn with_working_dir(mut self, working_dir: AbsolutePath) -> Self {
        self.working_dir = Some(working_dir);
        self
    }

    pub fn with_memory(mut self, memory: MemorySize) -> Self {
        self.memory = Some(memory);
        self
    }

    pub fn with_cpus(mut self, cpus: CpuCount) -> Self {
        self.cpus = Some(cpus);
        self
    }

    pub fn with_restart_policy(mut self, restart_policy: UnitRestartPolicy) -> Self {
        self.restart_policy = restart_policy;
        self
    }

    fn exec_start(&self, apptainer_path: &str) -> Vec<String> {
        let mut args = vec![
            apptainer_path.to_string(),
            match self.process {
                ApptainerProcess::RunScript(_) => "run",
                ApptainerProcess::Exec(_) => "exec",
            }
            .to_string(),
        ];
        let mut flag = |flag: &str| args.push(flag.to_string());

        match self.gpu {
            Some(ApptainerGpu::Nvidia) => flag("--nv"),
            Some(ApptainerGpu::NvidiaContainerCli) => {
                flag("--nv");
                flag("--nvccli");
            }
            Some(ApptainerGpu::Rocm) => flag("--rocm"),
            None => {}
        }
        if self.clean_env {
            flag("--cleanenv");
        }
        match self.isolation {
            Some(ApptainerIsolation::Contain) => flag("--contain"),
            Some(ApptainerIsolation::ContainAll) => flag("--containall"),
            None => {}
        }
        if self.writable_tmpfs {
            flag("--writable-tmpfs");
        }
        if self.fakeroot {
            flag("--fakeroot");
        }

        let mut option = |flag: &str, value: String| {
            args.push(flag.to_string());
            args.push(value);
        };
        if let Some(working_dir) = &self.working_dir {
            option("--pwd", working_dir.to_string());
        }
        if let Some(memory) = &self.memory {
            // Apptainer documents a number of bytes
            option("--memory", memory.bytes().to_string());
        }
        if let Some(cpus) = &self.cpus {
            option("--cpus", cpus.to_string());
        }
        for bind in self.binds.iter().flatten() {
            option("--bind", bind.apptainer_arg());
        }

        args.push(self.image.path().to_string());
        match &self.process {
            ApptainerProcess::RunScript(run_args) => args.extend(run_args.iter().cloned()),
            ApptainerProcess::Exec(command) => args.extend(command.args().iter().cloned()),
        }
        args
    }

    fn unit_content(&self, id: &ServiceUnitId, apptainer_path: &str) -> String {
        render_unit(
            id,
            &UnitSpec {
                exec_start: self.exec_start(apptainer_path),
                environment: Vec::new(),
                restart: self.restart_policy,
            },
        )
    }

    /// Content of the environment file, retrieving secrets if needed
    async fn env_content(
        &self,
        optional_secret_provider: &Option<SecretProvidersPool>,
    ) -> Result<String, RegentError> {
        let mut entries = Vec::new();
        if let Some(env) = &self.env {
            for (key, value) in env {
                entries.push((
                    format!("{}{}", APPTAINER_ENV_PREFIX, key),
                    value.clone().inner_raw(optional_secret_provider).await?,
                ));
            }
        }
        Ok(render_env_file(&entries))
    }
}

impl Timeout for ApptainerExpectedState {
    fn default_timeout(&self) -> Duration {
        Duration::from_secs(120)
    }
}

impl Check for ApptainerExpectedState {
    fn check(&self) -> Result<(), RegentError> {
        // Every value is validated when its type is built: an existing ApptainerExpectedState is valid
        Ok(())
    }

    fn check_host_compatibility(
        &self,
        host_properties: &HostProperties,
    ) -> Result<(), RegentError> {
        check_apptainer_host_compatibility(host_properties)
    }
}

impl<Handler: HostHandler> AssessCompliance<Handler> for ApptainerExpectedState {
    async fn assess_compliance(
        &self,
        host_handler: &mut Handler,
        host_properties: &Option<HostProperties>,
        privilege: &Privilege,
        optional_secret_provider: &Option<SecretProvidersPool>,
    ) -> Result<AttributeComplianceAssessment, RegentError> {
        if let Some(props) = host_properties {
            self.check_host_compatibility(props)?;
        }

        let (scope, _home) = super::service_unit::detect_scope(host_handler, privilege).await?;
        let id = ServiceUnitId::new(ServiceEngine::Apptainer, self.name.clone(), scope);

        let mut remediations: Vec<Remediation> = Vec::new();
        let mut push = |api_call: ApptainerInternalApiCall| {
            remediations.push(Remediation::Apptainer(ApptainerApiCall::from(
                api_call,
                privilege.clone(),
            )));
        };

        let (config, should_run) = match &self.state {
            ApptainerServiceState::Absent => {
                let observed = observe_service(host_handler, &id, false, privilege).await?;
                if needs_removal(&observed) {
                    push(ApptainerInternalApiCall::Service {
                        unit: id,
                        action: ServiceUnitAction::Remove,
                    });
                }
                return assessment(remediations);
            }
            ApptainerServiceState::Running(config) => (config, true),
            ApptainerServiceState::Stopped(config) => (config, false),
        };

        let Some(apptainer_path) = resolve_executable(host_handler, "apptainer", privilege).await?
        else {
            return Err(RegentError::FailedDryRunEvaluation(
                "Apptainer CLI (apptainer) is not available on this host".to_string(),
            ));
        };

        let mut image_pulled = false;
        if !file_exists(host_handler, config.image.path(), privilege).await? {
            match &config.image {
                ApptainerImage::Local(path) => {
                    return Ok(AttributeComplianceAssessment::NonCompliantFatal(format!(
                        "image {} is not present on the host",
                        path
                    )));
                }
                ApptainerImage::Pulled(pulled) => {
                    push(ApptainerInternalApiCall::Pull(pulled.clone()));
                    image_pulled = true;
                }
            }
        }

        let observed = observe_service(host_handler, &id, should_run, privilege).await?;
        let expected_unit = config.unit_content(&id, &apptainer_path);
        let expected_env = config.env_content(optional_secret_provider).await?;

        for step in plan_service(
            should_run,
            &expected_unit,
            &expected_env,
            &observed,
            image_pulled,
        ) {
            push(match step {
                ServiceStep::WriteFiles(reasons) => ApptainerInternalApiCall::WriteServiceFiles {
                    unit: id.clone(),
                    config: config.clone(),
                    apptainer_path: apptainer_path.clone(),
                    reasons,
                },
                ServiceStep::Action(action) => ApptainerInternalApiCall::Service {
                    unit: id.clone(),
                    action,
                },
            });
        }

        assessment(remediations)
    }
}

fn assessment(
    remediations: Vec<Remediation>,
) -> Result<AttributeComplianceAssessment, RegentError> {
    if remediations.is_empty() {
        Ok(AttributeComplianceAssessment::Compliant)
    } else {
        Ok(AttributeComplianceAssessment::NonCompliant(
            RemediationsList::from(remediations)?,
        ))
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase", rename_all_fields = "PascalCase")]
pub enum ApptainerInternalApiCall {
    Pull(ApptainerPulledImage),
    WriteServiceFiles {
        unit: ServiceUnitId,
        config: Box<ApptainerServiceConfig>,
        apptainer_path: String,
        reasons: Vec<String>,
    },
    Service {
        unit: ServiceUnitId,
        action: ServiceUnitAction,
    },
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ApptainerApiCall {
    pub api_call: ApptainerInternalApiCall,
    privilege: Privilege,
}

impl ApptainerApiCall {
    pub fn display(&self) -> String {
        match &self.api_call {
            ApptainerInternalApiCall::Pull(pulled) => {
                format!("Pull image {} into {}", pulled.source, pulled.path)
            }
            ApptainerInternalApiCall::WriteServiceFiles { unit, reasons, .. } => format!(
                "Write {} and its environment file ({})",
                unit,
                reasons.join("; ")
            ),
            ApptainerInternalApiCall::Service { unit, action } => action.display(unit),
        }
    }

    fn from(api_call: ApptainerInternalApiCall, privilege: Privilege) -> ApptainerApiCall {
        ApptainerApiCall {
            api_call,
            privilege,
        }
    }
}

impl Timeout for ApptainerApiCall {
    fn default_timeout(&self) -> Duration {
        match &self.api_call {
            // Images of inference servers weigh several GB
            ApptainerInternalApiCall::Pull(_) => Duration::from_secs(3600),
            _ => Duration::from_secs(180),
        }
    }
}

impl Check for ApptainerApiCall {
    fn check(&self) -> Result<(), RegentError> {
        Ok(())
    }

    fn check_host_compatibility(
        &self,
        host_properties: &HostProperties,
    ) -> Result<(), RegentError> {
        check_apptainer_host_compatibility(host_properties)
    }
}

impl<Handler: HostHandler> ReachCompliance<Handler> for ApptainerApiCall {
    async fn call(
        &self,
        host_handler: &mut Handler,
        host_properties: &Option<HostProperties>,
        optional_secret_provider: &Option<SecretProvidersPool>,
    ) -> Result<InternalApiCallOutcome, RegentError> {
        if let Some(props) = host_properties {
            self.check_host_compatibility(props)?;
        }

        match &self.api_call {
            ApptainerInternalApiCall::Pull(pulled) => {
                run_remediation(host_handler, &pull_command(pulled), &self.privilege, true).await
            }
            ApptainerInternalApiCall::WriteServiceFiles {
                unit,
                config,
                apptainer_path,
                ..
            } => {
                let env = config.env_content(optional_secret_provider).await?;
                write_files(
                    host_handler,
                    unit,
                    &config.unit_content(unit, apptainer_path),
                    &env,
                    &self.privilege,
                )
                .await
            }
            ApptainerInternalApiCall::Service { unit, action } => {
                run_action(host_handler, unit, *action, &self.privilege).await
            }
        }
    }
}

/// `mkdir -p <parent> && apptainer pull <path> <source>`
fn pull_command(pulled: &ApptainerPulledImage) -> String {
    format!(
        "mkdir -p {} && apptainer pull {} {}",
        shell_quote(pulled.path.parent()),
        shell_quote(pulled.path.as_str()),
        shell_quote(pulled.source.as_str())
    )
}

fn check_apptainer_host_compatibility(host_properties: &HostProperties) -> Result<(), RegentError> {
    match host_properties.os_kind() {
        OsKind::Linux(_) => Ok(()),
        incompatible_os_kind => Err(RegentError::IncompatibleHost(format!(
            "Host is {:?} but Apptainer services are only supported on Linux",
            incompatible_os_kind
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::secrets::SecretReference;
    use crate::state::attribute::container::service_unit::UnitScope;

    fn full_yaml() -> &'static str {
        "---
Name: triton
State: !Running
  Image: !Pulled
    Source: docker://nvcr.io/nvidia/tritonserver:24.08-py3
    Path: /opt/images/triton-24.08.sif
  Process: !Exec
    - tritonserver
    - --model-repository=/models
    - --log-format=%Y
  Gpu: Nvidia
  Binds:
    - /srv/triton/models:/models:ro
    - /srv/triton/cache
  Env:
    TZ: Europe/Paris
    NGC_API_KEY:
      SecRef: ngc_api_key
      Provider: files
  CleanEnv: true
  Isolation: Contain
  WritableTmpfs: true
  Fakeroot: false
  WorkingDir: /models
  Memory: 32g
  Cpus: 8
  RestartPolicy: Always
"
    }

    fn full_config() -> ApptainerServiceConfig {
        let state: ApptainerExpectedState = yaml_serde::from_str(full_yaml()).unwrap();
        match state.state {
            ApptainerServiceState::Running(config) => *config,
            other => panic!("unexpected state {:?}", other),
        }
    }

    fn system_id() -> ServiceUnitId {
        ServiceUnitId::new(
            ServiceEngine::Apptainer,
            "triton".parse().unwrap(),
            UnitScope::System,
        )
    }

    #[test]
    fn parsing_apptainer_module_block_from_yaml_str() {
        let config = full_config();
        assert_eq!(
            config.image,
            ApptainerImage::pulled(
                "docker://nvcr.io/nvidia/tritonserver:24.08-py3"
                    .parse()
                    .unwrap(),
                "/opt/images/triton-24.08.sif".parse().unwrap()
            )
        );
        assert_eq!(config.gpu, Some(ApptainerGpu::Nvidia));
        assert_eq!(config.restart_policy, UnitRestartPolicy::Always);
        assert_eq!(
            config
                .env
                .as_ref()
                .unwrap()
                .get(&"NGC_API_KEY".parse().unwrap()),
            Some(&Parameter::Secret(SecretReference::from(
                "ngc_api_key",
                Some("files".to_string())
            )))
        );

        let raw = "---
- Name: legacy
  State: Absent
- Name: app
  State: !Stopped
    Image: !Local /opt/images/app.sif
- Name: llm
  State: !Running
    Image: !Local /opt/images/llm.sif
    Process: !RunScript [--port, '8000']
    Gpu: !NvidiaContainerCli
    Isolation: !ContainAll
";
        let states: Vec<ApptainerExpectedState> = yaml_serde::from_str(raw).unwrap();
        assert_eq!(states[0].state, ApptainerServiceState::Absent);
        match &states[1].state {
            ApptainerServiceState::Stopped(config) => {
                assert_eq!(config.process, ApptainerProcess::RunScript(vec![]));
                assert_eq!(config.restart_policy, UnitRestartPolicy::OnFailure);
            }
            other => panic!("unexpected state {:?}", other),
        }
        match &states[2].state {
            ApptainerServiceState::Running(config) => {
                assert_eq!(config.gpu, Some(ApptainerGpu::NvidiaContainerCli));
                assert_eq!(config.isolation, Some(ApptainerIsolation::ContainAll));
            }
            other => panic!("unexpected state {:?}", other),
        }
    }

    #[test]
    fn serialization_round_trip_preserves_state() {
        // Templating (Attribute::consider_context) relies on a JSON round trip
        let state: ApptainerExpectedState = yaml_serde::from_str(full_yaml()).unwrap();
        let json = serde_json::to_string(&state).unwrap();
        assert_eq!(
            serde_json::from_str::<ApptainerExpectedState>(&json).unwrap(),
            state
        );
    }

    #[test]
    fn invalid_states_are_rejected_while_parsing() {
        let base = "Name: llm\nState: !Running\n  Image: !Local /opt/llm.sif\n";
        let rejected = [
            // Configuration makes no sense for an absent service
            (
                "Name: old\nState: !Absent\n  Image: !Local /opt/x.sif\n",
                "expected unit",
            ),
            // Image is mandatory for a service which must exist
            (
                "Name: llm\nState: !Running\n  Gpu: Nvidia\n",
                "missing field `Image`",
            ),
            // A local image has no source, a pulled image needs a destination
            (
                "Name: llm\nState: !Running\n  Image: !Local\n    Source: docker://vllm/vllm-openai\n    Path: /opt/x.sif\n",
                "expected a string",
            ),
            (
                "Name: llm\nState: !Running\n  Image: !Pulled\n    Source: docker://vllm/vllm-openai\n",
                "missing field `Path`",
            ),
            // Unsupported scheme, relative path
            (
                "Name: llm\nState: !Running\n  Image: !Pulled\n    Source: ftp://example.com/x.sif\n    Path: /opt/x.sif\n",
                "supported schemes",
            ),
            (
                "Name: llm\nState: !Running\n  Image: !Local images/x.sif\n",
                "absolute",
            ),
            // Empty command
            (
                &format!("{}  Process: !Exec []\n", base),
                "Command can't be empty",
            ),
            // Single GPU vendor, single isolation level
            (
                &format!("{}  Gpu: [Nvidia, Rocm]\n", base),
                "invalid type: sequence",
            ),
            (&format!("{}  Isolation: Contained\n", base), "Contained"),
            // Typed values
            (&format!("{}  Binds: ['/data:/data:Z']\n", base), "ro or rw"),
            (&format!("{}  Binds: ['data:/data']\n", base), "absolute"),
            (&format!("{}  Env:\n    HF-TOKEN: x\n", base), "[A-Za-z_]"),
            (&format!("{}  WorkingDir: models\n", base), "absolute"),
            (&format!("{}  Memory: lots\n", base), "memory size"),
            (&format!("{}  Cpus: 0\n", base), "strictly positive"),
            (&format!("{}  Network: host\n", base), "unknown field"),
            ("Name: /llm\nState: Absent\n", "container name"),
        ];
        for (raw, reason) in rejected {
            let error = yaml_serde::from_str::<ApptainerExpectedState>(raw)
                .expect_err(&format!("should be rejected: {}", raw))
                .to_string();
            assert!(
                error.contains(reason),
                "{:?} rejected for another reason: {}",
                raw,
                error
            );
        }
    }

    #[test]
    fn exec_start_follows_apptainer_cli() {
        assert_eq!(
            full_config().exec_start("/usr/bin/apptainer"),
            vec![
                "/usr/bin/apptainer",
                "exec",
                "--nv",
                "--cleanenv",
                "--contain",
                "--writable-tmpfs",
                "--pwd",
                "/models",
                "--memory",
                "34359738368",
                "--cpus",
                "8",
                "--bind",
                "/srv/triton/models:/models:ro",
                "--bind",
                "/srv/triton/cache:/srv/triton/cache:rw",
                "/opt/images/triton-24.08.sif",
                "tritonserver",
                "--model-repository=/models",
                "--log-format=%Y",
            ]
        );

        let simple =
            ApptainerServiceConfig::new(ApptainerImage::Local("/opt/app.sif".parse().unwrap()))
                .with_process(ApptainerProcess::RunScript(vec!["--port".to_string()]))
                .with_gpu(ApptainerGpu::NvidiaContainerCli)
                .with_fakeroot(true);
        assert_eq!(
            simple.exec_start("/opt/apptainer/bin/apptainer"),
            vec![
                "/opt/apptainer/bin/apptainer",
                "run",
                "--nv",
                "--nvccli",
                "--fakeroot",
                "/opt/app.sif",
                "--port"
            ]
        );
    }

    #[test]
    fn unit_and_environment_file_are_rendered() {
        let config = full_config();
        let unit = config.unit_content(&system_id(), "/usr/bin/apptainer");
        assert!(unit.contains(
            "\nExecStart=/usr/bin/apptainer exec --nv --cleanenv --contain --writable-tmpfs --pwd /models --memory 34359738368 --cpus 8 --bind /srv/triton/models:/models:ro --bind /srv/triton/cache:/srv/triton/cache:rw /opt/images/triton-24.08.sif tritonserver --model-repository=/models \"--log-format=%%Y\"\n"
        ));
        assert!(unit.contains("\nEnvironmentFile=/etc/regent-sdk/apptainer/triton.env\n"));
        assert!(unit.contains("\nRestart=always\n"));

        // Secret values only go to the environment file, prefixed for Apptainer
        let clear =
            ApptainerServiceConfig::new(ApptainerImage::Local("/opt/app.sif".parse().unwrap()))
                .with_env(
                    "HF_TOKEN".parse().unwrap(),
                    Parameter::Clear("hf_$ecret".to_string()),
                );
        let env = tokio_test_block_on(clear.env_content(&None)).unwrap();
        assert!(env.ends_with("\nAPPTAINERENV_HF_TOKEN=\"hf_\\$ecret\"\n"));
        assert!(
            !clear
                .unit_content(&system_id(), "/usr/bin/apptainer")
                .contains("ecret")
        );
    }

    #[test]
    fn remediations_never_show_secret_values() {
        let call = ApptainerApiCall::from(
            ApptainerInternalApiCall::WriteServiceFiles {
                unit: system_id(),
                config: Box::new(full_config()),
                apptainer_path: "/usr/bin/apptainer".to_string(),
                reasons: vec!["environment file differs".to_string()],
            },
            Privilege::WithSudo,
        );
        assert_eq!(
            call.display(),
            "Write regent-apptainer-triton.service and its environment file (environment file differs)"
        );
    }

    #[test]
    fn pull_command_creates_the_parent_directory() {
        let pulled = ApptainerPulledImage {
            source: "docker://vllm/vllm-openai:v0.6.3".parse().unwrap(),
            path: "/opt/my images/vllm.sif".parse().unwrap(),
        };
        assert_eq!(
            pull_command(&pulled),
            "mkdir -p '/opt/my images' && apptainer pull '/opt/my images/vllm.sif' 'docker://vllm/vllm-openai:v0.6.3'"
        );
        for uri in [
            "oras://ghcr.io/x/y:1",
            "library://alpine",
            "https://example.com/x.sif",
            "docker-archive:/tmp/x.tar",
        ] {
            assert!(uri.parse::<ApptainerImageUri>().is_ok(), "{}", uri);
        }
        for uri in ["docker://", "vllm/vllm-openai", "docker://a b"] {
            assert!(uri.parse::<ApptainerImageUri>().is_err(), "{}", uri);
        }
    }

    fn tokio_test_block_on<F: std::future::Future>(future: F) -> F::Output {
        tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap()
            .block_on(future)
    }
}
