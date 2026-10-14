//! Enroot service attribute
//!
//! This module provides the `EnrootExpectedState` type for running an
//! [Enroot](https://github.com/NVIDIA/enroot) container as a long-running service, such as an
//! inference server.
//!
//! **Compatible OS:** Linux with systemd
//!
//! An Enroot container is a root filesystem unpacked (`enroot create`) from a squashfs image,
//! itself imported (`enroot import`) from a registry or a local engine. Enroot has no daemon
//! keeping containers alive across reboots: the container runs in the foreground
//! (`enroot start`) of a **systemd service unit** (`regent-enroot-<name>.service`), which brings
//! the restart policy, the start at boot and the logs (`journalctl -u regent-enroot-<name>`).
//!
//! **System or user unit:** the attribute's `Privilege` decides. When it runs commands as root
//! (`!WithSudo`, or connected as root), a system unit is installed in `/etc/systemd/system` and
//! the containers of root are used. Otherwise (`!None` as a regular user), a user unit is
//! installed in `~/.config/systemd/user`, the containers of the user are used, and lingering is
//! enabled for the user so that the service runs without an open session and starts at boot.
//!
//! # Invalid states are unrepresentable
//!
//! - The service configuration only exists in the `Running` and `Stopped` states: an `Absent`
//!   service has nothing to configure.
//! - The image is either a `Local` squashfs file, or `Imported` from a source URI (with a
//!   scheme Enroot supports) into a squashfs file.
//! - GPUs are either `All` or a non-empty list of `Devices` with valid IDs. The variables they
//!   set (`NVIDIA_VISIBLE_DEVICES`, `NVIDIA_DRIVER_CAPABILITIES`) can't also be set in `Env`.
//! - `Env` can't set the variables configuring Enroot itself (`ENROOT_*`, `HOME`, `PATH`,
//!   `XDG_*`), as the environment file is also the environment of `enroot start`.
//! - Values with a syntax (name, paths, image URI, mounts, environment variable names, GPU IDs)
//!   have dedicated types which can only be built from a valid value.
//!
//! # How compliance is assessed
//!
//! - `enroot` must be available (`FailedDryRunEvaluation` otherwise). Its absolute path is
//!   written in the unit.
//! - A `Local` image must exist (`NonCompliantFatal` otherwise). An `Imported` image is imported
//!   (`enroot import -o <path> <source>`) **only if its file is missing**: to change the image,
//!   change `Path` too (put the version in the file name, e.g. `/opt/images/vllm-0.6.3.sqsh`).
//!   Importing a large image can be long: the default timeouts are generous, set `Timeout` on
//!   the attribute if needed.
//! - The container is created (`enroot create`) if it doesn't exist (`enroot list`). Enroot keeps
//!   no record of the image a container comes from, so regent-sdk records the image path and
//!   identity (size and modification time) in a marker file next to the environment file
//!   (`.../regent-sdk/enroot/<name>.image`). The container is **recreated** when the marker
//!   differs, or is missing (a container which was not created by Regent can't be verified).
//! - The unit file and the environment file are rendered and compared with the files on the
//!   host: if they differ, they are rewritten. The service is restarted if it must run and its
//!   files or its container changed.
//! - The service is then enabled and started (`Running`) or disabled and stopped (`Stopped`).
//! - `Absent` stops and disables the service, deletes its files, and removes the container and
//!   its marker. The image file is kept.
//!
//! `Env` values can be secrets. They are written in an environment file only readable by its
//! owner (mode 0600) and passed by name to the container (`--env NAME`). They never appear in
//! the unit file nor in remediation messages, but they are on the command line writing the
//! environment file.
//!
//! # Examples
//!
//! ## Rust API
//!
//! ```no_run
//! use regent_sdk::state::attribute::container::container_spec::ContainerCommand;
//! use regent_sdk::state::attribute::container::enroot::{EnrootExpectedState, EnrootServiceConfig};
//! use regent_sdk::state::expected_state::Parameter;
//! use regent_sdk::secrets::SecretReference;
//! use regent_sdk::{Attribute, ExpectedState, Privilege, RegentError};
//!
//! fn inference_server() -> Result<ExpectedState, RegentError> {
//!     let config = EnrootServiceConfig::from_imported_image(
//!         "docker://vllm/vllm-openai:v0.6.3".parse()?,
//!         "/opt/images/vllm-0.6.3.sqsh".parse()?,
//!     )
//!     .with_command(ContainerCommand::new(&[
//!         "vllm", "serve", "meta-llama/Llama-3.1-8B-Instruct", "--port", "8000",
//!     ])?)
//!     .with_all_gpus()
//!     .with_mounts(vec!["/srv/models:/root/.cache/huggingface".parse()?])
//!     .with_env(
//!         "HF_TOKEN".parse()?,
//!         Parameter::Secret(SecretReference::from("hf_token", Some("files".to_string()))),
//!     );
//!
//!     let vllm = EnrootExpectedState::running("vllm".parse()?, config);
//!
//!     Ok(ExpectedState::new()
//!         .with_attribute(Attribute::enroot(vllm, Privilege::None, None))
//!         .build())
//! }
//! ```
//!
//! ## YAML API
//!
//! ```yaml
//! Attributes:
//!   - Name: vLLM inference server must be running
//!     Privilege: !None              # user unit of the connected user; !WithSudo for a system unit
//!     Detail: !Enroot
//!       Name: vllm
//!       State: !Running             # !Running | !Stopped (same configuration) | Absent
//!         Image: !Imported          # !Local /opt/images/app.sqsh | !Imported
//!           Source: docker://vllm/vllm-openai:v0.6.3   # docker://[USER@][REGISTRY#]IMAGE[:TAG] | dockerd://IMAGE[:TAG] | podman://IMAGE[:TAG]
//!           Path: /opt/images/vllm-0.6.3.sqsh
//!         Command:                  # optional, image default command if omitted
//!           - vllm
//!           - serve
//!           - meta-llama/Llama-3.1-8B-Instruct
//!           - --port
//!           - "8000"
//!         Gpus: !Devices [0, 1]     # All | !Devices [index | GPU-<uuid> | MIG-<uuid>, ...]
//!         Mounts:                   # source[:target[:ro|rw]]
//!           - /srv/models:/root/.cache/huggingface
//!         Env:
//!           HF_TOKEN:               # secret retrieved from a secret provider
//!             SecRef: hf_token
//!             Provider: files
//!         Root: false               # --root
//!         ReadWrite: false          # --rw
//!         RestartPolicy: OnFailure  # No | OnFailure (default) | Always
//! ```
//!
//! To make sure a service and its container do not exist:
//!
//! ```yaml
//! Attributes:
//!   - Name: Old inference server must be removed
//!     Privilege: !None
//!     Detail: !Enroot
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

use super::container_spec::{ContainerCommand, ContainerName, GpuId, GpuSelection, invalid};
use super::service_unit::{
    AbsolutePath, BindMount, ServiceEngine, ServiceEnvVarName, ServiceStep, ServiceUnitAction,
    ServiceUnitId, UnitRestartPolicy, UnitScope, UnitSpec, file_exists, needs_removal,
    observe_service, plan_service, read_optional_file, render_env_file, render_unit,
    resolve_executable, run_action, run_remediation, write_files,
};

const NVIDIA_VISIBLE_DEVICES: &str = "NVIDIA_VISIBLE_DEVICES";
const NVIDIA_DRIVER_CAPABILITIES: &str = "NVIDIA_DRIVER_CAPABILITIES";
const GPU_DRIVER_CAPABILITIES: &str = "compute,utility";

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[serde(rename_all = "PascalCase")]
pub struct EnrootExpectedState {
    /// The unit is `regent-enroot-<name>.service`
    name: ContainerName,
    state: EnrootServiceState,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub enum EnrootServiceState {
    Running(Box<EnrootServiceConfig>),
    Stopped(Box<EnrootServiceConfig>),
    Absent,
}

impl EnrootExpectedState {
    pub fn running(name: ContainerName, config: EnrootServiceConfig) -> Self {
        Self {
            name,
            state: EnrootServiceState::Running(Box::new(config)),
        }
    }

    pub fn stopped(name: ContainerName, config: EnrootServiceConfig) -> Self {
        Self {
            name,
            state: EnrootServiceState::Stopped(Box::new(config)),
        }
    }

    pub fn absent(name: ContainerName) -> Self {
        Self {
            name,
            state: EnrootServiceState::Absent,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub enum EnrootImage {
    /// Not managed: the file must be present
    Local(AbsolutePath),
    Imported(EnrootImportedImage),
}

impl EnrootImage {
    /// Squashfs file which must be present on the host (not managed)
    pub fn local(path: AbsolutePath) -> Self {
        EnrootImage::Local(path)
    }

    /// Squashfs file imported from `source` (`enroot import`) if it is missing
    pub fn imported(source: EnrootImageUri, path: AbsolutePath) -> Self {
        EnrootImage::Imported(EnrootImportedImage { source, path })
    }

    pub fn path(&self) -> &AbsolutePath {
        match self {
            EnrootImage::Local(path) => path,
            EnrootImage::Imported(imported) => &imported.path,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[serde(rename_all = "PascalCase")]
pub struct EnrootImportedImage {
    source: EnrootImageUri,
    /// Squashfs file to create (include the version in the file name: an existing file is
    /// never imported again)
    path: AbsolutePath,
}

/// Source of `enroot import`: `docker://[USER@][REGISTRY#]IMAGE[:TAG]`, `dockerd://IMAGE[:TAG]`
/// or `podman://IMAGE[:TAG]`
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct EnrootImageUri(String);

const ENROOT_URI_SCHEMES: [&str; 3] = ["docker://", "dockerd://", "podman://"];

impl TryFrom<String> for EnrootImageUri {
    type Error = RegentError;

    fn try_from(uri: String) -> Result<Self, Self::Error> {
        let rest = ENROOT_URI_SCHEMES
            .iter()
            .find_map(|scheme| uri.strip_prefix(scheme));
        match rest {
            None => Err(invalid(
                "image URI",
                &uri,
                &format!("supported schemes are {}", ENROOT_URI_SCHEMES.join(", ")),
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

impl FromStr for EnrootImageUri {
    type Err = RegentError;

    fn from_str(uri: &str) -> Result<Self, Self::Err> {
        Self::try_from(uri.to_string())
    }
}

impl From<EnrootImageUri> for String {
    fn from(uri: EnrootImageUri) -> String {
        uri.0
    }
}

impl fmt::Display for EnrootImageUri {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl EnrootImageUri {
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(try_from = "EnrootServiceConfigFields")]
#[serde(rename_all = "PascalCase")]
pub struct EnrootServiceConfig {
    image: EnrootImage,
    /// Image default command if omitted
    command: Option<ContainerCommand>,
    gpus: Option<GpuSelection>,
    mounts: Option<Vec<BindMount>>,
    /// Environment variables of the container (values can be secrets)
    env: Option<BTreeMap<ServiceEnvVarName, Parameter<String>>>,
    /// Remap the user to root inside the container (`--root`)
    root: bool,
    /// Writable root filesystem (`--rw`)
    read_write: bool,
    restart_policy: UnitRestartPolicy,
}

/// Fields of `EnrootServiceConfig` before the checks between them
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
#[serde(rename_all = "PascalCase")]
struct EnrootServiceConfigFields {
    image: EnrootImage,
    command: Option<ContainerCommand>,
    gpus: Option<GpuSelection>,
    mounts: Option<Vec<BindMount>>,
    env: Option<BTreeMap<ServiceEnvVarName, Parameter<String>>>,
    #[serde(default)]
    root: bool,
    #[serde(default)]
    read_write: bool,
    #[serde(default)]
    restart_policy: UnitRestartPolicy,
}

impl TryFrom<EnrootServiceConfigFields> for EnrootServiceConfig {
    type Error = RegentError;

    fn try_from(fields: EnrootServiceConfigFields) -> Result<Self, Self::Error> {
        let config = Self {
            image: fields.image,
            command: fields.command,
            gpus: fields.gpus,
            mounts: fields.mounts,
            env: fields.env,
            root: fields.root,
            read_write: fields.read_write,
            restart_policy: fields.restart_policy,
        };
        config.validate()?;
        Ok(config)
    }
}

impl EnrootServiceConfig {
    pub fn new(image: EnrootImage) -> Self {
        Self {
            image,
            command: None,
            gpus: None,
            mounts: None,
            env: None,
            root: false,
            read_write: false,
            restart_policy: UnitRestartPolicy::default(),
        }
    }

    /// Service running a local squashfs file, which must be present on the host (not managed)
    pub fn from_local_image(path: AbsolutePath) -> Self {
        Self::new(EnrootImage::local(path))
    }

    /// Service running a squashfs file imported from `source` (`enroot import`) if it is missing
    pub fn from_imported_image(source: EnrootImageUri, path: AbsolutePath) -> Self {
        Self::new(EnrootImage::imported(source, path))
    }

    pub fn with_command(mut self, command: ContainerCommand) -> Self {
        self.command = Some(command);
        self
    }

    pub fn with_gpus(mut self, gpus: GpuSelection) -> Self {
        self.gpus = Some(gpus);
        self
    }

    /// Give all the GPUs to the container (`NVIDIA_VISIBLE_DEVICES=all`). Replaces the devices
    /// added before.
    pub fn with_all_gpus(self) -> Self {
        self.with_gpus(GpuSelection::All)
    }

    /// Give a GPU to the container, in addition to the devices added before. Replaces
    /// `with_all_gpus()`.
    pub fn with_gpu_device(mut self, gpu: GpuId) -> Self {
        self.gpus = Some(GpuSelection::add_device(self.gpus.take(), gpu));
        self
    }

    pub fn with_mounts(mut self, mounts: Vec<BindMount>) -> Self {
        self.mounts = Some(mounts);
        self
    }

    /// Add an environment variable (the value may be a secret reference)
    pub fn with_env(mut self, key: ServiceEnvVarName, value: Parameter<String>) -> Self {
        self.env
            .get_or_insert_with(BTreeMap::new)
            .insert(key, value);
        self
    }

    pub fn with_root(mut self, root: bool) -> Self {
        self.root = root;
        self
    }

    pub fn with_read_write(mut self, read_write: bool) -> Self {
        self.read_write = read_write;
        self
    }

    pub fn with_restart_policy(mut self, restart_policy: UnitRestartPolicy) -> Self {
        self.restart_policy = restart_policy;
        self
    }

    /// Never restart the service (`Restart=no`)
    pub fn with_restart_never(self) -> Self {
        self.with_restart_policy(UnitRestartPolicy::No)
    }

    /// Restart the service when it fails (`Restart=on-failure`, the default)
    pub fn with_restart_on_failure(self) -> Self {
        self.with_restart_policy(UnitRestartPolicy::OnFailure)
    }

    /// Always restart the service (`Restart=always`)
    pub fn with_restart_always(self) -> Self {
        self.with_restart_policy(UnitRestartPolicy::Always)
    }

    /// Checks between fields (run while parsing, and by `check()` for the Rust API)
    fn validate(&self) -> Result<(), RegentError> {
        for key in self.env.iter().flat_map(BTreeMap::keys) {
            let key = key.as_str();
            if key.starts_with("ENROOT_")
                || key.starts_with("XDG_")
                || key == "HOME"
                || key == "PATH"
            {
                return Err(invalid(
                    "environment variable",
                    key,
                    "it would also configure enroot itself",
                ));
            }
            if self.gpus.is_some()
                && (key == NVIDIA_VISIBLE_DEVICES || key == NVIDIA_DRIVER_CAPABILITIES)
            {
                return Err(invalid("environment variable", key, "it is set by Gpus"));
            }
        }
        Ok(())
    }

    fn gpu_env(&self) -> Vec<(String, String)> {
        match &self.gpus {
            Some(gpus) => vec![
                (
                    NVIDIA_VISIBLE_DEVICES.to_string(),
                    gpus.ids().into_iter().collect::<Vec<String>>().join(","),
                ),
                (
                    NVIDIA_DRIVER_CAPABILITIES.to_string(),
                    GPU_DRIVER_CAPABILITIES.to_string(),
                ),
            ],
            None => Vec::new(),
        }
    }

    /// Names of the variables of the environment file, passed with `--env NAME`
    fn env_names(&self) -> Vec<String> {
        let mut names: Vec<String> = self
            .env
            .iter()
            .flat_map(BTreeMap::keys)
            .map(ServiceEnvVarName::to_string)
            .collect();
        names.extend(self.gpu_env().into_iter().map(|(name, _)| name));
        names
    }

    fn exec_start(&self, enroot_path: &str, name: &ContainerName) -> Vec<String> {
        let mut args = vec![enroot_path.to_string(), "start".to_string()];
        if self.root {
            args.push("--root".to_string());
        }
        if self.read_write {
            args.push("--rw".to_string());
        }
        for mount in self.mounts.iter().flatten() {
            args.push("--mount".to_string());
            args.push(mount.enroot_arg());
        }
        for env_name in self.env_names() {
            args.push("--env".to_string());
            args.push(env_name);
        }
        args.push(name.to_string());
        args.extend(
            self.command
                .iter()
                .flat_map(|command| command.args().iter().cloned()),
        );
        args
    }

    /// `home` is the home directory of root, set in system units (Enroot finds its containers
    /// from it)
    fn unit_content(&self, id: &ServiceUnitId, enroot_path: &str, home: &Option<String>) -> String {
        render_unit(
            id,
            &UnitSpec {
                exec_start: self.exec_start(enroot_path, id.name()),
                environment: home
                    .iter()
                    .map(|home| ("HOME".to_string(), home.clone()))
                    .collect(),
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
                    key.to_string(),
                    value.clone().inner_raw(optional_secret_provider).await?,
                ));
            }
        }
        entries.extend(self.gpu_env());
        Ok(render_env_file(&entries))
    }
}

/// Content of the marker recording the image a container was created from
fn marker_content(image: &AbsolutePath, identity: &str) -> String {
    format!("image={}\nidentity={}\n", image, identity)
}

/// Reasons why the container must be recreated, from its marker (`None` if missing) and the
/// current identity of the image
fn recreation_reasons(marker: Option<&str>, image: &AbsolutePath, identity: &str) -> Vec<String> {
    let Some(marker) = marker else {
        return vec![
            "image can't be verified on a container which was not created by Regent".to_string(),
        ];
    };
    if marker == marker_content(image, identity) {
        return Vec::new();
    }
    let recorded = |key: &str| {
        marker
            .lines()
            .find_map(|line| line.strip_prefix(key))
            .unwrap_or_default()
            .to_string()
    };
    let recorded_image = recorded("image=");
    if recorded_image != image.as_str() {
        vec![format!(
            "container was created from {:?}, expected {}",
            recorded_image, image
        )]
    } else {
        vec![format!(
            "image {} changed since the container was created",
            image
        )]
    }
}

/// `size mtime` of a file, as printed by `stat -c '%s %Y'`
fn parse_identity(output: &str) -> Option<String> {
    output
        .lines()
        .map(str::trim)
        .find(|line| {
            let parts: Vec<&str> = line.split(' ').collect();
            parts.len() == 2
                && parts
                    .iter()
                    .all(|part| !part.is_empty() && part.chars().all(|c| c.is_ascii_digit()))
        })
        .map(String::from)
}

/// Container names of `enroot list` (one per line, other lines ignored by the caller)
fn is_listed(output: &str, name: &ContainerName) -> bool {
    output.lines().any(|line| line.trim() == name.as_str())
}

impl Timeout for EnrootExpectedState {
    fn default_timeout(&self) -> Duration {
        Duration::from_secs(120)
    }
}

impl Check for EnrootExpectedState {
    fn check(&self) -> Result<(), RegentError> {
        // Values are validated when their type is built, only the checks between fields remain
        // (the Rust API builder can't run them)
        match &self.state {
            EnrootServiceState::Running(config) | EnrootServiceState::Stopped(config) => {
                config.validate()
            }
            EnrootServiceState::Absent => Ok(()),
        }
    }

    fn check_host_compatibility(
        &self,
        host_properties: &HostProperties,
    ) -> Result<(), RegentError> {
        check_enroot_host_compatibility(host_properties)
    }
}

impl<Handler: HostHandler> AssessCompliance<Handler> for EnrootExpectedState {
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

        let (scope, home) = super::service_unit::detect_scope(host_handler, privilege).await?;
        let id = ServiceUnitId::new(ServiceEngine::Enroot, self.name.clone(), scope);
        let enroot_path = resolve_executable(host_handler, "enroot", privilege).await?;

        let mut remediations: Vec<Remediation> = Vec::new();
        let mut push = |api_call: EnrootInternalApiCall| {
            remediations.push(Remediation::Enroot(EnrootApiCall::from(
                api_call,
                privilege.clone(),
            )));
        };

        let (config, should_run) = match &self.state {
            EnrootServiceState::Absent => {
                let observed = observe_service(host_handler, &id, false, privilege).await?;
                if needs_removal(&observed) {
                    push(EnrootInternalApiCall::Service {
                        unit: id.clone(),
                        action: ServiceUnitAction::Remove,
                    });
                }
                // Without enroot, there is no container to remove
                let is_container_present = match &enroot_path {
                    Some(_) => is_container_listed(host_handler, &self.name, privilege).await?,
                    None => false,
                };
                let marker =
                    read_optional_file(host_handler, &marker_path(&id), "image marker", privilege)
                        .await?;
                if is_container_present || marker.is_some() {
                    push(EnrootInternalApiCall::RemoveContainer {
                        unit: id,
                        is_container_present,
                    });
                }
                return assessment(remediations);
            }
            EnrootServiceState::Running(config) => (config, true),
            EnrootServiceState::Stopped(config) => (config, false),
        };

        let Some(enroot_path) = enroot_path else {
            return Err(RegentError::FailedDryRunEvaluation(
                "Enroot CLI (enroot) is not available on this host".to_string(),
            ));
        };

        let image_path = config.image.path();
        let mut is_image_imported = false;
        if !file_exists(host_handler, image_path, privilege).await? {
            match &config.image {
                EnrootImage::Local(path) => {
                    return Ok(AttributeComplianceAssessment::NonCompliantFatal(format!(
                        "image {} is not present on the host",
                        path
                    )));
                }
                EnrootImage::Imported(imported) => {
                    push(EnrootInternalApiCall::Import(imported.clone()));
                    is_image_imported = true;
                }
            }
        }

        let is_container_present = is_container_listed(host_handler, &self.name, privilege).await?;
        let reasons = if is_image_imported {
            vec![format!("image {} will be imported", image_path)]
        } else {
            let identity = image_identity(host_handler, image_path, privilege).await?;
            let marker =
                read_optional_file(host_handler, &marker_path(&id), "image marker", privilege)
                    .await?;
            recreation_reasons(marker.as_deref(), image_path, &identity)
        };

        let container_changed = match (is_container_present, reasons.is_empty()) {
            (false, _) => {
                push(EnrootInternalApiCall::CreateContainer {
                    unit: id.clone(),
                    image: image_path.clone(),
                    reasons: Vec::new(),
                });
                true
            }
            (true, false) => {
                push(EnrootInternalApiCall::CreateContainer {
                    unit: id.clone(),
                    image: image_path.clone(),
                    reasons,
                });
                true
            }
            (true, true) => false,
        };

        let home = match scope {
            UnitScope::System if !home.is_empty() => Some(home),
            _ => None,
        };
        let observed = observe_service(host_handler, &id, should_run, privilege).await?;
        let expected_unit = config.unit_content(&id, &enroot_path, &home);
        let expected_env = config.env_content(optional_secret_provider).await?;

        for step in plan_service(
            should_run,
            &expected_unit,
            &expected_env,
            &observed,
            container_changed,
        ) {
            push(match step {
                ServiceStep::WriteFiles(reasons) => EnrootInternalApiCall::WriteServiceFiles {
                    unit: id.clone(),
                    config: config.clone(),
                    enroot_path: enroot_path.clone(),
                    home: home.clone(),
                    reasons,
                },
                ServiceStep::Action(action) => EnrootInternalApiCall::Service {
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

fn marker_path(id: &ServiceUnitId) -> String {
    id.regent_file("image")
}

async fn is_container_listed<Handler: HostHandler>(
    host_handler: &mut Handler,
    name: &ContainerName,
    privilege: &Privilege,
) -> Result<bool, RegentError> {
    let result = host_handler
        .run_command("enroot list", privilege)
        .await
        .map_err(|e| {
            RegentError::FailedDryRunEvaluation(format!("Unable to list containers: {:?}", e))
        })?;
    if result.return_code != 0 {
        return Err(RegentError::FailedDryRunEvaluation(format!(
            "Unable to list containers: {:?}",
            result
        )));
    }
    Ok(is_listed(&result.stdout, name))
}

async fn image_identity<Handler: HostHandler>(
    host_handler: &mut Handler,
    image: &AbsolutePath,
    privilege: &Privilege,
) -> Result<String, RegentError> {
    let result = host_handler
        .run_command(
            &format!("stat -c '%s %Y' {}", shell_quote(image.as_str())),
            privilege,
        )
        .await
        .map_err(|e| {
            RegentError::FailedDryRunEvaluation(format!("Unable to stat {}: {:?}", image, e))
        })?;
    parse_identity(&result.stdout).ok_or_else(|| {
        RegentError::FailedDryRunEvaluation(format!("Unable to stat {}: {:?}", image, result))
    })
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase", rename_all_fields = "PascalCase")]
pub enum EnrootInternalApiCall {
    Import(EnrootImportedImage),
    /// Create the container (removing it first if `reasons` is not empty: stop its service,
    /// remove it) and record its image in the marker
    CreateContainer {
        unit: ServiceUnitId,
        image: AbsolutePath,
        reasons: Vec<String>,
    },
    RemoveContainer {
        unit: ServiceUnitId,
        is_container_present: bool,
    },
    WriteServiceFiles {
        unit: ServiceUnitId,
        config: Box<EnrootServiceConfig>,
        enroot_path: String,
        home: Option<String>,
        reasons: Vec<String>,
    },
    Service {
        unit: ServiceUnitId,
        action: ServiceUnitAction,
    },
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct EnrootApiCall {
    pub api_call: EnrootInternalApiCall,
    privilege: Privilege,
}

impl EnrootApiCall {
    pub fn display(&self) -> String {
        match &self.api_call {
            EnrootInternalApiCall::Import(imported) => {
                format!("Import image {} into {}", imported.source, imported.path)
            }
            EnrootInternalApiCall::CreateContainer {
                unit,
                image,
                reasons,
            } => {
                if reasons.is_empty() {
                    format!("Create container {} from {}", unit.name(), image)
                } else {
                    format!(
                        "Recreate container {} from {} ({})",
                        unit.name(),
                        image,
                        reasons.join("; ")
                    )
                }
            }
            EnrootInternalApiCall::RemoveContainer { unit, .. } => {
                format!("Remove container {}", unit.name())
            }
            EnrootInternalApiCall::WriteServiceFiles { unit, reasons, .. } => format!(
                "Write {} and its environment file ({})",
                unit,
                reasons.join("; ")
            ),
            EnrootInternalApiCall::Service { unit, action } => action.display(unit),
        }
    }

    fn from(api_call: EnrootInternalApiCall, privilege: Privilege) -> EnrootApiCall {
        EnrootApiCall {
            api_call,
            privilege,
        }
    }
}

impl Timeout for EnrootApiCall {
    fn default_timeout(&self) -> Duration {
        match &self.api_call {
            // Images of inference servers weigh several GB
            EnrootInternalApiCall::Import(_) => Duration::from_secs(3600),
            // Unpacking the image
            EnrootInternalApiCall::CreateContainer { .. } => Duration::from_secs(900),
            _ => Duration::from_secs(180),
        }
    }
}

impl Check for EnrootApiCall {
    fn check(&self) -> Result<(), RegentError> {
        Ok(())
    }

    fn check_host_compatibility(
        &self,
        host_properties: &HostProperties,
    ) -> Result<(), RegentError> {
        check_enroot_host_compatibility(host_properties)
    }
}

impl<Handler: HostHandler> ReachCompliance<Handler> for EnrootApiCall {
    async fn call(
        &self,
        host_handler: &mut Handler,
        host_properties: &Option<HostProperties>,
        optional_secret_provider: &Option<SecretProvidersPool>,
    ) -> Result<InternalApiCallOutcome, RegentError> {
        if let Some(props) = host_properties {
            self.check_host_compatibility(props)?;
        }

        let command = match &self.api_call {
            EnrootInternalApiCall::Import(imported) => import_command(imported),
            EnrootInternalApiCall::CreateContainer {
                unit,
                image,
                reasons,
            } => create_command(unit, image, !reasons.is_empty()),
            EnrootInternalApiCall::RemoveContainer {
                unit,
                is_container_present,
            } => remove_command(unit, *is_container_present),
            EnrootInternalApiCall::WriteServiceFiles {
                unit,
                config,
                enroot_path,
                home,
                ..
            } => {
                let env = config.env_content(optional_secret_provider).await?;
                return write_files(
                    host_handler,
                    unit,
                    &config.unit_content(unit, enroot_path, home),
                    &env,
                    &self.privilege,
                )
                .await;
            }
            EnrootInternalApiCall::Service { unit, action } => {
                return run_action(host_handler, unit, *action, &self.privilege).await;
            }
        };
        run_remediation(host_handler, &command, &self.privilege, true).await
    }
}

/// `mkdir -p <parent> && enroot import -o <path> <source>`
fn import_command(imported: &EnrootImportedImage) -> String {
    format!(
        "mkdir -p {} && enroot import -o {} {}",
        shell_quote(imported.path.parent()),
        shell_quote(imported.path.as_str()),
        shell_quote(imported.source.as_str())
    )
}

/// Create the container (after removing it, its service stopped, if `recreate`), then record
/// the image path and identity in the marker
fn create_command(id: &ServiceUnitId, image: &AbsolutePath, recreate: bool) -> String {
    let name = shell_quote(id.name().as_str());
    let image_path = shell_quote(image.as_str());
    let removal = if recreate {
        format!(
            "{{ {} >/dev/null 2>&1; true; }} && enroot remove --force {} && ",
            id.systemctl(&["stop", &id.unit_name()]),
            name
        )
    } else {
        String::new()
    };
    format!(
        "{removal}enroot create --name {name} {image_path} && (umask 077 && mkdir -p {dir} && printf 'image=%s\\nidentity=%s\\n' {image_path} \"$(stat -c '%s %Y' {image_path})\" > {marker})",
        removal = removal,
        name = name,
        image_path = image_path,
        dir = id.regent_dir(),
        marker = marker_path(id),
    )
}

fn remove_command(id: &ServiceUnitId, is_container_present: bool) -> String {
    let marker_removal = format!("rm -f {}", marker_path(id));
    if is_container_present {
        format!(
            "enroot remove --force {} && {}",
            shell_quote(id.name().as_str()),
            marker_removal
        )
    } else {
        marker_removal
    }
}

fn check_enroot_host_compatibility(host_properties: &HostProperties) -> Result<(), RegentError> {
    match host_properties.os_kind() {
        OsKind::Linux(_) => Ok(()),
        incompatible_os_kind => Err(RegentError::IncompatibleHost(format!(
            "Host is {:?} but Enroot services are only supported on Linux",
            incompatible_os_kind
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::secrets::SecretReference;

    use crate::state::attribute::container::container_spec::GpuList;
    fn full_yaml() -> &'static str {
        "---
Name: vllm
State: !Running
  Image: !Imported
    Source: docker://nvcr.io#nvidia/vllm:24.10-py3
    Path: /opt/images/vllm-24.10.sqsh
  Command:
    - vllm
    - serve
    - meta-llama/Llama-3.1-8B-Instruct
    - --port
    - '8000'
  Gpus: !Devices [0, GPU-4b9d7a3c-2f1e-4d5a-9b8c-7e6f5a4b3c2d]
  Mounts:
    - /srv/models:/root/.cache/huggingface
    - /srv/config:/config:ro
  Env:
    TZ: Europe/Paris
    HF_TOKEN:
      SecRef: hf_token
      Provider: files
  Root: true
  ReadWrite: true
  RestartPolicy: Always
"
    }

    fn full_config() -> EnrootServiceConfig {
        let state: EnrootExpectedState = yaml_serde::from_str(full_yaml()).unwrap();
        match state.state {
            EnrootServiceState::Running(config) => *config,
            other => panic!("unexpected state {:?}", other),
        }
    }

    fn id(scope: UnitScope) -> ServiceUnitId {
        ServiceUnitId::new(ServiceEngine::Enroot, "vllm".parse().unwrap(), scope)
    }

    fn block_on<F: std::future::Future>(future: F) -> F::Output {
        tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap()
            .block_on(future)
    }

    #[test]
    fn parsing_enroot_module_block_from_yaml_str() {
        let config = full_config();
        assert_eq!(config.image.path().as_str(), "/opt/images/vllm-24.10.sqsh");
        assert_eq!(
            config
                .env
                .as_ref()
                .unwrap()
                .get(&"HF_TOKEN".parse().unwrap()),
            Some(&Parameter::Secret(SecretReference::from(
                "hf_token",
                Some("files".to_string())
            )))
        );
        assert!(config.root && config.read_write);

        let raw = "---
- Name: legacy
  State: Absent
- Name: app
  State: !Stopped
    Image: !Local /opt/images/app.sqsh
- Name: llm
  State: !Running
    Image: !Local /opt/images/llm.sqsh
    Gpus: All
";
        let states: Vec<EnrootExpectedState> = yaml_serde::from_str(raw).unwrap();
        assert_eq!(states[0].state, EnrootServiceState::Absent);
        match &states[1].state {
            EnrootServiceState::Stopped(config) => {
                assert_eq!(config.command, None);
                assert_eq!(config.restart_policy, UnitRestartPolicy::OnFailure);
                assert!(!config.root && !config.read_write);
            }
            other => panic!("unexpected state {:?}", other),
        }
        match &states[2].state {
            EnrootServiceState::Running(config) => {
                assert_eq!(config.gpus, Some(GpuSelection::All))
            }
            other => panic!("unexpected state {:?}", other),
        }
    }

    #[test]
    fn serialization_round_trip_preserves_state() {
        // Templating (Attribute::consider_context) relies on a JSON round trip
        let state: EnrootExpectedState = yaml_serde::from_str(full_yaml()).unwrap();
        let json = serde_json::to_string(&state).unwrap();
        assert_eq!(
            serde_json::from_str::<EnrootExpectedState>(&json).unwrap(),
            state
        );
    }

    #[test]
    fn invalid_states_are_rejected_while_parsing() {
        let base = "Name: llm\nState: !Running\n  Image: !Local /opt/llm.sqsh\n";
        let rejected = [
            // Configuration makes no sense for an absent service
            (
                "Name: old\nState: !Absent\n  Image: !Local /opt/x.sqsh\n",
                "expected unit",
            ),
            // Image is mandatory for a service which must exist
            (
                "Name: llm\nState: !Running\n  Root: true\n",
                "missing field `Image`",
            ),
            // Schemes of enroot import only
            (
                "Name: llm\nState: !Running\n  Image: !Imported\n    Source: oras://ghcr.io/x/y\n    Path: /opt/x.sqsh\n",
                "supported schemes",
            ),
            (
                "Name: llm\nState: !Running\n  Image: !Imported\n    Source: docker://vllm/vllm-openai\n",
                "missing field `Path`",
            ),
            (
                "Name: llm\nState: !Running\n  Image: !Local x.sqsh\n",
                "absolute",
            ),
            (
                &format!("{}  Command: []\n", base),
                "Command can't be empty",
            ),
            // GPUs: valid IDs, non-empty list, variables owned by Gpus
            (&format!("{}  Gpus: !Devices []\n", base), "can't be empty"),
            (&format!("{}  Gpus: !Devices [gpu0]\n", base), "GPU-<uuid>"),
            (
                &format!(
                    "{}  Gpus: All\n  Env:\n    NVIDIA_VISIBLE_DEVICES: '0'\n",
                    base
                ),
                "set by Gpus",
            ),
            // Variables configuring enroot itself
            (
                &format!("{}  Env:\n    ENROOT_DATA_PATH: /tmp\n", base),
                "configure enroot",
            ),
            (
                &format!("{}  Env:\n    PATH: /bin\n", base),
                "configure enroot",
            ),
            (&format!("{}  Mounts: [/srv:srv]\n", base), "absolute"),
            (&format!("{}  Mounts: ['/srv:/srv:z']\n", base), "ro or rw"),
            (&format!("{}  Privileged: true\n", base), "unknown field"),
        ];
        for (raw, reason) in rejected {
            let error = yaml_serde::from_str::<EnrootExpectedState>(raw)
                .expect_err(&format!("should be rejected: {}", raw))
                .to_string();
            assert!(
                error.contains(reason),
                "{:?} rejected for another reason: {}",
                raw,
                error
            );
        }

        // GPU variables are allowed without Gpus, and checked for the Rust API
        assert!(
            yaml_serde::from_str::<EnrootExpectedState>(&format!(
                "{}  Env:\n    NVIDIA_VISIBLE_DEVICES: '0'\n",
                base
            ))
            .is_ok()
        );
        let built = EnrootExpectedState::running(
            "llm".parse().unwrap(),
            EnrootServiceConfig::new(EnrootImage::Local("/opt/llm.sqsh".parse().unwrap()))
                .with_gpus(GpuSelection::All)
                .with_env(
                    "NVIDIA_DRIVER_CAPABILITIES".parse().unwrap(),
                    Parameter::Clear("all".to_string()),
                ),
        );
        assert!(built.check().is_err());
    }

    #[test]
    fn exec_start_follows_enroot_cli() {
        let name = "vllm".parse().unwrap();
        assert_eq!(
            full_config().exec_start("/usr/bin/enroot", &name),
            vec![
                "/usr/bin/enroot",
                "start",
                "--root",
                "--rw",
                "--mount",
                "/srv/models:/root/.cache/huggingface:none:x-create=auto,rbind",
                "--mount",
                "/srv/config:/config:none:x-create=auto,rbind,ro",
                "--env",
                "HF_TOKEN",
                "--env",
                "TZ",
                "--env",
                "NVIDIA_VISIBLE_DEVICES",
                "--env",
                "NVIDIA_DRIVER_CAPABILITIES",
                "vllm",
                "vllm",
                "serve",
                "meta-llama/Llama-3.1-8B-Instruct",
                "--port",
                "8000",
            ]
        );
        let simple = EnrootServiceConfig::new(EnrootImage::Local("/opt/a.sqsh".parse().unwrap()));
        assert_eq!(
            simple.exec_start("/usr/bin/enroot", &name),
            vec!["/usr/bin/enroot", "start", "vllm"]
        );
    }

    #[test]
    fn unit_and_environment_file_are_rendered() {
        let config = full_config();
        let unit = config.unit_content(
            &id(UnitScope::System),
            "/usr/bin/enroot",
            &Some("/root".to_string()),
        );
        assert!(unit.contains("\nEnvironment=HOME=/root\n"));
        assert!(unit.contains("\nEnvironmentFile=/etc/regent-sdk/enroot/vllm.env\n"));
        let unit = config.unit_content(&id(UnitScope::User), "/usr/bin/enroot", &None);
        assert!(!unit.contains("Environment=HOME"));
        assert!(unit.contains("\nEnvironmentFile=%E/regent-sdk/enroot/vllm.env\n"));

        let config = EnrootServiceConfig::new(EnrootImage::Local("/opt/a.sqsh".parse().unwrap()))
            .with_gpus(GpuSelection::Devices(
                vec!["1".parse().unwrap(), "0".parse().unwrap()]
                    .try_into()
                    .unwrap(),
            ))
            .with_env(
                "HF_TOKEN".parse().unwrap(),
                Parameter::Clear("hf_\"x\"".to_string()),
            );
        assert_eq!(
            block_on(config.env_content(&None)).unwrap(),
            "# Managed by regent-sdk: manual changes will be overwritten
HF_TOKEN=\"hf_\\\"x\\\"\"
NVIDIA_VISIBLE_DEVICES=\"0,1\"
NVIDIA_DRIVER_CAPABILITIES=\"compute,utility\"
"
        );
    }

    #[test]
    fn container_drift_is_detected_through_the_marker() {
        let image: AbsolutePath = "/opt/images/vllm-24.10.sqsh".parse().unwrap();
        let marker = marker_content(&image, "1234 1700000000");
        assert_eq!(
            marker,
            "image=/opt/images/vllm-24.10.sqsh\nidentity=1234 1700000000\n"
        );
        assert!(recreation_reasons(Some(&marker), &image, "1234 1700000000").is_empty());
        assert_eq!(
            recreation_reasons(None, &image, "1234 1700000000"),
            vec!["image can't be verified on a container which was not created by Regent"]
        );
        assert_eq!(
            recreation_reasons(Some(&marker), &image, "1234 1800000000"),
            vec!["image /opt/images/vllm-24.10.sqsh changed since the container was created"]
        );
        let other: AbsolutePath = "/opt/images/vllm-24.11.sqsh".parse().unwrap();
        assert_eq!(
            recreation_reasons(Some(&marker), &other, "1234 1700000000"),
            vec![
                "container was created from \"/opt/images/vllm-24.10.sqsh\", expected /opt/images/vllm-24.11.sqsh"
            ]
        );

        assert_eq!(
            parse_identity("stat: warning\n1234 1700000000\n"),
            Some("1234 1700000000".to_string())
        );
        assert_eq!(parse_identity("stat: cannot stat"), None);
        let name = "vllm".parse().unwrap();
        assert!(is_listed("other\nvllm\n", &name));
        assert!(!is_listed("vllm2\n", &name));
    }

    #[test]
    fn container_commands_follow_enroot_cli() {
        let image: AbsolutePath = "/opt/images/vllm.sqsh".parse().unwrap();
        assert_eq!(
            create_command(&id(UnitScope::System), &image, false),
            "enroot create --name 'vllm' '/opt/images/vllm.sqsh' && (umask 077 && mkdir -p /etc/regent-sdk/enroot && printf 'image=%s\\nidentity=%s\\n' '/opt/images/vllm.sqsh' \"$(stat -c '%s %Y' '/opt/images/vllm.sqsh')\" > /etc/regent-sdk/enroot/'vllm.image')"
        );
        assert!(
            create_command(&id(UnitScope::System), &image, true).starts_with(
                "{ 'systemctl' 'stop' 'regent-enroot-vllm.service' >/dev/null 2>&1; true; } && enroot remove --force 'vllm' && enroot create"
            )
        );
        assert_eq!(
            remove_command(&id(UnitScope::User), true),
            "enroot remove --force 'vllm' && rm -f \"${XDG_CONFIG_HOME:-$HOME/.config}\"/regent-sdk/enroot/'vllm.image'"
        );
        assert_eq!(
            import_command(&EnrootImportedImage {
                source: "docker://nvcr.io#nvidia/vllm:24.10-py3".parse().unwrap(),
                path: image,
            }),
            "mkdir -p '/opt/images' && enroot import -o '/opt/images/vllm.sqsh' 'docker://nvcr.io#nvidia/vllm:24.10-py3'"
        );
    }

    #[test]
    fn remediations_never_show_secret_values() {
        let call = EnrootApiCall::from(
            EnrootInternalApiCall::WriteServiceFiles {
                unit: id(UnitScope::User),
                config: Box::new(full_config()),
                enroot_path: "/usr/bin/enroot".to_string(),
                home: None,
                reasons: vec!["environment file differs".to_string()],
            },
            Privilege::None,
        );
        assert_eq!(
            call.display(),
            "Write regent-enroot-vllm.service (user unit) and its environment file (environment file differs)"
        );
    }

    #[test]
    fn choice_methods_match_the_explicit_enums() {
        let source = || {
            "docker://vllm/vllm-openai:v0.6.3"
                .parse::<EnrootImageUri>()
                .unwrap()
        };
        let path = || {
            "/opt/images/vllm-0.6.3.sqsh"
                .parse::<AbsolutePath>()
                .unwrap()
        };
        assert_eq!(EnrootImage::local(path()), EnrootImage::Local(path()));
        assert_eq!(
            EnrootServiceConfig::from_local_image(path()),
            EnrootServiceConfig::new(EnrootImage::Local(path()))
        );
        assert_eq!(
            EnrootServiceConfig::from_imported_image(source(), path()),
            EnrootServiceConfig::new(EnrootImage::Imported(EnrootImportedImage {
                source: source(),
                path: path(),
            }))
        );

        let new = || EnrootServiceConfig::from_local_image(path());
        assert_eq!(new().with_all_gpus(), new().with_gpus(GpuSelection::All));
        let devices = GpuSelection::Devices(
            GpuList::try_from(vec!["0".parse().unwrap(), "MIG-1a2b".parse().unwrap()]).unwrap(),
        );
        assert_eq!(
            new()
                .with_all_gpus()
                .with_gpu_device("0".parse().unwrap())
                .with_gpu_device("MIG-1a2b".parse().unwrap()),
            new().with_gpus(devices)
        );
        assert_eq!(
            new().with_gpu_device("0".parse().unwrap()).with_all_gpus(),
            new().with_gpus(GpuSelection::All)
        );

        for (config, policy) in [
            (new().with_restart_never(), UnitRestartPolicy::No),
            (
                new().with_restart_always().with_restart_on_failure(),
                UnitRestartPolicy::OnFailure,
            ),
            (new().with_restart_always(), UnitRestartPolicy::Always),
        ] {
            assert_eq!(config, new().with_restart_policy(policy));
        }
    }
}
