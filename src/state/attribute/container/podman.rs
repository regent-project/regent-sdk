//! Podman container attribute
//!
//! This module provides the `PodmanExpectedState` type for managing Podman containers
//! through the `podman` CLI (Podman 4+) available on the managed host.
//!
//! **Compatible OS:** Linux and macOS (any host where the `podman` CLI is available)
//!
//! **Rootful or rootless:** Podman keeps one container store per user. The attribute's
//! `Privilege` selects which one is managed: `!None` manages the rootless containers of the
//! connected user, `!WithSudo` the rootful containers of root.
//!
//! # Invalid states are unrepresentable
//!
//! - The container configuration only exists in the `Running` and `Stopped` states:
//!   an `Absent` container has nothing to configure.
//! - A container either joins a pod (`Placement: !Pod`) or is `!Standalone`. Joining a pod
//!   means sharing its network, IPC and UTS namespaces, so hostname, user namespace, IPC
//!   namespace, networks, published ports, DNS servers and extra hosts can only be set on a
//!   standalone container.
//! - The IPC namespace is either the host's (`Ipc: Host`) or the container's own: the size of
//!   `/dev/shm` (`ShmSize`) can only be set in the latter.
//! - Networking is either `Host`, `Isolated` (no network) or `Attached` to networks: ports,
//!   DNS servers and extra hosts can only be set in the latter.
//! - Values with a syntax (container and pod names, image, ports, volumes, devices, memory,
//!   CPUs, capabilities, extra hosts, environment variable names, network names) have
//!   dedicated types, shared with the Docker attribute in [`container_spec`](super::container_spec),
//!   which can only be built from a valid value.
//!
//! # How compliance is assessed
//!
//! The container is inspected (`podman container inspect`) and **only the options you set**
//! are compared with the current container. Options left out are not managed.
//!
//! - If an option differs, the container is **recreated** (removed, then created again).
//! - The image is compared by ID: the container is recreated when `Image` resolves locally to
//!   another image than the container's, which also covers a new pull of the same tag.
//! - The running state is then reached with `podman start` / `podman stop` / `podman unpause`.
//!
//! `Env` and `Labels` are checked as subsets: the image and Podman add their own entries.
//! The same goes for anonymous volumes (`Volumes` entries without `:`).
//!
//! Podman doesn't report some options the way they were given (capabilities are reported
//! relative to its default set, volume and log options are rewritten). These options
//! (`CapAdd`, `CapDrop`, volume options, `LogOptions`, `Userns`, `Gpus`, `Ipc`) are recorded
//! in the `io.regent-sdk.recorded-settings` label at creation and compared with it. A container
//! which was not created by Regent can't be verified on these options and is recreated.
//!
//! `Env` values can be secrets. They are resolved through the secret providers pool, but keep
//! in mind they end up on the `podman create` command line and in `podman inspect` output.
//!
//! Prefer fully qualified images (`docker.io/library/nginx:1.27`): short names may need an
//! interactive prompt to be resolved, depending on the `short-name-mode` of the host.
//!
//! In rootless mode, the `Always` and `UnlessStopped` restart policies only apply after a reboot
//! if the `podman-restart.service` user unit is enabled.
//!
//! # Examples
//!
//! ## Rust API
//!
//! ```no_run
//! use regent_sdk::state::attribute::container::container_spec::{NetworkList, RestartPolicy};
//! use regent_sdk::state::attribute::container::podman::{
//!     PodmanAttachedNetworking, PodmanContainerConfig, PodmanExpectedState, PodmanNetworking,
//!     PodmanPlacement, PodmanStandalone,
//! };
//! use regent_sdk::state::expected_state::Parameter;
//! use regent_sdk::{Attribute, ExpectedState, Privilege, RegentError};
//!
//! fn web_server() -> Result<ExpectedState, RegentError> {
//!     let networking = PodmanAttachedNetworking::new()
//!         .with_networks(NetworkList::try_from(vec!["frontend".parse()?])?)
//!         .with_ports(vec!["8080:80".parse()?]);
//!
//!     let config = PodmanContainerConfig::new("docker.io/library/nginx:1.27".parse()?)
//!         .with_placement(PodmanPlacement::Standalone(
//!             PodmanStandalone::new()
//!                 .with_hostname("web01")
//!                 .with_networking(PodmanNetworking::Attached(networking)),
//!         ))
//!         .with_volumes(vec!["/srv/www:/usr/share/nginx/html:ro,Z".parse()?])
//!         .with_env("TZ".parse()?, Parameter::Clear("Europe/Paris".to_string()))
//!         .with_restart_policy(RestartPolicy::Always);
//!
//!     let web = PodmanExpectedState::running("web".parse()?, config);
//!
//!     Ok(ExpectedState::new()
//!         .with_attribute(Attribute::podman(web, Privilege::None, None))
//!         .build())
//! }
//! ```
//!
//! ## YAML API
//!
//! ```yaml
//! Attributes:
//!   - Name: Web server container must be running
//!     Privilege: !None             # rootless container of the connected user
//!     Detail: !Podman
//!       Name: web
//!       State: !Running            # !Running | !Stopped (same configuration) | Absent
//!         Image: docker.io/library/nginx:1.27
//!         Pull: Missing            # Missing (default) | Never
//!         Entrypoint: /docker-entrypoint.sh
//!         Command: ["nginx", "-g", "daemon off;"]
//!         Env:
//!           TZ: Europe/Paris
//!           API_TOKEN:             # secret retrieved from a secret provider
//!             SecRef: web_api_token
//!             Provider: files
//!         Volumes:
//!           - /srv/www:/usr/share/nginx/html:ro,Z
//!           - nginx_cache:/var/cache/nginx
//!         Placement: !Standalone   # !Standalone | !Pod <pod name>
//!           Hostname: web01
//!           Userns: KeepId         # Host | Private | Auto | KeepId | NoMap
//!           Networking: !Attached  # Host | Isolated | !Attached
//!             Networks: [frontend, backend]
//!             Ports:
//!               - "8080:80"
//!               - "127.0.0.1:8443:443/tcp"
//!             Dns: [1.1.1.1]
//!             ExtraHosts: ["db.local:10.0.0.12"]
//!           Ipc: !Private          # Host | !Private | !Shareable
//!             ShmSize: 1g
//!         RestartPolicy: Always    # No | Always | UnlessStopped | !OnFailure <max retries, 0 = unlimited>
//!         User: "101:101"
//!         WorkingDir: /usr/share/nginx
//!         Labels:
//!           io.containers.autoupdate: registry
//!         Privileged: false
//!         ReadOnly: false
//!         Init: true
//!         CapAdd: [NET_BIND_SERVICE]
//!         CapDrop: [ALL]
//!         Memory: 512m
//!         Cpus: 1.5
//!         Devices: ["/dev/snd:/dev/snd:rw"]
//!         Gpus: All                # All | !Devices [0, 1] (indexes or GPU-<uuid>), through CDI
//!         LogDriver: journald
//!         LogOptions:
//!           tag: web
//! ```
//!
//! A GPU inference server ([vLLM](https://docs.vllm.ai)). GPUs are given through the CDI
//! specification generated by the NVIDIA Container Toolkit, see the
//! [`gpu`](crate::state::attribute::gpu) attributes:
//!
//! ```yaml
//! Attributes:
//!   - Name: vLLM OpenAI-compatible server must be running
//!     Privilege: !WithSudo
//!     Detail: !Podman
//!       Name: vllm
//!       State: !Running
//!         Image: docker.io/vllm/vllm-openai:v0.10.1
//!         Command: ["--model", "Qwen/Qwen3-8B"]
//!         Env:
//!           HF_TOKEN:
//!             SecRef: huggingface_token
//!             Provider: files
//!         Volumes: ["/srv/huggingface:/root/.cache/huggingface:Z"]
//!         Gpus: All
//!         Placement: !Standalone
//!           Ipc: Host
//!           Networking: !Attached
//!             Ports: ["8000:8000"]
//!         RestartPolicy: Always
//! ```
//!
//! A container joining an existing pod (pods are not managed by this attribute):
//!
//! ```yaml
//! Attributes:
//!   - Name: Application container must run in the app pod
//!     Privilege: !None
//!     Detail: !Podman
//!       Name: app
//!       State: !Running
//!         Image: ghcr.io/example/app:2.1
//!         Placement: !Pod app-pod
//! ```
//!
//! To make sure a container does not exist:
//!
//! ```yaml
//! Attributes:
//!   - Name: Old container must be removed
//!     Privilege: !None
//!     Detail: !Podman
//!       Name: legacy-app
//!       State: Absent
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
use crate::state::expected_state::Parameter;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::net::IpAddr;
use std::str::FromStr;
use std::time::Duration;

use super::container_spec::{
    Capability, ContainerCommand, ContainerImage, ContainerName, ContainerVolume, CpuCount,
    EnvVarName, ExtraHost, GpuSelection, HostDevice, IpcNamespace, MemorySize, NetworkList,
    PortBinding, PublishedPort, PullPolicy, RestartPolicy, compare_sets, invalid,
    is_valid_object_name, parse_inspect_output, pointer, quoted_command, string_list, to_strings,
};

/// Label in which the options Podman doesn't report faithfully are recorded at creation
const RECORDED_SETTINGS_LABEL: &str = "io.regent-sdk.recorded-settings";

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[serde(rename_all = "PascalCase")]
pub struct PodmanExpectedState {
    name: ContainerName,
    state: PodmanContainerState,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub enum PodmanContainerState {
    Running(Box<PodmanContainerConfig>),
    Stopped(Box<PodmanContainerConfig>),
    Absent,
}

impl PodmanExpectedState {
    pub fn running(name: ContainerName, config: PodmanContainerConfig) -> Self {
        Self {
            name,
            state: PodmanContainerState::Running(Box::new(config)),
        }
    }

    pub fn stopped(name: ContainerName, config: PodmanContainerConfig) -> Self {
        Self {
            name,
            state: PodmanContainerState::Stopped(Box::new(config)),
        }
    }

    pub fn absent(name: ContainerName) -> Self {
        Self {
            name,
            state: PodmanContainerState::Absent,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub enum PodmanPlacement {
    /// Join an existing pod (`--pod`), sharing its network and UTS namespaces
    Pod(PodName),
    Standalone(PodmanStandalone),
}

/// Namespace options of a container which is not in a pod
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[serde(rename_all = "PascalCase")]
pub struct PodmanStandalone {
    hostname: Option<String>,
    userns: Option<PodmanUserNamespace>,
    networking: Option<PodmanNetworking>,
    ipc: Option<IpcNamespace>,
}

impl PodmanStandalone {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_hostname(mut self, hostname: &str) -> Self {
        self.hostname = Some(hostname.to_string());
        self
    }

    pub fn with_userns(mut self, userns: PodmanUserNamespace) -> Self {
        self.userns = Some(userns);
        self
    }

    pub fn with_networking(mut self, networking: PodmanNetworking) -> Self {
        self.networking = Some(networking);
        self
    }

    pub fn with_ipc(mut self, ipc: IpcNamespace) -> Self {
        self.ipc = Some(ipc);
        self
    }
}

/// User namespace mode (`--userns`)
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub enum PodmanUserNamespace {
    /// `host`: no user namespace
    Host,
    /// `private`: new user namespace
    Private,
    /// `auto`: unique user namespace with automatically picked IDs
    Auto,
    /// `keep-id`: map the current user to the same UID inside the container (rootless)
    KeepId,
    /// `nomap`: don't map the current user inside the container (rootless)
    NoMap,
}

impl PodmanUserNamespace {
    fn as_cli_arg(&self) -> &'static str {
        match self {
            PodmanUserNamespace::Host => "host",
            PodmanUserNamespace::Private => "private",
            PodmanUserNamespace::Auto => "auto",
            PodmanUserNamespace::KeepId => "keep-id",
            PodmanUserNamespace::NoMap => "nomap",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub enum PodmanNetworking {
    /// Share the host network stack (`--network host`)
    Host,
    /// No network at all (`--network none`)
    Isolated,
    /// Attached to networks (or to the default network if `Networks` is omitted)
    Attached(PodmanAttachedNetworking),
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[serde(rename_all = "PascalCase")]
pub struct PodmanAttachedNetworking {
    networks: Option<NetworkList>,
    ports: Option<Vec<PublishedPort>>,
    dns: Option<Vec<IpAddr>>,
    extra_hosts: Option<Vec<ExtraHost>>,
}

impl PodmanAttachedNetworking {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_networks(mut self, networks: NetworkList) -> Self {
        self.networks = Some(networks);
        self
    }

    pub fn with_ports(mut self, ports: Vec<PublishedPort>) -> Self {
        self.ports = Some(ports);
        self
    }

    pub fn with_dns(mut self, dns: Vec<IpAddr>) -> Self {
        self.dns = Some(dns);
        self
    }

    pub fn with_extra_hosts(mut self, extra_hosts: Vec<ExtraHost>) -> Self {
        self.extra_hosts = Some(extra_hosts);
        self
    }
}

/// Configuration of a container which must exist
///
/// Every optional field left out is not managed (not compared, not passed to `podman create`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[serde(rename_all = "PascalCase")]
pub struct PodmanContainerConfig {
    /// Image reference (preferably fully qualified)
    image: ContainerImage,
    #[serde(default)]
    pull: PullPolicy,
    /// Command and arguments (overrides the image `CMD`)
    command: Option<ContainerCommand>,
    /// Entrypoint executable (overrides the image `ENTRYPOINT`, empty string to reset it)
    entrypoint: Option<String>,
    /// Environment variables (values can be secrets)
    env: Option<BTreeMap<EnvVarName, Parameter<String>>>,
    volumes: Option<Vec<ContainerVolume>>,
    /// Pod membership, or namespace options of a standalone container
    placement: Option<PodmanPlacement>,
    restart_policy: Option<RestartPolicy>,
    /// User (`name|uid[:group|gid]`)
    user: Option<String>,
    working_dir: Option<String>,
    labels: Option<BTreeMap<String, String>>,
    privileged: Option<bool>,
    read_only: Option<bool>,
    init: Option<bool>,
    cap_add: Option<Vec<Capability>>,
    cap_drop: Option<Vec<Capability>>,
    memory: Option<MemorySize>,
    cpus: Option<CpuCount>,
    devices: Option<Vec<HostDevice>>,
    /// GPUs, through the NVIDIA CDI specification (`--device nvidia.com/gpu=...`)
    gpus: Option<GpuSelection>,
    /// Logging driver (`journald`, `k8s-file`, `none`, `passthrough`)
    log_driver: Option<String>,
    log_options: Option<BTreeMap<String, String>>,
}

impl PodmanContainerConfig {
    pub fn new(image: ContainerImage) -> Self {
        Self {
            image,
            pull: PullPolicy::default(),
            command: None,
            entrypoint: None,
            env: None,
            volumes: None,
            placement: None,
            restart_policy: None,
            user: None,
            working_dir: None,
            labels: None,
            privileged: None,
            read_only: None,
            init: None,
            cap_add: None,
            cap_drop: None,
            memory: None,
            cpus: None,
            devices: None,
            gpus: None,
            log_driver: None,
            log_options: None,
        }
    }

    pub fn with_pull_policy(mut self, pull: PullPolicy) -> Self {
        self.pull = pull;
        self
    }

    pub fn with_command(mut self, command: ContainerCommand) -> Self {
        self.command = Some(command);
        self
    }

    pub fn with_entrypoint(mut self, entrypoint: &str) -> Self {
        self.entrypoint = Some(entrypoint.to_string());
        self
    }

    /// Add an environment variable (the value may be a secret reference)
    pub fn with_env(mut self, key: EnvVarName, value: Parameter<String>) -> Self {
        self.env
            .get_or_insert_with(BTreeMap::new)
            .insert(key, value);
        self
    }

    pub fn with_volumes(mut self, volumes: Vec<ContainerVolume>) -> Self {
        self.volumes = Some(volumes);
        self
    }

    pub fn with_placement(mut self, placement: PodmanPlacement) -> Self {
        self.placement = Some(placement);
        self
    }

    pub fn with_restart_policy(mut self, restart_policy: RestartPolicy) -> Self {
        self.restart_policy = Some(restart_policy);
        self
    }

    pub fn with_user(mut self, user: &str) -> Self {
        self.user = Some(user.to_string());
        self
    }

    pub fn with_working_dir(mut self, working_dir: &str) -> Self {
        self.working_dir = Some(working_dir.to_string());
        self
    }

    pub fn with_label(mut self, key: &str, value: &str) -> Self {
        self.labels
            .get_or_insert_with(BTreeMap::new)
            .insert(key.to_string(), value.to_string());
        self
    }

    pub fn with_privileged(mut self, privileged: bool) -> Self {
        self.privileged = Some(privileged);
        self
    }

    pub fn with_read_only(mut self, read_only: bool) -> Self {
        self.read_only = Some(read_only);
        self
    }

    pub fn with_init(mut self, init: bool) -> Self {
        self.init = Some(init);
        self
    }

    pub fn with_cap_add(mut self, capabilities: Vec<Capability>) -> Self {
        self.cap_add = Some(capabilities);
        self
    }

    pub fn with_cap_drop(mut self, capabilities: Vec<Capability>) -> Self {
        self.cap_drop = Some(capabilities);
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

    pub fn with_devices(mut self, devices: Vec<HostDevice>) -> Self {
        self.devices = Some(devices);
        self
    }

    pub fn with_gpus(mut self, gpus: GpuSelection) -> Self {
        self.gpus = Some(gpus);
        self
    }

    pub fn with_log_driver(mut self, log_driver: &str) -> Self {
        self.log_driver = Some(log_driver.to_string());
        self
    }

    pub fn with_log_option(mut self, key: &str, value: &str) -> Self {
        self.log_options
            .get_or_insert_with(BTreeMap::new)
            .insert(key.to_string(), value.to_string());
        self
    }

    fn standalone(&self) -> Option<&PodmanStandalone> {
        match &self.placement {
            Some(PodmanPlacement::Standalone(standalone)) => Some(standalone),
            _ => None,
        }
    }

    /// Options recorded in a label at creation, as Podman doesn't report them faithfully
    fn recorded_settings(&self) -> RecordedSettings {
        RecordedSettings {
            cap_add: self
                .cap_add
                .as_ref()
                .map(|caps| caps.iter().map(|cap| cap.to_string()).collect()),
            cap_drop: self
                .cap_drop
                .as_ref()
                .map(|caps| caps.iter().map(|cap| cap.to_string()).collect()),
            volumes: self
                .volumes
                .as_ref()
                .map(|volumes| volumes.iter().map(|volume| volume.to_string()).collect()),
            log_options: self.log_options.clone(),
            userns: self
                .standalone()
                .and_then(|standalone| standalone.userns.clone()),
            gpus: self.gpus.as_ref().map(GpuSelection::ids),
            ipc: self
                .standalone()
                .and_then(|standalone| standalone.ipc.clone()),
        }
    }

    /// Resolve environment variables, retrieving secrets if needed
    async fn resolve_env(
        &self,
        optional_secret_provider: &Option<SecretProvidersPool>,
    ) -> Result<Vec<(String, String)>, RegentError> {
        let mut resolved = Vec::new();
        if let Some(env) = &self.env {
            for (key, value) in env {
                resolved.push((
                    key.to_string(),
                    value.clone().inner_raw(optional_secret_provider).await?,
                ));
            }
        }
        Ok(resolved)
    }

    fn create_args(&self, name: &ContainerName, env: &[(String, String)]) -> Vec<String> {
        let mut args = to_strings(&["podman", "create", "--name", name.as_str()]);

        let mut push_option = |flag: &str, value: String| {
            args.push(flag.to_string());
            args.push(value);
        };

        match &self.placement {
            Some(PodmanPlacement::Pod(pod)) => push_option("--pod", pod.to_string()),
            Some(PodmanPlacement::Standalone(standalone)) => {
                if let Some(hostname) = &standalone.hostname {
                    push_option("--hostname", hostname.clone());
                }
                if let Some(userns) = &standalone.userns {
                    push_option("--userns", userns.as_cli_arg().to_string());
                }
                if let Some(ipc) = &standalone.ipc {
                    push_option("--ipc", ipc.mode().to_string());
                    if let Some(shm_size) = ipc.shm_size() {
                        push_option("--shm-size", shm_size.to_string());
                    }
                }
                match &standalone.networking {
                    Some(PodmanNetworking::Host) => push_option("--network", "host".to_string()),
                    Some(PodmanNetworking::Isolated) => {
                        push_option("--network", "none".to_string())
                    }
                    Some(PodmanNetworking::Attached(attached)) => {
                        for network in attached.networks.iter().flat_map(NetworkList::networks) {
                            push_option("--network", network.to_string());
                        }
                        for port in attached.ports.iter().flatten() {
                            push_option("--publish", port.to_string());
                        }
                        for dns in attached.dns.iter().flatten() {
                            push_option("--dns", dns.to_string());
                        }
                        for extra_host in attached.extra_hosts.iter().flatten() {
                            push_option("--add-host", extra_host.to_string());
                        }
                    }
                    None => {}
                }
            }
            None => {}
        }
        if let Some(user) = &self.user {
            push_option("--user", user.clone());
        }
        if let Some(working_dir) = &self.working_dir {
            push_option("--workdir", working_dir.clone());
        }
        if let Some(entrypoint) = &self.entrypoint {
            push_option("--entrypoint", entrypoint.clone());
        }
        for (key, value) in env {
            push_option("--env", format!("{}={}", key, value));
        }
        for volume in self.volumes.iter().flatten() {
            push_option("--volume", volume.to_string());
        }
        if let Some(restart_policy) = &self.restart_policy {
            push_option("--restart", restart_policy.as_cli_arg());
        }
        for (key, value) in self.labels.iter().flatten() {
            push_option("--label", format!("{}={}", key, value));
        }
        let recorded_settings = self.recorded_settings();
        if recorded_settings != RecordedSettings::default() {
            push_option(
                "--label",
                format!(
                    "{}={}",
                    RECORDED_SETTINGS_LABEL,
                    serde_json::to_string(&recorded_settings).unwrap_or_default()
                ),
            );
        }
        for capability in self.cap_add.iter().flatten() {
            push_option("--cap-add", capability.to_string());
        }
        for capability in self.cap_drop.iter().flatten() {
            push_option("--cap-drop", capability.to_string());
        }
        if let Some(memory) = &self.memory {
            push_option("--memory", memory.to_string());
        }
        if let Some(cpus) = &self.cpus {
            push_option("--cpus", cpus.to_string());
        }
        for device in self.devices.iter().flatten() {
            push_option("--device", device.to_string());
        }
        for gpu in self.gpus.iter().flat_map(GpuSelection::ids) {
            push_option("--device", format!("nvidia.com/gpu={}", gpu));
        }
        if let Some(log_driver) = &self.log_driver {
            push_option("--log-driver", log_driver.clone());
        }
        for (key, value) in self.log_options.iter().flatten() {
            push_option("--log-opt", format!("{}={}", key, value));
        }

        if self.privileged == Some(true) {
            args.push("--privileged".to_string());
        }
        if self.read_only == Some(true) {
            args.push("--read-only".to_string());
        }
        if self.init == Some(true) {
            args.push("--init".to_string());
        }

        args.push(self.image.to_string());
        args.extend(
            self.command
                .iter()
                .flat_map(|command| command.args().iter().cloned()),
        );

        args
    }

    /// `image_id` is the ID of the local image `Image` resolves to (`None` if not present)
    /// and `pod_id` the ID of the pod the container must join.
    ///
    /// Messages never contain environment variable values, as they might be secrets.
    fn recreation_reasons(
        &self,
        inspect: &Value,
        env: &[(String, String)],
        image_id: Option<&str>,
        pod_id: Option<&str>,
    ) -> Vec<String> {
        let mut reasons: Vec<String> = Vec::new();

        match image_id {
            Some(image_id) => {
                let current_image_id = image_id_without_prefix(
                    pointer(inspect, "/Image").as_str().unwrap_or_default(),
                );
                if current_image_id != image_id_without_prefix(image_id) {
                    reasons.push(format!(
                        "container image differs from the local image {}",
                        self.image
                    ));
                }
            }
            None => reasons.push(format!(
                "image {} is not present locally, it will be pulled",
                self.image
            )),
        }

        if let Some(command) = &self.command {
            let current = string_list(pointer(inspect, "/Config/Cmd"));
            if current != command.args() {
                reasons.push(format!(
                    "command is {:?}, expected {:?}",
                    current,
                    command.args()
                ));
            }
        }

        if let Some(entrypoint) = &self.entrypoint {
            // Podman 4+ reports an array, older versions a string
            let current = match pointer(inspect, "/Config/Entrypoint") {
                Value::String(entrypoint) => vec![entrypoint.clone()],
                other => string_list(other),
            };
            let is_matching = if entrypoint.is_empty() {
                current.iter().all(|part| part.is_empty())
            } else {
                current.len() == 1 && &current[0] == entrypoint
            };
            if !is_matching {
                reasons.push(format!(
                    "entrypoint is {:?}, expected {:?}",
                    current, entrypoint
                ));
            }
        }

        if !env.is_empty() {
            let current: BTreeMap<String, String> = string_list(pointer(inspect, "/Config/Env"))
                .into_iter()
                .filter_map(|entry| {
                    entry
                        .split_once('=')
                        .map(|(key, value)| (key.to_string(), value.to_string()))
                })
                .collect();
            for (key, value) in env {
                if current.get(key) != Some(value) {
                    reasons.push(format!("environment variable {} differs", key));
                }
            }
        }

        if let Some(volumes) = &self.volumes {
            let (current_mounts, current_anonymous) = current_mounts(inspect);
            compare_sets(
                &mut reasons,
                "mounts",
                volumes.iter().filter_map(expected_mount).collect(),
                current_mounts,
            );
            for volume in volumes {
                if let ContainerVolume::Anonymous { target } = volume
                    && !current_anonymous.contains(target)
                {
                    reasons.push(format!("anonymous volume {} is missing", target));
                }
            }
        }

        let current_pod_id = pointer(inspect, "/Pod").as_str().unwrap_or_default();
        match &self.placement {
            Some(PodmanPlacement::Pod(pod)) => {
                if Some(current_pod_id) != pod_id {
                    reasons.push(format!("container is not in pod {}", pod));
                }
            }
            Some(PodmanPlacement::Standalone(standalone)) => {
                if !current_pod_id.is_empty() {
                    reasons.push("container is in a pod, expected standalone".to_string());
                }
                if let Some(hostname) = &standalone.hostname {
                    let current = pointer(inspect, "/Config/Hostname")
                        .as_str()
                        .unwrap_or_default();
                    if current != hostname {
                        reasons.push(format!(
                            "hostname is {:?}, expected {:?}",
                            current, hostname
                        ));
                    }
                }
                if let Some(networking) = &standalone.networking {
                    networking_reasons(&mut reasons, networking, inspect);
                }
            }
            None => {}
        }

        if let Some(restart_policy) = &self.restart_policy {
            let current_name = pointer(inspect, "/HostConfig/RestartPolicy/Name")
                .as_str()
                .unwrap_or_default();
            let current_retries = pointer(inspect, "/HostConfig/RestartPolicy/MaximumRetryCount")
                .as_u64()
                .unwrap_or_default();
            if !restart_policy.matches(current_name, current_retries) {
                reasons.push(format!(
                    "restart policy is {:?}, expected {}",
                    current_name,
                    restart_policy.as_cli_arg()
                ));
            }
        }

        for (option_name, expected, path) in [
            ("user", &self.user, "/Config/User"),
            ("working directory", &self.working_dir, "/Config/WorkingDir"),
            ("log driver", &self.log_driver, "/HostConfig/LogConfig/Type"),
        ] {
            if let Some(expected) = expected {
                let current = pointer(inspect, path).as_str().unwrap_or_default();
                if current != expected {
                    reasons.push(format!(
                        "{} is {:?}, expected {:?}",
                        option_name, current, expected
                    ));
                }
            }
        }

        if let Some(labels) = &self.labels {
            let current = pointer(inspect, "/Config/Labels");
            for (key, value) in labels {
                if current.get(key).and_then(Value::as_str) != Some(value.as_str()) {
                    reasons.push(format!("label {} differs", key));
                }
            }
        }

        for (option_name, expected, path) in [
            ("privileged", &self.privileged, "/HostConfig/Privileged"),
            ("read-only", &self.read_only, "/HostConfig/ReadonlyRootfs"),
            ("init", &self.init, "/HostConfig/Init"),
        ] {
            if let Some(expected) = expected {
                // null means the option was not set, which is equivalent to false
                let current = pointer(inspect, path).as_bool().unwrap_or(false);
                if current != *expected {
                    reasons.push(format!(
                        "{} is {}, expected {}",
                        option_name, current, expected
                    ));
                }
            }
        }

        if let Some(memory) = &self.memory {
            let current = pointer(inspect, "/HostConfig/Memory")
                .as_i64()
                .unwrap_or_default();
            if current != memory.bytes() {
                reasons.push(format!(
                    "memory limit is {} bytes, expected {} bytes",
                    current,
                    memory.bytes()
                ));
            }
        }

        if let Some(cpus) = &self.cpus {
            let current = pointer(inspect, "/HostConfig/NanoCpus")
                .as_i64()
                .unwrap_or_default();
            if current != cpus.nano_cpus() {
                reasons.push(format!(
                    "CPU limit is {}, expected {}",
                    current as f64 / 1e9,
                    cpus
                ));
            }
        }

        if let Some(devices) = &self.devices {
            compare_sets(
                &mut reasons,
                "devices",
                devices.iter().map(|device| device.to_string()).collect(),
                pointer(inspect, "/HostConfig/Devices")
                    .as_array()
                    .into_iter()
                    .flatten()
                    .map(|device| {
                        format!(
                            "{}:{}:{}",
                            pointer(device, "/PathOnHost").as_str().unwrap_or_default(),
                            pointer(device, "/PathInContainer")
                                .as_str()
                                .unwrap_or_default(),
                            pointer(device, "/CgroupPermissions")
                                .as_str()
                                .unwrap_or_default()
                        )
                    })
                    .collect(),
            );
        }

        recorded_settings_reasons(&mut reasons, &self.recorded_settings(), inspect);

        reasons
    }
}

/// Options recorded in the `io.regent-sdk.recorded-settings` label (only the managed ones)
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct RecordedSettings {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    cap_add: Option<BTreeSet<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    cap_drop: Option<BTreeSet<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    volumes: Option<BTreeSet<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    log_options: Option<BTreeMap<String, String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    userns: Option<PodmanUserNamespace>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    gpus: Option<BTreeSet<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    ipc: Option<IpcNamespace>,
}

fn recorded_settings_reasons(
    reasons: &mut Vec<String>,
    expected: &RecordedSettings,
    inspect: &Value,
) {
    let recorded: Option<RecordedSettings> = pointer(
        inspect,
        &format!("/Config/Labels/{}", RECORDED_SETTINGS_LABEL),
    )
    .as_str()
    .and_then(|label| serde_json::from_str(label).ok());

    let mut check = |option_name: &str, is_managed: bool, is_matching: bool| {
        if is_managed && !is_matching {
            reasons.push(match &recorded {
                Some(_) => format!("{} differ from the ones set at creation", option_name),
                None => format!(
                    "{} can't be verified on a container which was not created by Regent",
                    option_name
                ),
            });
        }
    };

    let recorded = recorded.clone().unwrap_or_default();
    check(
        "added capabilities",
        expected.cap_add.is_some(),
        expected.cap_add == recorded.cap_add,
    );
    check(
        "dropped capabilities",
        expected.cap_drop.is_some(),
        expected.cap_drop == recorded.cap_drop,
    );
    check(
        "volume options",
        expected.volumes.is_some(),
        expected.volumes == recorded.volumes,
    );
    check(
        "log options",
        expected.log_options.is_some(),
        expected.log_options == recorded.log_options,
    );
    check(
        "user namespace options",
        expected.userns.is_some(),
        expected.userns == recorded.userns,
    );
    check(
        "GPUs",
        expected.gpus.is_some(),
        expected.gpus == recorded.gpus,
    );
    check(
        "IPC options",
        expected.ipc.is_some(),
        expected.ipc == recorded.ipc,
    );
}

fn networking_reasons(reasons: &mut Vec<String>, networking: &PodmanNetworking, inspect: &Value) {
    let current_mode = pointer(inspect, "/HostConfig/NetworkMode")
        .as_str()
        .unwrap_or_default();
    match networking {
        PodmanNetworking::Host | PodmanNetworking::Isolated => {
            let expected_mode = match networking {
                PodmanNetworking::Host => "host",
                _ => "none",
            };
            if current_mode != expected_mode {
                reasons.push(format!(
                    "network mode is {}, expected {}",
                    current_mode, expected_mode
                ));
            }
        }
        PodmanNetworking::Attached(attached) => {
            if current_mode == "host" || current_mode == "none" {
                reasons.push(format!(
                    "network mode is {}, expected attached networks",
                    current_mode
                ));
            }
            if let Some(networks) = &attached.networks {
                compare_sets(
                    reasons,
                    "networks",
                    networks
                        .networks()
                        .iter()
                        .map(|network| network.to_string())
                        .collect(),
                    pointer(inspect, "/NetworkSettings/Networks")
                        .as_object()
                        .map(|networks| networks.keys().cloned().collect())
                        .unwrap_or_default(),
                );
            }
            if let Some(ports) = &attached.ports {
                let expected: BTreeSet<PortBinding> = ports
                    .iter()
                    .flat_map(|port| port.bindings().iter().cloned())
                    .map(normalize_port_binding)
                    .collect();
                let current = current_port_bindings(inspect);
                if expected != current {
                    reasons.push(format!(
                        "published ports are {:?}, expected {:?}",
                        current, expected
                    ));
                }
            }
            if let Some(dns) = &attached.dns {
                compare_sets(
                    reasons,
                    "DNS servers",
                    dns.iter().map(|server| server.to_string()).collect(),
                    string_list(pointer(inspect, "/HostConfig/Dns"))
                        .into_iter()
                        .collect(),
                );
            }
            if let Some(extra_hosts) = &attached.extra_hosts {
                compare_sets(
                    reasons,
                    "extra hosts",
                    extra_hosts.iter().map(|host| host.to_string()).collect(),
                    string_list(pointer(inspect, "/HostConfig/ExtraHosts"))
                        .into_iter()
                        .collect(),
                );
            }
        }
    }
}

/// Podman may report an unspecified host IP as `0.0.0.0`
fn normalize_port_binding(mut binding: PortBinding) -> PortBinding {
    if binding.host_ip == "0.0.0.0" {
        binding.host_ip = String::new();
    }
    binding
}

fn current_port_bindings(inspect: &Value) -> BTreeSet<PortBinding> {
    let mut current = BTreeSet::new();
    if let Some(bindings) = pointer(inspect, "/HostConfig/PortBindings").as_object() {
        for (container_port, host_bindings) in bindings {
            for host_binding in host_bindings.as_array().into_iter().flatten() {
                current.insert(normalize_port_binding(PortBinding {
                    container_port: container_port.clone(),
                    host_ip: pointer(host_binding, "/HostIp")
                        .as_str()
                        .unwrap_or_default()
                        .to_string(),
                    host_port: pointer(host_binding, "/HostPort")
                        .as_str()
                        .unwrap_or_default()
                        .to_string(),
                }));
            }
        }
    }
    current
}

/// Mount as compared with `Mounts` of `podman inspect`: `<bind|volume> <source> -> <target> (<ro|rw>)`.
/// Other volume options (`z`, `Z`, `U`...) are compared through the recorded settings.
fn expected_mount(volume: &ContainerVolume) -> Option<String> {
    match volume {
        ContainerVolume::Bind {
            source,
            target,
            options,
        } => {
            let kind = if source.starts_with('/') {
                "bind"
            } else {
                "volume"
            };
            let is_read_only = options
                .as_deref()
                .is_some_and(|options| options.split(',').any(|option| option == "ro"));
            Some(format_mount(kind, source, target, !is_read_only))
        }
        ContainerVolume::Anonymous { .. } => None,
    }
}

fn format_mount(kind: &str, source: &str, target: &str, is_read_write: bool) -> String {
    format!(
        "{} {} -> {} ({})",
        kind,
        source,
        target,
        if is_read_write { "rw" } else { "ro" }
    )
}

/// Bind mounts and named volumes of the container, and destinations of its anonymous volumes
fn current_mounts(inspect: &Value) -> (BTreeSet<String>, BTreeSet<String>) {
    let mut mounts = BTreeSet::new();
    let mut anonymous = BTreeSet::new();
    for mount in pointer(inspect, "/Mounts").as_array().into_iter().flatten() {
        let destination = pointer(mount, "/Destination")
            .as_str()
            .unwrap_or_default()
            .to_string();
        let is_read_write = pointer(mount, "/RW").as_bool().unwrap_or(true);
        match pointer(mount, "/Type").as_str() {
            // The init binary mounted by --init is not a user volume
            Some("bind") if destination != "/run/podman-init" => {
                let source = pointer(mount, "/Source").as_str().unwrap_or_default();
                mounts.insert(format_mount("bind", source, &destination, is_read_write));
            }
            Some("volume") => {
                let name = pointer(mount, "/Name").as_str().unwrap_or_default();
                if is_anonymous_volume_name(name) {
                    anonymous.insert(destination);
                } else {
                    mounts.insert(format_mount("volume", name, &destination, is_read_write));
                }
            }
            _ => {}
        }
    }
    (mounts, anonymous)
}

/// Anonymous volumes are named after 64 random hexadecimal characters
fn is_anonymous_volume_name(name: &str) -> bool {
    name.len() == 64 && name.chars().all(|c| c.is_ascii_hexdigit())
}

fn image_id_without_prefix(image_id: &str) -> &str {
    image_id.trim_start_matches("sha256:")
}

impl Timeout for PodmanExpectedState {
    fn default_timeout(&self) -> Duration {
        // Pulling an image can take a while
        Duration::from_secs(300)
    }
}

impl Check for PodmanExpectedState {
    fn check(&self) -> Result<(), RegentError> {
        // Every value is validated when its type is built: an existing PodmanExpectedState is valid
        Ok(())
    }

    fn check_host_compatibility(
        &self,
        host_properties: &HostProperties,
    ) -> Result<(), RegentError> {
        check_podman_host_compatibility(host_properties)
    }
}

impl<Handler: HostHandler> AssessCompliance<Handler> for PodmanExpectedState {
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

        let command_available = host_handler
            .is_this_command_available("podman", privilege)
            .await
            .unwrap_or(false);
        if !command_available {
            return Err(RegentError::FailedDryRunEvaluation(
                "Podman CLI (podman) is not available on this host".to_string(),
            ));
        }

        let container = inspect_container(host_handler, &self.name, privilege).await?;

        let mut remediations: Vec<Remediation> = Vec::new();
        let mut push = |api_call: PodmanInternalApiCall| {
            remediations.push(Remediation::Podman(PodmanApiCall::from(
                api_call,
                privilege.clone(),
            )));
        };

        let (config, should_run) = match &self.state {
            PodmanContainerState::Absent => {
                if container.is_some() {
                    push(PodmanInternalApiCall::Remove(self.name.clone()));
                }
                (None, false)
            }
            PodmanContainerState::Running(config) => (Some(config), true),
            PodmanContainerState::Stopped(config) => (Some(config), false),
        };

        if let Some(config) = config {
            // Pods are not managed by this attribute: the pod must already exist
            let pod_id = match &config.placement {
                Some(PodmanPlacement::Pod(pod)) => {
                    match inspect_pod_id(host_handler, pod, privilege).await? {
                        Some(pod_id) => Some(pod_id),
                        None => {
                            return Ok(AttributeComplianceAssessment::NonCompliantFatal(format!(
                                "pod {} does not exist",
                                pod
                            )));
                        }
                    }
                }
                _ => None,
            };

            let image_id = inspect_image_id(host_handler, &config.image, privilege).await?;

            if image_id.is_none() {
                match config.pull {
                    PullPolicy::Missing => push(PodmanInternalApiCall::Pull(config.image.clone())),
                    PullPolicy::Never => {
                        return Ok(AttributeComplianceAssessment::NonCompliantFatal(format!(
                            "image {} is not present on the host and Pull is Never",
                            config.image
                        )));
                    }
                }
            }

            match container {
                None => {
                    push(PodmanInternalApiCall::Create {
                        name: self.name.clone(),
                        config: config.clone(),
                    });
                    if should_run {
                        push(PodmanInternalApiCall::Start(self.name.clone()));
                    }
                }
                Some(inspect) => {
                    let env = config.resolve_env(optional_secret_provider).await?;
                    let reasons = config.recreation_reasons(
                        &inspect,
                        &env,
                        image_id.as_deref(),
                        pod_id.as_deref(),
                    );

                    if !reasons.is_empty() {
                        push(PodmanInternalApiCall::Recreate {
                            name: self.name.clone(),
                            config: config.clone(),
                            reasons,
                        });
                        if should_run {
                            push(PodmanInternalApiCall::Start(self.name.clone()));
                        }
                    } else {
                        let is_running = pointer(&inspect, "/State/Running")
                            .as_bool()
                            .unwrap_or(false);
                        let is_paused = pointer(&inspect, "/State/Paused")
                            .as_bool()
                            .unwrap_or(false);
                        match (should_run, is_running, is_paused) {
                            (true, true, true) => {
                                push(PodmanInternalApiCall::Unpause(self.name.clone()))
                            }
                            (true, false, _) => {
                                push(PodmanInternalApiCall::Start(self.name.clone()))
                            }
                            (false, true, _) => {
                                push(PodmanInternalApiCall::Stop(self.name.clone()))
                            }
                            _ => {}
                        }
                    }
                }
            }
        }

        if remediations.is_empty() {
            Ok(AttributeComplianceAssessment::Compliant)
        } else {
            Ok(AttributeComplianceAssessment::NonCompliant(
                RemediationsList::from(remediations)?,
            ))
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase", rename_all_fields = "PascalCase")]
pub enum PodmanInternalApiCall {
    Pull(ContainerImage),
    Create {
        name: ContainerName,
        config: Box<PodmanContainerConfig>,
    },
    Recreate {
        name: ContainerName,
        config: Box<PodmanContainerConfig>,
        reasons: Vec<String>,
    },
    Remove(ContainerName),
    Start(ContainerName),
    Stop(ContainerName),
    Unpause(ContainerName),
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PodmanApiCall {
    pub api_call: PodmanInternalApiCall,
    privilege: Privilege,
}

impl PodmanApiCall {
    pub fn display(&self) -> String {
        match &self.api_call {
            PodmanInternalApiCall::Pull(image) => format!("Pull image {}", image),
            PodmanInternalApiCall::Create { name, config } => {
                format!("Create container {} from {}", name, config.image)
            }
            PodmanInternalApiCall::Recreate { name, reasons, .. } => {
                format!("Recreate container {} ({})", name, reasons.join("; "))
            }
            PodmanInternalApiCall::Remove(name) => format!("Remove container {}", name),
            PodmanInternalApiCall::Start(name) => format!("Start container {}", name),
            PodmanInternalApiCall::Stop(name) => format!("Stop container {}", name),
            PodmanInternalApiCall::Unpause(name) => format!("Unpause container {}", name),
        }
    }

    fn from(api_call: PodmanInternalApiCall, privilege: Privilege) -> PodmanApiCall {
        PodmanApiCall {
            api_call,
            privilege,
        }
    }
}

impl Timeout for PodmanApiCall {
    fn default_timeout(&self) -> Duration {
        Duration::from_secs(300)
    }
}

impl Check for PodmanApiCall {
    fn check(&self) -> Result<(), RegentError> {
        Ok(())
    }

    fn check_host_compatibility(
        &self,
        host_properties: &HostProperties,
    ) -> Result<(), RegentError> {
        check_podman_host_compatibility(host_properties)
    }
}

impl<Handler: HostHandler> ReachCompliance<Handler> for PodmanApiCall {
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
            PodmanInternalApiCall::Pull(image) => {
                run_podman(
                    host_handler,
                    &["podman", "pull", image.as_str()],
                    &self.privilege,
                )
                .await
            }
            PodmanInternalApiCall::Create { name, config } => {
                create_container(
                    host_handler,
                    name,
                    config,
                    optional_secret_provider,
                    &self.privilege,
                )
                .await
            }
            PodmanInternalApiCall::Recreate { name, config, .. } => {
                let outcome = run_podman(
                    host_handler,
                    &["podman", "rm", "--force", name.as_str()],
                    &self.privilege,
                )
                .await?;
                if let InternalApiCallOutcome::Failure(_) = outcome {
                    return Ok(outcome);
                }
                create_container(
                    host_handler,
                    name,
                    config,
                    optional_secret_provider,
                    &self.privilege,
                )
                .await
            }
            PodmanInternalApiCall::Remove(name) => {
                run_podman(
                    host_handler,
                    &["podman", "rm", "--force", name.as_str()],
                    &self.privilege,
                )
                .await
            }
            PodmanInternalApiCall::Start(name) => {
                run_podman(
                    host_handler,
                    &["podman", "start", name.as_str()],
                    &self.privilege,
                )
                .await
            }
            PodmanInternalApiCall::Stop(name) => {
                run_podman(
                    host_handler,
                    &["podman", "stop", name.as_str()],
                    &self.privilege,
                )
                .await
            }
            PodmanInternalApiCall::Unpause(name) => {
                run_podman(
                    host_handler,
                    &["podman", "unpause", name.as_str()],
                    &self.privilege,
                )
                .await
            }
        }
    }
}

fn check_podman_host_compatibility(host_properties: &HostProperties) -> Result<(), RegentError> {
    match host_properties.os_kind() {
        OsKind::Linux(_) | OsKind::MacOs(_) => Ok(()),
        incompatible_os_kind => Err(RegentError::IncompatibleHost(format!(
            "Host is {:?} but Podman container management is only supported on Linux and macOS",
            incompatible_os_kind
        ))),
    }
}

async fn create_container<Handler: HostHandler>(
    host_handler: &mut Handler,
    name: &ContainerName,
    config: &PodmanContainerConfig,
    optional_secret_provider: &Option<SecretProvidersPool>,
    privilege: &Privilege,
) -> Result<InternalApiCallOutcome, RegentError> {
    let env = config.resolve_env(optional_secret_provider).await?;
    let args = config.create_args(name, &env);
    let args: Vec<&str> = args.iter().map(String::as_str).collect();
    run_podman(host_handler, &args, privilege).await
}

async fn run_podman<Handler: HostHandler>(
    host_handler: &mut Handler,
    args: &[&str],
    privilege: &Privilege,
) -> Result<InternalApiCallOutcome, RegentError> {
    match host_handler
        .run_command(&quoted_command(args), privilege)
        .await
    {
        Ok(result) => {
            if result.return_code == 0 {
                Ok(InternalApiCallOutcome::Success(None))
            } else {
                Ok(InternalApiCallOutcome::Failure(format!(
                    "RC: {}, STDOUT: {}, STDERR: {}",
                    result.return_code, result.stdout, result.stderr
                )))
            }
        }
        Err(e) => Ok(InternalApiCallOutcome::Failure(format!(
            "Command execution failed: {:?}",
            e
        ))),
    }
}

async fn run_podman_inspect<Handler: HostHandler>(
    host_handler: &mut Handler,
    args: &[&str],
    object_description: &str,
    privilege: &Privilege,
) -> Result<Option<String>, RegentError> {
    let result = host_handler
        .run_command(&quoted_command(args), privilege)
        .await
        .map_err(|e| {
            RegentError::FailedDryRunEvaluation(format!(
                "Unable to inspect {}: {:?}",
                object_description, e
            ))
        })?;

    if result.return_code != 0 {
        let output = format!("{}{}", result.stdout, result.stderr).to_lowercase();
        if output.contains("no such") || output.contains("not known") {
            return Ok(None);
        }
        return Err(RegentError::FailedDryRunEvaluation(format!(
            "Unable to inspect {}: {:?}",
            object_description, result
        )));
    }

    Ok(Some(result.stdout))
}

async fn inspect_container<Handler: HostHandler>(
    host_handler: &mut Handler,
    name: &ContainerName,
    privilege: &Privilege,
) -> Result<Option<Value>, RegentError> {
    let Some(output) = run_podman_inspect(
        host_handler,
        &["podman", "container", "inspect", name.as_str()],
        &format!("container {}", name),
        privilege,
    )
    .await?
    else {
        return Ok(None);
    };

    let inspect = parse_inspect_output(&output).ok_or_else(|| {
        RegentError::FailureToParseContent(format!(
            "Unexpected output of podman container inspect: {}",
            output
        ))
    })?;

    // Inspecting by name also matches container IDs: make sure this is the right container
    let current_name = pointer(&inspect, "/Name").as_str().unwrap_or_default();
    if current_name.trim_start_matches('/') == name.as_str() {
        Ok(Some(inspect))
    } else {
        Ok(None)
    }
}

async fn inspect_image_id<Handler: HostHandler>(
    host_handler: &mut Handler,
    image: &ContainerImage,
    privilege: &Privilege,
) -> Result<Option<String>, RegentError> {
    let output = run_podman_inspect(
        host_handler,
        &[
            "podman",
            "image",
            "inspect",
            "--format",
            "{{.Id}}",
            image.as_str(),
        ],
        &format!("image {}", image),
        privilege,
    )
    .await?;
    output
        .map(|output| extract_id(&output, "image inspect"))
        .transpose()
}

async fn inspect_pod_id<Handler: HostHandler>(
    host_handler: &mut Handler,
    pod: &PodName,
    privilege: &Privilege,
) -> Result<Option<String>, RegentError> {
    let output = run_podman_inspect(
        host_handler,
        &[
            "podman",
            "pod",
            "inspect",
            "--format",
            "{{.Id}}",
            pod.as_str(),
        ],
        &format!("pod {}", pod),
        privilege,
    )
    .await?;
    output
        .map(|output| extract_id(&output, "pod inspect"))
        .transpose()
}

/// stderr is merged into stdout by the handlers, keep only the line holding the ID
fn extract_id(output: &str, command: &str) -> Result<String, RegentError> {
    output
        .lines()
        .map(str::trim)
        .find(|line| {
            let id = image_id_without_prefix(line);
            id.len() == 64 && id.chars().all(|c| c.is_ascii_hexdigit())
        })
        .map(String::from)
        .ok_or_else(|| {
            RegentError::FailureToParseContent(format!(
                "Unexpected output of podman {}: {}",
                command, output
            ))
        })
}

/// Pod name: `[a-zA-Z0-9][a-zA-Z0-9_.-]*`
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct PodName(String);

impl TryFrom<String> for PodName {
    type Error = RegentError;

    fn try_from(name: String) -> Result<Self, Self::Error> {
        if is_valid_object_name(&name) {
            Ok(Self(name))
        } else {
            Err(invalid(
                "pod name",
                &name,
                "allowed characters are [a-zA-Z0-9][a-zA-Z0-9_.-]*",
            ))
        }
    }
}

impl FromStr for PodName {
    type Err = RegentError;

    fn from_str(name: &str) -> Result<Self, Self::Err> {
        Self::try_from(name.to_string())
    }
}

impl From<PodName> for String {
    fn from(name: PodName) -> String {
        name.0
    }
}

impl fmt::Display for PodName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl PodName {
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::secrets::SecretReference;

    const IMAGE_ID: &str = "4f67c83422ec747235357c04556616234e66fc3fa39cb4f40b2d4441ddd8f100";

    fn full_yaml() -> &'static str {
        "---
Name: web
State: !Running
  Image: docker.io/library/nginx:1.27
  Pull: Missing
  Entrypoint: /docker-entrypoint.sh
  Command: [nginx, -g, daemon off;]
  Env:
    TZ: Europe/Paris
    API_TOKEN:
      SecRef: web_api_token
      Provider: files
  Volumes:
    - /srv/www:/usr/share/nginx/html:ro,Z
    - nginx_cache:/var/cache/nginx
    - /var/lib/nginx
  Placement: !Standalone
    Hostname: web01
    Userns: KeepId
    Networking: !Attached
      Networks: [frontend, backend]
      Ports:
        - 8080:80
        - 127.0.0.1:8443:443/tcp
      Dns: [1.1.1.1]
      ExtraHosts: ['db.local:10.0.0.12']
  RestartPolicy: Always
  User: '101:101'
  WorkingDir: /usr/share/nginx
  Labels:
    io.containers.autoupdate: registry
  Privileged: false
  ReadOnly: false
  Init: true
  CapAdd: [net_bind_service]
  CapDrop: [ALL]
  Memory: 512m
  Cpus: 1.5
  Devices: ['/dev/snd']
  LogDriver: journald
  LogOptions:
    tag: web
"
    }

    fn full_config() -> PodmanContainerConfig {
        let state: PodmanExpectedState = yaml_serde::from_str(full_yaml()).unwrap();
        match state.state {
            PodmanContainerState::Running(config) => *config,
            other => panic!("unexpected state {:?}", other),
        }
    }

    /// `podman container inspect` output of a container created from `full_yaml()`
    fn matching_inspect() -> Value {
        let recorded_settings = serde_json::to_string(&full_config().recorded_settings()).unwrap();
        serde_json::json!({
            "Name": "web",
            "Image": IMAGE_ID,
            "ImageName": "docker.io/library/nginx:1.27",
            "Pod": "",
            "State": { "Running": true, "Paused": false },
            "Mounts": [
                { "Type": "bind", "Source": "/srv/www", "Destination": "/usr/share/nginx/html", "RW": false, "Options": ["rbind"] },
                { "Type": "volume", "Name": "nginx_cache", "Source": "/var/lib/containers/storage/volumes/nginx_cache/_data", "Destination": "/var/cache/nginx", "RW": true },
                { "Type": "volume", "Name": "a3c9d05f3e2b1d2e8c4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d", "Destination": "/var/lib/nginx", "RW": true },
                { "Type": "bind", "Source": "/usr/libexec/podman/catatonit", "Destination": "/run/podman-init", "RW": false }
            ],
            "Config": {
                "Image": "docker.io/library/nginx:1.27",
                "Cmd": ["nginx", "-g", "daemon off;"],
                "Entrypoint": ["/docker-entrypoint.sh"],
                "Env": ["TZ=Europe/Paris", "API_TOKEN=s3cr3t", "container=podman", "HOSTNAME=web01"],
                "Hostname": "web01",
                "User": "101:101",
                "WorkingDir": "/usr/share/nginx",
                "Labels": {
                    "io.containers.autoupdate": "registry",
                    "maintainer": "NGINX",
                    "io.regent-sdk.recorded-settings": recorded_settings
                }
            },
            "HostConfig": {
                "Binds": ["/srv/www:/usr/share/nginx/html:ro,Z,rprivate,rbind"],
                "NetworkMode": "bridge",
                "PortBindings": {
                    "80/tcp": [{ "HostIp": "0.0.0.0", "HostPort": "8080" }],
                    "443/tcp": [{ "HostIp": "127.0.0.1", "HostPort": "8443" }]
                },
                "RestartPolicy": { "Name": "always", "MaximumRetryCount": 0 },
                "Privileged": false,
                "ReadonlyRootfs": false,
                "Init": true,
                "CapAdd": [],
                "CapDrop": ["CAP_CHOWN", "CAP_DAC_OVERRIDE", "CAP_FOWNER"],
                "Memory": 536870912,
                "NanoCpus": 1500000000i64,
                "ExtraHosts": ["db.local:10.0.0.12"],
                "Dns": ["1.1.1.1"],
                "Devices": [{ "PathOnHost": "/dev/snd", "PathInContainer": "/dev/snd", "CgroupPermissions": "rwm" }],
                "LogConfig": { "Type": "journald", "Config": null, "Tag": "web" }
            },
            "NetworkSettings": { "Networks": { "frontend": {}, "backend": {} } }
        })
    }

    fn resolved_env() -> Vec<(String, String)> {
        vec![
            ("API_TOKEN".to_string(), "s3cr3t".to_string()),
            ("TZ".to_string(), "Europe/Paris".to_string()),
        ]
    }

    #[test]
    fn parsing_podman_module_block_from_yaml_str() {
        let config = full_config();
        assert_eq!(
            config
                .env
                .as_ref()
                .unwrap()
                .get(&"API_TOKEN".parse().unwrap()),
            Some(&Parameter::Secret(SecretReference::from(
                "web_api_token",
                Some("files".to_string())
            )))
        );

        let raw = "---
- Name: legacy
  State: Absent
- Name: app
  State: !Stopped
    Image: ghcr.io/example/app:2.1
    Placement: !Pod app-pod
    RestartPolicy: !OnFailure 3
- Name: tool
  State: !Running
    Image: docker.io/library/busybox
    Placement: !Standalone
      Networking: Isolated
";
        let states: Vec<PodmanExpectedState> = yaml_serde::from_str(raw).unwrap();
        assert_eq!(states[0].state, PodmanContainerState::Absent);
        match &states[1].state {
            PodmanContainerState::Stopped(config) => assert_eq!(
                config.placement,
                Some(PodmanPlacement::Pod("app-pod".parse().unwrap()))
            ),
            other => panic!("unexpected state {:?}", other),
        }
    }

    #[test]
    fn serialization_round_trip_preserves_state() {
        // Templating (Attribute::consider_context) relies on a JSON round trip
        let state: PodmanExpectedState = yaml_serde::from_str(full_yaml()).unwrap();
        let json = serde_json::to_string(&state).unwrap();
        assert_eq!(
            serde_json::from_str::<PodmanExpectedState>(&json).unwrap(),
            state
        );
    }

    #[test]
    fn invalid_states_are_rejected_while_parsing() {
        let rejected = [
            // Configuration makes no sense for an absent container
            "Name: old\nState: !Absent\n  User: root\n",
            // Image is mandatory for a container which must exist
            "Name: web\nState: !Running\n  User: root\n",
            // Networks, ports and hostname come from the pod
            "Name: web\nState: !Running\n  Image: nginx\n  Placement: !Pod\n    Name: app-pod\n    Ports: ['80:80']\n",
            "Name: web\nState: !Running\n  Image: nginx\n  Hostname: web01\n  Placement: !Pod app-pod\n",
            "Name: web\nState: !Running\n  Image: nginx\n  Placement: !Pod /app-pod\n",
            // Ports and DNS servers need attached networks
            "Name: web\nState: !Running\n  Image: nginx\n  Placement: !Standalone\n    Networking: !Host\n      Ports: ['80:80']\n",
            "Name: web\nState: !Running\n  Image: nginx\n  Placement: !Standalone\n    Dns: [1.1.1.1]\n",
            // Network modes are not network names
            "Name: web\nState: !Running\n  Image: nginx\n  Placement: !Standalone\n    Networking: !Attached\n      Networks: [pasta]\n",
            "Name: web\nState: !Running\n  Image: nginx\n  Placement: !Standalone\n    Userns: keep-id:uid=1000\n",
            "Name: web\nState: !Running\n  Image: nginx\n  Memory: lots\n",
        ];
        for raw in rejected {
            assert!(
                yaml_serde::from_str::<PodmanExpectedState>(raw).is_err(),
                "should be rejected: {}",
                raw
            );
        }
    }

    #[test]
    fn matching_container_needs_no_recreation() {
        let reasons = full_config().recreation_reasons(
            &matching_inspect(),
            &resolved_env(),
            Some(&format!("sha256:{}", IMAGE_ID)),
            None,
        );
        assert!(reasons.is_empty(), "{:?}", reasons);
    }

    #[test]
    fn drifted_container_needs_recreation() {
        let config = full_config();
        let mut inspect = matching_inspect();
        inspect["HostConfig"]["PortBindings"]["80/tcp"][0]["HostPort"] = "9090".into();
        inspect["Config"]["Env"][1] = "API_TOKEN=old_secret".into();
        inspect["Mounts"][0]["RW"] = true.into();
        inspect["HostConfig"]["RestartPolicy"]["Name"] = "no".into();

        let reasons = config.recreation_reasons(&inspect, &resolved_env(), Some(IMAGE_ID), None);
        assert_eq!(reasons.len(), 4, "{:?}", reasons);
        // Secret values must never leak in remediation messages
        assert!(reasons.iter().all(|reason| !reason.contains("secret")));

        // A new image behind the same reference
        let reasons = config.recreation_reasons(
            &matching_inspect(),
            &resolved_env(),
            Some("1111111111111111111111111111111111111111111111111111111111111111"),
            None,
        );
        assert_eq!(reasons.len(), 1, "{:?}", reasons);
    }

    #[test]
    fn unobservable_options_are_verified_through_the_recorded_settings() {
        let config = full_config();

        let mut changed = config
            .clone()
            .with_cap_add(vec!["NET_ADMIN".parse().unwrap()]);
        changed.log_options = None;
        let reasons =
            changed.recreation_reasons(&matching_inspect(), &resolved_env(), Some(IMAGE_ID), None);
        assert_eq!(
            reasons,
            vec!["added capabilities differ from the ones set at creation"]
        );

        // Container created by another tool: these options can't be verified
        let mut inspect = matching_inspect();
        inspect["Config"]["Labels"]
            .as_object_mut()
            .unwrap()
            .remove(RECORDED_SETTINGS_LABEL);
        let reasons = config.recreation_reasons(&inspect, &resolved_env(), Some(IMAGE_ID), None);
        assert_eq!(reasons.len(), 5, "{:?}", reasons);
        assert!(
            reasons
                .iter()
                .all(|reason| reason.contains("not created by Regent"))
        );

        // Without such options, no label is needed
        let simple = PodmanContainerConfig::new("docker.io/library/nginx:1.27".parse().unwrap())
            .with_user("101:101");
        assert!(
            simple
                .recreation_reasons(&inspect, &[], Some(IMAGE_ID), None)
                .is_empty()
        );
    }

    #[test]
    fn gpu_inference_server() {
        let raw = "---
Name: vllm
State: !Running
  Image: docker.io/vllm/vllm-openai:v0.10.1
  Command: [--model, Qwen/Qwen3-8B]
  Gpus: !Devices [0, 1]
  Placement: !Standalone
    Ipc: !Private
      ShmSize: 16g
";
        let state: PodmanExpectedState = yaml_serde::from_str(raw).unwrap();
        let json = serde_json::to_string(&state).unwrap();
        assert_eq!(
            serde_json::from_str::<PodmanExpectedState>(&json).unwrap(),
            state
        );
        let PodmanContainerState::Running(config) = state.state else {
            panic!("unexpected state");
        };
        let args = config.create_args(&"vllm".parse().unwrap(), &[]);
        for expected in [
            ["--ipc", "private"],
            ["--shm-size", "16g"],
            ["--device", "nvidia.com/gpu=0"],
            ["--device", "nvidia.com/gpu=1"],
        ] {
            assert!(
                args.windows(2).any(|pair| pair == expected),
                "{:?} missing in {:?}",
                expected,
                args
            );
        }

        // GPUs and IPC options are verified through the recorded settings
        let label = args
            .iter()
            .find_map(|arg| arg.strip_prefix(&format!("{}=", RECORDED_SETTINGS_LABEL)))
            .unwrap();
        let inspect = serde_json::json!({
            "Image": IMAGE_ID,
            "Config": {
                "Cmd": ["--model", "Qwen/Qwen3-8B"],
                "Labels": { RECORDED_SETTINGS_LABEL: label }
            }
        });
        assert!(
            config
                .recreation_reasons(&inspect, &[], Some(IMAGE_ID), None)
                .is_empty()
        );
        let all_gpus = (*config).clone().with_gpus(GpuSelection::All);
        assert_eq!(
            all_gpus.recreation_reasons(&inspect, &[], Some(IMAGE_ID), None),
            vec!["GPUs differ from the ones set at creation"]
        );

        // A pod member shares the IPC namespace of the pod
        let rejected =
            "Name: app\nState: !Running\n  Image: app\n  Placement: !Pod app-pod\n  Ipc: Host\n";
        assert!(yaml_serde::from_str::<PodmanExpectedState>(rejected).is_err());
    }

    #[test]
    fn pod_membership_is_verified() {
        let pod_id = "9e3b2f0d1c4a5b6e7f8091a2b3c4d5e6f708192a3b4c5d6e7f8091a2b3c4d5e6";
        let config = PodmanContainerConfig::new("docker.io/library/nginx:1.27".parse().unwrap())
            .with_placement(PodmanPlacement::Pod("app-pod".parse().unwrap()));

        let mut inspect = matching_inspect();
        assert_eq!(
            config
                .recreation_reasons(&inspect, &[], Some(IMAGE_ID), Some(pod_id))
                .len(),
            1
        );
        inspect["Pod"] = pod_id.into();
        assert!(
            config
                .recreation_reasons(&inspect, &[], Some(IMAGE_ID), Some(pod_id))
                .is_empty()
        );

        let standalone =
            PodmanContainerConfig::new("docker.io/library/nginx:1.27".parse().unwrap())
                .with_placement(PodmanPlacement::Standalone(PodmanStandalone::new()));
        assert_eq!(
            standalone
                .recreation_reasons(&inspect, &[], Some(IMAGE_ID), None)
                .len(),
            1
        );
    }

    #[test]
    fn create_args_follow_podman_cli() {
        let config = PodmanContainerConfig::new("docker.io/library/nginx:1.27".parse().unwrap())
            .with_placement(PodmanPlacement::Standalone(
                PodmanStandalone::new()
                    .with_userns(PodmanUserNamespace::KeepId)
                    .with_networking(PodmanNetworking::Attached(
                        PodmanAttachedNetworking::new()
                            .with_networks(
                                NetworkList::try_from(vec![
                                    "frontend".parse().unwrap(),
                                    "backend".parse().unwrap(),
                                ])
                                .unwrap(),
                            )
                            .with_ports(vec!["8080:80".parse().unwrap()]),
                    )),
            ))
            .with_env(
                "TZ".parse().unwrap(),
                Parameter::Clear("Europe/Paris".to_string()),
            )
            .with_restart_policy(RestartPolicy::OnFailure(3))
            .with_command(ContainerCommand::new(&["nginx", "-g", "daemon off;"]).unwrap());
        let env = vec![("TZ".to_string(), "Europe/Paris".to_string())];
        assert_eq!(
            config.create_args(&"web".parse().unwrap(), &env),
            to_strings(&[
                "podman",
                "create",
                "--name",
                "web",
                "--userns",
                "keep-id",
                "--network",
                "frontend",
                "--network",
                "backend",
                "--publish",
                "8080:80",
                "--env",
                "TZ=Europe/Paris",
                "--restart",
                "on-failure:3",
                "--label",
                "io.regent-sdk.recorded-settings={\"Userns\":\"KeepId\"}",
                "docker.io/library/nginx:1.27",
                "nginx",
                "-g",
                "daemon off;",
            ])
        );
    }

    #[test]
    fn ids_are_extracted_despite_warnings() {
        let output = format!("WARN[0000] some warning\n{}\n", IMAGE_ID);
        assert_eq!(extract_id(&output, "image inspect").unwrap(), IMAGE_ID);
        assert!(extract_id("garbage", "image inspect").is_err());
    }
}
