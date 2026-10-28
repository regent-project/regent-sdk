//! Docker container attribute
//!
//! This module provides the `DockerExpectedState` type for managing Docker containers
//! through the `docker` CLI available on the managed host.
//!
//! **Compatible OS:** Linux and macOS (any host where the `docker` CLI is available)
//!
//! # Compliance is assessed using "docker container inspect"
//!
//! "Env" values can be secrets, resolved through the secret providers but be carefull
//! because they will still end up in the commands and "docker container inspect" output
//!
//! # Examples
//!
//! ## Rust API
//!
//! ```no_run
//! use regent_sdk::state::attribute::container::docker::{DockerContainerConfig, DockerExpectedState};
//! use regent_sdk::state::expected_state::Parameter;
//! use regent_sdk::{Attribute, ExpectedState, Privilege, RegentError};
//!
//! fn web_server() -> Result<ExpectedState, RegentError> {
//!     let config = DockerContainerConfig::new("nginx:1.27".parse()?)
//!         .with_network("frontend".parse()?)
//!         .with_published_port("8080:80".parse()?)
//!         .with_published_port("127.0.0.1:8443:443/tcp".parse()?)
//!         .with_volumes(vec!["/srv/www:/usr/share/nginx/html:ro".parse()?])
//!         .with_env("TZ".parse()?, Parameter::Clear("Europe/Paris".to_string()))
//!         .with_restart_unless_stopped();
//!
//!     let web = DockerExpectedState::running("web".parse()?, config);
//!
//!     Ok(ExpectedState::new()
//!         .with_attribute(Attribute::docker(web, Privilege::WithSudo, None))
//!         .build())
//! }
//! ```
//!
//! ## YAML API
//!
//! ```yaml
//! Attributes:
//!   - Name: Web server container must be running
//!     Privilege: !WithSudo
//!     Detail: !Docker
//!       ContainerName: web
//!       State: !Running
//!         Image: nginx:1.27
//!         Pull: Missing
//!         Entrypoint: /docker-entrypoint.sh
//!         Command: ["nginx", "-g", "daemon off;"]
//!         Env:
//!           TZ: Europe/Paris
//!           API_TOKEN:
//!             SecRef: web_api_token
//!             Provider: files
//!         Volumes:
//!           - /srv/www:/usr/share/nginx/html:ro
//!           - nginx_cache:/var/cache/nginx
//!         Networking: !Attached    # Host | Isolated | !Attached
//!           Networks: [frontend, backend]
//!           Ports:
//!             - "8080:80"
//!             - "127.0.0.1:8443:443/tcp"
//!         RestartPolicy: UnlessStopped
//!         Hostname: web01
//!         User: "101:101"
//!         WorkingDir: /usr/share/nginx
//!         Labels:
//!           traefik.enable: "true"
//!         Privileged: false
//!         ReadOnly: false
//!         Init: true
//!         CapAdd: [NET_BIND_SERVICE]
//!         CapDrop: [ALL]
//!         Memory: 512m
//!         Cpus: 1.5
//!         ExtraHosts: ["db.local:10.0.0.12"]
//!         Dns: [1.1.1.1]
//!         Devices: ["/dev/snd:/dev/snd:rw"]
//!         Gpus: All
//!         HealthCheck:
//!           Test: curl -f http://localhost || exit 1
//!           Interval: 30s
//!           Timeout: 5s
//!           Retries: 3
//!           StartPeriod: 10s
//!           StartInterval: 1s
//!         LogDriver: json-file
//!         LogOptions:
//!           max-size: 10m
//! ```
//!
//! To make sure a container does not exist:
//!
//! ```yaml
//! Attributes:
//!   - Name: Old container must be removed
//!     Privilege: !WithSudo
//!     Detail: !Docker
//!       ContainerName: legacy-app
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
use std::net::IpAddr;
use std::str::FromStr;
use std::time::Duration;

use super::container_spec::{
    Capability, ContainerCommand, ContainerImage, ContainerName, ContainerVolume, CpuCount,
    EnvVarName, ExtraHost, GpuId, GpuSelection, HostDevice, IpcNamespace, MemorySize, NetworkList,
    NetworkName, PortBinding, PublishedPort, PullPolicy, RestartPolicy, compare_sets, invalid,
    normalize_capability, parse_inspect_output, pointer, quoted_command, string_list, to_strings,
};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[serde(rename_all = "PascalCase")]
pub struct DockerExpectedState {
    name: ContainerName,
    state: DockerContainerState,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub enum DockerContainerState {
    Running(Box<DockerContainerConfig>),
    Stopped(Box<DockerContainerConfig>),
    Absent,
}

impl DockerExpectedState {
    pub fn running(name: ContainerName, config: DockerContainerConfig) -> Self {
        Self {
            name,
            state: DockerContainerState::Running(Box::new(config)),
        }
    }

    pub fn stopped(name: ContainerName, config: DockerContainerConfig) -> Self {
        Self {
            name,
            state: DockerContainerState::Stopped(Box::new(config)),
        }
    }

    pub fn absent(name: ContainerName) -> Self {
        Self {
            name,
            state: DockerContainerState::Absent,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub enum DockerNetworking {
    /// Share the host network stack (`--network host`), ports can't be published
    Host,
    /// No network at all (`--network none`), ports can't be published
    Isolated,
    /// Attached to networks, with published ports
    Attached(DockerAttachedNetworking),
}

impl DockerNetworking {
    pub fn attached(networks: Option<NetworkList>, ports: Option<Vec<PublishedPort>>) -> Self {
        DockerNetworking::Attached(DockerAttachedNetworking { networks, ports })
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[serde(rename_all = "PascalCase")]
pub struct DockerAttachedNetworking {
    networks: Option<NetworkList>,
    ports: Option<Vec<PublishedPort>>,
}

/// The test command runs inside the container through `/bin/sh -c`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[serde(rename_all = "PascalCase")]
pub struct HealthCheck {
    test: HealthCheckTest,
    interval: Option<HealthDuration>,
    timeout: Option<HealthDuration>,
    start_period: Option<HealthDuration>,
    start_interval: Option<HealthDuration>,
    retries: Option<u32>,
}

impl HealthCheck {
    pub fn new(test: HealthCheckTest) -> Self {
        Self {
            test,
            interval: None,
            timeout: None,
            start_period: None,
            start_interval: None,
            retries: None,
        }
    }

    pub fn with_interval(mut self, interval: HealthDuration) -> Self {
        self.interval = Some(interval);
        self
    }

    pub fn with_timeout(mut self, timeout: HealthDuration) -> Self {
        self.timeout = Some(timeout);
        self
    }

    pub fn with_start_period(mut self, start_period: HealthDuration) -> Self {
        self.start_period = Some(start_period);
        self
    }

    pub fn with_start_interval(mut self, start_interval: HealthDuration) -> Self {
        self.start_interval = Some(start_interval);
        self
    }

    pub fn with_retries(mut self, retries: u32) -> Self {
        self.retries = Some(retries);
        self
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct HealthCheckTest(String);

impl TryFrom<String> for HealthCheckTest {
    type Error = RegentError;

    fn try_from(test: String) -> Result<Self, Self::Error> {
        if test.trim().is_empty() {
            Err(invalid("health check test", &test, "must be non-empty"))
        } else {
            Ok(Self(test))
        }
    }
}

impl HealthCheckTest {
    fn as_string(&self) -> String {
        self.0.clone()
    }
}

impl std::fmt::Display for HealthCheckTest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_string())
    }
}

impl FromStr for HealthCheckTest {
    type Err = RegentError;

    fn from_str(test: &str) -> Result<Self, Self::Err> {
        Self::try_from(test.to_string())
    }
}

impl From<HealthCheckTest> for String {
    fn from(test: HealthCheckTest) -> String {
        test.as_string()
    }
}

/// Duration in the Go syntax of the Docker CLI (`30s`, `1m30s`, `500ms`), strictly positive
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct HealthDuration {
    spec: String,
    nanos: i64,
}

impl TryFrom<String> for HealthDuration {
    type Error = RegentError;

    fn try_from(spec: String) -> Result<Self, Self::Error> {
        let error = || {
            invalid(
                "health check duration",
                &spec,
                "expected a Go duration like 30s, 1m30s or 500ms",
            )
        };
        // One or more <number><unit> pairs, units ns, us, ms, s, m, h (Go syntax)
        let mut nanos: f64 = 0.0;
        let mut rest = spec.as_str();
        let mut pairs = 0;
        while !rest.is_empty() {
            let number_len = rest
                .find(|c: char| !(c.is_ascii_digit() || c == '.'))
                .unwrap_or(rest.len());
            if number_len == 0 {
                return Err(error());
            }
            let number: f64 = rest[..number_len].parse().map_err(|_| error())?;
            rest = &rest[number_len..];
            let unit_len = rest
                .find(|c: char| c.is_ascii_digit() || c == '.')
                .unwrap_or(rest.len());
            let (unit, tail) = rest.split_at(unit_len);
            let multiplier: f64 = match unit {
                "ns" => 1.0,
                "us" | "µs" | "μs" => 1e3,
                "ms" => 1e6,
                "s" => 1e9,
                "m" => 60e9,
                "h" => 3600e9,
                _ => return Err(error()),
            };
            nanos += number * multiplier;
            rest = tail;
            pairs += 1;
        }
        let nanos = nanos.round() as i64;
        if pairs == 0 || nanos <= 0 {
            return Err(error());
        }
        Ok(Self { spec, nanos })
    }
}

impl HealthDuration {
    fn as_string(&self) -> String {
        self.spec.clone()
    }

    fn nanos(&self) -> i64 {
        self.nanos
    }
}

impl std::fmt::Display for HealthDuration {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_string())
    }
}

impl FromStr for HealthDuration {
    type Err = RegentError;

    fn from_str(spec: &str) -> Result<Self, Self::Err> {
        Self::try_from(spec.to_string())
    }
}

impl From<HealthDuration> for String {
    fn from(duration: HealthDuration) -> String {
        duration.as_string()
    }
}

/// Every optional field left out is not managed (no regent's defaults here, only docker's)
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[serde(rename_all = "PascalCase")]
pub struct DockerContainerConfig {
    image: ContainerImage,
    #[serde(default)]
    pull: PullPolicy,
    command: Option<ContainerCommand>,
    entrypoint: Option<String>,
    env: Option<BTreeMap<EnvVarName, Parameter<String>>>,
    volumes: Option<Vec<ContainerVolume>>,
    networking: Option<DockerNetworking>,
    restart_policy: Option<RestartPolicy>,
    hostname: Option<String>,
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
    extra_hosts: Option<Vec<ExtraHost>>,
    dns: Option<Vec<IpAddr>>,
    devices: Option<Vec<HostDevice>>,
    /// GPUs (`--gpus`, requires the NVIDIA Container Toolkit)
    gpus: Option<GpuSelection>,
    ipc: Option<IpcNamespace>,
    health_check: Option<HealthCheck>,
    log_driver: Option<String>,
    log_options: Option<BTreeMap<String, String>>,
}

impl DockerContainerConfig {
    pub fn new(image: ContainerImage) -> Self {
        Self {
            image,
            pull: PullPolicy::default(),
            command: None,
            entrypoint: None,
            env: None,
            volumes: None,
            networking: None,
            restart_policy: None,
            hostname: None,
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
            extra_hosts: None,
            dns: None,
            devices: None,
            gpus: None,
            ipc: None,
            health_check: None,
            log_driver: None,
            log_options: None,
        }
    }

    pub fn with_pull_policy(mut self, pull: PullPolicy) -> Self {
        self.pull = pull;
        self
    }

    /// Pull the image only if it is not present on the host (default, `PullPolicy::Missing`)
    pub fn with_pull_if_missing(self) -> Self {
        self.with_pull_policy(PullPolicy::Missing)
    }

    /// Never pull the image: a missing image makes the attribute non-compliant (`PullPolicy::Never`)
    pub fn with_pull_never(self) -> Self {
        self.with_pull_policy(PullPolicy::Never)
    }

    pub fn with_command(mut self, command: ContainerCommand) -> Self {
        self.command = Some(command);
        self
    }

    pub fn with_entrypoint(mut self, entrypoint: &str) -> Self {
        self.entrypoint = Some(entrypoint.to_string());
        self
    }

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

    pub fn with_networking(mut self, networking: DockerNetworking) -> Self {
        self.networking = Some(networking);
        self
    }

    /// Share the host network stack (`--network host`). Replaces the networks and published
    /// ports set before.
    pub fn with_host_networking(self) -> Self {
        self.with_networking(DockerNetworking::Host)
    }

    /// No network at all (`--network none`). Replaces the networks and published ports set
    /// before.
    pub fn with_isolated_networking(self) -> Self {
        self.with_networking(DockerNetworking::Isolated)
    }

    /// Attach the container to a network, after the networks added before (the first one is
    /// used at creation). Replaces `Host` or `Isolated` networking.
    pub fn with_network(mut self, network: NetworkName) -> Self {
        let mut attached = self.take_attached_networking();
        attached.networks = Some(NetworkList::add(attached.networks, network));
        self.with_networking(DockerNetworking::Attached(attached))
    }

    /// Publish a port, in addition to the ports published before. Ports can only be published
    /// on attached networking: replaces `Host` or `Isolated` networking.
    pub fn with_published_port(mut self, port: PublishedPort) -> Self {
        let mut attached = self.take_attached_networking();
        attached.ports.get_or_insert_with(Vec::new).push(port);
        self.with_networking(DockerNetworking::Attached(attached))
    }

    /// Current attached networking, or an empty one if networking is `Host`, `Isolated` or not set
    fn take_attached_networking(&mut self) -> DockerAttachedNetworking {
        match self.networking.take() {
            Some(DockerNetworking::Attached(attached)) => attached,
            _ => DockerAttachedNetworking {
                networks: None,
                ports: None,
            },
        }
    }

    pub fn with_restart_policy(mut self, restart_policy: RestartPolicy) -> Self {
        self.restart_policy = Some(restart_policy);
        self
    }

    /// Never restart the container (`--restart no`)
    pub fn with_restart_never(self) -> Self {
        self.with_restart_policy(RestartPolicy::No)
    }

    /// Always restart the container (`--restart always`)
    pub fn with_restart_always(self) -> Self {
        self.with_restart_policy(RestartPolicy::Always)
    }

    /// Restart the container unless it was stopped (`--restart unless-stopped`)
    pub fn with_restart_unless_stopped(self) -> Self {
        self.with_restart_policy(RestartPolicy::UnlessStopped)
    }

    /// Restart the container when it fails, at most `max_retries` times (0 means unlimited,
    /// `--restart on-failure[:max-retries]`)
    pub fn with_restart_on_failure(self, max_retries: u32) -> Self {
        self.with_restart_policy(RestartPolicy::OnFailure(max_retries))
    }

    pub fn with_hostname(mut self, hostname: &str) -> Self {
        self.hostname = Some(hostname.to_string());
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

    pub fn with_extra_hosts(mut self, extra_hosts: Vec<ExtraHost>) -> Self {
        self.extra_hosts = Some(extra_hosts);
        self
    }

    pub fn with_dns(mut self, dns: Vec<IpAddr>) -> Self {
        self.dns = Some(dns);
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

    /// Give all the GPUs to the container (`--gpus all`). Replaces the devices added before.
    pub fn with_all_gpus(self) -> Self {
        self.with_gpus(GpuSelection::All)
    }

    /// Give a GPU to the container, in addition to the devices added before. Replaces
    /// `with_all_gpus()`.
    pub fn with_gpu_device(mut self, gpu: GpuId) -> Self {
        self.gpus = Some(GpuSelection::add_device(self.gpus.take(), gpu));
        self
    }

    pub fn with_ipc(mut self, ipc: IpcNamespace) -> Self {
        self.ipc = Some(ipc);
        self
    }

    /// Share the host IPC namespace and `/dev/shm` (`--ipc host`). Replaces a private namespace
    /// and its `/dev/shm` size.
    pub fn with_host_ipc(self) -> Self {
        self.with_ipc(IpcNamespace::Host)
    }

    /// Own IPC namespace (`--ipc private`). Replaces the host namespace, keeps the `/dev/shm`
    /// size set before.
    pub fn with_private_ipc(mut self) -> Self {
        self.ipc = Some(IpcNamespace::private(self.ipc.take()));
        self
    }

    /// Own IPC namespace which other containers can join (`--ipc shareable`). Replaces the host
    /// namespace, keeps the `/dev/shm` size set before.
    pub fn with_shareable_ipc(mut self) -> Self {
        self.ipc = Some(IpcNamespace::shareable(self.ipc.take()));
        self
    }

    /// Size of `/dev/shm` (`--shm-size`), which only exists in the container's own IPC
    /// namespace: replaces the host namespace by a private one (a shareable namespace stays
    /// shareable).
    pub fn with_shm_size(mut self, shm_size: MemorySize) -> Self {
        self.ipc = Some(IpcNamespace::with_shm_size(self.ipc.take(), shm_size));
        self
    }

    pub fn with_health_check(mut self, health_check: HealthCheck) -> Self {
        self.health_check = Some(health_check);
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

    fn additional_networks(&self) -> &[NetworkName] {
        match &self.networking {
            Some(DockerNetworking::Attached(DockerAttachedNetworking {
                networks: Some(networks),
                ..
            })) => &networks.networks()[1..],
            _ => &[],
        }
    }

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
        let mut args = to_strings(&["docker", "create", "--name", name.as_str()]);

        let mut push_option = |flag: &str, value: String| {
            args.push(flag.to_string());
            args.push(value);
        };

        if let Some(hostname) = &self.hostname {
            push_option("--hostname", hostname.clone());
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
        match &self.networking {
            Some(DockerNetworking::Host) => push_option("--network", "host".to_string()),
            Some(DockerNetworking::Isolated) => push_option("--network", "none".to_string()),
            Some(DockerNetworking::Attached(attached)) => {
                if let Some(networks) = &attached.networks {
                    push_option("--network", networks.networks()[0].to_string());
                }
                for port in attached.ports.iter().flatten() {
                    push_option("--publish", port.to_string());
                }
            }
            None => {}
        }
        if let Some(restart_policy) = &self.restart_policy {
            push_option("--restart", restart_policy.as_cli_arg());
        }
        for (key, value) in self.labels.iter().flatten() {
            push_option("--label", format!("{}={}", key, value));
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
        for extra_host in self.extra_hosts.iter().flatten() {
            push_option("--add-host", extra_host.to_string());
        }
        for dns in self.dns.iter().flatten() {
            push_option("--dns", dns.to_string());
        }
        for device in self.devices.iter().flatten() {
            push_option("--device", device.to_string());
        }
        match &self.gpus {
            Some(GpuSelection::All) => push_option("--gpus", "all".to_string()),
            Some(GpuSelection::Devices(gpus)) => {
                // The value is parsed as CSV: the list needs quotes around it
                let ids: Vec<String> = gpus.gpus().iter().map(|gpu| gpu.to_string()).collect();
                push_option("--gpus", format!("\"device={}\"", ids.join(",")));
            }
            None => {}
        }
        if let Some(ipc) = &self.ipc {
            push_option("--ipc", ipc.mode().to_string());
            if let Some(shm_size) = ipc.shm_size() {
                push_option("--shm-size", shm_size.to_string());
            }
        }
        if let Some(health_check) = &self.health_check {
            push_option("--health-cmd", health_check.test.to_string());
            if let Some(interval) = &health_check.interval {
                push_option("--health-interval", interval.to_string());
            }
            if let Some(timeout) = &health_check.timeout {
                push_option("--health-timeout", timeout.to_string());
            }
            if let Some(start_period) = &health_check.start_period {
                push_option("--health-start-period", start_period.to_string());
            }
            if let Some(start_interval) = &health_check.start_interval {
                push_option("--health-start-interval", start_interval.to_string());
            }
            if let Some(retries) = &health_check.retries {
                push_option("--health-retries", retries.to_string());
            }
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

    /// Returns the list of differences requiring the container to be recreated (empty if none).
    /// Messages never contain environment variable values, as they might be secrets.
    fn recreation_reasons(&self, inspect: &Value, env: &[(String, String)]) -> Vec<String> {
        let mut reasons: Vec<String> = Vec::new();

        let current_image = pointer(inspect, "/Config/Image")
            .as_str()
            .unwrap_or_default();
        if current_image != self.image.as_str() {
            reasons.push(format!(
                "image is {}, expected {}",
                current_image, self.image
            ));
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
            let current = string_list(pointer(inspect, "/Config/Entrypoint"));
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
            // Binds are compared exactly, anonymous volumes as a subset (the image may declare some)
            compare_sets(
                &mut reasons,
                "volumes",
                volumes
                    .iter()
                    .filter(|volume| matches!(volume, ContainerVolume::Bind { .. }))
                    .map(|volume| volume.to_string())
                    .collect(),
                string_list(pointer(inspect, "/HostConfig/Binds"))
                    .into_iter()
                    .collect(),
            );
            let current_anonymous = pointer(inspect, "/Config/Volumes");
            for volume in volumes {
                if let ContainerVolume::Anonymous { target } = volume
                    && current_anonymous.get(target).is_none()
                {
                    reasons.push(format!("anonymous volume {} is missing", target));
                }
            }
        }

        if let Some(networking) = &self.networking {
            let current_mode = pointer(inspect, "/HostConfig/NetworkMode")
                .as_str()
                .unwrap_or_default();
            match networking {
                DockerNetworking::Host | DockerNetworking::Isolated => {
                    let expected_mode = match networking {
                        DockerNetworking::Host => "host",
                        _ => "none",
                    };
                    if current_mode != expected_mode {
                        reasons.push(format!(
                            "network mode is {}, expected {}",
                            current_mode, expected_mode
                        ));
                    }
                }
                DockerNetworking::Attached(attached) => {
                    if current_mode == "host" || current_mode == "none" {
                        reasons.push(format!(
                            "network mode is {}, expected attached networks",
                            current_mode
                        ));
                    }
                    if let Some(networks) = &attached.networks {
                        compare_sets(
                            &mut reasons,
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
                            .collect();
                        let current = current_port_bindings(inspect);
                        if expected != current {
                            reasons.push(format!(
                                "published ports are {:?}, expected {:?}",
                                current, expected
                            ));
                        }
                    }
                }
            }
        }

        for (option_name, expected, path) in [
            ("hostname", &self.hostname, "/Config/Hostname"),
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

        for (option_name, expected, path) in [
            ("labels", &self.labels, "/Config/Labels"),
            (
                "log options",
                &self.log_options,
                "/HostConfig/LogConfig/Config",
            ),
        ] {
            if let Some(expected) = expected {
                let current = pointer(inspect, path);
                for (key, value) in expected {
                    if current.get(key).and_then(Value::as_str) != Some(value.as_str()) {
                        reasons.push(format!("{} entry {} differs", option_name, key));
                    }
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

        for (option_name, expected, path) in [
            ("added capabilities", &self.cap_add, "/HostConfig/CapAdd"),
            (
                "dropped capabilities",
                &self.cap_drop,
                "/HostConfig/CapDrop",
            ),
        ] {
            if let Some(expected) = expected {
                compare_sets(
                    &mut reasons,
                    option_name,
                    expected.iter().map(|cap| cap.to_string()).collect(),
                    string_list(pointer(inspect, path))
                        .iter()
                        .map(|cap| normalize_capability(cap))
                        .collect(),
                );
            }
        }

        if let Some(extra_hosts) = &self.extra_hosts {
            compare_sets(
                &mut reasons,
                "extra hosts",
                extra_hosts.iter().map(|host| host.to_string()).collect(),
                string_list(pointer(inspect, "/HostConfig/ExtraHosts"))
                    .into_iter()
                    .collect(),
            );
        }

        if let Some(dns) = &self.dns {
            compare_sets(
                &mut reasons,
                "DNS servers",
                dns.iter().map(|server| server.to_string()).collect(),
                string_list(pointer(inspect, "/HostConfig/Dns"))
                    .into_iter()
                    .collect(),
            );
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

        if let Some(gpus) = &self.gpus {
            let current = current_gpus(inspect);
            let expected = gpus.ids();
            if current != expected {
                reasons.push(format!("GPUs are {:?}, expected {:?}", current, expected));
            }
        }

        if let Some(ipc) = &self.ipc {
            let current = pointer(inspect, "/HostConfig/IpcMode")
                .as_str()
                .unwrap_or_default();
            if current != ipc.mode() {
                reasons.push(format!(
                    "IPC mode is {:?}, expected {:?}",
                    current,
                    ipc.mode()
                ));
            }
            if let Some(shm_size) = ipc.shm_size() {
                let current = pointer(inspect, "/HostConfig/ShmSize")
                    .as_i64()
                    .unwrap_or_default();
                if current != shm_size.bytes() {
                    reasons.push(format!(
                        "/dev/shm size is {} bytes, expected {} bytes",
                        current,
                        shm_size.bytes()
                    ));
                }
            }
        }

        if let Some(health_check) = &self.health_check {
            let current = pointer(inspect, "/Config/Healthcheck");
            let expected_test = vec!["CMD-SHELL".to_string(), health_check.test.to_string()];
            let current_test = string_list(pointer(current, "/Test"));
            if current_test != expected_test {
                reasons.push(format!(
                    "health check command is {:?}, expected {:?}",
                    current_test, expected_test
                ));
            }
            for (option_name, expected, path) in [
                ("health check interval", &health_check.interval, "/Interval"),
                ("health check timeout", &health_check.timeout, "/Timeout"),
                (
                    "health check start period",
                    &health_check.start_period,
                    "/StartPeriod",
                ),
                (
                    "health check start interval",
                    &health_check.start_interval,
                    "/StartInterval",
                ),
            ] {
                if let Some(expected) = expected {
                    let current = pointer(current, path).as_i64().unwrap_or_default();
                    if current != expected.nanos() {
                        reasons.push(format!(
                            "{} is {} nanoseconds, expected {} nanoseconds",
                            option_name,
                            current,
                            expected.nanos()
                        ));
                    }
                }
            }
            if let Some(retries) = &health_check.retries {
                let current = pointer(current, "/Retries").as_i64().unwrap_or_default();
                if current != *retries as i64 {
                    reasons.push(format!(
                        "health check retries is {}, expected {}",
                        current, retries
                    ));
                }
            }
        }

        reasons
    }

    fn is_restart_policy_compliant(&self, inspect: &Value) -> bool {
        match &self.restart_policy {
            Some(restart_policy) => restart_policy.matches(
                pointer(inspect, "/HostConfig/RestartPolicy/Name")
                    .as_str()
                    .unwrap_or_default(),
                pointer(inspect, "/HostConfig/RestartPolicy/MaximumRetryCount")
                    .as_u64()
                    .unwrap_or_default(),
            ),
            None => true,
        }
    }
}

impl Timeout for DockerExpectedState {
    fn default_timeout(&self) -> Duration {
        // Pulling an image can take a while
        Duration::from_secs(300)
    }
}

impl Check for DockerExpectedState {
    fn check(&self) -> Result<(), RegentError> {
        // Every value is validated when its type is built: an existing DockerExpectedState is valid
        Ok(())
    }

    fn check_host_compatibility(
        &self,
        host_properties: &HostProperties,
    ) -> Result<(), RegentError> {
        check_docker_host_compatibility(host_properties)
    }
}

impl<Handler: HostHandler> AssessCompliance<Handler> for DockerExpectedState {
    async fn assess_compliance(
        &self,
        host_handler: &mut Handler,
        host_properties: &Option<HostProperties>,
        privilege: &Privilege,
        optional_secret_provider: &Option<SecretProvidersPool>,
    ) -> Result<AttributeComplianceAssessment, RegentError> {
        // Early check: verify we're on a compatible host
        if let Some(props) = host_properties {
            self.check_host_compatibility(props)?;
        }

        let command_available = host_handler
            .is_this_command_available("docker", privilege)
            .await
            .unwrap_or(false);
        if !command_available {
            return Err(RegentError::FailedDryRunEvaluation(
                "Docker CLI (docker) is not available on this host".to_string(),
            ));
        }

        let container = inspect_container(host_handler, &self.name, privilege).await?;

        let mut remediations: Vec<Remediation> = Vec::new();
        let mut push = |api_call: DockerInternalApiCall| {
            remediations.push(Remediation::Docker(DockerApiCall::from(
                api_call,
                privilege.clone(),
            )));
        };

        let (config, should_run) = match &self.state {
            DockerContainerState::Absent => {
                if container.is_some() {
                    push(DockerInternalApiCall::Remove(self.name.clone()));
                }
                (None, false)
            }
            DockerContainerState::Running(config) => (Some(config), true),
            DockerContainerState::Stopped(config) => (Some(config), false),
        };

        if let Some(config) = config {
            let image_id = inspect_image_id(host_handler, &config.image, privilege).await?;

            if image_id.is_none() {
                match config.pull {
                    PullPolicy::Missing => push(DockerInternalApiCall::Pull(config.image.clone())),
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
                    push(DockerInternalApiCall::Create {
                        name: self.name.clone(),
                        config: config.clone(),
                    });
                    if should_run {
                        push(DockerInternalApiCall::Start(self.name.clone()));
                    }
                }
                Some(inspect) => {
                    let env = config.resolve_env(optional_secret_provider).await?;
                    let mut reasons = config.recreation_reasons(&inspect, &env);

                    // Same image reference but the local image changed (e.g. new pull of a tag)
                    let current_image_id = pointer(&inspect, "/Image").as_str();
                    match &image_id {
                        Some(image_id)
                            if reasons.is_empty()
                                && current_image_id != Some(image_id.as_str()) =>
                        {
                            reasons.push(format!("image {} has been updated", config.image));
                        }
                        None => reasons.push(format!(
                            "image {} is not present locally, it will be pulled",
                            config.image
                        )),
                        _ => {}
                    }

                    if !reasons.is_empty() {
                        push(DockerInternalApiCall::Recreate {
                            name: self.name.clone(),
                            config: config.clone(),
                            reasons,
                        });
                        if should_run {
                            push(DockerInternalApiCall::Start(self.name.clone()));
                        }
                    } else {
                        if let Some(restart_policy) = &config.restart_policy
                            && !config.is_restart_policy_compliant(&inspect)
                        {
                            push(DockerInternalApiCall::UpdateRestartPolicy {
                                name: self.name.clone(),
                                restart_policy: restart_policy.clone(),
                            });
                        }

                        let is_running = pointer(&inspect, "/State/Running")
                            .as_bool()
                            .unwrap_or(false);
                        let is_paused = pointer(&inspect, "/State/Paused")
                            .as_bool()
                            .unwrap_or(false);
                        match (should_run, is_running, is_paused) {
                            (true, true, true) => {
                                push(DockerInternalApiCall::Unpause(self.name.clone()))
                            }
                            (true, false, _) => {
                                push(DockerInternalApiCall::Start(self.name.clone()))
                            }
                            (false, true, _) => {
                                push(DockerInternalApiCall::Stop(self.name.clone()))
                            }
                            _ => {
                                // Already in the expected running state
                            }
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
pub enum DockerInternalApiCall {
    Pull(ContainerImage),
    /// Create a container (not started)
    Create {
        name: ContainerName,
        config: Box<DockerContainerConfig>,
    },
    /// Remove then create a container, with the reasons why
    Recreate {
        name: ContainerName,
        config: Box<DockerContainerConfig>,
        reasons: Vec<String>,
    },
    /// Remove a container (forced)
    Remove(ContainerName),
    Start(ContainerName),
    Stop(ContainerName),
    Unpause(ContainerName),
    UpdateRestartPolicy {
        name: ContainerName,
        restart_policy: RestartPolicy,
    },
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DockerApiCall {
    pub api_call: DockerInternalApiCall,
    privilege: Privilege,
}

impl DockerApiCall {
    pub fn display(&self) -> String {
        match &self.api_call {
            DockerInternalApiCall::Pull(image) => format!("Pull image {}", image),
            DockerInternalApiCall::Create { name, config } => {
                format!("Create container {} from {}", name, config.image)
            }
            DockerInternalApiCall::Recreate { name, reasons, .. } => {
                format!("Recreate container {} ({})", name, reasons.join("; "))
            }
            DockerInternalApiCall::Remove(name) => format!("Remove container {}", name),
            DockerInternalApiCall::Start(name) => format!("Start container {}", name),
            DockerInternalApiCall::Stop(name) => format!("Stop container {}", name),
            DockerInternalApiCall::Unpause(name) => format!("Unpause container {}", name),
            DockerInternalApiCall::UpdateRestartPolicy {
                name,
                restart_policy,
            } => format!(
                "Set restart policy of container {} to {}",
                name,
                restart_policy.as_cli_arg()
            ),
        }
    }

    fn from(api_call: DockerInternalApiCall, privilege: Privilege) -> DockerApiCall {
        DockerApiCall {
            api_call,
            privilege,
        }
    }
}

impl Timeout for DockerApiCall {
    fn default_timeout(&self) -> Duration {
        Duration::from_secs(300)
    }
}

impl Check for DockerApiCall {
    fn check(&self) -> Result<(), RegentError> {
        Ok(())
    }

    fn check_host_compatibility(
        &self,
        host_properties: &HostProperties,
    ) -> Result<(), RegentError> {
        check_docker_host_compatibility(host_properties)
    }
}

impl<Handler: HostHandler> ReachCompliance<Handler> for DockerApiCall {
    async fn call(
        &self,
        host_handler: &mut Handler,
        host_properties: &Option<HostProperties>,
        optional_secret_provider: &Option<SecretProvidersPool>,
    ) -> Result<InternalApiCallOutcome, RegentError> {
        // Early check: verify we're on a compatible host
        if let Some(props) = host_properties {
            self.check_host_compatibility(props)?;
        }

        match &self.api_call {
            DockerInternalApiCall::Pull(image) => {
                run_docker(
                    host_handler,
                    &["docker", "pull", image.as_str()],
                    &self.privilege,
                )
                .await
            }
            DockerInternalApiCall::Create { name, config } => {
                create_container(
                    host_handler,
                    name,
                    config,
                    optional_secret_provider,
                    &self.privilege,
                )
                .await
            }
            DockerInternalApiCall::Recreate { name, config, .. } => {
                let outcome = run_docker(
                    host_handler,
                    &["docker", "rm", "--force", name.as_str()],
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
            DockerInternalApiCall::Remove(name) => {
                run_docker(
                    host_handler,
                    &["docker", "rm", "--force", name.as_str()],
                    &self.privilege,
                )
                .await
            }
            DockerInternalApiCall::Start(name) => {
                run_docker(
                    host_handler,
                    &["docker", "start", name.as_str()],
                    &self.privilege,
                )
                .await
            }
            DockerInternalApiCall::Stop(name) => {
                run_docker(
                    host_handler,
                    &["docker", "stop", name.as_str()],
                    &self.privilege,
                )
                .await
            }
            DockerInternalApiCall::Unpause(name) => {
                run_docker(
                    host_handler,
                    &["docker", "unpause", name.as_str()],
                    &self.privilege,
                )
                .await
            }
            DockerInternalApiCall::UpdateRestartPolicy {
                name,
                restart_policy,
            } => {
                run_docker(
                    host_handler,
                    &[
                        "docker",
                        "update",
                        "--restart",
                        &restart_policy.as_cli_arg(),
                        name.as_str(),
                    ],
                    &self.privilege,
                )
                .await
            }
        }
    }
}

fn check_docker_host_compatibility(host_properties: &HostProperties) -> Result<(), RegentError> {
    match host_properties.os_kind() {
        OsKind::Linux(_) | OsKind::MacOs(_) => Ok(()),
        incompatible_os_kind => Err(RegentError::IncompatibleHost(format!(
            "Host is {:?} but Docker container management is only supported on Linux and macOS",
            incompatible_os_kind
        ))),
    }
}

/// Create the container, then connect it to the additional networks
async fn create_container<Handler: HostHandler>(
    host_handler: &mut Handler,
    name: &ContainerName,
    config: &DockerContainerConfig,
    optional_secret_provider: &Option<SecretProvidersPool>,
    privilege: &Privilege,
) -> Result<InternalApiCallOutcome, RegentError> {
    let env = config.resolve_env(optional_secret_provider).await?;
    let args = config.create_args(name, &env);
    let args: Vec<&str> = args.iter().map(String::as_str).collect();

    let outcome = run_docker(host_handler, &args, privilege).await?;
    if let InternalApiCallOutcome::Failure(_) = outcome {
        return Ok(outcome);
    }

    for network in config.additional_networks() {
        let outcome = run_docker(
            host_handler,
            &[
                "docker",
                "network",
                "connect",
                network.as_str(),
                name.as_str(),
            ],
            privilege,
        )
        .await?;
        if let InternalApiCallOutcome::Failure(_) = outcome {
            return Ok(outcome);
        }
    }

    Ok(InternalApiCallOutcome::Success(None))
}

async fn run_docker<Handler: HostHandler>(
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

/// Inspect a container by name. Returns `None` if it doesn't exist.
async fn inspect_container<Handler: HostHandler>(
    host_handler: &mut Handler,
    name: &ContainerName,
    privilege: &Privilege,
) -> Result<Option<Value>, RegentError> {
    let result = host_handler
        .run_command(
            &quoted_command(&["docker", "container", "inspect", name.as_str()]),
            privilege,
        )
        .await
        .map_err(|e| {
            RegentError::FailedDryRunEvaluation(format!(
                "Unable to inspect container {}: {:?}",
                name, e
            ))
        })?;

    if result.return_code != 0 {
        let output = format!("{}{}", result.stdout, result.stderr);
        if output.contains("No such container") || output.contains("No such object") {
            return Ok(None);
        }
        return Err(RegentError::FailedDryRunEvaluation(format!(
            "Unable to inspect container {}: {:?}",
            name, result
        )));
    }

    let inspect = parse_inspect_output(&result.stdout).ok_or_else(|| {
        RegentError::FailureToParseContent(format!(
            "Unexpected output of docker container inspect: {}",
            result.stdout
        ))
    })?;

    // Inspecting by name also matches container IDs: make sure this is the right container
    if pointer(&inspect, "/Name").as_str() == Some(&format!("/{}", name)) {
        Ok(Some(inspect))
    } else {
        Ok(None)
    }
}

/// Get the ID of a local image. Returns `None` if the image is not present.
async fn inspect_image_id<Handler: HostHandler>(
    host_handler: &mut Handler,
    image: &ContainerImage,
    privilege: &Privilege,
) -> Result<Option<String>, RegentError> {
    let result = host_handler
        .run_command(
            &quoted_command(&[
                "docker",
                "image",
                "inspect",
                "--format",
                "{{.Id}}",
                image.as_str(),
            ]),
            privilege,
        )
        .await
        .map_err(|e| {
            RegentError::FailedDryRunEvaluation(format!(
                "Unable to inspect image {}: {:?}",
                image, e
            ))
        })?;

    if result.return_code != 0 {
        let output = format!("{}{}", result.stdout, result.stderr);
        if output.contains("No such image") || output.contains("No such object") {
            return Ok(None);
        }
        return Err(RegentError::FailedDryRunEvaluation(format!(
            "Unable to inspect image {}: {:?}",
            image, result
        )));
    }

    // stderr is merged into stdout by the handlers, keep only the ID line
    match result
        .stdout
        .lines()
        .map(str::trim)
        .find(|line| line.starts_with("sha256:"))
    {
        Some(image_id) => Ok(Some(image_id.to_string())),
        None => Err(RegentError::FailureToParseContent(format!(
            "Unexpected output of docker image inspect: {}",
            result.stdout
        ))),
    }
}

/// GPUs requested by the container (`all` for all of them)
fn current_gpus(inspect: &Value) -> BTreeSet<String> {
    let mut gpus = BTreeSet::new();
    for request in pointer(inspect, "/HostConfig/DeviceRequests")
        .as_array()
        .into_iter()
        .flatten()
    {
        let is_gpu_request = pointer(request, "/Capabilities")
            .as_array()
            .into_iter()
            .flatten()
            .any(|capabilities| string_list(capabilities).iter().any(|cap| cap == "gpu"));
        if !is_gpu_request {
            continue;
        }
        if pointer(request, "/Count").as_i64() == Some(-1) {
            gpus.insert("all".to_string());
        }
        gpus.extend(string_list(pointer(request, "/DeviceIDs")));
    }
    gpus
}

fn current_port_bindings(inspect: &Value) -> BTreeSet<PortBinding> {
    let mut current = BTreeSet::new();
    if let Some(bindings) = pointer(inspect, "/HostConfig/PortBindings").as_object() {
        for (container_port, host_bindings) in bindings {
            for host_binding in host_bindings.as_array().into_iter().flatten() {
                current.insert(PortBinding {
                    container_port: container_port.clone(),
                    host_ip: pointer(host_binding, "/HostIp")
                        .as_str()
                        .unwrap_or_default()
                        .to_string(),
                    host_port: pointer(host_binding, "/HostPort")
                        .as_str()
                        .unwrap_or_default()
                        .to_string(),
                });
            }
        }
    }
    current
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::secrets::SecretReference;
    use crate::state::attribute::container::container_spec::{GpuList, PrivateIpc};

    fn full_yaml() -> &'static str {
        "---
Name: web
State: !Running
  Image: nginx:1.27
  Pull: Missing
  Entrypoint: /docker-entrypoint.sh
  Command: [nginx, -g, daemon off;]
  Env:
    TZ: Europe/Paris
    API_TOKEN:
      SecRef: web_api_token
      Provider: files
  Volumes:
    - /srv/www:/usr/share/nginx/html:ro
    - /var/cache/nginx
  Networking: !Attached
    Networks: [frontend, backend]
    Ports:
      - 8080:80
      - 127.0.0.1:8443:443/tcp
  RestartPolicy: UnlessStopped
  Hostname: web01
  User: '101:101'
  WorkingDir: /usr/share/nginx
  Labels:
    traefik.enable: 'true'
  Privileged: false
  ReadOnly: false
  Init: true
  CapAdd: [net_bind_service]
  CapDrop: [ALL]
  Memory: 512m
  Cpus: 1.5
  ExtraHosts: ['db.local:10.0.0.12']
  Dns: [1.1.1.1]
  Devices: ['/dev/snd']
  HealthCheck:
    Test: curl -f http://localhost || exit 1
    Interval: 30s
    Timeout: 5s
    StartPeriod: 10s
    StartInterval: 1s
    Retries: 3
  LogDriver: json-file
  LogOptions:
    max-size: 10m
"
    }

    fn full_config() -> DockerContainerConfig {
        let state: DockerExpectedState = yaml_serde::from_str(full_yaml()).unwrap();
        match state.state {
            DockerContainerState::Running(config) => *config,
            other => panic!("unexpected state {:?}", other),
        }
    }

    /// `docker container inspect` output of a container matching `full_yaml()`
    fn matching_inspect() -> Value {
        serde_json::json!({
            "Name": "/web",
            "Image": "sha256:abc",
            "State": { "Running": true, "Paused": false },
            "Config": {
                "Image": "nginx:1.27",
                "Cmd": ["nginx", "-g", "daemon off;"],
                "Entrypoint": ["/docker-entrypoint.sh"],
                "Env": ["TZ=Europe/Paris", "API_TOKEN=s3cr3t", "PATH=/usr/bin", "NGINX_VERSION=1.27"],
                "Hostname": "web01",
                "User": "101:101",
                "WorkingDir": "/usr/share/nginx",
                "Labels": { "traefik.enable": "true", "maintainer": "NGINX" },
                "Volumes": { "/var/cache/nginx": {} },
                "Healthcheck": {
                    "Test": ["CMD-SHELL", "curl -f http://localhost || exit 1"],
                    "Interval": 30000000000i64,
                    "Timeout": 5000000000i64,
                    "StartPeriod": 10000000000i64,
                    "StartInterval": 1000000000i64,
                    "Retries": 3
                }
            },
            "HostConfig": {
                "Binds": ["/srv/www:/usr/share/nginx/html:ro"],
                "NetworkMode": "frontend",
                "PortBindings": {
                    "80/tcp": [{ "HostIp": "", "HostPort": "8080" }],
                    "443/tcp": [{ "HostIp": "127.0.0.1", "HostPort": "8443" }]
                },
                "RestartPolicy": { "Name": "unless-stopped", "MaximumRetryCount": 0 },
                "Privileged": false,
                "ReadonlyRootfs": false,
                "Init": true,
                "CapAdd": ["CAP_NET_BIND_SERVICE"],
                "CapDrop": ["ALL"],
                "Memory": 536870912,
                "NanoCpus": 1500000000i64,
                "ExtraHosts": ["db.local:10.0.0.12"],
                "Dns": ["1.1.1.1"],
                "Devices": [{ "PathOnHost": "/dev/snd", "PathInContainer": "/dev/snd", "CgroupPermissions": "rwm" }],
                "LogConfig": { "Type": "json-file", "Config": { "max-size": "10m", "max-file": "1" } }
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
    fn parsing_docker_module_block_from_yaml_str() {
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
- Name: worker
  State: !Stopped
    Image: busybox
    Networking: Host
    RestartPolicy: !OnFailure 3
";
        let states: Vec<DockerExpectedState> = yaml_serde::from_str(raw).unwrap();
        assert_eq!(states[0].state, DockerContainerState::Absent);
        match &states[1].state {
            DockerContainerState::Stopped(config) => {
                assert_eq!(config.networking, Some(DockerNetworking::Host));
                assert_eq!(config.restart_policy, Some(RestartPolicy::OnFailure(3)));
            }
            other => panic!("unexpected state {:?}", other),
        }
    }

    #[test]
    fn serialization_round_trip_preserves_state() {
        // Templating (Attribute::consider_context) relies on a JSON round trip
        let state: DockerExpectedState = yaml_serde::from_str(full_yaml()).unwrap();
        let json = serde_json::to_string(&state).unwrap();
        assert_eq!(
            serde_json::from_str::<DockerExpectedState>(&json).unwrap(),
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
            // Unknown field
            "Name: web\nState: !Running\n  Image: nginx\n  Port: 80:80\n",
            // Ports can't be published with host networking
            "Name: web\nState: !Running\n  Image: nginx\n  Networking: !Host\n    Ports: ['80:80']\n",
            // host is a networking mode, not a network to attach to
            "Name: web\nState: !Running\n  Image: nginx\n  Networking: !Attached\n    Networks: [host, frontend]\n",
            "Name: web\nState: !Running\n  Image: nginx\n  Networking: !Attached\n    Networks: []\n",
            "Name: /web\nState: Absent\n",
            "Name: web\nState: !Running\n  Image: ''\n",
            "Name: web\nState: !Running\n  Image: nginx\n  Command: []\n",
            "Name: web\nState: !Running\n  Image: nginx\n  Memory: lots\n",
            "Name: web\nState: !Running\n  Image: nginx\n  Cpus: 0\n",
            "Name: web\nState: !Running\n  Image: nginx\n  Volumes: [relative/path]\n",
            "Name: web\nState: !Running\n  Image: nginx\n  Env: {'A=B': c}\n",
            "Name: web\nState: !Running\n  Image: nginx\n  ExtraHosts: ['db.local:not-an-ip']\n",
            "Name: web\nState: !Running\n  Image: nginx\n  Devices: ['/dev/snd:/dev/snd:x']\n",
            "Name: web\nState: !Running\n  Image: nginx\n  Dns: [dns.example.com]\n",
            // /dev/shm size can only be set on a private IPC namespace
            "Name: web\nState: !Running\n  Image: nginx\n  Ipc: !Host\n    ShmSize: 1g\n",
            "Name: web\nState: !Running\n  Image: nginx\n  Gpus: !Devices []\n",
            "Name: web\nState: !Running\n  Image: nginx\n  Gpus: !Devices [gpu0]\n",
            // The health check test is mandatory and never empty
            "Name: web\nState: !Running\n  Image: nginx\n  HealthCheck:\n    Interval: 30s\n",
            "Name: web\nState: !Running\n  Image: nginx\n  HealthCheck:\n    Test: ''\n",
            // Health check durations follow the Go syntax and are strictly positive
            "Name: web\nState: !Running\n  Image: nginx\n  HealthCheck:\n    Test: curl\n    Interval: 30\n",
            "Name: web\nState: !Running\n  Image: nginx\n  HealthCheck:\n    Test: curl\n    Interval: lots\n",
            "Name: web\nState: !Running\n  Image: nginx\n  HealthCheck:\n    Test: curl\n    StartPeriod: 0s\n",
            "Name: web\nState: !Running\n  Image: nginx\n  HealthCheck:\n    Test: curl\n    Retries: -1\n",
            "Name: web\nState: !Running\n  Image: nginx\n  HealthCheck:\n    Test: curl\n    Unknown: x\n",
        ];
        for raw in rejected {
            assert!(
                yaml_serde::from_str::<DockerExpectedState>(raw).is_err(),
                "should be rejected: {}",
                raw
            );
        }
    }

    #[test]
    fn matching_container_needs_no_recreation() {
        let config = full_config();
        let reasons = config.recreation_reasons(&matching_inspect(), &resolved_env());
        assert!(reasons.is_empty(), "{:?}", reasons);
        assert!(config.is_restart_policy_compliant(&matching_inspect()));
    }

    #[test]
    fn drifted_container_needs_recreation() {
        let config = full_config();
        let mut inspect = matching_inspect();
        inspect["HostConfig"]["PortBindings"]["80/tcp"][0]["HostPort"] = "9090".into();
        inspect["Config"]["Env"][1] = "API_TOKEN=old_secret".into();
        inspect["NetworkSettings"]["Networks"] = serde_json::json!({ "bridge": {} });

        let reasons = config.recreation_reasons(&inspect, &resolved_env());
        assert_eq!(reasons.len(), 3, "{:?}", reasons);
        // Secret values must never leak in remediation messages
        assert!(reasons.iter().all(|reason| !reason.contains("secret")));
    }

    #[test]
    fn network_mode_drift_is_detected() {
        let mut inspect = matching_inspect();
        inspect["HostConfig"]["NetworkMode"] = "host".into();

        let attached = DockerContainerConfig::new("nginx:1.27".parse().unwrap()).with_networking(
            DockerNetworking::attached(None, Some(vec!["8080:80".parse().unwrap()])),
        );
        let reasons = attached.recreation_reasons(&inspect, &[]);
        assert!(
            reasons
                .iter()
                .any(|reason| reason.starts_with("network mode is host")),
            "{:?}",
            reasons
        );

        let host = DockerContainerConfig::new("nginx:1.27".parse().unwrap())
            .with_networking(DockerNetworking::Host);
        assert!(host.recreation_reasons(&inspect, &[]).is_empty());
    }

    #[test]
    fn restart_policy_drift_is_detected() {
        let config = DockerContainerConfig::new("nginx".parse().unwrap())
            .with_restart_policy(RestartPolicy::OnFailure(5));
        assert!(!config.is_restart_policy_compliant(&matching_inspect()));

        let config = DockerContainerConfig::new("nginx".parse().unwrap())
            .with_restart_policy(RestartPolicy::No);
        let inspect = serde_json::json!({ "HostConfig": { "RestartPolicy": { "Name": "", "MaximumRetryCount": 0 } } });
        assert!(config.is_restart_policy_compliant(&inspect));
    }

    #[test]
    fn gpu_inference_server() {
        let raw = "---
Name: vllm
State: !Running
  Image: vllm/vllm-openai:v0.10.1
  Command: [--model, Qwen/Qwen3-8B]
  Gpus: !Devices [0, GPU-4b2c7f1e-9a3d-4e6f-8b1a-2c3d4e5f6a7b]
  Ipc: !Private
    ShmSize: 16g
";
        let state: DockerExpectedState = yaml_serde::from_str(raw).unwrap();
        let json = serde_json::to_string(&state).unwrap();
        assert_eq!(
            serde_json::from_str::<DockerExpectedState>(&json).unwrap(),
            state
        );
        let DockerContainerState::Running(config) = state.state else {
            panic!("unexpected state");
        };
        let args = config.create_args(&"vllm".parse().unwrap(), &[]);
        assert_eq!(
            args[4..10],
            to_strings(&[
                "--gpus",
                "\"device=0,GPU-4b2c7f1e-9a3d-4e6f-8b1a-2c3d4e5f6a7b\"",
                "--ipc",
                "private",
                "--shm-size",
                "16g",
            ])
        );

        let inspect = serde_json::json!({
            "Config": { "Image": "vllm/vllm-openai:v0.10.1", "Cmd": ["--model", "Qwen/Qwen3-8B"] },
            "HostConfig": {
                "IpcMode": "private",
                "ShmSize": 17179869184i64,
                "DeviceRequests": [{
                    "Driver": "",
                    "Count": 0,
                    "DeviceIDs": ["0", "GPU-4b2c7f1e-9a3d-4e6f-8b1a-2c3d4e5f6a7b"],
                    "Capabilities": [["gpu"]],
                }]
            }
        });
        assert!(config.recreation_reasons(&inspect, &[]).is_empty());

        let all_gpus = DockerContainerConfig::new("vllm/vllm-openai:v0.10.1".parse().unwrap())
            .with_gpus(GpuSelection::All)
            .with_ipc(IpcNamespace::Host);
        let reasons = all_gpus.recreation_reasons(&inspect, &[]);
        assert_eq!(reasons.len(), 2, "{:?}", reasons);

        let mut inspect = inspect;
        inspect["HostConfig"]["IpcMode"] = "host".into();
        inspect["HostConfig"]["DeviceRequests"][0]["Count"] = (-1).into();
        inspect["HostConfig"]["DeviceRequests"][0]["DeviceIDs"] = Value::Null;
        assert!(all_gpus.recreation_reasons(&inspect, &[]).is_empty());
        assert_eq!(
            all_gpus.create_args(&"vllm".parse().unwrap(), &[])[4..8],
            to_strings(&["--gpus", "all", "--ipc", "host"])
        );
    }

    #[test]
    fn create_args_follow_docker_cli() {
        let config = DockerContainerConfig::new("nginx:1.27".parse().unwrap())
            .with_networking(DockerNetworking::attached(
                Some(
                    NetworkList::try_from(vec![
                        "frontend".parse().unwrap(),
                        "backend".parse().unwrap(),
                    ])
                    .unwrap(),
                ),
                Some(vec!["8080:80".parse().unwrap()]),
            ))
            .with_env(
                "TZ".parse().unwrap(),
                Parameter::Clear("Europe/Paris".to_string()),
            )
            .with_init(true)
            .with_restart_policy(RestartPolicy::OnFailure(3))
            .with_health_check(
                HealthCheck::new("curl -f http://localhost || exit 1".parse().unwrap())
                    .with_interval("30s".parse().unwrap())
                    .with_retries(3),
            )
            .with_command(ContainerCommand::new(&["nginx", "-g", "daemon off;"]).unwrap());
        let env = vec![("TZ".to_string(), "Europe/Paris".to_string())];
        assert_eq!(
            config.create_args(&"web".parse().unwrap(), &env),
            to_strings(&[
                "docker",
                "create",
                "--name",
                "web",
                "--env",
                "TZ=Europe/Paris",
                "--network",
                "frontend",
                "--publish",
                "8080:80",
                "--restart",
                "on-failure:3",
                "--health-cmd",
                "curl -f http://localhost || exit 1",
                "--health-interval",
                "30s",
                "--health-retries",
                "3",
                "--init",
                "nginx:1.27",
                "nginx",
                "-g",
                "daemon off;",
            ])
        );
        assert_eq!(
            config
                .additional_networks()
                .iter()
                .map(NetworkName::as_str)
                .collect::<Vec<_>>(),
            vec!["backend"]
        );
    }

    #[test]
    fn health_check_durations_follow_go_syntax() {
        let nanos = |spec: &str| {
            spec.parse::<HealthDuration>()
                .map(|duration| duration.nanos())
        };
        assert_eq!(nanos("30s").unwrap(), 30_000_000_000);
        assert_eq!(nanos("1m30s").unwrap(), 90_000_000_000);
        assert_eq!(nanos("500ms").unwrap(), 500_000_000);
        assert_eq!(nanos("1.5s").unwrap(), 1_500_000_000);
        assert_eq!(nanos("2h").unwrap(), 7_200_000_000_000);
        assert_eq!(nanos("100us").unwrap(), 100_000);
        assert_eq!("30s".parse::<HealthDuration>().unwrap().to_string(), "30s");
        for rejected in ["", "30", "lots", "0s", "-5s", "1x", "s", "1.2.3s"] {
            assert!(
                nanos(rejected).is_err(),
                "should be rejected: {:?}",
                rejected
            );
        }

        assert!("".parse::<HealthCheckTest>().is_err());
        assert!("  ".parse::<HealthCheckTest>().is_err());
        assert_eq!(
            "curl -f http://localhost || exit 1"
                .parse::<HealthCheckTest>()
                .unwrap()
                .to_string(),
            "curl -f http://localhost || exit 1"
        );
    }

    #[test]
    fn health_check_drift_is_detected() {
        let config = DockerContainerConfig::new("nginx".parse().unwrap()).with_health_check(
            HealthCheck::new("curl -f http://localhost || exit 1".parse().unwrap())
                .with_interval("30s".parse().unwrap())
                .with_timeout("5s".parse().unwrap())
                .with_start_period("10m".parse().unwrap())
                .with_retries(5),
        );

        // No health check on the container: every managed field drifts
        let inspect = serde_json::json!({ "Config": { "Image": "nginx" } });
        let reasons = config.recreation_reasons(&inspect, &[]);
        assert_eq!(reasons.len(), 5, "{:?}", reasons);

        // Matching health check
        let inspect = serde_json::json!({
            "Config": {
                "Image": "nginx",
                "Healthcheck": {
                    "Test": ["CMD-SHELL", "curl -f http://localhost || exit 1"],
                    "Interval": 30000000000i64,
                    "Timeout": 5000000000i64,
                    "StartPeriod": 600000000000i64,
                    "Retries": 5
                }
            }
        });
        assert!(config.recreation_reasons(&inspect, &[]).is_empty());

        // Drifted retries
        let mut inspect = inspect;
        inspect["Config"]["Healthcheck"]["Retries"] = 3.into();
        let reasons = config.recreation_reasons(&inspect, &[]);
        assert_eq!(reasons.len(), 1, "{:?}", reasons);
        assert!(reasons[0].contains("retries"), "{:?}", reasons);

        // Only the fields set are compared (the daemon defaults are not managed)
        let minimal = DockerContainerConfig::new("nginx".parse().unwrap()).with_health_check(
            HealthCheck::new("curl -f http://localhost || exit 1".parse().unwrap()),
        );
        assert!(minimal.recreation_reasons(&inspect, &[]).is_empty());
    }

    #[test]
    fn choice_methods_match_the_explicit_enums() {
        let new = || DockerContainerConfig::new("nginx:1.27".parse().unwrap());

        assert_eq!(
            new().with_pull_never(),
            new().with_pull_policy(PullPolicy::Never)
        );
        assert_eq!(
            new().with_pull_never().with_pull_if_missing(),
            new().with_pull_policy(PullPolicy::Missing)
        );

        for (config, policy) in [
            (new().with_restart_never(), RestartPolicy::No),
            (new().with_restart_always(), RestartPolicy::Always),
            (
                new().with_restart_unless_stopped(),
                RestartPolicy::UnlessStopped,
            ),
            (
                new().with_restart_on_failure(3),
                RestartPolicy::OnFailure(3),
            ),
        ] {
            assert_eq!(config, new().with_restart_policy(policy));
        }

        assert_eq!(
            new().with_host_networking(),
            new().with_networking(DockerNetworking::Host)
        );
        assert_eq!(
            new().with_isolated_networking(),
            new().with_networking(DockerNetworking::Isolated)
        );
        let attached = DockerNetworking::attached(
            Some(
                NetworkList::try_from(vec![
                    "frontend".parse().unwrap(),
                    "backend".parse().unwrap(),
                ])
                .unwrap(),
            ),
            Some(vec![
                "8080:80".parse().unwrap(),
                "127.0.0.1:8443:443".parse().unwrap(),
            ]),
        );
        assert_eq!(
            new()
                .with_network("frontend".parse().unwrap())
                .with_published_port("8080:80".parse().unwrap())
                .with_network("backend".parse().unwrap())
                .with_published_port("127.0.0.1:8443:443".parse().unwrap()),
            new().with_networking(attached.clone())
        );
        // Attaching a network or publishing a port replaces Host or Isolated networking...
        assert_eq!(
            new()
                .with_host_networking()
                .with_published_port("8080:80".parse().unwrap()),
            new().with_networking(DockerNetworking::attached(
                None,
                Some(vec!["8080:80".parse().unwrap()])
            ))
        );
        assert_eq!(
            new()
                .with_isolated_networking()
                .with_network("frontend".parse().unwrap()),
            new().with_networking(DockerNetworking::attached(
                Some(NetworkList::try_from(vec!["frontend".parse().unwrap()]).unwrap()),
                None
            ))
        );
        // ...and Host or Isolated networking replaces the networks and ports
        assert_eq!(
            new().with_networking(attached).with_host_networking(),
            new().with_networking(DockerNetworking::Host)
        );

        assert_eq!(new().with_all_gpus(), new().with_gpus(GpuSelection::All));
        let devices = GpuSelection::Devices(
            GpuList::try_from(vec!["0".parse().unwrap(), "1".parse().unwrap()]).unwrap(),
        );
        assert_eq!(
            new()
                .with_gpu_device("0".parse().unwrap())
                .with_gpu_device("1".parse().unwrap()),
            new().with_gpus(devices.clone())
        );
        assert_eq!(
            new()
                .with_all_gpus()
                .with_gpu_device("0".parse().unwrap())
                .with_gpu_device("1".parse().unwrap()),
            new().with_gpus(devices)
        );
        assert_eq!(
            new().with_gpu_device("0".parse().unwrap()).with_all_gpus(),
            new().with_gpus(GpuSelection::All)
        );

        let shm_size = || "16g".parse::<MemorySize>().unwrap();
        let own = || PrivateIpc::new().with_shm_size(shm_size());
        assert_eq!(new().with_host_ipc(), new().with_ipc(IpcNamespace::Host));
        assert_eq!(
            new().with_private_ipc(),
            new().with_ipc(IpcNamespace::Private(PrivateIpc::new()))
        );
        assert_eq!(
            new().with_shareable_ipc(),
            new().with_ipc(IpcNamespace::Shareable(PrivateIpc::new()))
        );
        assert_eq!(
            new().with_shm_size(shm_size()),
            new().with_ipc(IpcNamespace::Private(own()))
        );
        // The /dev/shm size replaces the host namespace, and is kept between own namespaces
        assert_eq!(
            new().with_host_ipc().with_shm_size(shm_size()),
            new().with_ipc(IpcNamespace::Private(own()))
        );
        assert_eq!(
            new().with_shareable_ipc().with_shm_size(shm_size()),
            new().with_ipc(IpcNamespace::Shareable(own()))
        );
        assert_eq!(
            new().with_shm_size(shm_size()).with_shareable_ipc(),
            new().with_ipc(IpcNamespace::Shareable(own()))
        );
        assert_eq!(
            new().with_shm_size(shm_size()).with_host_ipc(),
            new().with_ipc(IpcNamespace::Host)
        );
    }
}
