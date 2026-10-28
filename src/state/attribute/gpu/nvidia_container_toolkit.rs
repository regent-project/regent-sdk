//! NVIDIA Container Toolkit attribute
//!
//! This module provides the `NvidiaContainerToolkitExpectedState` type for installing the
//! [NVIDIA Container Toolkit](https://docs.nvidia.com/datacenter/cloud-native/container-toolkit/latest/install-guide.html)
//! from NVIDIA's repository (`https://nvidia.github.io/libnvidia-container/stable/`) and setting up
//! what GPU containers need on the host: the `nvidia` runtime of Docker, containerd and CRI-O,
//! and the CDI (Container Device Interface) specification used by Podman
//! (`podman run --device nvidia.com/gpu=all ...`).
//!
//! The toolkit also installs `nvidia-container-cli` (`libnvidia-container-tools`), which is what
//! the Enroot GPU hook relies on.
//!
//! **Compatible OS:** Linux distributions based on `apt-get`, `dnf` or `zypper` (detected from
//! `/etc/os-release` at assessment time, like the `NvidiaDriver` attribute).
//!
//! **Privilege:** installing packages and configuring the engines needs root, use `!WithSudo`.
//! Rootless Docker (`~/.config/docker/daemon.json`) is not managed.
//!
//! The NVIDIA driver itself is managed by the [`NvidiaDriver`](super::nvidia_driver) attribute:
//! place it before this one.
//!
//! # Invalid states are unrepresentable
//!
//! - The toolkit configuration only exists in the `Present` state: an `Absent` toolkit has
//!   nothing to configure.
//! - Runtimes are a set of known engines: an engine can't be listed twice nor be misspelled.
//! - The version is a full package version (`<major>.<minor>.<patch>-<release>`, e.g. `1.20.1-1`),
//!   as needed to pin the four toolkit packages to the same version.
//! - The automatic CDI specification refresh only exists from toolkit 1.18.0 on: `Cdi: Automatic`
//!   can't be combined with an older `Version`.
//!
//! # How compliance is assessed
//!
//! 1. The NVIDIA Container Toolkit repository must be configured (`nvidia-container-toolkit.list`
//!    and its signing key for apt, `nvidia-container-toolkit.repo` for dnf and zypper). It is never
//!    removed by this attribute.
//! 2. `nvidia-container-toolkit` must be installed. With `Version`, each of the four toolkit
//!    packages (`nvidia-container-toolkit`, `nvidia-container-toolkit-base`,
//!    `libnvidia-container-tools`, `libnvidia-container1`) must be installed in that version: the
//!    ones in another version are upgraded or downgraded. Without it, the toolkit is installed
//!    once and not upgraded afterwards.
//! 3. Each engine of `Runtimes` must know the `nvidia` runtime: `runtimes.nvidia` in
//!    `/etc/docker/daemon.json` for Docker, a runtime using `nvidia-container-runtime` in the
//!    containerd (`/etc/containerd/config.toml`, `/etc/containerd/conf.d/`) or CRI-O
//!    (`/etc/crio/`) configuration. If not, `nvidia-ctk runtime configure --runtime=<engine>` is
//!    run, then the engine is restarted if it is running, which restarts its containers. Engines
//!    left out of `Runtimes` are not managed.
//! 4. `Cdi`, if set, manages the CDI specification of the GPUs. It embeds the paths of the
//!    driver libraries, which contain the driver version, so it must be generated again when the
//!    driver changes. The specification is current when it declares `nvidia.com/gpu` devices and
//!    mentions the version of the loaded driver (`/proc/driver/nvidia/version`).
//!    - `Automatic` (toolkit 1.18.0+): the `nvidia-cdi-refresh` systemd units generate
//!      `/var/run/cdi/nvidia.yaml` at boot and when the driver or toolkit is installed or
//!      upgraded. They must be enabled, and the specification current (it is refreshed if not).
//!    - `Static`: `/etc/cdi/nvidia.yaml` is generated with `nvidia-ctk cdi generate`. The
//!      automatic refresh is disabled and its `/var/run/cdi/nvidia.yaml` removed, as it would
//!      take precedence over `/etc/cdi`.
//!
//!    The driver must be loaded to generate the specification: if it isn't, the remediation
//!    fails and says so. MIG reconfigurations are not detected: regenerate the specification
//!    after them.
//!
//! `Absent` removes the four toolkit packages, but keeps the repository, the engine
//! configurations (which then point to a missing `nvidia-container-runtime`) and the CDI
//! specifications.
//!
//! **Prerequisites:** `curl` (or `wget`) and, for apt, `gpg` to install the repository key.
//!
//! # Examples
//!
//! ## Rust API
//!
//! ```no_run
//! use regent_sdk::state::attribute::gpu::nvidia_container_toolkit::{
//!     NvidiaContainerToolkitConfig, NvidiaContainerToolkitExpectedState,
//! };
//! use regent_sdk::{Attribute, ExpectedState, Privilege, RegentError};
//!
//! fn gpu_containers() -> Result<ExpectedState, RegentError> {
//!     let config = NvidiaContainerToolkitConfig::new()
//!         .with_version("1.20.1-1".parse()?)?
//!         .with_docker_runtime() // | with_containerd_runtime() | with_crio_runtime()
//!         .with_automatic_cdi()?; // toolkit 1.18+ | with_static_cdi()
//!
//!     Ok(ExpectedState::new()
//!         .with_attribute(Attribute::nvidia_container_toolkit(
//!             NvidiaContainerToolkitExpectedState::present(config),
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
//!   - Name: NVIDIA Container Toolkit must be installed
//!     Privilege: !WithSudo
//!     Detail: !NvidiaContainerToolkit
//!       State: !Present
//!         Version: 1.20.1-1                # optional, pins the toolkit packages
//!         Runtimes: [Docker, Containerd]   # Docker | Containerd | CriO
//!         Cdi: Automatic                   # optional: Automatic (toolkit 1.18+) | Static
//! ```
//!
//! For Podman only, the CDI specification is enough:
//!
//! ```yaml
//! Attributes:
//!   - Name: GPUs must be available to Podman
//!     Privilege: !WithSudo
//!     Detail: !NvidiaContainerToolkit
//!       State: !Present
//!         Cdi: Static
//! ```
//!
//! To remove the toolkit:
//!
//! ```yaml
//! Attributes:
//!   - Name: NVIDIA Container Toolkit must be removed
//!     Privilege: !WithSudo
//!     Detail: !NvidiaContainerToolkit
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
use crate::state::attribute::container::container_spec::quoted_command;
use crate::state::compliance::AttributeComplianceAssessment;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::cmp::Ordering;
use std::collections::BTreeSet;
use std::fmt;
use std::str::FromStr;
use std::time::Duration;

use crate::attribute::shared::{
    PackageFamily, UnitEnablement, add_repo_file, check_linux_host, download, host_package_family,
    installed_packages, is_repository_configured, is_success, loaded_driver, make_temp_dir, query,
    remove_temp_dir, run_step, run_steps, unit_state,
};
use std::collections::BTreeMap;

const ATTRIBUTE: &str = "NvidiaContainerToolkit";

/// Packages of the toolkit, all pinned to the same version
const TOOLKIT_PACKAGES: [&str; 4] = [
    "nvidia-container-toolkit",
    "nvidia-container-toolkit-base",
    "libnvidia-container-tools",
    "libnvidia-container1",
];

const REPOSITORY_URL_FRAGMENT: &str = "nvidia.github.io/libnvidia-container";
const GPG_KEY_URL: &str = "https://nvidia.github.io/libnvidia-container/gpgkey";
const APT_LIST_URL: &str =
    "https://nvidia.github.io/libnvidia-container/stable/deb/nvidia-container-toolkit.list";
const RPM_REPO_URL: &str =
    "https://nvidia.github.io/libnvidia-container/stable/rpm/nvidia-container-toolkit.repo";
const APT_KEYRING: &str = "/usr/share/keyrings/nvidia-container-toolkit-keyring.gpg";
const APT_LIST: &str = "/etc/apt/sources.list.d/nvidia-container-toolkit.list";

/// CDI specification generated by the nvidia-cdi-refresh units
const AUTOMATIC_CDI_SPEC: &str = "/var/run/cdi/nvidia.yaml";
/// CDI specification generated by this attribute
const STATIC_CDI_SPEC: &str = "/etc/cdi/nvidia.yaml";
const CDI_REFRESH_PATH_UNIT: &str = "nvidia-cdi-refresh.path";
const CDI_REFRESH_SERVICE_UNIT: &str = "nvidia-cdi-refresh.service";

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[serde(rename_all = "PascalCase")]
pub struct NvidiaContainerToolkitExpectedState {
    state: NvidiaContainerToolkitState,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub enum NvidiaContainerToolkitState {
    /// Toolkit installed with this configuration
    Present(Box<NvidiaContainerToolkitConfig>),
    Absent,
}

impl NvidiaContainerToolkitExpectedState {
    pub fn present(config: NvidiaContainerToolkitConfig) -> Self {
        Self {
            state: NvidiaContainerToolkitState::Present(Box::new(config)),
        }
    }

    pub fn absent() -> Self {
        Self {
            state: NvidiaContainerToolkitState::Absent,
        }
    }
}

/// Optional fields left out are not managed.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(try_from = "NvidiaContainerToolkitConfigFields")]
#[serde(rename_all = "PascalCase")]
pub struct NvidiaContainerToolkitConfig {
    version: Option<ToolkitVersion>,
    /// Container engines which must know the `nvidia` runtime
    runtimes: BTreeSet<ContainerRuntime>,
    cdi: Option<CdiMode>,
}

/// Fields of [`NvidiaContainerToolkitConfig`] before their consistency is checked
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
#[serde(rename_all = "PascalCase")]
struct NvidiaContainerToolkitConfigFields {
    version: Option<ToolkitVersion>,
    #[serde(default)]
    runtimes: BTreeSet<ContainerRuntime>,
    cdi: Option<CdiMode>,
}

impl TryFrom<NvidiaContainerToolkitConfigFields> for NvidiaContainerToolkitConfig {
    type Error = RegentError;

    fn try_from(fields: NvidiaContainerToolkitConfigFields) -> Result<Self, Self::Error> {
        let config = Self {
            version: fields.version,
            runtimes: fields.runtimes,
            cdi: fields.cdi,
        };
        config.validated()
    }
}

impl NvidiaContainerToolkitConfig {
    /// Latest toolkit, no runtime and no CDI specification managed
    pub fn new() -> Self {
        Self::default()
    }

    /// Pin the toolkit packages to this version
    pub fn with_version(mut self, version: ToolkitVersion) -> Result<Self, RegentError> {
        self.version = Some(version);
        self.validated()
    }

    /// Configure the `nvidia` runtime of this engine
    pub fn with_runtime(mut self, runtime: ContainerRuntime) -> Self {
        self.runtimes.insert(runtime);
        self
    }

    pub fn with_docker_runtime(self) -> Self {
        self.with_runtime(ContainerRuntime::Docker)
    }

    pub fn with_containerd_runtime(self) -> Self {
        self.with_runtime(ContainerRuntime::Containerd)
    }

    pub fn with_crio_runtime(self) -> Self {
        self.with_runtime(ContainerRuntime::CriO)
    }

    pub fn with_cdi(mut self, cdi: CdiMode) -> Result<Self, RegentError> {
        self.cdi = Some(cdi);
        self.validated()
    }

    /// Keep the CDI specification current with the `nvidia-cdi-refresh` units: needs the
    /// toolkit 1.18.0 or later
    pub fn with_automatic_cdi(self) -> Result<Self, RegentError> {
        self.with_cdi(CdiMode::Automatic)
    }

    /// Generate the CDI specification with `nvidia-ctk cdi generate`, automatic refresh
    /// disabled (any toolkit version)
    pub fn with_static_cdi(mut self) -> Self {
        self.cdi = Some(CdiMode::Static);
        self
    }

    fn validated(self) -> Result<Self, RegentError> {
        if let (Some(CdiMode::Automatic), Some(version)) = (&self.cdi, &self.version)
            && !version.has_automatic_cdi_refresh()
        {
            return Err(RegentError::IncoherentExpectedState(format!(
                "Cdi: Automatic needs the nvidia-cdi-refresh units of the toolkit 1.18.0 or later, but Version is {}: use Cdi: Static",
                version
            )));
        }
        Ok(self)
    }
}

/// Container engine whose `nvidia` runtime is configured with `nvidia-ctk runtime configure`
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub enum ContainerRuntime {
    Docker,
    Containerd,
    CriO,
}

impl ContainerRuntime {
    /// Value of `nvidia-ctk runtime configure --runtime`
    fn ctk_name(&self) -> &'static str {
        match self {
            ContainerRuntime::Docker => "docker",
            ContainerRuntime::Containerd => "containerd",
            ContainerRuntime::CriO => "crio",
        }
    }

    /// systemd service of the engine
    fn service(&self) -> &'static str {
        self.ctk_name()
    }

    /// Command printing what [`has_nvidia_runtime`](Self::has_nvidia_runtime) inspects: the
    /// Docker configuration, or the configuration lines of containerd and CRI-O mentioning
    /// `nvidia-container-runtime`. Missing files make it fail: only the output matters.
    fn config_command(&self) -> String {
        match self {
            ContainerRuntime::Docker => quoted_command(&["cat", "/etc/docker/daemon.json"]),
            ContainerRuntime::Containerd => quoted_command(&[
                "grep",
                "-rhsF",
                "nvidia-container-runtime",
                "/etc/containerd/config.toml",
                "/etc/containerd/conf.d",
            ]),
            ContainerRuntime::CriO => quoted_command(&[
                "grep",
                "-rhsF",
                "nvidia-container-runtime",
                "/etc/crio/crio.conf",
                "/etc/crio/crio.conf.d",
                "/etc/crio/conf.d",
            ]),
        }
    }

    fn has_nvidia_runtime(&self, config: &str) -> bool {
        match self {
            ContainerRuntime::Docker => serde_json::from_str::<Value>(config)
                .ok()
                .and_then(|config| config.pointer("/runtimes/nvidia").cloned())
                .is_some(),
            ContainerRuntime::Containerd | ContainerRuntime::CriO => config
                .lines()
                .map(str::trim)
                .filter(|line| !line.starts_with('#'))
                .any(|line| line.contains("nvidia-container-runtime")),
        }
    }
}

impl fmt::Display for ContainerRuntime {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ContainerRuntime::Docker => write!(f, "Docker"),
            ContainerRuntime::Containerd => write!(f, "containerd"),
            ContainerRuntime::CriO => write!(f, "CRI-O"),
        }
    }
}

/// How the CDI specification of the GPUs is generated
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub enum CdiMode {
    /// `nvidia-cdi-refresh` systemd units (toolkit 1.18.0+), `/var/run/cdi/nvidia.yaml`
    Automatic,
    /// `nvidia-ctk cdi generate`, `/etc/cdi/nvidia.yaml`, automatic refresh disabled
    Static,
}

impl CdiMode {
    fn spec_path(&self) -> &'static str {
        match self {
            CdiMode::Automatic => AUTOMATIC_CDI_SPEC,
            CdiMode::Static => STATIC_CDI_SPEC,
        }
    }
}

/// Whether a CDI specification is current: it declares GPUs and mentions the loaded driver
/// version (the driver libraries it lists are named after it)
fn is_cdi_spec_current(spec: &str, driver_version: Option<&str>) -> bool {
    let declares_gpus = spec.lines().any(|line| {
        let line = line.trim();
        line.starts_with("kind:") && line.contains("nvidia.com/gpu")
    });
    declares_gpus && driver_version.is_some_and(|version| spec.contains(version))
}

/// Toolkit package version: `<major>.<minor>.<patch>-<release>` (e.g. `1.20.1-1`)
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct ToolkitVersion {
    major: u32,
    minor: u32,
    patch: u32,
    release: String,
}

impl TryFrom<String> for ToolkitVersion {
    type Error = RegentError;

    fn try_from(text: String) -> Result<Self, Self::Error> {
        let invalid = || {
            RegentError::IncoherentExpectedState(format!(
                "Invalid NVIDIA Container Toolkit version {:?}: expected <major>.<minor>.<patch>-<release> such as 1.20.1-1",
                text
            ))
        };
        let (upstream, release) = text.split_once('-').ok_or_else(invalid)?;
        let numbers: Vec<u32> = upstream
            .split('.')
            .map(|part| {
                (!part.is_empty() && part.chars().all(|c| c.is_ascii_digit()))
                    .then(|| part.parse().ok())
                    .flatten()
            })
            .collect::<Option<Vec<u32>>>()
            .ok_or_else(invalid)?;
        let is_valid_release = release.starts_with(|c: char| c.is_ascii_digit())
            && release
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '~');
        match numbers[..] {
            [major, minor, patch] if is_valid_release => Ok(Self {
                major,
                minor,
                patch,
                release: release.to_string(),
            }),
            _ => Err(invalid()),
        }
    }
}

impl FromStr for ToolkitVersion {
    type Err = RegentError;

    fn from_str(text: &str) -> Result<Self, Self::Err> {
        Self::try_from(text.to_string())
    }
}

impl From<ToolkitVersion> for String {
    fn from(version: ToolkitVersion) -> String {
        version.to_string()
    }
}

impl fmt::Display for ToolkitVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}.{}.{}-{}",
            self.major, self.minor, self.patch, self.release
        )
    }
}

impl ToolkitVersion {
    fn has_automatic_cdi_refresh(&self) -> bool {
        (self.major, self.minor) >= (1, 18)
    }

    /// Order with an installed package version (`1.20.1-1`, possibly with an epoch)
    fn compare_with_installed(&self, installed: &str) -> Option<Ordering> {
        let installed: ToolkitVersion = installed
            .split_once(':')
            .map_or(installed, |(_, version)| version)
            .parse()
            .ok()?;
        let release_key = |release: &str| {
            release
                .split(|c: char| !c.is_ascii_digit())
                .next()
                .and_then(|number| number.parse::<u64>().ok())
                .unwrap_or_default()
        };
        Some(
            (
                self.major,
                self.minor,
                self.patch,
                release_key(&self.release),
            )
                .cmp(&(
                    installed.major,
                    installed.minor,
                    installed.patch,
                    release_key(&installed.release),
                )),
        )
    }

    /// Package specification pinning `package` to this version
    fn package_spec(&self, package: &str, family: PackageFamily) -> String {
        match family {
            PackageFamily::Apt => format!("{}={}", package, self),
            PackageFamily::Dnf | PackageFamily::Zypper => format!("{}-{}", package, self),
        }
    }

    /// Toolkit packages to install or upgrade, and to downgrade, to reach this version
    fn packages_to_change(
        &self,
        installed: &BTreeMap<String, String>,
    ) -> (Vec<String>, Vec<String>) {
        let mut upgrades = Vec::new();
        let mut downgrades = Vec::new();
        for package in TOOLKIT_PACKAGES {
            let ordering = installed
                .get(package)
                .map(|installed| self.compare_with_installed(installed));
            match ordering {
                Some(Some(Ordering::Equal)) => {}
                Some(Some(Ordering::Less)) => downgrades.push(package.to_string()),
                _ => upgrades.push(package.to_string()),
            }
        }
        (upgrades, downgrades)
    }
}

async fn setup_repository<Handler: HostHandler>(
    host_handler: &mut Handler,
    family: PackageFamily,
    privilege: &Privilege,
) -> Result<InternalApiCallOutcome, RegentError> {
    if family != PackageFamily::Apt {
        return add_repo_file(
            host_handler,
            family,
            RPM_REPO_URL,
            "nvidia-container-toolkit.repo",
            privilege,
        )
        .await;
    }
    let tmp = match make_temp_dir(host_handler, privilege).await? {
        Ok(tmp) => tmp,
        Err(failure) => return Ok(failure),
    };
    let key = format!("{}/gpgkey", tmp);
    let list = format!("{}/list", tmp);
    let mut outcome = download(host_handler, GPG_KEY_URL, &key, privilege).await;
    if is_success(&outcome) {
        outcome = download(host_handler, APT_LIST_URL, &list, privilege).await;
    }
    if is_success(&outcome) {
        outcome = run_steps(
            host_handler,
            &apt_repository_commands(&key, &list),
            privilege,
        )
        .await;
    }
    remove_temp_dir(host_handler, &tmp, privilege).await;
    Ok(outcome)
}

/// Commands installing the downloaded key and list of the apt repository
fn apt_repository_commands(key: &str, list: &str) -> Vec<String> {
    vec![
        quoted_command(&[
            "gpg",
            "--batch",
            "--yes",
            "--dearmor",
            "-o",
            APT_KEYRING,
            key,
        ]),
        quoted_command(&[
            "sed",
            "-i",
            &format!("s#deb https://#deb [signed-by={}] https://#g", APT_KEYRING),
            list,
        ]),
        quoted_command(&["install", "-m", "0644", list, APT_LIST]),
        quoted_command(&["apt-get", "update"]),
    ]
}

/// Failure message when a CDI specification is requested without a loaded driver
fn driver_not_loaded_message() -> String {
    "The NVIDIA driver is not loaded: the CDI specification can't be generated (install and load it first, see the NvidiaDriver attribute)".to_string()
}

impl Timeout for NvidiaContainerToolkitExpectedState {
    fn default_timeout(&self) -> Duration {
        Duration::from_secs(600)
    }
}

impl Check for NvidiaContainerToolkitExpectedState {
    fn check(&self) -> Result<(), RegentError> {
        // Every value is validated when its type is built: an existing
        // NvidiaContainerToolkitExpectedState is valid
        Ok(())
    }

    fn check_host_compatibility(
        &self,
        host_properties: &HostProperties,
    ) -> Result<(), RegentError> {
        check_linux_host(host_properties, ATTRIBUTE)
    }
}

impl<Handler: HostHandler> AssessCompliance<Handler> for NvidiaContainerToolkitExpectedState {
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
                "the distribution (/etc/os-release) is not based on apt-get, dnf or zypper: the NVIDIA Container Toolkit can't be installed".to_string(),
            ));
        };

        let mut remediations: Vec<Remediation> = Vec::new();
        let mut push = |api_call: NvidiaContainerToolkitInternalApiCall| {
            remediations.push(Remediation::NvidiaContainerToolkit(
                NvidiaContainerToolkitApiCall::from(api_call, privilege.clone()),
            ));
        };

        let installed =
            installed_packages(host_handler, family, &TOOLKIT_PACKAGES, privilege).await?;

        match &self.state {
            NvidiaContainerToolkitState::Absent => {
                if !installed.is_empty() {
                    push(NvidiaContainerToolkitInternalApiCall::RemovePackages {
                        family,
                        packages: installed.into_keys().collect(),
                    });
                }
            }
            NvidiaContainerToolkitState::Present(config) => {
                if !is_repository_configured(
                    host_handler,
                    family,
                    REPOSITORY_URL_FRAGMENT,
                    privilege,
                )
                .await?
                {
                    push(NvidiaContainerToolkitInternalApiCall::AddRepository(family));
                }

                let installed_version = installed.get(TOOLKIT_PACKAGES[0]);
                let (upgrades, downgrades) = match &config.version {
                    Some(version) => version.packages_to_change(&installed),
                    None if installed_version.is_none() => {
                        (vec![TOOLKIT_PACKAGES[0].to_string()], Vec::new())
                    }
                    None => (Vec::new(), Vec::new()),
                };
                let is_installing = !upgrades.is_empty() || !downgrades.is_empty();
                if is_installing {
                    push(NvidiaContainerToolkitInternalApiCall::Install {
                        family,
                        version: config.version.clone(),
                        upgrades,
                        downgrades,
                    });
                }

                for runtime in &config.runtimes {
                    let result = query(host_handler, &runtime.config_command(), privilege).await?;
                    if !runtime.has_nvidia_runtime(&result.stdout) {
                        push(NvidiaContainerToolkitInternalApiCall::ConfigureRuntime(
                            *runtime,
                        ));
                    }
                }

                if let Some(cdi) = config.cdi {
                    let driver_version = loaded_driver(host_handler, privilege)
                        .await?
                        .map(|driver| driver.version);
                    let spec = query(
                        host_handler,
                        &quoted_command(&["cat", cdi.spec_path()]),
                        privilege,
                    )
                    .await?;
                    let is_spec_current = spec.return_code == 0
                        && is_cdi_spec_current(&spec.stdout, driver_version.as_deref());
                    let refresh =
                        unit_state(host_handler, CDI_REFRESH_PATH_UNIT, privilege).await?;

                    match cdi {
                        CdiMode::Automatic => {
                            if !is_installing && !refresh.exists() {
                                return Ok(AttributeComplianceAssessment::NonCompliantFatal(
                                    format!(
                                        "the installed NVIDIA Container Toolkit ({}) has no {} unit (toolkit 1.18.0 or later): use Cdi: Static or a newer Version",
                                        installed_version.cloned().unwrap_or_default(),
                                        CDI_REFRESH_PATH_UNIT
                                    ),
                                ));
                            }
                            let is_refresh_enabled = matches!(
                                refresh.enablement,
                                UnitEnablement::Enabled | UnitEnablement::Static
                            );
                            if !(is_refresh_enabled && refresh.active && is_spec_current) {
                                push(NvidiaContainerToolkitInternalApiCall::RefreshCdiSpec);
                            }
                        }
                        CdiMode::Static => {
                            let automatic_spec = query(
                                host_handler,
                                &quoted_command(&["test", "-e", AUTOMATIC_CDI_SPEC]),
                                privilege,
                            )
                            .await?;
                            if refresh.enablement == UnitEnablement::Enabled
                                || refresh.active
                                || automatic_spec.return_code == 0
                            {
                                push(NvidiaContainerToolkitInternalApiCall::DisableCdiRefresh);
                            }
                            if !is_spec_current {
                                push(NvidiaContainerToolkitInternalApiCall::GenerateCdiSpec);
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
pub enum NvidiaContainerToolkitInternalApiCall {
    /// Configure the NVIDIA Container Toolkit repository
    AddRepository(PackageFamily),
    /// Install the toolkit: the latest one, or its packages pinned to `version` (upgraded or
    /// installed, and downgraded)
    Install {
        family: PackageFamily,
        version: Option<ToolkitVersion>,
        upgrades: Vec<String>,
        downgrades: Vec<String>,
    },
    RemovePackages {
        family: PackageFamily,
        packages: Vec<String>,
    },
    /// `nvidia-ctk runtime configure`, then restart the engine if it is running
    ConfigureRuntime(ContainerRuntime),
    /// Enable the nvidia-cdi-refresh units and refresh `/var/run/cdi/nvidia.yaml`
    RefreshCdiSpec,
    /// Disable the nvidia-cdi-refresh units and remove `/var/run/cdi/nvidia.yaml`
    DisableCdiRefresh,
    /// Generate `/etc/cdi/nvidia.yaml`
    GenerateCdiSpec,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct NvidiaContainerToolkitApiCall {
    pub api_call: NvidiaContainerToolkitInternalApiCall,
    privilege: Privilege,
}

impl NvidiaContainerToolkitApiCall {
    pub fn display(&self) -> String {
        match &self.api_call {
            NvidiaContainerToolkitInternalApiCall::AddRepository(family) => {
                format!("Add the NVIDIA Container Toolkit repository ({})", family)
            }
            NvidiaContainerToolkitInternalApiCall::Install {
                version: Some(version),
                upgrades,
                downgrades,
                ..
            } => format!(
                "Install the NVIDIA Container Toolkit {}: {}",
                version,
                upgrades
                    .iter()
                    .map(|package| format!("install or upgrade {}", package))
                    .chain(
                        downgrades
                            .iter()
                            .map(|package| format!("downgrade {}", package))
                    )
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
            NvidiaContainerToolkitInternalApiCall::Install { version: None, .. } => {
                "Install the NVIDIA Container Toolkit".to_string()
            }
            NvidiaContainerToolkitInternalApiCall::RemovePackages { packages, .. } => {
                format!("Remove {}", packages.join(", "))
            }
            NvidiaContainerToolkitInternalApiCall::ConfigureRuntime(runtime) => format!(
                "Configure the nvidia runtime of {} and restart it if running",
                runtime
            ),
            NvidiaContainerToolkitInternalApiCall::RefreshCdiSpec => format!(
                "Enable the automatic CDI specification refresh and regenerate {}",
                AUTOMATIC_CDI_SPEC
            ),
            NvidiaContainerToolkitInternalApiCall::DisableCdiRefresh => format!(
                "Disable the automatic CDI specification refresh and remove {}",
                AUTOMATIC_CDI_SPEC
            ),
            NvidiaContainerToolkitInternalApiCall::GenerateCdiSpec => {
                format!("Generate the CDI specification {}", STATIC_CDI_SPEC)
            }
        }
    }

    fn from(
        api_call: NvidiaContainerToolkitInternalApiCall,
        privilege: Privilege,
    ) -> NvidiaContainerToolkitApiCall {
        NvidiaContainerToolkitApiCall {
            api_call,
            privilege,
        }
    }

    /// Commands of the remediations which don't need to inspect the host
    fn commands(&self) -> Vec<String> {
        match &self.api_call {
            NvidiaContainerToolkitInternalApiCall::Install {
                family,
                version,
                upgrades,
                downgrades,
            } => {
                let specs = |packages: &[String]| -> Vec<String> {
                    packages
                        .iter()
                        .map(|package| match version {
                            Some(version) => version.package_spec(package, *family),
                            None => package.clone(),
                        })
                        .collect()
                };
                let mut commands = Vec::new();
                if *family == PackageFamily::Apt {
                    commands.push(quoted_command(&["apt-get", "update"]));
                }
                if !upgrades.is_empty() {
                    commands.push(family.install_command(&specs(upgrades), false));
                }
                if !downgrades.is_empty() {
                    commands.push(family.install_command(&specs(downgrades), true));
                }
                commands
            }
            NvidiaContainerToolkitInternalApiCall::RemovePackages { family, packages } => {
                vec![family.remove_command(packages)]
            }
            NvidiaContainerToolkitInternalApiCall::RefreshCdiSpec => vec![
                quoted_command(&["systemctl", "enable", "--now", CDI_REFRESH_PATH_UNIT]),
                quoted_command(&["systemctl", "enable", CDI_REFRESH_SERVICE_UNIT]),
                quoted_command(&["systemctl", "restart", CDI_REFRESH_SERVICE_UNIT]),
            ],
            NvidiaContainerToolkitInternalApiCall::GenerateCdiSpec => vec![
                quoted_command(&["mkdir", "-p", "/etc/cdi"]),
                quoted_command(&[
                    "nvidia-ctk",
                    "cdi",
                    "generate",
                    &format!("--output={}", STATIC_CDI_SPEC),
                ]),
            ],
            NvidiaContainerToolkitInternalApiCall::AddRepository(_)
            | NvidiaContainerToolkitInternalApiCall::ConfigureRuntime(_)
            | NvidiaContainerToolkitInternalApiCall::DisableCdiRefresh => Vec::new(),
        }
    }
}

impl Timeout for NvidiaContainerToolkitApiCall {
    fn default_timeout(&self) -> Duration {
        match &self.api_call {
            NvidiaContainerToolkitInternalApiCall::Install { .. }
            | NvidiaContainerToolkitInternalApiCall::AddRepository(_) => Duration::from_secs(600),
            _ => Duration::from_secs(300),
        }
    }
}

impl Check for NvidiaContainerToolkitApiCall {
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

impl<Handler: HostHandler> ReachCompliance<Handler> for NvidiaContainerToolkitApiCall {
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
            NvidiaContainerToolkitInternalApiCall::AddRepository(family) => {
                return setup_repository(host_handler, *family, privilege).await;
            }
            NvidiaContainerToolkitInternalApiCall::ConfigureRuntime(runtime) => {
                return configure_runtime(host_handler, *runtime, privilege).await;
            }
            NvidiaContainerToolkitInternalApiCall::DisableCdiRefresh => {
                return disable_cdi_refresh(host_handler, privilege).await;
            }
            _ => {}
        }
        let cdi_mode = match &self.api_call {
            NvidiaContainerToolkitInternalApiCall::RefreshCdiSpec => Some(CdiMode::Automatic),
            NvidiaContainerToolkitInternalApiCall::GenerateCdiSpec => Some(CdiMode::Static),
            _ => None,
        };

        let Some(cdi_mode) = cdi_mode else {
            return Ok(run_steps(host_handler, &self.commands(), privilege).await);
        };

        // A CDI specification generated without driver would be empty
        let Some(driver) = loaded_driver(host_handler, privilege).await? else {
            return Ok(InternalApiCallOutcome::Failure(driver_not_loaded_message()));
        };
        let outcome = run_steps(host_handler, &self.commands(), privilege).await;
        if let InternalApiCallOutcome::Failure(_) = outcome {
            return Ok(outcome);
        }
        let spec = query(
            host_handler,
            &quoted_command(&["cat", cdi_mode.spec_path()]),
            privilege,
        )
        .await?;
        if spec.return_code == 0 && is_cdi_spec_current(&spec.stdout, Some(&driver.version)) {
            Ok(InternalApiCallOutcome::Success(Some(format!(
                "CDI specification {} generated for driver {}",
                cdi_mode.spec_path(),
                driver.version
            ))))
        } else {
            Ok(InternalApiCallOutcome::Failure(format!(
                "{} doesn't declare the GPUs of driver {} after its generation",
                cdi_mode.spec_path(),
                driver.version
            )))
        }
    }
}

/// `nvidia-ctk runtime configure`, then restart the engine if it is running (a missing engine
/// keeps the configuration for when it is installed)
async fn configure_runtime<Handler: HostHandler>(
    host_handler: &mut Handler,
    runtime: ContainerRuntime,
    privilege: &Privilege,
) -> Result<InternalApiCallOutcome, RegentError> {
    let outcome = run_step(
        host_handler,
        &quoted_command(&[
            "nvidia-ctk",
            "runtime",
            "configure",
            &format!("--runtime={}", runtime.ctk_name()),
        ]),
        privilege,
    )
    .await;
    if !is_success(&outcome) {
        return Ok(outcome);
    }
    if !unit_state(host_handler, runtime.service(), privilege)
        .await?
        .active
    {
        return Ok(outcome);
    }
    Ok(run_step(
        host_handler,
        &quoted_command(&["systemctl", "restart", runtime.service()]),
        privilege,
    )
    .await)
}

/// Disable and stop the nvidia-cdi-refresh units, then remove the specification they generated
async fn disable_cdi_refresh<Handler: HostHandler>(
    host_handler: &mut Handler,
    privilege: &Privilege,
) -> Result<InternalApiCallOutcome, RegentError> {
    let mut commands = Vec::new();
    for unit in [CDI_REFRESH_PATH_UNIT, CDI_REFRESH_SERVICE_UNIT] {
        let state = unit_state(host_handler, unit, privilege).await?;
        if state.enablement == UnitEnablement::Enabled {
            commands.push(quoted_command(&["systemctl", "disable", unit]));
        }
        if state.active {
            commands.push(quoted_command(&["systemctl", "stop", unit]));
        }
    }
    commands.push(quoted_command(&["rm", "-f", AUTOMATIC_CDI_SPEC]));
    Ok(run_steps(host_handler, &commands, privilege).await)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn full_yaml() -> &'static str {
        "---
State: !Present
  Version: 1.20.1-1
  Runtimes: [Docker, Containerd, CriO]
  Cdi: Automatic
"
    }

    fn full_config() -> NvidiaContainerToolkitConfig {
        let state: NvidiaContainerToolkitExpectedState = yaml_serde::from_str(full_yaml()).unwrap();
        match state.state {
            NvidiaContainerToolkitState::Present(config) => *config,
            other => panic!("unexpected state {:?}", other),
        }
    }

    fn rejection(raw: &str) -> String {
        match yaml_serde::from_str::<NvidiaContainerToolkitExpectedState>(raw) {
            Ok(state) => panic!("should be rejected: {}\nparsed as {:?}", raw, state),
            Err(error) => error.to_string(),
        }
    }

    #[test]
    fn parsing_nvidia_container_toolkit_module_block_from_yaml_str() {
        let config = full_config();
        assert_eq!(config.version.as_ref().unwrap().to_string(), "1.20.1-1");
        assert_eq!(config.runtimes.len(), 3);
        assert_eq!(config.cdi, Some(CdiMode::Automatic));

        let raw = "---
- State: Absent
- State: !Present {}
- State: !Present
    Cdi: Static
- State: !Present
    Version: 1.17.8-1
    Runtimes: [Docker]
";
        let states: Vec<NvidiaContainerToolkitExpectedState> = yaml_serde::from_str(raw).unwrap();
        assert_eq!(states[0], NvidiaContainerToolkitExpectedState::absent());
        assert_eq!(
            states[1],
            NvidiaContainerToolkitExpectedState::present(NvidiaContainerToolkitConfig::new())
        );
        assert_eq!(
            states[2],
            NvidiaContainerToolkitExpectedState::present(
                NvidiaContainerToolkitConfig::new()
                    .with_cdi(CdiMode::Static)
                    .unwrap()
            )
        );
        assert_eq!(
            states[3],
            NvidiaContainerToolkitExpectedState::present(
                NvidiaContainerToolkitConfig::new()
                    .with_version("1.17.8-1".parse().unwrap())
                    .unwrap()
                    .with_runtime(ContainerRuntime::Docker)
            )
        );
    }

    #[test]
    fn serialization_round_trip_preserves_state() {
        // Templating (Attribute::consider_context) relies on a JSON round trip
        for raw in [full_yaml(), "State: Absent\n", "State: !Present {}\n"] {
            let state: NvidiaContainerToolkitExpectedState = yaml_serde::from_str(raw).unwrap();
            let json = serde_json::to_string(&state).unwrap();
            assert_eq!(
                serde_json::from_str::<NvidiaContainerToolkitExpectedState>(&json).unwrap(),
                state,
                "{}",
                json
            );
        }
    }

    #[test]
    fn invalid_states_are_rejected_while_parsing() {
        let rejected = [
            // Configuration makes no sense for an absent toolkit
            ("State: !Absent\n  Cdi: Static\n", "expected unit"),
            // Automatic CDI refresh appeared in 1.18.0
            (
                "State: !Present\n  Version: 1.17.8-1\n  Cdi: Automatic\n",
                "1.18.0 or later",
            ),
            // The release is needed to pin the four packages
            (
                "State: !Present\n  Version: 1.20.1\n",
                "<major>.<minor>.<patch>-<release>",
            ),
            (
                "State: !Present\n  Version: latest\n",
                "<major>.<minor>.<patch>-<release>",
            ),
            (
                "State: !Present\n  Version: 1.20-1\n",
                "<major>.<minor>.<patch>-<release>",
            ),
            (
                "State: !Present\n  Version: \"1.20.1-1; rm -rf /\"\n",
                "<major>.<minor>.<patch>-<release>",
            ),
            // Unknown engines and duplicated settings
            ("State: !Present\n  Runtimes: [Podman]\n", "unknown variant"),
            ("State: !Present\n  Cdi: Dynamic\n", "unknown variant"),
            ("State: !Present\n  Runtime: [Docker]\n", "unknown field"),
        ];
        for (raw, reason) in rejected {
            let error = rejection(raw);
            assert!(
                error.contains(reason),
                "{:?} rejected for another reason: {}",
                raw,
                error
            );
        }

        // Same rules through the Rust API
        assert!(
            NvidiaContainerToolkitConfig::new()
                .with_cdi(CdiMode::Automatic)
                .unwrap()
                .with_version("1.17.8-1".parse().unwrap())
                .is_err()
        );
    }

    #[test]
    fn runtime_and_cdi_shortcuts_match_the_explicit_form() {
        let new = NvidiaContainerToolkitConfig::new;
        assert_eq!(
            new()
                .with_docker_runtime()
                .with_containerd_runtime()
                .with_crio_runtime(),
            new()
                .with_runtime(ContainerRuntime::Docker)
                .with_runtime(ContainerRuntime::Containerd)
                .with_runtime(ContainerRuntime::CriO)
        );
        assert_eq!(
            new().with_automatic_cdi().unwrap(),
            new().with_cdi(CdiMode::Automatic).unwrap()
        );
        assert_eq!(
            new().with_static_cdi(),
            new().with_cdi(CdiMode::Static).unwrap()
        );

        // The automatic refresh still needs the toolkit 1.18.0 or later
        let old_version = || new().with_version("1.17.8-1".parse().unwrap()).unwrap();
        assert!(old_version().with_automatic_cdi().is_err());
        assert_eq!(
            old_version().with_static_cdi(),
            old_version().with_cdi(CdiMode::Static).unwrap()
        );
    }

    #[test]
    fn versions_are_compared_with_installed_packages() {
        let version: ToolkitVersion = "1.20.1-1".parse().unwrap();
        assert_eq!(
            version.compare_with_installed("1.20.1-1"),
            Some(Ordering::Equal)
        );
        assert_eq!(
            version.compare_with_installed("1.21.0-1"),
            Some(Ordering::Less)
        );
        assert_eq!(
            version.compare_with_installed("1.9.0-1"),
            Some(Ordering::Greater)
        );
        assert_eq!(
            version.compare_with_installed("0:1.20.1-1"),
            Some(Ordering::Equal)
        );
        assert_eq!(version.compare_with_installed("garbage"), None);
        assert_eq!(
            version.package_spec("nvidia-container-toolkit", PackageFamily::Apt),
            "nvidia-container-toolkit=1.20.1-1"
        );
        assert_eq!(
            version.package_spec("libnvidia-container1", PackageFamily::Dnf),
            "libnvidia-container1-1.20.1-1"
        );

        let installed: BTreeMap<String, String> = [
            ("nvidia-container-toolkit", "1.20.1-1"),
            ("nvidia-container-toolkit-base", "1.21.0-1"),
            ("libnvidia-container1", "1.17.8-1"),
        ]
        .into_iter()
        .map(|(name, version)| (name.to_string(), version.to_string()))
        .collect();
        assert_eq!(
            version.packages_to_change(&installed),
            (
                vec![
                    "libnvidia-container-tools".to_string(),
                    "libnvidia-container1".to_string()
                ],
                vec!["nvidia-container-toolkit-base".to_string()]
            )
        );
    }

    #[test]
    fn engine_configurations_are_inspected() {
        let docker =
            r#"{"runtimes": {"nvidia": {"args": [], "path": "nvidia-container-runtime"}}}"#;
        assert!(ContainerRuntime::Docker.has_nvidia_runtime(docker));
        assert!(!ContainerRuntime::Docker.has_nvidia_runtime(r#"{"log-driver": "journald"}"#));
        assert!(!ContainerRuntime::Docker.has_nvidia_runtime(""));

        let containerd = "version = 3\n[plugins.\"io.containerd.cri.v1.runtime\".containerd.runtimes.nvidia.options]\n  BinaryName = \"/usr/bin/nvidia-container-runtime\"\n";
        assert!(ContainerRuntime::Containerd.has_nvidia_runtime(containerd));
        assert!(
            !ContainerRuntime::Containerd
                .has_nvidia_runtime("# BinaryName = \"nvidia-container-runtime\"\n")
        );

        let crio = "[crio.runtime.runtimes.nvidia]\nruntime_path = \"/usr/bin/nvidia-container-runtime\"\n";
        assert!(ContainerRuntime::CriO.has_nvidia_runtime(crio));
    }

    #[test]
    fn cdi_specifications_must_match_the_loaded_driver() {
        let spec = "---\ncdiVersion: 0.5.0\nkind: nvidia.com/gpu\ndevices:\n- name: \"0\"\ncontainerEdits:\n  mounts:\n  - hostPath: /usr/lib/x86_64-linux-gnu/libcuda.so.580.105.08\n";
        assert!(is_cdi_spec_current(spec, Some("580.105.08")));
        assert!(!is_cdi_spec_current(spec, Some("590.48.01")));
        assert!(!is_cdi_spec_current(spec, None));
        assert!(!is_cdi_spec_current(
            "cdiVersion: 0.5.0\n",
            Some("580.105.08")
        ));
    }

    #[test]
    fn remediation_commands_are_quoted() {
        let api_call =
            |api_call| NvidiaContainerToolkitApiCall::from(api_call, Privilege::WithSudo);
        assert_eq!(
            api_call(NvidiaContainerToolkitInternalApiCall::Install {
                family: PackageFamily::Zypper,
                version: Some("1.20.1-1".parse().unwrap()),
                upgrades: vec!["nvidia-container-toolkit".to_string()],
                downgrades: vec!["libnvidia-container1".to_string()],
            })
            .commands(),
            vec![
                "'zypper' '--non-interactive' '--gpg-auto-import-keys' 'install' '--force-resolution' 'nvidia-container-toolkit-1.20.1-1'",
                "'zypper' '--non-interactive' '--gpg-auto-import-keys' 'install' '--force-resolution' '--oldpackage' 'libnvidia-container1-1.20.1-1'"
            ]
        );
        assert_eq!(
            api_call(NvidiaContainerToolkitInternalApiCall::Install {
                family: PackageFamily::Apt,
                version: None,
                upgrades: vec!["nvidia-container-toolkit".to_string()],
                downgrades: Vec::new(),
            })
            .commands(),
            vec![
                "'apt-get' 'update'",
                "DEBIAN_FRONTEND=noninteractive 'apt-get' 'install' '-y' 'nvidia-container-toolkit'"
            ]
        );
        assert_eq!(
            apt_repository_commands("/tmp/x/gpgkey", "/tmp/x/list"),
            vec![
                "'gpg' '--batch' '--yes' '--dearmor' '-o' '/usr/share/keyrings/nvidia-container-toolkit-keyring.gpg' '/tmp/x/gpgkey'",
                "'sed' '-i' 's#deb https://#deb [signed-by=/usr/share/keyrings/nvidia-container-toolkit-keyring.gpg] https://#g' '/tmp/x/list'",
                "'install' '-m' '0644' '/tmp/x/list' '/etc/apt/sources.list.d/nvidia-container-toolkit.list'",
                "'apt-get' 'update'"
            ]
        );
        assert!(
            api_call(NvidiaContainerToolkitInternalApiCall::RefreshCdiSpec)
                .display()
                .contains("/var/run/cdi/nvidia.yaml")
        );
    }
}
