//! NVIDIA driver attribute
//!
//! This module provides the `NvidiaDriverExpectedState` type for installing the NVIDIA GPU
//! driver (and optionally the CUDA toolkit) from NVIDIA's CUDA network repository,
//! `https://developer.download.nvidia.com/compute/cuda/repos/<distro>/<arch>/`, as described in
//! the [NVIDIA Driver Installation Guide](https://docs.nvidia.com/datacenter/tesla/driver-installation-guide/).
//!
//! **Compatible OS:** Linux, on the distributions served by the CUDA network repository:
//! Ubuntu 22.04/24.04/26.04, Debian 12/13, RHEL/Rocky/AlmaLinux/Oracle Linux/CentOS Stream
//! 8/9/10, Fedora 42/43/44, Amazon Linux 2023, SLES 15/16 and openSUSE Leap 15, on `x86_64` or
//! `aarch64` servers (`sbsa` repositories; Jetson boards use JetPack instead). The distribution
//! and architecture are detected at assessment time (`/etc/os-release`, `uname -m`): an
//! unsupported host is reported as a fatal non-compliance.
//!
//! **Privilege:** installing packages needs root, use `!WithSudo`.
//!
//! # Invalid states are unrepresentable
//!
//! - The driver configuration only exists in the `Present` state: an `Absent` driver has nothing
//!   to configure.
//! - The kernel module flavor carries the driver branch. The open kernel modules (default, the
//!   only flavor supporting Blackwell GPUs, recommended from Turing on) accept `Latest` or a
//!   branch number. The proprietary modules (needed by Maxwell, Pascal and Volta GPUs) were
//!   removed from the packages after branch 610, so they require an explicit branch between 570
//!   and 610: `!Proprietary Latest` or `!Proprietary 615` can't be built.
//! - Branches before 570 don't follow the current packaging conventions and are rejected.
//! - The CUDA toolkit version is a `<major>.<minor>` version (`cuda-toolkit-<major>-<minor>`).
//!
//! # How compliance is assessed
//!
//! 1. The CUDA network repository of the host must be configured (cuda-keyring package for apt,
//!    `cuda-<distro>.repo` for dnf and zypper). It is never removed by this attribute.
//! 2. The driver branch is selected the way NVIDIA documents it for the distribution. On
//!    Ubuntu and Debian, the branch is pinned by installing its meta package
//!    `nvidia-driver-<branch>` (proprietary kernel modules) or `nvidia-driver-<branch>-open`
//!    (open kernel modules), shipped by the CUDA repository or by the distribution archive
//!    once NVIDIA prunes the branch from the CUDA repository: the branch-suffixed packages
//!    keep the driver in the branch. Elsewhere, the `nvidia-driver` DNF module stream is
//!    enabled (`open-dkms`, `<branch>-open`, `<branch>-dkms`; RHEL 8/9, Amazon Linux 2023),
//!    `dnf versionlock` on `*nvidia*<branch>*` is set (RHEL 10, Fedora) or a
//!    `*nvidia* >= <branch + 1>` zypper lock is added (SUSE). `Latest` removes these pins
//!    and locks.
//! 3. The driver meta package must be installed: on Ubuntu and Debian, the branch meta
//!    package (`nvidia-driver-<branch>` / `nvidia-driver-<branch>-open`) when a branch is
//!    pinned, `nvidia-open` (open kernel modules) or `cuda-drivers` (proprietary kernel
//!    modules) for the latest branch; on the other distributions, `nvidia-open` or
//!    `cuda-drivers`, together with the kernel headers DKMS needs to build the modules. Its
//!    version must belong to the expected branch: if it doesn't, the driver is removed then
//!    installed again. `Latest` installs the newest driver once and doesn't upgrade it
//!    afterwards (upgrades are left to the system updates).
//! 4. The kernel module must be loaded with the expected flavor (`/proc/driver/nvidia/version`
//!    tells `Open Kernel Module` apart) and `nvidia-smi` must work (no
//!    `Driver/library version mismatch`). If not, a remediation tries to (re)load the module
//!    with `modprobe` and **fails with an explicit "reboot required" message** when it can't:
//!    the host is never rebooted automatically. A reboot is typically needed after a first
//!    installation when `nouveau` is loaded, or after an upgrade while the GPU is in use.
//! 5. `CudaToolkit`, if set, requires the `cuda-toolkit-<major>-<minor>` package (not needed to
//!    run CUDA containers, which ship their own CUDA runtime).
//! 6. `PersistenceMode`, if set, requires the `nvidia-persistenced` service to be enabled and
//!    running (`true`) or disabled and stopped (`false`). It keeps the GPUs initialized, which
//!    avoids a delay at each start of a GPU application.
//!
//! `Absent` removes the driver packages (as listed in the "Removing the Driver" section of the
//! guide) and the branch pins and locks (module stream reset, version locks, zypper lock), but
//! keeps the repository, the CUDA toolkit and the NVIDIA Container Toolkit. A reboot is needed to
//! unload a module still in memory.
//!
//! Installing the driver builds the kernel modules with DKMS, which can take a while: the
//! default timeout is 30 minutes.
//!
//! **Prerequisites** (not managed by this attribute, see the guide's "Pre-installation Actions"):
//! the `contrib` component on Debian, EPEL and CodeReady Builder / CRB on RHEL-compatible
//! distributions (for DKMS), the PackageHub module on SLES.
//!
//! **Secure Boot:** with Secure Boot enabled, the modules built by DKMS must be signed with a key
//! enrolled in the MOK database (`mokutil --import`, then a confirmation on the console at the
//! next boot), otherwise loading them fails with "Key was rejected by service". When the module
//! can't be loaded, the remediation reports the Secure Boot state given by `mokutil --sb-state`.
//!
//! # Examples
//!
//! ## Rust API
//!
//! ```no_run
//! use regent_sdk::state::attribute::gpu::nvidia_driver::{NvidiaDriverConfig, NvidiaDriverExpectedState};
//! use regent_sdk::{Attribute, ExpectedState, Privilege, RegentError};
//!
//! fn gpu_node() -> Result<ExpectedState, RegentError> {
//!     // with_latest_open_kernel_modules() (default) | with_open_kernel_modules(<branch>)
//!     // | with_proprietary_kernel_modules(<branch 570-610>)
//!     let config = NvidiaDriverConfig::new()
//!         .with_open_kernel_modules(580)?
//!         .with_cuda_toolkit("12.8".parse()?)
//!         .with_persistence_mode(true);
//!
//!     Ok(ExpectedState::new()
//!         .with_attribute(Attribute::nvidia_driver(
//!             NvidiaDriverExpectedState::present(config),
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
//!   - Name: NVIDIA driver must be installed
//!     Privilege: !WithSudo
//!     Detail: !NvidiaDriver
//!       State: !Present
//!         KernelModules: !Open 580   # !Open Latest (default) | !Open <branch> | !Proprietary <branch 570-610>
//!         CudaToolkit: "12.8"        # optional, cuda-toolkit-12-8
//!         PersistenceMode: true      # optional, nvidia-persistenced service
//! ```
//!
//! With the defaults (newest driver, open kernel modules):
//!
//! ```yaml
//! Attributes:
//!   - Name: NVIDIA driver must be installed
//!     Privilege: !WithSudo
//!     Detail: !NvidiaDriver
//!       State: !Present {}
//! ```
//!
//! To remove the driver:
//!
//! ```yaml
//! Attributes:
//!   - Name: NVIDIA driver must be removed
//!     Privilege: !WithSudo
//!     Detail: !NvidiaDriver
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
use std::collections::BTreeMap;
use std::fmt;
use std::str::FromStr;
use std::time::Duration;

use crate::attribute::shared::{
    CudaRepository, DriverDistro, KernelModuleFlavor, LoadedDriver, PackageFamily, UnitEnablement,
    UnitState, check_linux_host, cuda_repository, installed_packages, is_container_toolkit_package,
    is_repository_configured, is_success, loaded_driver, loaded_kernel_modules, parse_os_release,
    query, query_output, run_step, run_steps, unit_state, upstream_version,
};

const ATTRIBUTE: &str = "NvidiaDriver";

/// First branch following the current packaging conventions (pinning packages, module streams)
const FIRST_SUPPORTED_BRANCH: u32 = 570;

/// Last branch shipping the proprietary kernel modules
const LAST_PROPRIETARY_BRANCH: u32 = 610;

/// Service keeping the GPUs initialized
const PERSISTENCE_DAEMON: &str = "nvidia-persistenced";

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[serde(rename_all = "PascalCase")]
pub struct NvidiaDriverExpectedState {
    state: NvidiaDriverState,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub enum NvidiaDriverState {
    /// Driver installed and loaded with this configuration
    Present(Box<NvidiaDriverConfig>),
    Absent,
}

impl NvidiaDriverExpectedState {
    /// Driver must be installed and loaded with this configuration
    pub fn present(config: NvidiaDriverConfig) -> Self {
        Self {
            state: NvidiaDriverState::Present(Box::new(config)),
        }
    }

    pub fn absent() -> Self {
        Self {
            state: NvidiaDriverState::Absent,
        }
    }
}

/// Optional fields left out are not managed.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[serde(rename_all = "PascalCase")]
pub struct NvidiaDriverConfig {
    /// Kernel module flavor and driver branch (open modules, latest branch by default)
    #[serde(default)]
    kernel_modules: KernelModules,
    /// CUDA toolkit to install (`cuda-toolkit-<major>-<minor>`)
    cuda_toolkit: Option<CudaVersion>,
    /// `nvidia-persistenced` service enabled and running (`true`) or disabled and stopped (`false`)
    persistence_mode: Option<bool>,
}

impl NvidiaDriverConfig {
    /// Open kernel modules, latest branch
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_kernel_modules(mut self, kernel_modules: KernelModules) -> Self {
        self.kernel_modules = kernel_modules;
        self
    }

    /// Open kernel modules, newest driver branch (the default)
    pub fn with_latest_open_kernel_modules(self) -> Self {
        self.with_kernel_modules(KernelModules::Open(DriverBranch::Latest))
    }

    /// Open kernel modules, driver pinned to this branch (from 570 on)
    pub fn with_open_kernel_modules(self, branch: u32) -> Result<Self, RegentError> {
        let branch = BranchNumber::try_from(branch)?;
        Ok(self.with_kernel_modules(KernelModules::Open(DriverBranch::Branch(branch))))
    }

    /// Proprietary kernel modules, driver pinned to this branch (570 to 610)
    pub fn with_proprietary_kernel_modules(self, branch: u32) -> Result<Self, RegentError> {
        let branch = ProprietaryBranch::try_from(branch)?;
        Ok(self.with_kernel_modules(KernelModules::Proprietary(branch)))
    }

    pub fn with_cuda_toolkit(mut self, cuda_toolkit: CudaVersion) -> Self {
        self.cuda_toolkit = Some(cuda_toolkit);
        self
    }

    pub fn with_persistence_mode(mut self, persistence_mode: bool) -> Self {
        self.persistence_mode = Some(persistence_mode);
        self
    }
}

/// Kernel module flavor, carrying the driver branch
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub enum KernelModules {
    /// Open GPU kernel modules (`nvidia-open`): required on Blackwell, recommended from Turing on
    Open(DriverBranch),
    /// Proprietary kernel modules (`cuda-drivers`): needed by Maxwell, Pascal and Volta GPUs,
    /// only available up to branch 610
    Proprietary(ProprietaryBranch),
}

impl Default for KernelModules {
    fn default() -> Self {
        KernelModules::Open(DriverBranch::Latest)
    }
}

impl KernelModules {
    pub fn flavor(&self) -> KernelModuleFlavor {
        match self {
            KernelModules::Open(_) => KernelModuleFlavor::Open,
            KernelModules::Proprietary(_) => KernelModuleFlavor::Proprietary,
        }
    }

    /// Pinned branch, `None` for the latest one
    pub fn branch(&self) -> Option<u32> {
        match self {
            KernelModules::Open(DriverBranch::Latest) => None,
            KernelModules::Open(DriverBranch::Branch(branch)) => Some(branch.number()),
            KernelModules::Proprietary(branch) => Some(branch.number()),
        }
    }

    /// Floating meta package installing the whole driver (latest branch)
    pub fn package(&self) -> &'static str {
        match self {
            KernelModules::Open(_) => OPEN_PACKAGE,
            KernelModules::Proprietary(_) => PROPRIETARY_PACKAGE,
        }
    }

    /// Meta package installing the driver with the expected branch: on apt, the branch
    /// meta package `nvidia-driver-<branch>[-open]` (pinning the branch by construction,
    /// shipped by the CUDA repository or the distribution archive); the floating meta
    /// package otherwise
    fn install_package(&self, distro: DriverDistro) -> String {
        match (distro, self.branch()) {
            (DriverDistro::Ubuntu | DriverDistro::Debian, Some(branch)) => match self.flavor() {
                KernelModuleFlavor::Proprietary => format!("nvidia-driver-{}", branch),
                KernelModuleFlavor::Open => format!("nvidia-driver-{}-open", branch),
            },
            _ => self.package().to_string(),
        }
    }

    /// How the branch is selected on a distribution, `None` when the driver meta package
    /// itself pins the branch (apt)
    fn branch_selection(&self, distro: DriverDistro) -> Option<BranchSelection> {
        let branch = self.branch();
        match distro {
            DriverDistro::Ubuntu | DriverDistro::Debian => None,
            DriverDistro::RhelModular | DriverDistro::AmazonLinux => {
                Some(BranchSelection::ModuleStream(Some(match self {
                    KernelModules::Open(DriverBranch::Latest) => "open-dkms".to_string(),
                    KernelModules::Open(DriverBranch::Branch(branch)) => {
                        format!("{}-open", branch)
                    }
                    KernelModules::Proprietary(branch) => format!("{}-dkms", branch),
                })))
            }
            DriverDistro::Rhel10 | DriverDistro::Fedora => {
                Some(BranchSelection::VersionLock(branch))
            }
            DriverDistro::Suse => Some(BranchSelection::ZypperLock(branch)),
        }
    }
}

/// Selection leaving no branch pinned nor locked, `None` on apt (pinned by the meta package)
fn unpinned_selection(distro: DriverDistro) -> Option<BranchSelection> {
    match distro {
        DriverDistro::Ubuntu | DriverDistro::Debian => None,
        DriverDistro::RhelModular | DriverDistro::AmazonLinux => {
            Some(BranchSelection::ModuleStream(None))
        }
        DriverDistro::Rhel10 | DriverDistro::Fedora => Some(BranchSelection::VersionLock(None)),
        DriverDistro::Suse => Some(BranchSelection::ZypperLock(None)),
    }
}

/// Driver branch of the open kernel modules: `Latest` or a branch number (e.g. `580`)
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "RawBranch", into = "RawBranch")]
pub enum DriverBranch {
    /// Newest driver available when installing
    Latest,
    /// Driver branch, pinned
    Branch(BranchNumber),
}

/// Branch as written in YAML or JSON: a number, `Latest`, or a number as a string
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
enum RawBranch {
    Number(u32),
    Text(String),
}

impl TryFrom<RawBranch> for DriverBranch {
    type Error = RegentError;

    fn try_from(raw: RawBranch) -> Result<Self, Self::Error> {
        match raw {
            RawBranch::Number(number) => Ok(DriverBranch::Branch(BranchNumber::try_from(number)?)),
            RawBranch::Text(text) => text.parse(),
        }
    }
}

impl From<DriverBranch> for RawBranch {
    fn from(branch: DriverBranch) -> RawBranch {
        match branch {
            DriverBranch::Latest => RawBranch::Text("Latest".to_string()),
            DriverBranch::Branch(branch) => RawBranch::Number(branch.number()),
        }
    }
}

impl FromStr for DriverBranch {
    type Err = RegentError;

    fn from_str(text: &str) -> Result<Self, Self::Err> {
        if text.eq_ignore_ascii_case("latest") {
            Ok(DriverBranch::Latest)
        } else {
            Ok(DriverBranch::Branch(text.parse()?))
        }
    }
}

impl fmt::Display for DriverBranch {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DriverBranch::Latest => write!(f, "Latest"),
            DriverBranch::Branch(branch) => write!(f, "{}", branch),
        }
    }
}

/// Driver branch number (major version of the driver, e.g. `580`), from 570 on
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(try_from = "u32", into = "u32")]
pub struct BranchNumber(u32);

impl TryFrom<u32> for BranchNumber {
    type Error = RegentError;

    fn try_from(number: u32) -> Result<Self, Self::Error> {
        if (FIRST_SUPPORTED_BRANCH..1000).contains(&number) {
            Ok(Self(number))
        } else {
            Err(invalid_value(
                "NVIDIA driver branch",
                &number.to_string(),
                &format!(
                    "branches from {} on are supported (older branches use other package names)",
                    FIRST_SUPPORTED_BRANCH
                ),
            ))
        }
    }
}

impl FromStr for BranchNumber {
    type Err = RegentError;

    fn from_str(text: &str) -> Result<Self, Self::Err> {
        let number = text.trim().parse::<u32>().map_err(|_| {
            invalid_value(
                "NVIDIA driver branch",
                text,
                "expected Latest or a branch number such as 580",
            )
        })?;
        Self::try_from(number)
    }
}

impl From<BranchNumber> for u32 {
    fn from(branch: BranchNumber) -> u32 {
        branch.0
    }
}

impl fmt::Display for BranchNumber {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl BranchNumber {
    pub fn number(&self) -> u32 {
        self.0
    }
}

/// Branch of the proprietary kernel modules: from 570 to 610 (the last branch shipping them)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "RawBranch", into = "u32")]
pub struct ProprietaryBranch(BranchNumber);

impl TryFrom<RawBranch> for ProprietaryBranch {
    type Error = RegentError;

    fn try_from(raw: RawBranch) -> Result<Self, Self::Error> {
        match raw {
            RawBranch::Number(number) => Self::try_from(number),
            RawBranch::Text(text) => text.parse(),
        }
    }
}

impl TryFrom<u32> for ProprietaryBranch {
    type Error = RegentError;

    fn try_from(number: u32) -> Result<Self, Self::Error> {
        let branch = BranchNumber::try_from(number)?;
        if number <= LAST_PROPRIETARY_BRANCH {
            Ok(Self(branch))
        } else {
            Err(invalid_value(
                "proprietary kernel modules branch",
                &number.to_string(),
                &format!(
                    "the proprietary kernel modules were removed after branch {}, use the open kernel modules",
                    LAST_PROPRIETARY_BRANCH
                ),
            ))
        }
    }
}

impl FromStr for ProprietaryBranch {
    type Err = RegentError;

    fn from_str(text: &str) -> Result<Self, Self::Err> {
        if text.eq_ignore_ascii_case("latest") {
            return Err(invalid_value(
                "proprietary kernel modules branch",
                text,
                &format!(
                    "the proprietary kernel modules need a pinned branch (570 to {}): the latest branches only ship the open kernel modules",
                    LAST_PROPRIETARY_BRANCH
                ),
            ));
        }
        Self::try_from(BranchNumber::from_str(text)?.number())
    }
}

impl From<ProprietaryBranch> for u32 {
    fn from(branch: ProprietaryBranch) -> u32 {
        branch.0.number()
    }
}

impl fmt::Display for ProprietaryBranch {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl ProprietaryBranch {
    /// Branch number of the proprietary kernel modules (e.g. `580`), from 570 to 610
    ///
    /// # Panics
    ///
    /// When the branch does not ship the proprietary kernel modules — use
    /// `ProprietaryBranch::try_from` to handle an invalid branch.
    pub fn new(branch: u32) -> Self {
        Self::try_from(branch).unwrap_or_else(|error| panic!("{error}"))
    }

    pub fn number(&self) -> u32 {
        self.0.number()
    }
}

/// CUDA toolkit version `<major>.<minor>` (e.g. `12.8`, `13.0`)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct CudaVersion {
    major: u16,
    minor: u16,
}

impl TryFrom<String> for CudaVersion {
    type Error = RegentError;

    fn try_from(text: String) -> Result<Self, Self::Error> {
        let parse = |part: &str| {
            (!part.is_empty() && part.len() <= 2 && part.chars().all(|c| c.is_ascii_digit()))
                .then(|| part.parse::<u16>().ok())
                .flatten()
        };
        match text.split_once('.') {
            Some((major, minor)) => match (parse(major), parse(minor)) {
                (Some(major), Some(minor)) if major >= 10 => Ok(Self { major, minor }),
                _ => Err(invalid_cuda_version(&text)),
            },
            None => Err(invalid_cuda_version(&text)),
        }
    }
}

fn invalid_cuda_version(text: &str) -> RegentError {
    invalid_value(
        "CUDA toolkit version",
        text,
        "expected <major>.<minor> such as 12.8 (quote it in YAML: \"12.10\")",
    )
}

impl FromStr for CudaVersion {
    type Err = RegentError;

    fn from_str(text: &str) -> Result<Self, Self::Err> {
        Self::try_from(text.to_string())
    }
}

impl From<CudaVersion> for String {
    fn from(version: CudaVersion) -> String {
        version.to_string()
    }
}

impl fmt::Display for CudaVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}.{}", self.major, self.minor)
    }
}

impl CudaVersion {
    /// `cuda-toolkit-<major>-<minor>`
    pub fn package(&self) -> String {
        format!("cuda-toolkit-{}-{}", self.major, self.minor)
    }
}

fn invalid_value(what: &str, value: &str, details: &str) -> RegentError {
    RegentError::IncoherentExpectedState(format!("Invalid {} {:?}: {}", what, value, details))
}

/// How a driver branch is selected (`None`: latest branch, no pin or lock)
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub enum BranchSelection {
    /// Enabled stream of the `nvidia-driver` DNF module, `None` for a reset module
    ModuleStream(Option<String>),
    /// `dnf versionlock` on `*nvidia*<branch>*`
    VersionLock(Option<u32>),
    /// zypper lock `*nvidia* >= <branch + 1>`
    ZypperLock(Option<u32>),
}

impl fmt::Display for BranchSelection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            BranchSelection::ModuleStream(Some(stream)) => {
                write!(f, "enable DNF module stream nvidia-driver:{}", stream)
            }
            BranchSelection::ModuleStream(None) => write!(f, "reset the nvidia-driver DNF module"),
            BranchSelection::VersionLock(Some(branch)) => {
                write!(
                    f,
                    "lock the NVIDIA packages to branch {} (dnf versionlock)",
                    branch
                )
            }
            BranchSelection::VersionLock(None) => {
                write!(f, "remove the NVIDIA package version locks")
            }
            BranchSelection::ZypperLock(Some(branch)) => {
                write!(f, "lock the NVIDIA packages to branch {} (zypper)", branch)
            }
            BranchSelection::ZypperLock(None) => write!(f, "remove the NVIDIA package locks"),
        }
    }
}

/// Branch selection currently in place, with what must be undone to change it
#[derive(Debug, Clone, PartialEq, Eq)]
enum CurrentSelection {
    /// Enabled `nvidia-driver` module stream
    ModuleStream(Option<String>),
    /// Version locks of NVIDIA packages
    VersionLocks(Vec<LockedPackage>),
    /// zypper locks on `*nvidia*`
    ZypperLocks(Vec<ZypperLock>),
}

impl CurrentSelection {
    fn matches(&self, expected: &BranchSelection) -> bool {
        match (self, expected) {
            (CurrentSelection::ModuleStream(current), BranchSelection::ModuleStream(stream)) => {
                current == stream
            }
            (CurrentSelection::VersionLocks(locks), BranchSelection::VersionLock(branch)) => {
                match branch {
                    None => locks.is_empty(),
                    Some(branch) => {
                        !locks.is_empty()
                            && locks
                                .iter()
                                .all(|lock| version_branch(&lock.version) == Some(*branch))
                    }
                }
            }
            (CurrentSelection::ZypperLocks(locks), BranchSelection::ZypperLock(branch)) => {
                match branch {
                    None => locks.is_empty(),
                    Some(branch) => {
                        locks.len() == 1 && locks[0].version == zypper_lock_condition(*branch)
                    }
                }
            }
            _ => false,
        }
    }

    /// Pins and locks to remove before applying a new selection
    fn to_undo(&self) -> Vec<String> {
        match self {
            CurrentSelection::ModuleStream(_) => Vec::new(),
            CurrentSelection::VersionLocks(locks) => {
                let mut names: Vec<String> = locks.iter().map(|lock| lock.name.clone()).collect();
                names.dedup();
                names
            }
            CurrentSelection::ZypperLocks(locks) => locks.iter().map(ZypperLock::spec).collect(),
        }
    }
}

/// Branch (major version) of a driver version: `3:580.105.08-1.el10` -> 580
fn version_branch(version: &str) -> Option<u32> {
    upstream_version(version)
        .split('.')
        .next()
        .and_then(|major| major.parse().ok())
}

fn is_in_branch(version: &str, branch: Option<u32>) -> bool {
    branch.is_none_or(|branch| version_branch(version) == Some(branch))
}

/// Package locked by `dnf versionlock`
#[derive(Debug, Clone, PartialEq, Eq)]
struct LockedPackage {
    name: String,
    /// `[epoch:]version-release`
    version: String,
}

/// Parse `dnf versionlock list`, keeping the NVIDIA driver packages. DNF 4 prints one
/// `name-[epoch:]version-release.*` entry per line, DNF 5 a `Package name: <name>` line followed
/// by `evr = <version>` conditions. Exclusions (`!name...`) are ignored.
fn parse_versionlock_list(output: &str) -> Vec<LockedPackage> {
    let mut locks = Vec::new();
    let mut dnf5_name: Option<String> = None;
    for line in output.lines().map(str::trim) {
        if let Some(name) = line.strip_prefix("Package name:") {
            dnf5_name = Some(name.trim().to_string());
            continue;
        }
        if let Some(name) = &dnf5_name
            && line.starts_with("evr")
            && let Some((_, version)) = line.split_once('=')
        {
            locks.push(LockedPackage {
                name: name.clone(),
                version: version.trim().to_string(),
            });
            continue;
        }
        if line.is_empty() || line.starts_with('#') || line.starts_with('!') || line.contains(' ') {
            continue;
        }
        // DNF 4: nvidia-open-3:580.105.08-1.el10.*
        let entry = line.trim_end_matches(".*");
        let Some((name_and_epoch, version_release)) = entry.split_once(':') else {
            continue;
        };
        if let Some((name, _epoch)) = name_and_epoch.rsplit_once('-') {
            locks.push(LockedPackage {
                name: name.to_string(),
                version: version_release.to_string(),
            });
        }
    }
    locks.retain(|lock| lock.name.contains("nvidia") && !is_container_toolkit_package(&lock.name));
    locks
}

/// Lock of the `/etc/zypp/locks` file on `*nvidia*`
#[derive(Debug, Clone, PartialEq, Eq)]
struct ZypperLock {
    name: String,
    /// Version condition, whitespace normalized (`>= 581`)
    version: String,
}

impl ZypperLock {
    /// Lock as given to `zypper addlock` / `zypper removelock`
    fn spec(&self) -> String {
        if self.version.is_empty() {
            self.name.clone()
        } else {
            format!("{} {}", self.name, self.version)
        }
    }
}

const ZYPPER_LOCK_NAME: &str = "*nvidia*";

/// Version condition excluding the branches after `branch`
fn zypper_lock_condition(branch: u32) -> String {
    format!(">= {}", branch + 1)
}

/// Parse `/etc/zypp/locks` (blocks of `key: value` lines), keeping the `*nvidia*` locks
fn parse_zypper_locks(content: &str) -> Vec<ZypperLock> {
    let mut locks = Vec::new();
    for block in content.split("\n\n") {
        let mut name = None;
        let mut version = String::new();
        for line in block.lines() {
            if let Some((key, value)) = line.split_once(':') {
                match key.trim() {
                    "solvable_name" => name = Some(value.trim().to_string()),
                    "version" => version = value.split_whitespace().collect::<Vec<_>>().join(" "),
                    _ => {}
                }
            }
        }
        if let Some(name) = name
            && name == ZYPPER_LOCK_NAME
        {
            locks.push(ZypperLock { name, version });
        }
    }
    locks
}

/// Parse `dnf module list --enabled nvidia-driver`: enabled stream, if any
fn parse_enabled_module_stream(output: &str) -> Option<String> {
    output.lines().find_map(|line| {
        let mut tokens = line.split_whitespace();
        if tokens.next() != Some("nvidia-driver") {
            return None;
        }
        let stream = tokens.next()?;
        let markers: Vec<&str> = tokens.take_while(|token| token.starts_with('[')).collect();
        markers
            .iter()
            .any(|marker| marker.contains("[e]"))
            .then(|| stream.to_string())
    })
}

/// Commands applying a branch selection, `undo` being what [`CurrentSelection::to_undo`] returned
fn branch_selection_commands(
    selection: &BranchSelection,
    distro: DriverDistro,
    undo: &[String],
) -> Vec<String> {
    let mut commands = Vec::new();
    match selection {
        BranchSelection::ModuleStream(stream) => {
            commands.push(quoted_command(&[
                "dnf",
                "-y",
                "module",
                "reset",
                "nvidia-driver",
            ]));
            if let Some(stream) = stream {
                commands.push(quoted_command(&[
                    "dnf",
                    "-y",
                    "module",
                    "enable",
                    &format!("nvidia-driver:{}", stream),
                ]));
            }
        }
        BranchSelection::VersionLock(branch) => {
            if distro == DriverDistro::Rhel10 {
                // DNF 4 needs the versionlock plugin (built into DNF 5)
                commands.push(quoted_command(&[
                    "dnf",
                    "-y",
                    "install",
                    "python3-dnf-plugin-versionlock",
                ]));
            }
            if !undo.is_empty() {
                let mut args = vec!["dnf", "versionlock", "delete"];
                args.extend(undo.iter().map(String::as_str));
                commands.push(quoted_command(&args));
            }
            if let Some(branch) = branch {
                commands.push(quoted_command(&[
                    "dnf",
                    "versionlock",
                    "add",
                    &format!("*nvidia*{}*", branch),
                ]));
            }
        }
        BranchSelection::ZypperLock(branch) => {
            for lock in undo {
                commands.push(quoted_command(&[
                    "zypper",
                    "--non-interactive",
                    "removelock",
                    lock,
                ]));
            }
            if let Some(branch) = branch {
                commands.push(quoted_command(&[
                    "zypper",
                    "--non-interactive",
                    "addlock",
                    &format!("{} {}", ZYPPER_LOCK_NAME, zypper_lock_condition(*branch)),
                ]));
            }
        }
    }
    commands
}

/// Meta package of the driver with the open kernel modules
const OPEN_PACKAGE: &str = "nvidia-open";
/// Meta package of the driver with the proprietary kernel modules (up to branch 610, then a
/// transitional package depending on `nvidia-open`)
const PROPRIETARY_PACKAGE: &str = "cuda-drivers";

/// Installed driver compared with the expected one
#[derive(Debug, Clone, PartialEq, Eq)]
enum InstalledDriver {
    /// Expected flavor, in the expected branch
    Expected,
    /// No driver meta package installed
    Missing,
    /// Another flavor or branch is installed, with the reason why it must be replaced
    Different(String),
}

/// Driver meta package installed on an apt host: kernel module flavor, and branch for
/// the branch meta packages (`nvidia-driver-580`, `nvidia-driver-580-open`,
/// `nvidia-driver-580-server`, ...). `None` for the floating meta packages
/// (`cuda-drivers`, `nvidia-driver`, `nvidia-open`, `nvidia-driver-open`).
fn apt_driver_meta(name: &str) -> Option<(KernelModuleFlavor, Option<u32>)> {
    match name {
        PROPRIETARY_PACKAGE | "nvidia-driver" => Some((KernelModuleFlavor::Proprietary, None)),
        OPEN_PACKAGE | "nvidia-driver-open" => Some((KernelModuleFlavor::Open, None)),
        _ => name.strip_prefix("nvidia-driver-").and_then(|rest| {
            let (branch, flavor) = if let Some(branch) = rest.strip_suffix("-server-open") {
                (branch, KernelModuleFlavor::Open)
            } else if let Some(branch) = rest.strip_suffix("-server") {
                (branch, KernelModuleFlavor::Proprietary)
            } else if let Some(branch) = rest.strip_suffix("-open") {
                (branch, KernelModuleFlavor::Open)
            } else {
                (rest, KernelModuleFlavor::Proprietary)
            };
            branch
                .parse::<u32>()
                .ok()
                .map(|branch| (flavor, Some(branch)))
        }),
    }
}

/// Meta packages telling which driver is installed: the floating ones, and on apt the
/// branch ones (`nvidia-driver-<branch>[-open]`, pinning the branch by construction)
fn driver_meta_patterns(distro: DriverDistro) -> &'static [&'static str] {
    match distro {
        DriverDistro::Ubuntu | DriverDistro::Debian => &[
            OPEN_PACKAGE,
            PROPRIETARY_PACKAGE,
            "nvidia-driver",
            "nvidia-driver-open",
            "nvidia-driver-[0-9]*",
        ],
        _ => &[OPEN_PACKAGE, PROPRIETARY_PACKAGE],
    }
}

/// Compare the installed driver meta packages (name -> version) with the expected driver
fn installed_driver_status(
    installed: &BTreeMap<String, String>,
    modules: &KernelModules,
    distro: DriverDistro,
) -> InstalledDriver {
    let branch = modules.branch();
    if matches!(distro, DriverDistro::Ubuntu | DriverDistro::Debian) {
        // On apt, the branch is pinned by its meta package: the expected driver is the
        // branch meta package `nvidia-driver-<branch>[-open]` (or the floating meta
        // package for the latest branch), any other driver meta package is another driver
        let is_expected = |name: &str| {
            apt_driver_meta(name).is_some_and(|(flavor, meta_branch)| {
                flavor == modules.flavor() && meta_branch == branch
            })
        };
        if installed.keys().any(|name| is_expected(name)) {
            return InstalledDriver::Expected;
        }
        return match installed
            .iter()
            .find(|(name, _)| apt_driver_meta(name).is_some())
        {
            Some((name, version)) => InstalledDriver::Different(format!(
                "{} {} is installed, expected {} ({} kernel modules)",
                name,
                version,
                modules.install_package(distro),
                modules.flavor()
            )),
            None => InstalledDriver::Missing,
        };
    }
    // dnf/zypper: the floating meta package, kept in the expected branch by the module
    // stream or the version locks
    let other_flavor = match modules.flavor() {
        KernelModuleFlavor::Open => installed
            .get(PROPRIETARY_PACKAGE)
            .filter(|version| {
                version_branch(version).is_some_and(|branch| branch <= LAST_PROPRIETARY_BRANCH)
            })
            .map(|version| {
                (
                    PROPRIETARY_PACKAGE,
                    version,
                    KernelModuleFlavor::Proprietary,
                )
            }),
        KernelModuleFlavor::Proprietary => installed
            .get(OPEN_PACKAGE)
            .map(|version| (OPEN_PACKAGE, version, KernelModuleFlavor::Open)),
    };
    if let Some((package, version, flavor)) = other_flavor {
        return InstalledDriver::Different(format!(
            "{} {} ({} kernel modules) is installed, expected the {} kernel modules",
            package,
            version,
            flavor,
            modules.flavor()
        ));
    }
    match installed.get(modules.package()) {
        None => InstalledDriver::Missing,
        Some(version) if is_in_branch(version, branch) => InstalledDriver::Expected,
        Some(version) => InstalledDriver::Different(format!(
            "{} {} is installed, expected branch {}",
            modules.package(),
            version,
            branch.unwrap_or_default()
        )),
    }
}

/// Packages of the driver, as listed in the "Removing the Driver" section of the guide
fn driver_package_patterns(distro: DriverDistro) -> &'static [&'static str] {
    match distro {
        DriverDistro::Ubuntu => &[
            "cuda-compat*",
            "cuda-drivers*",
            "libnvidia-cfg1*",
            "libnvidia-compute*",
            "libnvidia-decode*",
            "libnvidia-encode*",
            "libnvidia-extra*",
            "libnvidia-fbc1*",
            "libnvidia-gl*",
            "libnvidia-gpucomp*",
            "libnvidia-nscq*",
            "libnvsdm*",
            "libxnvctrl*",
            "nvidia-dkms*",
            "nvidia-driver*",
            "nvidia-fabricmanager*",
            "nvidia-firmware*",
            "nvidia-headless*",
            "nvidia-imex*",
            "nvidia-kernel-common*",
            "nvidia-kernel-source*",
            "nvidia-modprobe*",
            "nvidia-open*",
            "nvidia-persistenced*",
            "nvidia-settings*",
            "nvidia-utils*",
            "nvidia-compute-utils*",
            "nvidia-xconfig*",
            "xserver-xorg-video-nvidia*",
        ],
        DriverDistro::Debian => &[
            "cuda-compat*",
            "cuda-drivers*",
            "cuda-mps*",
            "firmware-nvidia-gsp*",
            "libcuda1*",
            "libcudadebugger1*",
            "libegl-nvidia0*",
            "libgles-nvidia1*",
            "libgles-nvidia2*",
            "libglx-nvidia0*",
            "libnvcuvid1*",
            "libnvidia-*",
            "libnvoptix1*",
            "libnvsdm*",
            "libxnvctrl*",
            "nvidia-alternative*",
            "nvidia-detect*",
            "nvidia-driver*",
            "nvidia-egl-common*",
            "nvidia-egl-icd*",
            "nvidia-fabricmanager*",
            "nvidia-imex*",
            "nvidia-kernel-*",
            "nvidia-legacy*",
            "nvidia-modprobe*",
            "nvidia-open*",
            "nvidia-opencl*",
            "nvidia-persistenced*",
            "nvidia-powerd*",
            "nvidia-settings*",
            "nvidia-smi*",
            "nvidia-support*",
            "nvidia-suspend-common*",
            "nvidia-vdpau-driver*",
            "nvidia-vulkan*",
            "nvidia-xconfig*",
            "xserver-xorg-video-nvidia*",
        ],
        DriverDistro::RhelModular
        | DriverDistro::AmazonLinux
        | DriverDistro::Rhel10
        | DriverDistro::Fedora => &[
            "cuda-drivers*",
            "kmod-nvidia*",
            "libnvidia*",
            "nvidia-driver*",
            "nvidia-kmod-common",
            "nvidia-libXNVCtrl*",
            "nvidia-modprobe",
            "nvidia-open*",
            "nvidia-persistenced",
            "nvidia-settings",
            "nvidia-xconfig",
            "xorg-x11-nvidia*",
        ],
        DriverDistro::Suse => &["cuda-compat*", "cuda-drivers*", "libnvidia-*", "nvidia-*"],
    }
}

/// Installed driver packages to remove: the container toolkit is kept
fn driver_packages_to_remove<'a>(installed: impl Iterator<Item = &'a String>) -> Vec<String> {
    installed
        .filter(|name| !is_container_toolkit_package(name) && !name.starts_with("cuda-toolkit"))
        .cloned()
        .collect()
}

/// Outcome of `nvidia-smi --query-gpu=driver_version --format=csv,noheader`
#[derive(Debug, Clone, PartialEq, Eq)]
enum SmiStatus {
    /// Driver version reported for each GPU
    Working(String),
    /// User space libraries and kernel module versions differ
    VersionMismatch,
    /// Any other failure (driver not loaded, no device, nvidia-smi missing)
    Failing(String),
}

fn smi_command() -> String {
    quoted_command(&[
        "nvidia-smi",
        "--query-gpu=driver_version",
        "--format=csv,noheader",
    ])
}

fn parse_smi(return_code: i64, output: &str) -> SmiStatus {
    if output.contains("Driver/library version mismatch") {
        return SmiStatus::VersionMismatch;
    }
    let version = output
        .lines()
        .map(str::trim)
        .find(|line| version_branch(line).is_some() && line.contains('.'));
    match (return_code, version) {
        (0, Some(version)) => SmiStatus::Working(version.to_string()),
        _ => SmiStatus::Failing(output.trim().to_string()),
    }
}

/// Why the loaded driver is not the expected one, `None` if it is
fn runtime_issue(
    loaded: Option<&LoadedDriver>,
    smi: &SmiStatus,
    flavor: KernelModuleFlavor,
    branch: Option<u32>,
) -> Option<String> {
    let Some(loaded) = loaded else {
        return Some("the NVIDIA kernel module is not loaded".to_string());
    };
    if loaded.flavor != flavor {
        return Some(format!(
            "the {} kernel module is loaded, expected the {} one",
            loaded.flavor, flavor
        ));
    }
    if !is_in_branch(&loaded.version, branch) {
        return Some(format!(
            "driver {} is loaded, expected branch {}",
            loaded.version,
            branch.unwrap_or_default()
        ));
    }
    match smi {
        SmiStatus::Working(_) => None,
        SmiStatus::VersionMismatch => Some(format!(
            "driver {} is loaded but the installed libraries are another version (Driver/library version mismatch)",
            loaded.version
        )),
        SmiStatus::Failing(output) => Some(format!("nvidia-smi fails: {}", output)),
    }
}

/// Command printing `<path>:<value>` for the vendor and class of each PCI device (the glob is
/// expanded by the shell)
const PCI_DEVICES_COMMAND: &str =
    "grep -H . /sys/bus/pci/devices/*/vendor /sys/bus/pci/devices/*/class";

/// Whether an NVIDIA display or 3D controller (vendor 0x10de, class 0x03xxxx) is present, from
/// the output of [`PCI_DEVICES_COMMAND`]
fn has_nvidia_gpu(pci_devices: &str) -> bool {
    let mut devices: BTreeMap<&str, (Option<&str>, Option<&str>)> = BTreeMap::new();
    for line in pci_devices.lines() {
        let Some((path, value)) = line.trim().rsplit_once(':') else {
            continue;
        };
        let Some((device, file)) = path.rsplit_once('/') else {
            continue;
        };
        let entry = devices.entry(device).or_default();
        match file {
            "vendor" => entry.0 = Some(value),
            "class" => entry.1 = Some(value),
            _ => {}
        }
    }
    devices.values().any(|(vendor, class)| {
        *vendor == Some("0x10de") && class.is_some_and(|class| class.starts_with("0x03"))
    })
}

/// Secure Boot state from `mokutil --sb-state`
fn parse_secure_boot(output: &str) -> Option<bool> {
    if output.contains("SecureBoot enabled") {
        Some(true)
    } else if output.contains("SecureBoot disabled") {
        Some(false)
    } else {
        None
    }
}

/// Whether `nvidia-persistenced` is in the expected state. A static unit can't be enabled nor
/// disabled: only whether it runs matters.
fn is_persistence_mode_set(state: &UnitState, persistence_mode: bool) -> bool {
    if persistence_mode {
        state.active
            && matches!(
                state.enablement,
                UnitEnablement::Enabled | UnitEnablement::Static
            )
    } else {
        !state.active && state.enablement != UnitEnablement::Enabled
    }
}

/// Commands bringing `nvidia-persistenced` from `state` to the expected one
fn persistence_mode_commands(state: &UnitState, persistence_mode: bool) -> Vec<String> {
    let mut commands = Vec::new();
    if persistence_mode {
        if state.enablement == UnitEnablement::Masked {
            commands.push(quoted_command(&["systemctl", "unmask", PERSISTENCE_DAEMON]));
        }
        if matches!(
            state.enablement,
            UnitEnablement::Disabled | UnitEnablement::Masked
        ) {
            commands.push(quoted_command(&["systemctl", "enable", PERSISTENCE_DAEMON]));
        }
        if !state.active {
            commands.push(quoted_command(&["systemctl", "start", PERSISTENCE_DAEMON]));
        }
    } else {
        if state.enablement == UnitEnablement::Enabled {
            commands.push(quoted_command(&[
                "systemctl",
                "disable",
                PERSISTENCE_DAEMON,
            ]));
        }
        if state.active {
            commands.push(quoted_command(&["systemctl", "stop", PERSISTENCE_DAEMON]));
        }
    }
    commands
}

/// NVIDIA kernel modules, unloaded in this order before loading the expected one
const NVIDIA_MODULES: [&str; 5] = [
    "nvidia_uvm",
    "nvidia_drm",
    "nvidia_modeset",
    "nvidia_peermem",
    "nvidia",
];

/// Host characteristics detected at assessment time
struct DriverHost {
    repository: CudaRepository,
    /// `uname -r`
    kernel_release: String,
}

/// Detect the CUDA repository of the host. `Ok(Err(..))` for unsupported hosts.
async fn detect_host<Handler: HostHandler>(
    host_handler: &mut Handler,
    privilege: &Privilege,
) -> Result<Result<DriverHost, String>, RegentError> {
    let os_release =
        parse_os_release(&query_output(host_handler, "cat /etc/os-release", privilege).await?);
    let machine = query_output(host_handler, "uname -m", privilege).await?;
    let kernel_release = query_output(host_handler, "uname -r", privilege)
        .await?
        .trim()
        .to_string();
    if kernel_release.is_empty()
        || !kernel_release
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || "._+~-".contains(c))
    {
        return Err(RegentError::FailedDryRunEvaluation(format!(
            "Unexpected kernel release (uname -r): {:?}",
            kernel_release
        )));
    }
    Ok(
        cuda_repository(&os_release, &machine).map(|repository| DriverHost {
            repository,
            kernel_release,
        }),
    )
}

async fn current_selection<Handler: HostHandler>(
    host_handler: &mut Handler,
    selection: &BranchSelection,
    privilege: &Privilege,
) -> Result<CurrentSelection, RegentError> {
    match selection {
        BranchSelection::ModuleStream(_) => {
            // Fails when no stream is enabled: the output is what matters
            let result = query(
                host_handler,
                &quoted_command(&["dnf", "-q", "module", "list", "--enabled", "nvidia-driver"]),
                privilege,
            )
            .await?;
            Ok(CurrentSelection::ModuleStream(parse_enabled_module_stream(
                &result.stdout,
            )))
        }
        BranchSelection::VersionLock(_) => {
            // Fails when the versionlock plugin is not installed: no lock then
            let result = query(
                host_handler,
                &quoted_command(&["dnf", "versionlock", "list"]),
                privilege,
            )
            .await?;
            let locks = if result.return_code == 0 {
                parse_versionlock_list(&result.stdout)
            } else {
                Vec::new()
            };
            Ok(CurrentSelection::VersionLocks(locks))
        }
        BranchSelection::ZypperLock(_) => {
            let result = query(
                host_handler,
                &quoted_command(&["cat", "/etc/zypp/locks"]),
                privilege,
            )
            .await?;
            let locks = if result.return_code == 0 {
                parse_zypper_locks(&result.stdout)
            } else {
                Vec::new()
            };
            Ok(CurrentSelection::ZypperLocks(locks))
        }
    }
}

impl Timeout for NvidiaDriverExpectedState {
    fn default_timeout(&self) -> Duration {
        // Installing the driver builds the kernel modules with DKMS
        Duration::from_secs(1800)
    }
}

impl Check for NvidiaDriverExpectedState {
    fn check(&self) -> Result<(), RegentError> {
        // Every value is validated when its type is built: an existing NvidiaDriverExpectedState is valid
        Ok(())
    }

    fn check_host_compatibility(
        &self,
        host_properties: &HostProperties,
    ) -> Result<(), RegentError> {
        check_linux_host(host_properties, ATTRIBUTE)
    }
}

impl<Handler: HostHandler> AssessCompliance<Handler> for NvidiaDriverExpectedState {
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

        let host = match detect_host(host_handler, privilege).await? {
            Ok(host) => host,
            Err(reason) => return Ok(AttributeComplianceAssessment::NonCompliantFatal(reason)),
        };
        let distro = host.repository.distro;
        let family = distro.package_family();

        let mut remediations: Vec<Remediation> = Vec::new();
        let mut push = |api_call: NvidiaDriverInternalApiCall| {
            remediations.push(Remediation::NvidiaDriver(NvidiaDriverApiCall::from(
                api_call,
                privilege.clone(),
            )));
        };

        match &self.state {
            NvidiaDriverState::Absent => {
                let installed = installed_packages(
                    host_handler,
                    family,
                    driver_package_patterns(distro),
                    privilege,
                )
                .await?;
                let packages = driver_packages_to_remove(installed.keys());
                if !packages.is_empty() {
                    push(NvidiaDriverInternalApiCall::RemoveDriver {
                        distro,
                        packages,
                        reason: "the driver must be absent".to_string(),
                    });
                }
                if let Some(selection) = unpinned_selection(distro) {
                    let current = current_selection(host_handler, &selection, privilege).await?;
                    if !current.matches(&selection) {
                        push(NvidiaDriverInternalApiCall::SelectBranch {
                            distro,
                            selection,
                            undo: current.to_undo(),
                        });
                    }
                }
            }
            NvidiaDriverState::Present(config) => {
                let modules = &config.kernel_modules;
                let branch = modules.branch();

                if !is_repository_configured(
                    host_handler,
                    family,
                    &host.repository.url_fragment(),
                    privilege,
                )
                .await?
                {
                    push(NvidiaDriverInternalApiCall::AddRepository(
                        host.repository.clone(),
                    ));
                }

                let installed = installed_packages(
                    host_handler,
                    family,
                    driver_meta_patterns(distro),
                    privilege,
                )
                .await?;
                let installed_driver = installed_driver_status(&installed, modules, distro);
                let needs_install = installed_driver != InstalledDriver::Expected;

                // Another branch or flavor: remove the current driver, then install the expected one
                if let InstalledDriver::Different(reason) = installed_driver {
                    let installed = installed_packages(
                        host_handler,
                        family,
                        driver_package_patterns(distro),
                        privilege,
                    )
                    .await?;
                    push(NvidiaDriverInternalApiCall::RemoveDriver {
                        distro,
                        packages: driver_packages_to_remove(installed.keys()),
                        reason,
                    });
                }

                // On apt, the branch meta package pins the branch: nothing to select
                if let Some(selection) = modules.branch_selection(distro) {
                    let current = current_selection(host_handler, &selection, privilege).await?;
                    if !current.matches(&selection) {
                        push(NvidiaDriverInternalApiCall::SelectBranch {
                            distro,
                            selection,
                            undo: current.to_undo(),
                        });
                    }
                }

                if needs_install {
                    let mut packages = vec![modules.install_package(distro)];
                    packages.extend(distro.kernel_headers_packages(&host.kernel_release));
                    push(NvidiaDriverInternalApiCall::InstallDriver { family, packages });
                }

                if let Some(cuda_toolkit) = &config.cuda_toolkit {
                    let package = cuda_toolkit.package();
                    let installed =
                        installed_packages(host_handler, family, &[&package], privilege).await?;
                    if !installed.contains_key(&package) {
                        push(NvidiaDriverInternalApiCall::InstallCudaToolkit {
                            family,
                            version: *cuda_toolkit,
                        });
                    }
                }

                // Loading fails with "reboot required" when the module can't be replaced, which
                // stops the remediations after it: only the persistence mode, which needs the module, comes after
                if needs_install {
                    push(NvidiaDriverInternalApiCall::LoadKernelModule {
                        flavor: modules.flavor(),
                        branch,
                        reason: format!("{} is being installed", modules.install_package(distro)),
                    });
                } else {
                    let loaded = loaded_driver(host_handler, privilege).await?;
                    let smi = query(host_handler, &smi_command(), privilege).await?;
                    let smi = parse_smi(smi.return_code, &smi.stdout);
                    if let Some(reason) =
                        runtime_issue(loaded.as_ref(), &smi, modules.flavor(), branch)
                    {
                        if loaded.is_none() {
                            let pci_devices =
                                query(host_handler, PCI_DEVICES_COMMAND, privilege).await?;
                            if !has_nvidia_gpu(&pci_devices.stdout) {
                                return Ok(AttributeComplianceAssessment::NonCompliantFatal(
                                    "the NVIDIA driver is installed but no NVIDIA GPU was found on the PCI bus (vendor 0x10de): the kernel module can't be loaded".to_string(),
                                ));
                            }
                        }
                        push(NvidiaDriverInternalApiCall::LoadKernelModule {
                            flavor: modules.flavor(),
                            branch,
                            reason,
                        });
                    }
                }

                if let Some(persistence_mode) = config.persistence_mode {
                    let state = unit_state(host_handler, PERSISTENCE_DAEMON, privilege).await?;
                    let is_compliant = is_persistence_mode_set(&state, persistence_mode);
                    if !is_compliant {
                        push(NvidiaDriverInternalApiCall::SetPersistenceMode(
                            persistence_mode,
                        ));
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
pub enum NvidiaDriverInternalApiCall {
    /// Configure the NVIDIA CUDA network repository
    AddRepository(CudaRepository),
    /// Pin or lock the driver branch, after removing the pins and locks in `undo`
    SelectBranch {
        distro: DriverDistro,
        selection: BranchSelection,
        undo: Vec<String>,
    },
    RemoveDriver {
        distro: DriverDistro,
        packages: Vec<String>,
        reason: String,
    },
    /// Install the driver meta package and the kernel headers
    InstallDriver {
        family: PackageFamily,
        packages: Vec<String>,
    },
    /// Install `cuda-toolkit-<major>-<minor>`
    InstallCudaToolkit {
        family: PackageFamily,
        version: CudaVersion,
    },
    /// (Re)load the NVIDIA kernel module, failing with "reboot required" when it can't
    LoadKernelModule {
        flavor: KernelModuleFlavor,
        branch: Option<u32>,
        reason: String,
    },
    /// Enable and start (`true`) or disable and stop (`false`) nvidia-persistenced
    SetPersistenceMode(bool),
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct NvidiaDriverApiCall {
    pub api_call: NvidiaDriverInternalApiCall,
    privilege: Privilege,
}

impl NvidiaDriverApiCall {
    pub fn display(&self) -> String {
        match &self.api_call {
            NvidiaDriverInternalApiCall::AddRepository(repository) => {
                format!("Add the NVIDIA CUDA repository {}", repository.base_url())
            }
            NvidiaDriverInternalApiCall::SelectBranch { selection, .. } => {
                format!("Select the NVIDIA driver branch: {}", selection)
            }
            NvidiaDriverInternalApiCall::RemoveDriver {
                packages, reason, ..
            } => {
                format!(
                    "Remove the NVIDIA driver packages {} ({}); reboot to unload the kernel module",
                    packages.join(", "),
                    reason
                )
            }
            NvidiaDriverInternalApiCall::InstallDriver { packages, .. } => {
                format!("Install the NVIDIA driver: {}", packages.join(", "))
            }
            NvidiaDriverInternalApiCall::InstallCudaToolkit { version, .. } => {
                format!(
                    "Install the CUDA toolkit {} ({})",
                    version,
                    version.package()
                )
            }
            NvidiaDriverInternalApiCall::LoadKernelModule { flavor, reason, .. } => format!(
                "Load the {} NVIDIA kernel module ({}); a reboot is required if it can't be loaded",
                flavor, reason
            ),
            NvidiaDriverInternalApiCall::SetPersistenceMode(true) => {
                format!("Enable and start {}", PERSISTENCE_DAEMON)
            }
            NvidiaDriverInternalApiCall::SetPersistenceMode(false) => {
                format!("Disable and stop {}", PERSISTENCE_DAEMON)
            }
        }
    }

    fn from(api_call: NvidiaDriverInternalApiCall, privilege: Privilege) -> NvidiaDriverApiCall {
        NvidiaDriverApiCall {
            api_call,
            privilege,
        }
    }
}

impl Timeout for NvidiaDriverApiCall {
    fn default_timeout(&self) -> Duration {
        match &self.api_call {
            NvidiaDriverInternalApiCall::InstallDriver { .. }
            | NvidiaDriverInternalApiCall::InstallCudaToolkit { .. } => Duration::from_secs(1800),
            NvidiaDriverInternalApiCall::RemoveDriver { .. } => Duration::from_secs(900),
            _ => Duration::from_secs(300),
        }
    }
}

impl Check for NvidiaDriverApiCall {
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

impl<Handler: HostHandler> ReachCompliance<Handler> for NvidiaDriverApiCall {
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
            NvidiaDriverInternalApiCall::AddRepository(repository) => {
                repository.setup(host_handler, privilege).await
            }
            NvidiaDriverInternalApiCall::SelectBranch {
                distro,
                selection,
                undo,
            } => Ok(run_steps(
                host_handler,
                &branch_selection_commands(selection, *distro, undo),
                privilege,
            )
            .await),
            NvidiaDriverInternalApiCall::RemoveDriver {
                distro, packages, ..
            } => Ok(run_step(
                host_handler,
                &distro.package_family().remove_command(packages),
                privilege,
            )
            .await),
            NvidiaDriverInternalApiCall::InstallDriver { family, packages } => Ok(run_steps(
                host_handler,
                &family.install_commands(packages, false),
                privilege,
            )
            .await),
            NvidiaDriverInternalApiCall::InstallCudaToolkit { family, version } => Ok(run_steps(
                host_handler,
                &family.install_commands(&[version.package()], false),
                privilege,
            )
            .await),
            NvidiaDriverInternalApiCall::LoadKernelModule { flavor, branch, .. } => {
                load_kernel_module(host_handler, *flavor, *branch, privilege).await
            }
            NvidiaDriverInternalApiCall::SetPersistenceMode(persistence_mode) => {
                let state = unit_state(host_handler, PERSISTENCE_DAEMON, privilege).await?;
                let outcome = run_steps(
                    host_handler,
                    &persistence_mode_commands(&state, *persistence_mode),
                    privilege,
                )
                .await;
                if !is_success(&outcome) {
                    return Ok(outcome);
                }
                let state = unit_state(host_handler, PERSISTENCE_DAEMON, privilege).await?;
                if is_persistence_mode_set(&state, *persistence_mode) {
                    Ok(outcome)
                } else {
                    Ok(InternalApiCallOutcome::Failure(format!(
                        "{} is still {:?} and {} after the change",
                        PERSISTENCE_DAEMON,
                        state.enablement,
                        if state.active { "active" } else { "inactive" }
                    )))
                }
            }
        }
    }
}

/// Load the NVIDIA kernel module and verify the driver works, never rebooting the host
async fn load_kernel_module<Handler: HostHandler>(
    host_handler: &mut Handler,
    flavor: KernelModuleFlavor,
    branch: Option<u32>,
    privilege: &Privilege,
) -> Result<InternalApiCallOutcome, RegentError> {
    let pci_devices = query(host_handler, PCI_DEVICES_COMMAND, privilege).await?;
    if !has_nvidia_gpu(&pci_devices.stdout) {
        return Ok(InternalApiCallOutcome::Failure(
            "No NVIDIA GPU found on the PCI bus (vendor 0x10de): the NVIDIA kernel module can't be loaded".to_string(),
        ));
    }

    // The daemon holds the module: stop it while reloading, and start it again whatever happens
    let persistenced = unit_state(host_handler, PERSISTENCE_DAEMON, privilege).await?;
    if persistenced.active {
        run_step(
            host_handler,
            &quoted_command(&["systemctl", "stop", PERSISTENCE_DAEMON]),
            privilege,
        )
        .await;
    }
    let (mut problem, modprobe_output) = reload_kernel_module(host_handler, privilege).await?;
    if persistenced.active {
        run_step(
            host_handler,
            &quoted_command(&["systemctl", "start", PERSISTENCE_DAEMON]),
            privilege,
        )
        .await;
    }

    if problem.is_none() {
        let loaded = loaded_driver(host_handler, privilege).await?;
        let smi = query(host_handler, &smi_command(), privilege).await?;
        let smi = parse_smi(smi.return_code, &smi.stdout);
        problem = runtime_issue(loaded.as_ref(), &smi, flavor, branch);
        if problem.is_none() {
            let version = loaded.map(|loaded| loaded.version).unwrap_or_default();
            return Ok(InternalApiCallOutcome::Success(Some(format!(
                "NVIDIA driver {} loaded",
                version
            ))));
        }
    }

    let mut message = format!(
        "Reboot required: {}. The host is not rebooted automatically.",
        problem.unwrap_or_default()
    );
    let is_signature_issue = modprobe_output.contains("Key was rejected")
        || modprobe_output.contains("Required key not available");
    let secure_boot = if host_handler
        .is_this_command_available("mokutil", privilege)
        .await
        .unwrap_or(false)
    {
        let output = query(
            host_handler,
            &quoted_command(&["mokutil", "--sb-state"]),
            privilege,
        )
        .await?;
        parse_secure_boot(&format!("{}{}", output.stdout, output.stderr))
    } else {
        None
    };
    if is_signature_issue || secure_boot == Some(true) {
        message.push_str(
            " Secure Boot is enabled: the DKMS modules must be signed with a key enrolled in the MOK database (mokutil --import, then confirm on the console at boot).",
        );
    }
    Ok(InternalApiCallOutcome::Failure(message))
}

/// Unload the loaded NVIDIA modules and nouveau, then load `nvidia` and `nvidia_uvm`: the problem
/// preventing it, if any, with the output of the failed modprobe
async fn reload_kernel_module<Handler: HostHandler>(
    host_handler: &mut Handler,
    privilege: &Privilege,
) -> Result<(Option<String>, String), RegentError> {
    let loaded_modules = loaded_kernel_modules(host_handler, privilege).await?;
    let is_loaded = |module: &str| loaded_modules.iter().any(|loaded| loaded == module);
    for module in NVIDIA_MODULES
        .into_iter()
        .filter(|module| is_loaded(module))
    {
        let result = query(
            host_handler,
            &quoted_command(&["modprobe", "-r", module]),
            privilege,
        )
        .await?;
        if result.return_code != 0 {
            return Ok((
                Some(format!(
                    "the loaded NVIDIA kernel module {} is in use and can't be replaced",
                    module
                )),
                format!("{}{}", result.stdout, result.stderr),
            ));
        }
    }
    if is_loaded("nouveau") {
        let result = query(
            host_handler,
            &quoted_command(&["modprobe", "-r", "nouveau"]),
            privilege,
        )
        .await?;
        if result.return_code != 0 {
            return Ok((
                Some("the nouveau driver is in use and can't be unloaded".to_string()),
                format!("{}{}", result.stdout, result.stderr),
            ));
        }
    }
    for module in ["nvidia", "nvidia_uvm"] {
        let result = query(
            host_handler,
            &quoted_command(&["modprobe", module]),
            privilege,
        )
        .await?;
        let output = format!("{}{}", result.stdout, result.stderr);
        if result.return_code != 0 {
            return Ok((
                Some(format!("modprobe {} failed: {}", module, output.trim())),
                output,
            ));
        }
    }
    Ok((None, String::new()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn full_yaml() -> &'static str {
        "---
State: !Present
  KernelModules: !Open 580
  CudaToolkit: '12.8'
  PersistenceMode: true
"
    }

    fn full_config() -> NvidiaDriverConfig {
        let state: NvidiaDriverExpectedState = yaml_serde::from_str(full_yaml()).unwrap();
        match state.state {
            NvidiaDriverState::Present(config) => *config,
            other => panic!("unexpected state {:?}", other),
        }
    }

    fn rejection(raw: &str) -> String {
        match yaml_serde::from_str::<NvidiaDriverExpectedState>(raw) {
            Ok(state) => panic!("should be rejected: {}\nparsed as {:?}", raw, state),
            Err(error) => error.to_string(),
        }
    }

    #[test]
    fn parsing_nvidia_driver_module_block_from_yaml_str() {
        let config = full_config();
        assert_eq!(
            config.kernel_modules,
            KernelModules::Open(DriverBranch::Branch("580".parse().unwrap()))
        );
        assert_eq!(config.cuda_toolkit.unwrap().package(), "cuda-toolkit-12-8");
        assert_eq!(config.persistence_mode, Some(true));

        let raw = "---
- State: Absent
- State: !Present {}
- State: !Present
    KernelModules: !Open Latest
- State: !Present
    KernelModules: !Proprietary 580
    CudaToolkit: 13.0
- State: !Present
    CudaToolkit: 12.10
";
        let states: Vec<NvidiaDriverExpectedState> = yaml_serde::from_str(raw).unwrap();
        assert_eq!(states[0], NvidiaDriverExpectedState::absent());
        assert_eq!(
            states[1],
            NvidiaDriverExpectedState::present(NvidiaDriverConfig::new())
        );
        assert_eq!(states[1], states[2]);
        match &states[3].state {
            NvidiaDriverState::Present(config) => {
                assert_eq!(
                    config.kernel_modules.flavor(),
                    KernelModuleFlavor::Proprietary
                );
                assert_eq!(config.kernel_modules.branch(), Some(580));
                assert_eq!(config.kernel_modules.package(), "cuda-drivers");
                assert_eq!(config.cuda_toolkit.unwrap().to_string(), "13.0");
            }
            other => panic!("unexpected state {:?}", other),
        }
        // Unquoted, YAML would read a float: the version is kept as written
        match &states[4].state {
            NvidiaDriverState::Present(config) => {
                assert_eq!(config.cuda_toolkit.unwrap().package(), "cuda-toolkit-12-10")
            }
            other => panic!("unexpected state {:?}", other),
        }
    }

    #[test]
    fn serialization_round_trip_preserves_state() {
        // Templating (Attribute::consider_context) relies on a JSON round trip
        for raw in [
            full_yaml(),
            "State: Absent\n",
            "State: !Present\n  KernelModules: !Proprietary 570\n",
            "State: !Present {}\n",
        ] {
            let state: NvidiaDriverExpectedState = yaml_serde::from_str(raw).unwrap();
            let json = serde_json::to_string(&state).unwrap();
            assert_eq!(
                serde_json::from_str::<NvidiaDriverExpectedState>(&json).unwrap(),
                state,
                "{}",
                json
            );
        }
    }

    #[test]
    fn invalid_states_are_rejected_while_parsing() {
        let rejected = [
            // Configuration makes no sense for an absent driver
            ("State: !Absent\n  PersistenceMode: true\n", "expected unit"),
            // Proprietary modules need a pinned branch up to 610
            (
                "State: !Present\n  KernelModules: !Proprietary Latest\n",
                "need a pinned branch",
            ),
            (
                "State: !Present\n  KernelModules: !Proprietary 615\n",
                "removed after branch 610",
            ),
            // Branches before 570 use other package names
            (
                "State: !Present\n  KernelModules: !Open 550\n",
                "from 570 on",
            ),
            (
                "State: !Present\n  KernelModules: !Open newest\n",
                "expected Latest or a branch number",
            ),
            // The flavor is mandatory when a branch is given
            ("State: !Present\n  KernelModules: 580\n", "KernelModules"),
            ("State: !Present\n  CudaToolkit: '12'\n", "<major>.<minor>"),
            (
                "State: !Present\n  CudaToolkit: 12.8.1\n",
                "<major>.<minor>",
            ),
            ("State: !Present\n  CudaToolkit: 9.2\n", "<major>.<minor>"),
            ("State: !Present\n  Branch: 580\n", "unknown field"),
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
    }

    #[test]
    fn proprietary_branch_is_built_from_an_integer() {
        let branch = ProprietaryBranch::new(580);
        assert_eq!(branch.number(), 580);
        assert_eq!(u32::from(branch), 580);
        assert_eq!(branch.to_string(), "580");
        assert_eq!(KernelModules::Proprietary(branch).branch(), Some(580));
        assert_eq!(ProprietaryBranch::new(570).number(), 570);
        assert_eq!(ProprietaryBranch::new(610).number(), 610);
    }

    #[test]
    fn kernel_modules_shortcuts_match_the_explicit_form() {
        let with = |kernel_modules| NvidiaDriverConfig::new().with_kernel_modules(kernel_modules);
        assert_eq!(
            NvidiaDriverConfig::new()
                .with_proprietary_kernel_modules(580)
                .unwrap()
                .with_latest_open_kernel_modules(),
            with(KernelModules::Open(DriverBranch::Latest))
        );
        assert_eq!(
            NvidiaDriverConfig::new().with_latest_open_kernel_modules(),
            NvidiaDriverConfig::new()
        );
        assert_eq!(
            NvidiaDriverConfig::new()
                .with_open_kernel_modules(580)
                .unwrap(),
            with(KernelModules::Open(DriverBranch::Branch(
                "580".parse().unwrap()
            )))
        );
        assert_eq!(
            NvidiaDriverConfig::new()
                .with_proprietary_kernel_modules(580)
                .unwrap(),
            with(KernelModules::Proprietary(ProprietaryBranch::new(580)))
        );
        // Open modules exist on every branch from 570 on
        assert!(
            NvidiaDriverConfig::new()
                .with_open_kernel_modules(615)
                .is_ok()
        );
    }

    #[test]
    fn kernel_modules_shortcuts_reject_invalid_branches() {
        let rejected = [
            (
                NvidiaDriverConfig::new().with_open_kernel_modules(550),
                "from 570 on",
            ),
            (
                NvidiaDriverConfig::new().with_proprietary_kernel_modules(550),
                "from 570 on",
            ),
            (
                NvidiaDriverConfig::new().with_proprietary_kernel_modules(615),
                "removed after branch 610",
            ),
        ];
        for (result, reason) in rejected {
            let error = result.unwrap_err().to_string();
            assert!(
                error.contains(reason),
                "rejected for another reason: {}",
                error
            );
        }
    }

    #[test]
    #[should_panic(expected = "proprietary kernel modules branch")]
    fn proprietary_branch_new_panics_on_a_branch_without_proprietary_modules() {
        ProprietaryBranch::new(615);
    }

    #[test]
    fn branch_selection_follows_the_distribution() {
        let open_580 = KernelModules::Open(DriverBranch::Branch("580".parse().unwrap()));
        let proprietary = KernelModules::Proprietary(ProprietaryBranch::new(575));
        let latest = KernelModules::default();
        // On apt, the branch meta package pins the branch: no separate selection
        assert_eq!(open_580.branch_selection(DriverDistro::Ubuntu), None);
        assert_eq!(proprietary.branch_selection(DriverDistro::Debian), None);
        assert_eq!(
            open_580.branch_selection(DriverDistro::RhelModular),
            Some(BranchSelection::ModuleStream(Some("580-open".to_string())))
        );
        assert_eq!(
            latest.branch_selection(DriverDistro::AmazonLinux),
            Some(BranchSelection::ModuleStream(Some("open-dkms".to_string())))
        );
        assert_eq!(
            proprietary.branch_selection(DriverDistro::RhelModular),
            Some(BranchSelection::ModuleStream(Some("575-dkms".to_string())))
        );
        assert_eq!(unpinned_selection(DriverDistro::Ubuntu), None);
        assert_eq!(
            unpinned_selection(DriverDistro::RhelModular),
            Some(BranchSelection::ModuleStream(None))
        );
        assert_eq!(
            latest.branch_selection(DriverDistro::Fedora),
            Some(BranchSelection::VersionLock(None))
        );
    }

    #[test]
    fn install_package_pins_the_branch_on_apt() {
        let open_580 = KernelModules::Open(DriverBranch::Branch("580".parse().unwrap()));
        let proprietary_580 = KernelModules::Proprietary(ProprietaryBranch::new(580));
        let latest = KernelModules::default();
        assert_eq!(
            proprietary_580.install_package(DriverDistro::Ubuntu),
            "nvidia-driver-580"
        );
        assert_eq!(
            open_580.install_package(DriverDistro::Debian),
            "nvidia-driver-580-open"
        );
        assert_eq!(latest.install_package(DriverDistro::Ubuntu), "nvidia-open");
        assert_eq!(latest.install_package(DriverDistro::Fedora), "nvidia-open");
        assert_eq!(
            proprietary_580.install_package(DriverDistro::Fedora),
            "cuda-drivers"
        );
    }

    #[test]
    fn current_branch_selection_is_compared() {
        let stream = CurrentSelection::ModuleStream(Some("580-open".to_string()));
        assert!(stream.matches(&BranchSelection::ModuleStream(Some("580-open".to_string()))));
        assert!(!stream.matches(&BranchSelection::ModuleStream(Some(
            "open-dkms".to_string()
        ))));
        assert!(!stream.matches(&BranchSelection::ModuleStream(None)));
        assert!(
            !CurrentSelection::ModuleStream(None).matches(&BranchSelection::ModuleStream(Some(
                "open-dkms".to_string()
            )))
        );
        assert!(CurrentSelection::ModuleStream(None).matches(&BranchSelection::ModuleStream(None)));

        let locks = CurrentSelection::ZypperLocks(vec![ZypperLock {
            name: "*nvidia*".to_string(),
            version: ">= 581".to_string(),
        }]);
        assert!(locks.matches(&BranchSelection::ZypperLock(Some(580))));
        assert!(!locks.matches(&BranchSelection::ZypperLock(None)));
        assert_eq!(locks.to_undo(), vec!["*nvidia* >= 581"]);
    }

    #[test]
    fn dnf_versionlock_lists_are_parsed() {
        let dnf4 = "Last metadata expiration check: 0:01:02 ago.\nnvidia-open-3:580.105.08-1.el10.*\nlibnvidia-ml-3:580.105.08-1.el10.*\n!kernel-0:6.12.0-55.el10.*\nbash-0:5.2.26-6.el10.*\nnvidia-container-toolkit-0:1.17.8-1.*\n";
        let locks = parse_versionlock_list(dnf4);
        assert_eq!(
            locks,
            vec![
                LockedPackage {
                    name: "nvidia-open".to_string(),
                    version: "580.105.08-1.el10".to_string()
                },
                LockedPackage {
                    name: "libnvidia-ml".to_string(),
                    version: "580.105.08-1.el10".to_string()
                },
            ]
        );
        let current = CurrentSelection::VersionLocks(locks);
        assert!(current.matches(&BranchSelection::VersionLock(Some(580))));
        assert!(!current.matches(&BranchSelection::VersionLock(Some(590))));

        let dnf5 = "# Added by 'versionlock add' command on 2026-05-04 10:12:31\nPackage name: nvidia-open\nevr = 3:590.48.01-1.fc44\n\nPackage name: htop\nevr = 3.3.0-1.fc44\n";
        assert_eq!(
            parse_versionlock_list(dnf5),
            vec![LockedPackage {
                name: "nvidia-open".to_string(),
                version: "3:590.48.01-1.fc44".to_string()
            }]
        );
        assert!(
            CurrentSelection::VersionLocks(parse_versionlock_list(dnf5))
                .matches(&BranchSelection::VersionLock(Some(590)))
        );
    }

    #[test]
    fn zypper_locks_and_module_streams_are_parsed() {
        let locks = "type: package\nmatch_type: glob\ncase_sensitive: on\nsolvable_name: *nvidia*\nversion: >=   581\n\ntype: package\nsolvable_name: kernel-default\n";
        assert_eq!(
            parse_zypper_locks(locks),
            vec![ZypperLock {
                name: "*nvidia*".to_string(),
                version: ">= 581".to_string()
            }]
        );

        let modules = "CUDA and drivers from NVIDIA\nName           Stream            Profiles                      Summary\nnvidia-driver  580-open [e]      default [d], fm, ks, src      Nvidia driver for 580-open branch\n\nHint: [d]efault, [e]nabled, [x]disabled, [i]nstalled\n";
        assert_eq!(
            parse_enabled_module_stream(modules),
            Some("580-open".to_string())
        );
        assert_eq!(
            parse_enabled_module_stream("nvidia-driver  latest-dkms [d][e]  default [d]"),
            Some("latest-dkms".to_string())
        );
        assert_eq!(
            parse_enabled_module_stream("Error: No matching Modules to list"),
            None
        );
    }

    #[test]
    fn branch_selection_commands_are_quoted() {
        assert_eq!(
            branch_selection_commands(
                &BranchSelection::ModuleStream(Some("580-open".to_string())),
                DriverDistro::RhelModular,
                &[]
            ),
            vec![
                "'dnf' '-y' 'module' 'reset' 'nvidia-driver'",
                "'dnf' '-y' 'module' 'enable' 'nvidia-driver:580-open'"
            ]
        );
        assert_eq!(
            branch_selection_commands(
                &BranchSelection::ModuleStream(None),
                DriverDistro::AmazonLinux,
                &[]
            ),
            vec!["'dnf' '-y' 'module' 'reset' 'nvidia-driver'"]
        );
        assert_eq!(
            branch_selection_commands(
                &BranchSelection::VersionLock(Some(580)),
                DriverDistro::Rhel10,
                &["nvidia-open".to_string()]
            ),
            vec![
                "'dnf' '-y' 'install' 'python3-dnf-plugin-versionlock'",
                "'dnf' 'versionlock' 'delete' 'nvidia-open'",
                "'dnf' 'versionlock' 'add' '*nvidia*580*'"
            ]
        );
        assert_eq!(
            branch_selection_commands(
                &BranchSelection::ZypperLock(Some(580)),
                DriverDistro::Suse,
                &["*nvidia* >= 591".to_string()]
            ),
            vec![
                "'zypper' '--non-interactive' 'removelock' '*nvidia* >= 591'",
                "'zypper' '--non-interactive' 'addlock' '*nvidia* >= 581'"
            ]
        );
    }

    #[test]
    fn installed_driver_is_compared_with_the_expected_one() {
        let installed = |packages: &[(&str, &str)]| -> BTreeMap<String, String> {
            packages
                .iter()
                .map(|(name, version)| (name.to_string(), version.to_string()))
                .collect()
        };
        let open_580 = KernelModules::Open(DriverBranch::Branch("580".parse().unwrap()));
        let proprietary_580 = KernelModules::Proprietary(ProprietaryBranch::new(580));

        // dnf/zypper: the floating meta package, kept in the expected branch
        assert_eq!(
            installed_driver_status(&installed(&[]), &open_580, DriverDistro::Fedora),
            InstalledDriver::Missing
        );
        assert_eq!(
            installed_driver_status(
                &installed(&[("nvidia-open", "580.105.08-1ubuntu1")]),
                &open_580,
                DriverDistro::Fedora
            ),
            InstalledDriver::Expected
        );
        assert_eq!(
            installed_driver_status(
                &installed(&[("nvidia-open", "590.48.01-1ubuntu1")]),
                &KernelModules::default(),
                DriverDistro::Fedora
            ),
            InstalledDriver::Expected
        );
        assert!(matches!(
            installed_driver_status(
                &installed(&[("nvidia-open", "590.48.01-1")]),
                &open_580,
                DriverDistro::Fedora
            ),
            InstalledDriver::Different(reason) if reason.contains("expected branch 580")
        ));
        assert!(matches!(
            installed_driver_status(
                &installed(&[("cuda-drivers", "580.105.08-1")]),
                &open_580,
                DriverDistro::Fedora
            ),
            InstalledDriver::Different(reason) if reason.contains("proprietary kernel modules) is installed")
        ));
        assert!(matches!(
            installed_driver_status(
                &installed(&[("nvidia-open", "580.105.08-1")]),
                &proprietary_580,
                DriverDistro::Fedora
            ),
            InstalledDriver::Different(_)
        ));
        // From branch 615, cuda-drivers is a transitional package depending on nvidia-open
        assert_eq!(
            installed_driver_status(
                &installed(&[
                    ("nvidia-open", "615.71.09-1"),
                    ("cuda-drivers", "615.71.09-2")
                ]),
                &KernelModules::default(),
                DriverDistro::Fedora
            ),
            InstalledDriver::Expected
        );

        // apt: the branch meta package pins the branch
        assert_eq!(
            installed_driver_status(
                &installed(&[("nvidia-driver-580", "580.178.04-0ubuntu0.26.04.1")]),
                &proprietary_580,
                DriverDistro::Ubuntu
            ),
            InstalledDriver::Expected
        );
        assert_eq!(
            installed_driver_status(
                &installed(&[("nvidia-driver-580-server", "580.178.04-0ubuntu0.26.04.1")]),
                &proprietary_580,
                DriverDistro::Ubuntu
            ),
            InstalledDriver::Expected
        );
        assert_eq!(
            installed_driver_status(
                &installed(&[("nvidia-driver-580-open", "580.178.04-1")]),
                &open_580,
                DriverDistro::Ubuntu
            ),
            InstalledDriver::Expected
        );
        // The floating meta package is another driver, even in the expected branch
        assert!(matches!(
            installed_driver_status(
                &installed(&[("cuda-drivers", "580.105.08-1")]),
                &proprietary_580,
                DriverDistro::Ubuntu
            ),
            InstalledDriver::Different(reason) if reason.contains("expected nvidia-driver-580")
        ));
        // Another branch, another flavor
        assert!(matches!(
            installed_driver_status(
                &installed(&[("nvidia-driver-575", "575.143.08-1")]),
                &proprietary_580,
                DriverDistro::Ubuntu
            ),
            InstalledDriver::Different(reason) if reason.contains("nvidia-driver-575")
        ));
        assert!(matches!(
            installed_driver_status(
                &installed(&[("nvidia-driver-580-open", "580.178.04-1")]),
                &proprietary_580,
                DriverDistro::Ubuntu
            ),
            InstalledDriver::Different(reason) if reason.contains("expected nvidia-driver-580")
        ));
        // Latest branch: the floating meta package, not a branch meta package
        assert_eq!(
            installed_driver_status(
                &installed(&[("nvidia-open", "615.71.09-1")]),
                &KernelModules::default(),
                DriverDistro::Ubuntu
            ),
            InstalledDriver::Expected
        );
        assert!(matches!(
            installed_driver_status(
                &installed(&[("nvidia-driver-580", "580.178.04-1")]),
                &KernelModules::default(),
                DriverDistro::Ubuntu
            ),
            InstalledDriver::Different(reason) if reason.contains("expected nvidia-open")
        ));
        // Pinning packages and other nvidia-driver-* packages are not driver meta packages
        assert_eq!(
            installed_driver_status(
                &installed(&[("nvidia-driver-pinning-580", "580.105.08")]),
                &proprietary_580,
                DriverDistro::Ubuntu
            ),
            InstalledDriver::Missing
        );
    }

    #[test]
    fn driver_removal_keeps_the_container_toolkit() {
        let installed = [
            "nvidia-open",
            "nvidia-driver-580-open",
            "nvidia-driver-pinning-580",
            "nvidia-container-toolkit",
            "libnvidia-container1",
            "libnvidia-compute-580",
        ]
        .map(String::from);
        assert_eq!(
            driver_packages_to_remove(installed.iter()),
            vec![
                "nvidia-open",
                "nvidia-driver-580-open",
                "nvidia-driver-pinning-580",
                "libnvidia-compute-580"
            ]
        );
    }

    #[test]
    fn runtime_issues_tell_when_a_reload_or_reboot_is_needed() {
        let open_580 = LoadedDriver {
            version: "580.105.08".to_string(),
            flavor: KernelModuleFlavor::Open,
        };
        let working = parse_smi(0, "580.105.08\n580.105.08\n");
        assert_eq!(working, SmiStatus::Working("580.105.08".to_string()));
        assert_eq!(
            runtime_issue(
                Some(&open_580),
                &working,
                KernelModuleFlavor::Open,
                Some(580)
            ),
            None
        );
        assert_eq!(
            runtime_issue(Some(&open_580), &working, KernelModuleFlavor::Open, None),
            None
        );
        assert!(
            runtime_issue(None, &working, KernelModuleFlavor::Open, None)
                .unwrap()
                .contains("not loaded")
        );
        assert!(
            runtime_issue(
                Some(&open_580),
                &working,
                KernelModuleFlavor::Proprietary,
                Some(580)
            )
            .unwrap()
            .contains("the open kernel module is loaded")
        );
        assert!(
            runtime_issue(
                Some(&open_580),
                &working,
                KernelModuleFlavor::Open,
                Some(590)
            )
            .unwrap()
            .contains("expected branch 590")
        );
        let mismatch = parse_smi(
            18,
            "Failed to initialize NVML: Driver/library version mismatch\nNVML library version: 580.126\n",
        );
        assert_eq!(mismatch, SmiStatus::VersionMismatch);
        assert!(
            runtime_issue(Some(&open_580), &mismatch, KernelModuleFlavor::Open, None)
                .unwrap()
                .contains("version mismatch")
        );
        assert!(matches!(
            parse_smi(
                9,
                "NVIDIA-SMI has failed because it couldn't communicate with the NVIDIA driver."
            ),
            SmiStatus::Failing(_)
        ));
    }

    #[test]
    fn gpus_and_secure_boot_are_detected() {
        let devices = |nvidia_class: &str| {
            format!(
                "/sys/bus/pci/devices/0000:00:00.0/vendor:0x8086\n/sys/bus/pci/devices/0000:01:00.0/vendor:0x10de\n/sys/bus/pci/devices/0000:00:00.0/class:0x060000\n/sys/bus/pci/devices/0000:01:00.0/class:{}\n",
                nvidia_class
            )
        };
        assert!(has_nvidia_gpu(&devices("0x030200")));
        assert!(!has_nvidia_gpu(&devices("0x040300")));
        assert_eq!(parse_secure_boot("SecureBoot enabled\n"), Some(true));
        assert_eq!(
            parse_secure_boot("SecureBoot disabled\nPlatform is in Setup Mode"),
            Some(false)
        );
        assert_eq!(
            parse_secure_boot("EFI variables are not supported on this system"),
            None
        );
    }

    #[test]
    fn persistence_mode_handles_static_and_masked_units() {
        let state = |enablement, active| UnitState { enablement, active };
        let static_stopped = state(UnitEnablement::Static, false);
        assert!(is_persistence_mode_set(&static_stopped, false));
        assert!(!is_persistence_mode_set(&static_stopped, true));
        assert_eq!(
            persistence_mode_commands(&static_stopped, true),
            vec!["'systemctl' 'start' 'nvidia-persistenced'"]
        );
        assert_eq!(
            persistence_mode_commands(&state(UnitEnablement::Static, true), false),
            vec!["'systemctl' 'stop' 'nvidia-persistenced'"]
        );
        assert_eq!(
            persistence_mode_commands(&state(UnitEnablement::Masked, false), true),
            vec![
                "'systemctl' 'unmask' 'nvidia-persistenced'",
                "'systemctl' 'enable' 'nvidia-persistenced'",
                "'systemctl' 'start' 'nvidia-persistenced'"
            ]
        );
        assert_eq!(
            persistence_mode_commands(&state(UnitEnablement::Enabled, true), false),
            vec![
                "'systemctl' 'disable' 'nvidia-persistenced'",
                "'systemctl' 'stop' 'nvidia-persistenced'"
            ]
        );
        assert!(is_persistence_mode_set(&UnitState::default(), false));
    }

    #[test]
    fn display_explains_remediations() {
        let api_call = NvidiaDriverApiCall::from(
            NvidiaDriverInternalApiCall::LoadKernelModule {
                flavor: KernelModuleFlavor::Open,
                branch: None,
                reason: "nvidia-open is being installed".to_string(),
            },
            Privilege::WithSudo,
        );
        assert!(api_call.display().contains("reboot is required"));
        assert_eq!(api_call.default_timeout(), Duration::from_secs(300));
    }
}
