use crate::error::RegentError;
use crate::hosts::command::CommandResult;
use crate::hosts::managed_host::InternalApiCallOutcome;
use crate::hosts::properties::{HostProperties, LinuxFlavor, OsKind};
use crate::state::attribute::HostHandler;
use crate::state::attribute::Privilege;
use crate::state::attribute::container::container_spec::quoted_command;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub enum PackageFamily {
    /// `apt-get` / `dpkg` (Ubuntu, Debian)
    Apt,
    /// `dnf` / `rpm` (RHEL and rebuilds, Fedora, Amazon Linux)
    Dnf,
    /// `zypper` / `rpm` (SLES, openSUSE)
    Zypper,
}

impl fmt::Display for PackageFamily {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PackageFamily::Apt => write!(f, "apt"),
            PackageFamily::Dnf => write!(f, "dnf"),
            PackageFamily::Zypper => write!(f, "zypper"),
        }
    }
}

impl PackageFamily {
    /// Directories (or files) holding the repository definitions
    pub(crate) fn repository_locations(&self) -> &'static [&'static str] {
        match self {
            PackageFamily::Apt => &["/etc/apt/sources.list", "/etc/apt/sources.list.d"],
            PackageFamily::Dnf => &["/etc/yum.repos.d"],
            PackageFamily::Zypper => &["/etc/zypp/repos.d"],
        }
    }

    /// Command telling (through its return code) whether a repository mentioning `url` is defined
    pub(crate) fn repository_check_command(&self, url: &str) -> String {
        let mut args = vec!["grep", "-rlsF", url];
        args.extend(self.repository_locations());
        quoted_command(&args)
    }

    /// Command listing the installed packages matching the given names or glob patterns.
    /// Its output is parsed by [`parse_installed_packages`].
    pub(crate) fn installed_packages_command(&self, patterns: &[&str]) -> String {
        let mut args = match self {
            PackageFamily::Apt => vec![
                "dpkg-query",
                "-W",
                "-f=${Package} ${Version} ${db:Status-Abbrev}\\n",
            ],
            PackageFamily::Dnf | PackageFamily::Zypper => {
                vec!["rpm", "-qa", "--qf", "%{NAME} %{VERSION}-%{RELEASE} ii\\n"]
            }
        };
        args.extend(patterns);
        quoted_command(&args)
    }

    /// Commands installing packages non interactively, after refreshing the apt package lists
    /// (dnf and zypper refresh expired metadata themselves)
    pub(crate) fn install_commands(
        &self,
        packages: &[String],
        allow_downgrade: bool,
    ) -> Vec<String> {
        let mut commands = Vec::new();
        if *self == PackageFamily::Apt {
            commands.push(quoted_command(&["apt-get", "update"]));
        }
        commands.push(self.install_command(packages, allow_downgrade));
        commands
    }

    pub(crate) fn install_command(&self, packages: &[String], allow_downgrade: bool) -> String {
        let mut args: Vec<&str> = match self {
            PackageFamily::Apt => vec!["apt-get", "install", "-y"],
            PackageFamily::Dnf if allow_downgrade => vec!["dnf", "-y", "downgrade"],
            PackageFamily::Dnf => vec!["dnf", "-y", "install"],
            PackageFamily::Zypper => vec![
                "zypper",
                "--non-interactive",
                "--gpg-auto-import-keys",
                "install",
                "--force-resolution",
            ],
        };
        if allow_downgrade {
            match self {
                PackageFamily::Apt => args.push("--allow-downgrades"),
                PackageFamily::Zypper => args.push("--oldpackage"),
                PackageFamily::Dnf => {}
            }
        }
        args.extend(packages.iter().map(String::as_str));
        let command = quoted_command(&args);
        match self {
            PackageFamily::Apt => format!("DEBIAN_FRONTEND=noninteractive {}", command),
            _ => command,
        }
    }

    /// Command removing packages non interactively
    pub(crate) fn remove_command(&self, packages: &[String]) -> String {
        let mut args: Vec<&str> = match self {
            PackageFamily::Apt => vec!["apt-get", "remove", "--autoremove", "--purge", "-y"],
            PackageFamily::Dnf => vec!["dnf", "-y", "remove"],
            PackageFamily::Zypper => vec!["zypper", "--non-interactive", "remove"],
        };
        args.extend(packages.iter().map(String::as_str));
        let command = quoted_command(&args);
        match self {
            PackageFamily::Apt => format!("DEBIAN_FRONTEND=noninteractive {}", command),
            _ => command,
        }
    }
}

/// Content of `/etc/os-release` (only the fields used to pick the NVIDIA repository)
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct OsRelease {
    /// `ID` (e.g. `ubuntu`, `rhel`, `rocky`, `sles`)
    pub id: String,
    /// `ID_LIKE`, split on whitespace
    pub id_like: Vec<String>,
    /// `VERSION_ID` (e.g. `24.04`, `9.4`, `2023`)
    pub version_id: String,
    /// `PRETTY_NAME`, for messages
    pub pretty_name: String,
}

impl OsRelease {
    /// Major version (`VERSION_ID` up to the first dot)
    pub fn major_version(&self) -> &str {
        self.version_id
            .split('.')
            .next()
            .unwrap_or(&self.version_id)
    }

    fn description(&self) -> String {
        if self.pretty_name.is_empty() {
            format!("{} {}", self.id, self.version_id)
        } else {
            self.pretty_name.clone()
        }
    }
}

/// Parse the content of `/etc/os-release` (values may be quoted or not)
pub fn parse_os_release(content: &str) -> OsRelease {
    let mut os_release = OsRelease::default();
    for line in content.lines() {
        let Some((key, value)) = line.trim().split_once('=') else {
            continue;
        };
        let value = value.trim().trim_matches(|c| c == '"' || c == '\'');
        match key {
            "ID" => os_release.id = value.to_lowercase(),
            "ID_LIKE" => {
                os_release.id_like = value.split_whitespace().map(str::to_lowercase).collect()
            }
            "VERSION_ID" => os_release.version_id = value.to_string(),
            "PRETTY_NAME" => os_release.pretty_name = value.to_string(),
            _ => {}
        }
    }
    os_release
}

/// Package manager of a Linux distribution, from the `ID` and `ID_LIKE` of `/etc/os-release`
pub fn package_family(os_release: &OsRelease) -> Option<PackageFamily> {
    std::iter::once(&os_release.id)
        .chain(&os_release.id_like)
        .find_map(|id| match id.as_str() {
            "debian" | "ubuntu" => Some(PackageFamily::Apt),
            "rhel" | "fedora" | "centos" | "rocky" | "almalinux" | "ol" | "amzn" => {
                Some(PackageFamily::Dnf)
            }
            "suse" | "sles" | "sled" | "opensuse" | "opensuse-leap" | "opensuse-tumbleweed" => {
                Some(PackageFamily::Zypper)
            }
            _ => None,
        })
}

/// CPU architecture as named in the NVIDIA CUDA repositories
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub enum CudaArch {
    X86_64,
    /// `sbsa`: 64-bit ARM servers (Arm SBSA, e.g. Grace). Jetson boards use JetPack instead.
    Sbsa,
}

impl CudaArch {
    pub fn repo_name(&self) -> &'static str {
        match self {
            CudaArch::X86_64 => "x86_64",
            CudaArch::Sbsa => "sbsa",
        }
    }
}

/// Map the output of `uname -m` to a CUDA repository architecture
pub fn parse_machine_arch(uname_m: &str) -> Result<CudaArch, String> {
    match uname_m.trim() {
        "x86_64" | "amd64" => Ok(CudaArch::X86_64),
        "aarch64" | "arm64" => Ok(CudaArch::Sbsa),
        other => Err(format!(
            "CPU architecture {:?} is not supported by the NVIDIA CUDA repositories (x86_64 and aarch64 only)",
            other
        )),
    }
}

/// How the NVIDIA driver packages are installed and how a driver branch is selected,
/// following the NVIDIA Driver Installation Guide
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub enum DriverDistro {
    /// Ubuntu 22.04 / 24.04 / 26.04: branch pinned by installing its meta package
    /// `nvidia-driver-<branch>[-open]`
    Ubuntu,
    /// Debian 12 / 13: branch pinned by installing its meta package
    /// `nvidia-driver-<branch>[-open]`
    Debian,
    /// RHEL-compatible 8 and 9 (RHEL, Rocky, AlmaLinux, Oracle Linux, CentOS Stream):
    /// branch selected with the `nvidia-driver` DNF module stream
    RhelModular,
    /// Amazon Linux 2023: branch selected with the `nvidia-driver` DNF module stream
    AmazonLinux,
    /// RHEL-compatible 10 (DNF 4): branch locked with the versionlock plugin
    Rhel10,
    /// Fedora (DNF 5): branch locked with `dnf versionlock`
    Fedora,
    /// SLES / openSUSE Leap: branch locked with a zypper lock
    Suse,
}

impl DriverDistro {
    pub fn package_family(&self) -> PackageFamily {
        match self {
            DriverDistro::Ubuntu | DriverDistro::Debian => PackageFamily::Apt,
            DriverDistro::RhelModular
            | DriverDistro::AmazonLinux
            | DriverDistro::Rhel10
            | DriverDistro::Fedora => PackageFamily::Dnf,
            DriverDistro::Suse => PackageFamily::Zypper,
        }
    }

    /// Kernel development packages DKMS needs to build the modules for `kernel_release` (`uname -r`)
    pub fn kernel_headers_packages(&self, kernel_release: &str) -> Vec<String> {
        match self {
            DriverDistro::Ubuntu | DriverDistro::Debian => {
                vec![format!("linux-headers-{}", kernel_release)]
            }
            DriverDistro::RhelModular => vec![
                format!("kernel-devel-{}", kernel_release),
                "kernel-headers".to_string(),
            ],
            DriverDistro::AmazonLinux => vec![
                format!("kernel-devel-{}", kernel_release),
                format!("kernel-headers-{}", kernel_release),
            ],
            DriverDistro::Rhel10 | DriverDistro::Fedora => vec![
                "kernel-devel-matched".to_string(),
                "kernel-headers".to_string(),
            ],
            DriverDistro::Suse => {
                // 6.4.0-150600.23.25-default -> kernel-default-devel=6.4.0-150600.23.25
                match kernel_release.rsplit_once('-') {
                    Some((version, variant))
                        if !variant.is_empty() && !variant.starts_with(char::is_numeric) =>
                    {
                        vec![format!("kernel-{}-devel={}", variant, version)]
                    }
                    _ => vec!["kernel-default-devel".to_string()],
                }
            }
        }
    }
}

/// NVIDIA CUDA network repository matching the host
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct CudaRepository {
    /// Distribution name in the repository URL (e.g. `ubuntu2404`, `rhel9`)
    pub distro_name: String,
    pub arch: CudaArch,
    pub distro: DriverDistro,
}

pub(crate) const CUDA_REPOS_URL: &str = "https://developer.download.nvidia.com/compute/cuda/repos";

impl CudaRepository {
    /// `https://developer.download.nvidia.com/compute/cuda/repos/<distro>/<arch>/`
    pub fn base_url(&self) -> String {
        format!(
            "{}/{}/{}/",
            CUDA_REPOS_URL,
            self.distro_name,
            self.arch.repo_name()
        )
    }

    /// Part of the URL looked for in the repository definitions
    pub fn url_fragment(&self) -> String {
        format!(
            "developer.download.nvidia.com/compute/cuda/repos/{}/{}",
            self.distro_name,
            self.arch.repo_name()
        )
    }

    /// Configure the repository (cuda-keyring for apt, `.repo` file for dnf and zypper)
    pub(crate) async fn setup<Handler: HostHandler>(
        &self,
        host_handler: &mut Handler,
        privilege: &Privilege,
    ) -> Result<InternalApiCallOutcome, RegentError> {
        let family = self.distro.package_family();
        if family != PackageFamily::Apt {
            return add_repo_file(
                host_handler,
                family,
                &format!("{}cuda-{}.repo", self.base_url(), self.distro_name),
                &format!("cuda-{}.repo", self.distro_name),
                privilege,
            )
            .await;
        }
        let tmp = match make_temp_dir(host_handler, privilege).await? {
            Ok(tmp) => tmp,
            Err(failure) => return Ok(failure),
        };
        let keyring = format!("{}/cuda-keyring.deb", tmp);
        let mut outcome = download(
            host_handler,
            &format!("{}cuda-keyring_1.1-1_all.deb", self.base_url()),
            &keyring,
            privilege,
        )
        .await;
        if is_success(&outcome) {
            outcome = run_steps(
                host_handler,
                &[
                    quoted_command(&["dpkg", "-i", &keyring]),
                    quoted_command(&["apt-get", "update"]),
                ],
                privilege,
            )
            .await;
        }
        remove_temp_dir(host_handler, &tmp, privilege).await;
        Ok(outcome)
    }
}

const SUPPORTED_DISTROS: &str = "Ubuntu 22.04/24.04/26.04, Debian 12/13, RHEL/Rocky/AlmaLinux/Oracle Linux/CentOS Stream 8/9/10, Fedora 42/43/44, Amazon Linux 2023, SLES 15/16, openSUSE Leap 15";

/// Pick the NVIDIA CUDA repository for a host from its `/etc/os-release` and `uname -m`
pub fn cuda_repository(os_release: &OsRelease, uname_m: &str) -> Result<CudaRepository, String> {
    let arch = parse_machine_arch(uname_m)?;
    let major = os_release.major_version();
    let unsupported = || {
        format!(
            "{} is not supported by the NVIDIA CUDA network repository (supported: {})",
            os_release.description(),
            SUPPORTED_DISTROS
        )
    };

    let (distro_name, distro) = match os_release.id.as_str() {
        "ubuntu" => match os_release.version_id.as_str() {
            "22.04" | "24.04" | "26.04" => (
                format!("ubuntu{}", os_release.version_id.replace('.', "")),
                DriverDistro::Ubuntu,
            ),
            _ => return Err(unsupported()),
        },
        "debian" => match major {
            "12" | "13" => (format!("debian{}", major), DriverDistro::Debian),
            _ => return Err(unsupported()),
        },
        "fedora" => match major {
            "42" | "43" | "44" => (format!("fedora{}", major), DriverDistro::Fedora),
            _ => return Err(unsupported()),
        },
        "amzn" => match major {
            "2023" => ("amzn2023".to_string(), DriverDistro::AmazonLinux),
            _ => return Err(unsupported()),
        },
        "sles" | "sled" => match major {
            "15" | "16" => (format!("sles{}", major), DriverDistro::Suse),
            _ => return Err(unsupported()),
        },
        "opensuse-leap" => match major {
            "15" => ("opensuse15".to_string(), DriverDistro::Suse),
            _ => return Err(unsupported()),
        },
        "rhel" | "rocky" | "almalinux" | "ol" | "centos" => {
            rhel_like(major).ok_or_else(unsupported)?
        }
        // Other RHEL rebuilds
        _ if os_release.id_like.iter().any(|id| id == "rhel") => {
            rhel_like(major).ok_or_else(unsupported)?
        }
        _ => return Err(unsupported()),
    };

    Ok(CudaRepository {
        distro_name,
        arch,
        distro,
    })
}

fn rhel_like(major: &str) -> Option<(String, DriverDistro)> {
    match major {
        "8" | "9" => Some((format!("rhel{}", major), DriverDistro::RhelModular)),
        "10" => Some(("rhel10".to_string(), DriverDistro::Rhel10)),
        _ => None,
    }
}

/// Parse the output of [`PackageFamily::installed_packages_command`]: installed package name -> version.
///
/// Lines are `<name> <version> <status>`; a package is installed when the second letter of
/// its dpkg status is `i` (`ii`, `hi`). Other lines (warnings, "no packages found") are ignored.
pub fn parse_installed_packages(output: &str) -> BTreeMap<String, String> {
    output
        .lines()
        .filter_map(|line| {
            let mut parts = line.split_whitespace();
            let (name, version, status) = (parts.next()?, parts.next()?, parts.next()?);
            let is_installed = status.chars().nth(1) == Some('i');
            let is_version = version.starts_with(|c: char| c.is_ascii_digit());
            (is_installed && is_version && parts.next().is_none())
                .then(|| (name.to_string(), version.to_string()))
        })
        .collect()
}

/// Upstream part of a package version: `1:580.105.08-1ubuntu1` -> `580.105.08`
pub fn upstream_version(version: &str) -> &str {
    let without_epoch = version.split_once(':').map_or(version, |(_, rest)| rest);
    without_epoch
        .split_once('-')
        .map_or(without_epoch, |(upstream, _)| upstream)
}

/// `systemctl is-enabled` of a unit
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum UnitEnablement {
    #[default]
    NotFound,
    Enabled,
    Disabled,
    /// `static`, `indirect`, `generated` or `transient`: started by other units, `systemctl
    /// enable` and `systemctl disable` have no effect
    Static,
    Masked,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct UnitState {
    pub enablement: UnitEnablement,
    pub active: bool,
}

impl UnitState {
    pub fn exists(&self) -> bool {
        self.enablement != UnitEnablement::NotFound
    }
}

/// Parse the outputs of `systemctl is-enabled <unit>` and `systemctl is-active <unit>`. A missing
/// unit prints an error (possibly folded into the output by the handler) instead of a state.
pub fn parse_unit_state(is_enabled_output: &str, is_active_output: &str) -> UnitState {
    let last_line = |output: &str| {
        output
            .lines()
            .map(str::trim)
            .rfind(|line| !line.is_empty())
            .unwrap_or_default()
            .to_string()
    };
    let enablement = match last_line(is_enabled_output).as_str() {
        "enabled" | "enabled-runtime" | "alias" | "linked" | "linked-runtime" => {
            UnitEnablement::Enabled
        }
        "disabled" => UnitEnablement::Disabled,
        "static" | "indirect" | "generated" | "transient" => UnitEnablement::Static,
        "masked" | "masked-runtime" => UnitEnablement::Masked,
        _ => UnitEnablement::NotFound,
    };
    let active = matches!(last_line(is_active_output).as_str(), "active" | "reloading");
    UnitState { enablement, active }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub enum KernelModuleFlavor {
    /// Open GPU kernel modules (MIT/GPLv2)
    Open,
    /// Proprietary (closed source) kernel modules
    Proprietary,
}

impl fmt::Display for KernelModuleFlavor {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            KernelModuleFlavor::Open => write!(f, "open"),
            KernelModuleFlavor::Proprietary => write!(f, "proprietary"),
        }
    }
}

/// NVIDIA kernel module currently loaded
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LoadedDriver {
    /// Driver version (e.g. `580.105.08`)
    pub version: String,
    pub flavor: KernelModuleFlavor,
}

/// Path of the file describing the loaded NVIDIA kernel module
pub(crate) const PROC_DRIVER_VERSION: &str = "/proc/driver/nvidia/version";

/// Parse `/proc/driver/nvidia/version`:
///
/// ```text
/// NVRM version: NVIDIA UNIX Open Kernel Module for x86_64  580.105.08  Release Build  (dvs-builder@U16-I3-B03-4-3)  Thu Oct 30 2025
/// NVRM version: NVIDIA UNIX x86_64 Kernel Module  550.54.14  Thu Feb 22 01:44:30 UTC 2024
/// ```
pub fn parse_loaded_driver(proc_version: &str) -> Option<LoadedDriver> {
    let line = proc_version
        .lines()
        .find(|line| line.trim_start().starts_with("NVRM version:"))?;
    let version = line.split_whitespace().find(|token| {
        let parts: Vec<&str> = token.split('.').collect();
        parts.len() >= 2
            && parts
                .iter()
                .all(|part| !part.is_empty() && part.chars().all(|c| c.is_ascii_digit()))
    })?;
    Some(LoadedDriver {
        version: version.to_string(),
        flavor: if line.contains("Open Kernel Module") {
            KernelModuleFlavor::Open
        } else {
            KernelModuleFlavor::Proprietary
        },
    })
}

/// Read the loaded NVIDIA driver, `None` if the module is not loaded
pub(crate) async fn loaded_driver<Handler: HostHandler>(
    host_handler: &mut Handler,
    privilege: &Privilege,
) -> Result<Option<LoadedDriver>, RegentError> {
    let result = query(
        host_handler,
        &quoted_command(&["cat", PROC_DRIVER_VERSION]),
        privilege,
    )
    .await?;
    if result.return_code != 0 {
        return Ok(None);
    }
    Ok(parse_loaded_driver(&result.stdout))
}

/// Linux only: other OS kinds are rejected
pub(crate) fn check_linux_host(
    host_properties: &HostProperties,
    attribute: &str,
) -> Result<(), RegentError> {
    match host_properties.os_kind() {
        OsKind::Linux(specifics) => match specifics.linux_flavor {
            LinuxFlavor::Arch | LinuxFlavor::Gentoo => Err(RegentError::IncompatibleHost(format!(
                "Host is {:?} Linux but {} only supports distributions with an NVIDIA network repository (apt, dnf or zypper based)",
                specifics.linux_flavor, attribute
            ))),
            _ => Ok(()),
        },
        incompatible_os_kind => Err(RegentError::IncompatibleHost(format!(
            "Host is {:?} but {} is only supported on Linux",
            incompatible_os_kind, attribute
        ))),
    }
}

/// Run a read-only command during assessment. Only a failure to run the command is an error:
/// the caller interprets the return code.
pub(crate) async fn query<Handler: HostHandler>(
    host_handler: &mut Handler,
    command: &str,
    privilege: &Privilege,
) -> Result<CommandResult, RegentError> {
    host_handler
        .run_command(command, privilege)
        .await
        .map_err(|e| {
            RegentError::FailedDryRunEvaluation(format!("Unable to run {:?}: {:?}", command, e))
        })
}

/// Run a command during assessment and return its output, failing on a non-zero return code
pub(crate) async fn query_output<Handler: HostHandler>(
    host_handler: &mut Handler,
    command: &str,
    privilege: &Privilege,
) -> Result<String, RegentError> {
    let result = query(host_handler, command, privilege).await?;
    if result.return_code != 0 {
        return Err(RegentError::FailedDryRunEvaluation(format!(
            "{:?} failed (RC {}): {}{}",
            command, result.return_code, result.stdout, result.stderr
        )));
    }
    Ok(result.stdout)
}

/// Installed packages matching the given names or glob patterns: name -> version
pub(crate) async fn installed_packages<Handler: HostHandler>(
    host_handler: &mut Handler,
    family: PackageFamily,
    patterns: &[&str],
    privilege: &Privilege,
) -> Result<BTreeMap<String, String>, RegentError> {
    // dpkg-query returns 1 when a pattern matches nothing: the output is what matters
    let result = query(
        host_handler,
        &family.installed_packages_command(patterns),
        privilege,
    )
    .await?;
    Ok(parse_installed_packages(&result.stdout))
}

pub(crate) async fn is_repository_configured<Handler: HostHandler>(
    host_handler: &mut Handler,
    family: PackageFamily,
    url_fragment: &str,
    privilege: &Privilege,
) -> Result<bool, RegentError> {
    let result = query(
        host_handler,
        &family.repository_check_command(url_fragment),
        privilege,
    )
    .await?;
    Ok(result.return_code == 0 && !result.stdout.trim().is_empty())
}

pub(crate) async fn unit_state<Handler: HostHandler>(
    host_handler: &mut Handler,
    unit: &str,
    privilege: &Privilege,
) -> Result<UnitState, RegentError> {
    // Both commands return non-zero for disabled or inactive units: the output is what matters
    let is_enabled = query(
        host_handler,
        &quoted_command(&["systemctl", "is-enabled", unit]),
        privilege,
    )
    .await?;
    let is_active = query(
        host_handler,
        &quoted_command(&["systemctl", "is-active", unit]),
        privilege,
    )
    .await?;
    Ok(parse_unit_state(&is_enabled.stdout, &is_active.stdout))
}

/// Names of the loaded kernel modules, from `/proc/modules`
pub(crate) async fn loaded_kernel_modules<Handler: HostHandler>(
    host_handler: &mut Handler,
    privilege: &Privilege,
) -> Result<Vec<String>, RegentError> {
    let modules = query_output(
        host_handler,
        &quoted_command(&["cat", "/proc/modules"]),
        privilege,
    )
    .await?;
    Ok(parse_proc_modules(&modules))
}

pub fn parse_proc_modules(content: &str) -> Vec<String> {
    content
        .lines()
        .filter_map(|line| line.split_whitespace().next())
        .map(str::to_string)
        .collect()
}

/// Package family of the host, from `/etc/os-release`
pub(crate) async fn host_package_family<Handler: HostHandler>(
    host_handler: &mut Handler,
    privilege: &Privilege,
) -> Result<Option<PackageFamily>, RegentError> {
    let os_release = parse_os_release(
        &query_output(
            host_handler,
            &quoted_command(&["cat", "/etc/os-release"]),
            privilege,
        )
        .await?,
    );
    Ok(package_family(&os_release))
}

/// Download `url` to `destination` with curl, or wget if curl is missing
pub(crate) async fn download<Handler: HostHandler>(
    host_handler: &mut Handler,
    url: &str,
    destination: &str,
    privilege: &Privilege,
) -> InternalApiCallOutcome {
    let has_curl = host_handler
        .is_this_command_available("curl", privilege)
        .await
        .unwrap_or(false);
    let command = if has_curl {
        quoted_command(&["curl", "-fsSL", "-o", destination, url])
    } else {
        quoted_command(&["wget", "-q", "-O", destination, url])
    };
    run_step(host_handler, &command, privilege).await
}

/// Create a private temporary directory: its path, or the failure outcome
pub(crate) async fn make_temp_dir<Handler: HostHandler>(
    host_handler: &mut Handler,
    privilege: &Privilege,
) -> Result<Result<String, InternalApiCallOutcome>, RegentError> {
    let result = query(host_handler, &quoted_command(&["mktemp", "-d"]), privilege).await?;
    let path = result.stdout.trim();
    if result.return_code != 0 || !path.starts_with('/') || path.contains(char::is_whitespace) {
        return Ok(Err(InternalApiCallOutcome::Failure(format!(
            "mktemp -d failed (RC {}): {}{}",
            result.return_code, result.stdout, result.stderr
        ))));
    }
    Ok(Ok(path.to_string()))
}

/// Best effort: a leftover temporary directory doesn't change the outcome
pub(crate) async fn remove_temp_dir<Handler: HostHandler>(
    host_handler: &mut Handler,
    path: &str,
    privilege: &Privilege,
) {
    let _ = host_handler
        .run_command(&quoted_command(&["rm", "-rf", path]), privilege)
        .await;
}

/// Add a repository described by a `.repo` file (dnf and zypper)
pub(crate) async fn add_repo_file<Handler: HostHandler>(
    host_handler: &mut Handler,
    family: PackageFamily,
    repo_file_url: &str,
    repo_file_name: &str,
    privilege: &Privilege,
) -> Result<InternalApiCallOutcome, RegentError> {
    Ok(match family {
        PackageFamily::Apt => InternalApiCallOutcome::Failure(
            "apt repositories are not described by a .repo file".to_string(),
        ),
        PackageFamily::Dnf => {
            let outcome = download(
                host_handler,
                repo_file_url,
                &format!("/etc/yum.repos.d/{}", repo_file_name),
                privilege,
            )
            .await;
            if !is_success(&outcome) {
                return Ok(outcome);
            }
            run_step(
                host_handler,
                &quoted_command(&["dnf", "clean", "expire-cache"]),
                privilege,
            )
            .await
        }
        PackageFamily::Zypper => {
            run_steps(
                host_handler,
                &[
                    quoted_command(&["zypper", "--non-interactive", "addrepo", repo_file_url]),
                    quoted_command(&[
                        "zypper",
                        "--non-interactive",
                        "--gpg-auto-import-keys",
                        "refresh",
                    ]),
                ],
                privilege,
            )
            .await
        }
    })
}

pub(crate) fn is_success(outcome: &InternalApiCallOutcome) -> bool {
    !matches!(outcome, InternalApiCallOutcome::Failure(_))
}

/// Run a remediation command: a non-zero return code is a failure carrying the output
pub(crate) async fn run_step<Handler: HostHandler>(
    host_handler: &mut Handler,
    command: &str,
    privilege: &Privilege,
) -> InternalApiCallOutcome {
    match host_handler.run_command(command, privilege).await {
        Ok(result) if result.return_code == 0 => InternalApiCallOutcome::Success(None),
        Ok(result) => InternalApiCallOutcome::Failure(format!(
            "RC: {}, STDOUT: {}, STDERR: {}",
            result.return_code, result.stdout, result.stderr
        )),
        Err(e) => InternalApiCallOutcome::Failure(format!("Command execution failed: {:?}", e)),
    }
}

/// Run remediation commands in order, stopping at the first failure
pub(crate) async fn run_steps<Handler: HostHandler>(
    host_handler: &mut Handler,
    commands: &[String],
    privilege: &Privilege,
) -> InternalApiCallOutcome {
    for command in commands {
        let outcome = run_step(host_handler, command, privilege).await;
        if let InternalApiCallOutcome::Failure(_) = outcome {
            return outcome;
        }
    }
    InternalApiCallOutcome::Success(None)
}

/// Packages of the NVIDIA Container Toolkit, never removed with the driver
pub(crate) fn is_container_toolkit_package(name: &str) -> bool {
    name.starts_with("nvidia-container") || name.starts_with("libnvidia-container")
}
