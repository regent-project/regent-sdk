//! Host inspection helpers shared by the GPU attributes
//!
//! [`HostProperties`](crate::hosts::properties::HostProperties) is optional and coarse (Ubuntu is
//! reported as a Debian flavor), so the GPU attributes detect what they need at assessment time:
//! `/etc/os-release`, `uname -m`, `uname -r`, installed packages, systemd units and the loaded
//! NVIDIA kernel module. The parsing is done by pure functions, tested without any host.
//!
//! Every value placed in a command is quoted with [`shell_quote`]. Multi-step scripts are run with
//! `sh -c` so they behave the same whatever the login shell of the connected user.

use crate::error::RegentError;
use crate::hosts::command::CommandResult;
use crate::hosts::handlers::shell_quote;
use crate::hosts::managed_host::InternalApiCallOutcome;
use crate::hosts::properties::{HostProperties, LinuxFlavor, OsKind};
use crate::state::attribute::HostHandler;
use crate::state::attribute::Privilege;
use crate::state::attribute::container::container_spec::quoted_command;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fmt;

/// Package manager used to install the NVIDIA packages
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

    /// Command installing packages non interactively
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

    /// Script adding a repository from an URL (a `.repo` file for dnf and zypper)
    pub(crate) fn add_repo_file_script(&self, repo_file_url: &str, repo_file_name: &str) -> String {
        match self {
            PackageFamily::Apt => {
                // apt repositories are not described by a single file: see each attribute
                String::new()
            }
            PackageFamily::Dnf => format!(
                "set -e; {}; dnf clean expire-cache",
                download_command(
                    repo_file_url,
                    &shell_quote(&format!("/etc/yum.repos.d/{}", repo_file_name))
                )
            ),
            PackageFamily::Zypper => format!(
                "set -e; {}; {}",
                quoted_command(&["zypper", "--non-interactive", "addrepo", repo_file_url]),
                quoted_command(&[
                    "zypper",
                    "--non-interactive",
                    "--gpg-auto-import-keys",
                    "refresh"
                ])
            ),
        }
    }
}

/// Shell snippet downloading `url` to `quoted_destination` (a shell word, already quoted)
/// with curl, or wget if curl is missing
pub(crate) fn download_command(url: &str, quoted_destination: &str) -> String {
    format!(
        "if command -v curl >/dev/null 2>&1; then curl -fsSL -o {dest} {url}; else wget -qO {dest} {url}; fi",
        dest = quoted_destination,
        url = shell_quote(url)
    )
}

/// Wrap a multi-step script so it runs with `sh` whatever the login shell
pub(crate) fn sh_script(script: &str) -> String {
    format!("sh -c {}", shell_quote(script))
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

/// CPU architecture as named in the NVIDIA CUDA repositories
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub enum CudaArch {
    /// `x86_64`
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
    /// Ubuntu 22.04 / 24.04 / 26.04: branch selected with `nvidia-driver-pinning-<branch>`
    Ubuntu,
    /// Debian 12 / 13: branch selected with `nvidia-driver-pinning-<branch>`
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

    /// Script configuring the repository (cuda-keyring for apt, `.repo` file for dnf and zypper)
    pub fn setup_script(&self) -> String {
        let family = self.distro.package_family();
        match family {
            PackageFamily::Apt => format!(
                "set -e; tmp=$(mktemp -d); trap 'rm -rf \"$tmp\"' EXIT; {}; dpkg -i \"$tmp/cuda-keyring.deb\"; apt-get update",
                download_command(
                    &format!("{}cuda-keyring_1.1-1_all.deb", self.base_url()),
                    // a shell variable: let the shell expand it
                    "\"$tmp/cuda-keyring.deb\""
                )
            ),
            PackageFamily::Dnf | PackageFamily::Zypper => family.add_repo_file_script(
                &format!("{}cuda-{}.repo", self.base_url(), self.distro_name),
                &format!("cuda-{}.repo", self.distro_name),
            ),
        }
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

/// State of a systemd unit
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct UnitState {
    pub exists: bool,
    /// Enabled (or `static`/`indirect`/`generated`: started by something else)
    pub enabled: bool,
    pub active: bool,
}

/// Command printing `systemctl is-enabled` then `systemctl is-active` of a unit, one per line
pub(crate) fn unit_state_command(unit: &str) -> String {
    let unit = shell_quote(unit);
    sh_script(&format!(
        "systemctl is-enabled {unit} 2>&1 | tail -n 1; systemctl is-active {unit} 2>&1 | tail -n 1"
    ))
}

/// Parse the output of [`unit_state_command`]
pub fn parse_unit_state(output: &str) -> UnitState {
    let mut lines = output
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty());
    let enabled_state = lines.next().unwrap_or_default();
    let active_state = lines.next().unwrap_or_default();
    let exists = !(enabled_state.contains("No such file")
        || enabled_state.contains("not-found")
        || enabled_state.contains("not found")
        || enabled_state.is_empty());
    UnitState {
        exists,
        enabled: exists
            && matches!(
                enabled_state,
                "enabled" | "enabled-runtime" | "static" | "indirect" | "generated" | "alias"
            ),
        active: active_state == "active" || active_state == "reloading",
    }
}

/// Flavor of the NVIDIA kernel module
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

/// Whether a repository mentioning `url_fragment` is defined
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
    let result = query(host_handler, &unit_state_command(unit), privilege).await?;
    Ok(parse_unit_state(&result.stdout))
}

/// Package manager available on the host (apt-get, then dnf, then zypper)
pub(crate) async fn available_package_family<Handler: HostHandler>(
    host_handler: &mut Handler,
    privilege: &Privilege,
) -> Result<Option<PackageFamily>, RegentError> {
    for (command, family) in [
        ("apt-get", PackageFamily::Apt),
        ("dnf", PackageFamily::Dnf),
        ("zypper", PackageFamily::Zypper),
    ] {
        if host_handler
            .is_this_command_available(command, privilege)
            .await
            .unwrap_or(false)
        {
            return Ok(Some(family));
        }
    }
    Ok(None)
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

#[cfg(test)]
mod tests {
    use super::*;

    fn os(content: &str) -> OsRelease {
        parse_os_release(content)
    }

    #[test]
    fn os_release_is_parsed_with_or_without_quotes() {
        let os_release = os(
            "NAME=\"Rocky Linux\"\nID=\"rocky\"\nID_LIKE=\"rhel centos fedora\"\nVERSION_ID=\"9.4\"\nPRETTY_NAME=\"Rocky Linux 9.4 (Blue Onyx)\"\n",
        );
        assert_eq!(os_release.id, "rocky");
        assert_eq!(os_release.id_like, vec!["rhel", "centos", "fedora"]);
        assert_eq!(os_release.major_version(), "9");
        assert_eq!(os("ID=debian\nVERSION_ID=12\n").version_id, "12");
    }

    #[test]
    fn cuda_repository_is_picked_from_os_release_and_architecture() {
        let cases = [
            (
                "ID=ubuntu\nVERSION_ID=\"24.04\"",
                "x86_64",
                "ubuntu2404",
                DriverDistro::Ubuntu,
            ),
            (
                "ID=ubuntu\nVERSION_ID=\"22.04\"",
                "aarch64",
                "ubuntu2204",
                DriverDistro::Ubuntu,
            ),
            (
                "ID=debian\nVERSION_ID=\"13\"",
                "x86_64",
                "debian13",
                DriverDistro::Debian,
            ),
            (
                "ID=\"rhel\"\nVERSION_ID=\"8.10\"",
                "x86_64",
                "rhel8",
                DriverDistro::RhelModular,
            ),
            (
                "ID=\"almalinux\"\nID_LIKE=\"rhel centos fedora\"\nVERSION_ID=\"9.5\"",
                "x86_64",
                "rhel9",
                DriverDistro::RhelModular,
            ),
            (
                "ID=\"rocky\"\nVERSION_ID=\"10.0\"",
                "aarch64",
                "rhel10",
                DriverDistro::Rhel10,
            ),
            (
                "ID=\"ol\"\nID_LIKE=\"fedora\"\nVERSION_ID=\"9.4\"",
                "x86_64",
                "rhel9",
                DriverDistro::RhelModular,
            ),
            (
                "ID=fedora\nVERSION_ID=43",
                "x86_64",
                "fedora43",
                DriverDistro::Fedora,
            ),
            (
                "ID=\"amzn\"\nID_LIKE=\"fedora\"\nVERSION_ID=\"2023\"",
                "aarch64",
                "amzn2023",
                DriverDistro::AmazonLinux,
            ),
            (
                "ID=\"sles\"\nVERSION_ID=\"15.6\"",
                "x86_64",
                "sles15",
                DriverDistro::Suse,
            ),
            (
                "ID=\"opensuse-leap\"\nVERSION_ID=\"15.6\"",
                "x86_64",
                "opensuse15",
                DriverDistro::Suse,
            ),
        ];
        for (content, machine, distro_name, distro) in cases {
            let repository = cuda_repository(&os(content), machine).unwrap();
            assert_eq!(repository.distro_name, distro_name, "{}", content);
            assert_eq!(repository.distro, distro, "{}", content);
        }

        let repository =
            cuda_repository(&os("ID=ubuntu\nVERSION_ID=\"24.04\""), "aarch64").unwrap();
        assert_eq!(
            repository.base_url(),
            "https://developer.download.nvidia.com/compute/cuda/repos/ubuntu2404/sbsa/"
        );
    }

    #[test]
    fn unsupported_hosts_are_reported_clearly() {
        let error = cuda_repository(
            &os("ID=ubuntu\nVERSION_ID=\"20.04\"\nPRETTY_NAME=\"Ubuntu 20.04.6 LTS\""),
            "x86_64",
        )
        .unwrap_err();
        assert!(
            error.contains("Ubuntu 20.04.6 LTS is not supported"),
            "{}",
            error
        );
        let error = cuda_repository(&os("ID=arch"), "x86_64").unwrap_err();
        assert!(error.contains("not supported"), "{}", error);
        let error = cuda_repository(&os("ID=ubuntu\nVERSION_ID=\"24.04\""), "ppc64le").unwrap_err();
        assert!(error.contains("\"ppc64le\""), "{}", error);
        // RHEL 7 has no supported driver
        assert!(cuda_repository(&os("ID=\"centos\"\nVERSION_ID=\"7\""), "x86_64").is_err());
    }

    #[test]
    fn installed_packages_are_parsed_leniently() {
        let dpkg = "dpkg-query: no packages found matching cuda-drivers*\nnvidia-open 580.105.08-1ubuntu1 ii \nnvidia-driver-pinning-570 570-1ubuntu1 rc \nnvidia-dkms-open 580.105.08-1ubuntu1 hi \n";
        let installed = parse_installed_packages(dpkg);
        assert_eq!(installed.len(), 2, "{:?}", installed);
        assert_eq!(installed["nvidia-open"], "580.105.08-1ubuntu1");

        let rpm = "nvidia-open 580.105.08-1.el9 ii\nkmod-nvidia-open-dkms 580.105.08-1.el9 ii\n";
        assert_eq!(parse_installed_packages(rpm).len(), 2);
        assert!(parse_installed_packages("package nvidia-open is not installed").is_empty());
    }

    #[test]
    fn upstream_versions_drop_epoch_and_revision() {
        assert_eq!(upstream_version("580.105.08-1ubuntu1"), "580.105.08");
        assert_eq!(upstream_version("3:580.105.08-1.el9"), "580.105.08");
        assert_eq!(upstream_version("580.105.08"), "580.105.08");
    }

    #[test]
    fn loaded_driver_is_parsed_from_proc() {
        let open = "NVRM version: NVIDIA UNIX Open Kernel Module for x86_64  580.105.08  Release Build  (dvs-builder@U16-I3-B03-4-3)  Thu Oct 30 2025\nGCC version:  gcc version 13.3.0 (Ubuntu 13.3.0-6ubuntu2~24.04)\n";
        assert_eq!(
            parse_loaded_driver(open),
            Some(LoadedDriver {
                version: "580.105.08".to_string(),
                flavor: KernelModuleFlavor::Open
            })
        );
        let proprietary = "NVRM version: NVIDIA UNIX aarch64 Kernel Module  550.54.14  Thu Feb 22 01:44:30 UTC 2024\n";
        assert_eq!(
            parse_loaded_driver(proprietary),
            Some(LoadedDriver {
                version: "550.54.14".to_string(),
                flavor: KernelModuleFlavor::Proprietary
            })
        );
        assert_eq!(
            parse_loaded_driver("cat: /proc/driver/nvidia/version: No such file or directory"),
            None
        );
    }

    #[test]
    fn unit_states_are_parsed() {
        assert_eq!(
            parse_unit_state("enabled\nactive\n"),
            UnitState {
                exists: true,
                enabled: true,
                active: true
            }
        );
        assert_eq!(
            parse_unit_state("disabled\ninactive\n"),
            UnitState {
                exists: true,
                enabled: false,
                active: false
            }
        );
        assert!(!parse_unit_state("Failed to get unit file state for nvidia-persistenced.service: No such file or directory\ninactive\n").exists);
        assert!(parse_unit_state("static\nactive").enabled);
    }

    #[test]
    fn suse_kernel_headers_follow_the_kernel_variant() {
        assert_eq!(
            DriverDistro::Suse.kernel_headers_packages("6.4.0-150600.23.25-default"),
            vec!["kernel-default-devel=6.4.0-150600.23.25"]
        );
        assert_eq!(
            DriverDistro::Ubuntu.kernel_headers_packages("6.8.0-45-generic"),
            vec!["linux-headers-6.8.0-45-generic"]
        );
    }

    #[test]
    fn commands_quote_every_value() {
        assert_eq!(
            PackageFamily::Apt.installed_packages_command(&["nvidia-open*"]),
            "'dpkg-query' '-W' '-f=${Package} ${Version} ${db:Status-Abbrev}\\n' 'nvidia-open*'"
        );
        assert_eq!(
            PackageFamily::Dnf.install_command(&["nvidia-open".to_string()], false),
            "'dnf' '-y' 'install' 'nvidia-open'"
        );
        let repository = cuda_repository(&os("ID=ubuntu\nVERSION_ID=\"24.04\""), "x86_64").unwrap();
        let script = repository.setup_script();
        assert!(script.contains("'https://developer.download.nvidia.com/compute/cuda/repos/ubuntu2404/x86_64/cuda-keyring_1.1-1_all.deb'"), "{}", script);
        assert!(
            script.contains("-o \"$tmp/cuda-keyring.deb\""),
            "{}",
            script
        );
        let repository = cuda_repository(&os("ID=rhel\nVERSION_ID=\"9.4\""), "x86_64").unwrap();
        assert!(
            repository
                .setup_script()
                .contains("'/etc/yum.repos.d/cuda-rhel9.repo'")
        );
    }
}
