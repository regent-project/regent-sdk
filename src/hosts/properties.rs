use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use crate::hosts::handlers::HostHandler;

use crate::{Privilege, RegentError};

#[derive(Clone, Serialize, Deserialize, Debug)]
#[serde(deny_unknown_fields)]
pub struct HostProperties {
    os_kind: OsKind,
    hostname: Option<String>,
}

impl HostProperties {
    pub async fn collect_dynamically<Handler: HostHandler>(
        host_handler: &mut Handler,
    ) -> Result<HostProperties, RegentError> {
        if !host_handler.is_connected().await {
            return Err(RegentError::NotConnectedToHost);
        }

        let mut os_kind = OsKind::Unknown;

        // Linux & FreeBSD -> try to get file /etc/os-release
        if let Ok(os_release_file_content) = host_handler
            .get_file(PathBuf::from("/etc/os-release"))
            .await
        {
            let content = String::from_utf8_lossy(&os_release_file_content);
            for line in content.lines() {
                if line.starts_with("NAME=") {
                    // Some distributions are using quotes, others are not...
                    let mut equals_iterator = line.split('=');
                    equals_iterator.next().unwrap(); // 'NAME'
                    let os_name_part = equals_iterator.next().unwrap();

                    let os_name = if os_name_part.starts_with('"') {
                        &os_name_part[1..os_name_part.len() - 1]
                    } else {
                        os_name_part
                    };

                    if os_name.contains("FreeBSD") {
                        os_kind = OsKind::FreeBsd(FreeBsdSpecifics);
                    } else {
                        let linux_flavor = if os_name.contains("Arch") {
                            LinuxFlavor::Arch
                        } else if os_name.contains("CentOS") {
                            LinuxFlavor::Fedora
                        } else if os_name.contains("Debian") {
                            LinuxFlavor::Debian
                        } else if os_name.contains("Ubuntu") {
                            LinuxFlavor::Debian
                        } else if os_name.contains("Arch") {
                            LinuxFlavor::Arch
                        } else if os_name.contains("openSUSE") {
                            LinuxFlavor::Suse
                        } else {
                            // Unknown Linux flavor, but still Linux
                            LinuxFlavor::Debian
                        };

                        let init_system = Self::detect_init_system(host_handler).await;
                        os_kind = OsKind::Linux(LinuxSpecifics {
                            linux_flavor,
                            init_system,
                        });
                    }

                    break;
                }
            }
        }

        // OsKind still unknown, trying to detect Windows -> run "systeminfo"
        if let OsKind::Unknown = os_kind {
            if let Ok(cmd_result) = host_handler.run_windows_command("systeminfo").await {
                if cmd_result.stdout.contains("Microsoft Windows") {
                    os_kind = OsKind::Windows(WindowsSpecifics);
                }
            }
        }

        // OsKind still unknown, trying to detect MacOS -> run "sw_vers -productName"
        if let OsKind::Unknown = os_kind {
            if let Ok(cmd_result) = host_handler
                .run_command("sw_vers -productName", &Privilege::None)
                .await
            {
                if cmd_result.stdout.contains("macOS") {
                    os_kind = OsKind::MacOs(MacOsSpecifics);
                }
            }
        }

        let hostname = Self::collect_hostname(host_handler, os_kind.clone()).await;

        Ok(HostProperties { os_kind, hostname })
    }

    pub fn os_kind(&self) -> &OsKind {
        &self.os_kind
    }

    pub fn hostname(&self) -> &Option<String> {
        &self.hostname
    }

    async fn collect_hostname<Handler: HostHandler>(
        host_handler: &mut Handler,
        os_kind: OsKind,
    ) -> Option<String> {
        match os_kind {
            OsKind::Unknown => None,
            OsKind::Windows(_) => {
                let cmd_result = host_handler.run_windows_command("hostname").await.ok()?;
                if cmd_result.return_code == 0 {
                    Some(cmd_result.stdout.trim().to_string())
                } else {
                    None
                }
            }
            OsKind::Linux(_) | OsKind::FreeBsd(_) | OsKind::MacOs(_) => {
                if let Ok(hostname_file_content) =
                    host_handler.get_file(PathBuf::from("/etc/hostname")).await
                {
                    Some(
                        String::from_utf8_lossy(&hostname_file_content)
                            .trim()
                            .to_string(),
                    )
                } else {
                    let cmd_result = host_handler
                        .run_command("hostname", &Privilege::None)
                        .await
                        .ok()?;
                    if cmd_result.return_code == 0 {
                        Some(cmd_result.stdout.trim().to_string())
                    } else {
                        None
                    }
                }
            }
        }
    }

    async fn detect_init_system<Handler: HostHandler>(host_handler: &mut Handler) -> InitSystem {
        // Check for systemd by looking for the /run/systemd/system directory
        if host_handler
            .get_file(PathBuf::from("/run/systemd/system"))
            .await
            .is_ok()
        {
            return InitSystem::Systemd;
        }

        // Alternative check: see if systemd is PID 1
        if let Ok(cmd_result) = host_handler
            .run_command("ps -p 1 -o comm=", &Privilege::None)
            .await
        {
            if cmd_result.return_code == 0 {
                let process_name = cmd_result.stdout.trim();
                if process_name == "systemd" || process_name.contains("systemd") {
                    return InitSystem::Systemd;
                }
            }
        }

        InitSystem::Unknown
    }
}

#[derive(Clone, Serialize, Deserialize, Debug)]
pub enum OsKind {
    Unknown,
    Windows(WindowsSpecifics),
    FreeBsd(FreeBsdSpecifics),
    MacOs(MacOsSpecifics),
    Linux(LinuxSpecifics),
}

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct LinuxSpecifics {
    pub linux_flavor: LinuxFlavor,
    pub init_system: InitSystem,
}

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct MacOsSpecifics;

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct FreeBsdSpecifics;

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct WindowsSpecifics;

#[derive(Clone, Serialize, Deserialize, Debug)]
pub enum LinuxFlavor {
    Debian,
    Fedora,
    Arch,
    Suse,
    Gentoo,
}

#[derive(Clone, Serialize, Deserialize, Debug)]
pub enum InitSystem {
    Unknown,
    Systemd,
}
