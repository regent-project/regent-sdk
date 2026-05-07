use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use crate::hosts::handlers::HostHandler;

use crate::{Privilege, RegentError};

#[derive(Clone, Serialize, Deserialize, Debug)]
#[serde(deny_unknown_fields)]
pub struct HostProperties {
    os_kind: OsKind,
}

impl HostProperties {
    pub fn collect_dynamically<Handler: HostHandler>(
        host_handler: &mut Handler,
    ) -> Result<HostProperties, RegentError> {
        if !host_handler.is_connected() {
            return Err(RegentError::NotConnectedToHost);
        }

        let mut os_kind = OsKind::Unknown;

        // Linux & FreeBSD -> try to get file /etc/os-release
        if let Ok(os_release_file_content) = host_handler.get_file(PathBuf::from("/etc/os-release"))
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

                    os_kind = if os_name.contains("Arch") {
                        OsKind::Linux(LinuxFlavor::Arch)
                    } else if os_name.contains("CentOS") {
                        OsKind::Linux(LinuxFlavor::Fedora)
                    } else if os_name.contains("Debian") {
                        OsKind::Linux(LinuxFlavor::Debian)
                    } else if os_name.contains("Ubuntu") {
                        OsKind::Linux(LinuxFlavor::Debian)
                    } else if os_name.contains("Arch") {
                        OsKind::Linux(LinuxFlavor::Arch)
                    } else if os_name.contains("openSUSE") {
                        OsKind::Linux(LinuxFlavor::Suse)
                    } else if os_name.contains("FreeBSD") {
                        OsKind::FreeBsd
                    } else {
                        OsKind::Unknown
                    };

                    break;
                }
            }
        }

        // OsKind stille unknown, trying to detect Windows -> run "systeminfo"
        if let OsKind::Unknown = os_kind {
            if let Ok(cmd_result) = host_handler.run_windows_command("systeminfo") {
                if cmd_result.stdout.contains("Microsoft Windows") {
                    os_kind = OsKind::Windows;
                }
            }
        }

        // OsKind stille unknown, trying to detect MacOS -> run "sw_vers -productName"
        if let OsKind::Unknown = os_kind {
            if let Ok(cmd_result) =
                host_handler.run_command("sw_vers -productName", &Privilege::None)
            {
                if cmd_result.stdout.contains("macOS") {
                    os_kind = OsKind::MacOs;
                }
            }
        }

        Ok(HostProperties { os_kind })
    }
}

#[derive(Clone, Serialize, Deserialize, Debug)]
pub enum OsKind {
    Unknown,
    Windows,
    FreeBsd,
    MacOs,
    Linux(LinuxFlavor),
}

#[derive(Clone, Serialize, Deserialize, Debug)]
pub enum LinuxFlavor {
    Debian,
    Fedora,
    Arch,
    Suse,
    Gentoo,
}
