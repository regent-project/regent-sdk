use crate::error::Error;
use crate::host::hostlist::{find_host_in_list, HostList};
use crate::host::hosts::{Group, Host};
use serde::Deserialize;
use std::collections::HashMap;

#[derive(Debug, Deserialize, Clone)]
pub struct HostListVarsUnparsed {
    pub vars: Option<HashMap<String, String>>,
    pub hosts: Option<Vec<String>>,
    pub groups: Option<Vec<Group>>,
}

impl HostListVarsUnparsed {
    pub fn parse_host_vars(&self) -> HostListFile {
        match &self.hosts {
            Some(hosts_list) => {
                let mut parsed_hosts: Vec<Host> = Vec::new();

                for host_string in hosts_list {
                    let mut line = host_string.split(['[', ']']);
                    let hostname = line.next().unwrap().trim();

                    match line.next() {
                        Some(vars_content) => {
                            let mut vars_list: HashMap<String, String> = HashMap::new();
                            for vardef in vars_content.split(',') {
                                let mut vardef_parsed = vardef.split('=');
                                let key = vardef_parsed.next().unwrap().trim();
                                let value = vardef_parsed.next().unwrap().trim();
                                vars_list.insert(key.to_string(), value.to_string());
                            }
                            parsed_hosts.push(Host {
                                address: hostname.to_string(),
                                vars: Some(vars_list),
                                groups: None,
                            })
                        }
                        None => parsed_hosts.push(Host {
                            address: hostname.to_string(),
                            vars: None,
                            groups: None,
                        }),
                    }
                }

                HostListFile {
                    hosts: Some(parsed_hosts),
                    groups: self.groups.clone(),
                    vars: self.vars.clone(),
                }
            }
            None => HostListFile {
                hosts: None,
                groups: self.groups.clone(),
                vars: self.vars.clone(),
            },
        }
    }
}

#[derive(Debug, Deserialize, Clone)]
pub struct HostListFile {
    pub vars: Option<HashMap<String, String>>,
    pub hosts: Option<Vec<Host>>,
    pub groups: Option<Vec<Group>>,
}

impl HostListFile {
    pub fn new() -> HostListFile {
        HostListFile {
            vars: Some(HashMap::new()),
            hosts: Some(Vec::new()),
            groups: Some(Vec::new()),
        }
    }

    pub fn from_hosts(hosts: Vec<Host>, vars: Option<HashMap<String, String>>) -> HostListFile {
        if hosts.is_empty() {
            HostListFile {
                vars: None,
                hosts: None,
                groups: None,
            }
        } else {
            match vars {
                Some(variables) => HostListFile {
                    vars: Some(variables),
                    hosts: Some(hosts),
                    groups: None,
                },
                None => HostListFile {
                    vars: None,
                    hosts: Some(hosts),
                    groups: None,
                },
            }
        }
    }

    // This method will gather all elements about a host and create a Host object / per host
    // -> address + all variables which applies to this host + all groups this host belongs to
    pub fn generate_hostlist(&self) -> HostList {
        let mut final_hostlist: Vec<Host> = Vec::new();

        match &self.groups {
            Some(groups_list) => {
                for group in groups_list {
                    match &group.hosts {
                        Some(host_list) => {
                            for host_address in host_list {
                                match find_host_in_list(&final_hostlist, &host_address) {
                                    Some(index) => {
                                        final_hostlist[index].add_to_group(&group.name);
                                        // Only add group level variables because the host is already in the list, meaning it already has HostList level variables
                                        final_hostlist[index]
                                            .add_vars(&group.vars.as_ref().unwrap());
                                    }
                                    None => {
                                        let mut temp_host = Host::from_string(host_address.clone());
                                        temp_host.add_to_group(&group.name);
                                        // First, add HostList level variables
                                        if let Some(vars_content) = &self.vars.as_ref() {
                                            temp_host.add_vars(vars_content);
                                        }
                                        // Then add group level variables (surcharge)
                                        if let Some(vars_content) = &group.vars.as_ref() {
                                            temp_host.add_vars(vars_content);
                                        }

                                        final_hostlist.push(temp_host);
                                    }
                                }
                            }
                        }
                        None => {}
                    }
                }
            }
            None => {}
        }

        match &self.hosts {
            Some(host_list) => {
                for host in host_list {
                    match find_host_in_list(&final_hostlist, &host.address) {
                        Some(index) => {
                            // Host is already part of a group, only host vars need to be added
                            final_hostlist[index].add_vars(host.vars.as_ref().unwrap());
                        }
                        None => {
                            let mut temp_host = Host::from_string(host.address.clone());
                            // First, add HostList level variables
                            if let Some(vars_content) = &self.vars.as_ref() {
                                temp_host.add_vars(vars_content);
                            }
                            // Then add host level variables (surcharge)
                            if let Some(vars_content) = &host.vars.as_ref() {
                                temp_host.add_vars(vars_content);
                            }

                            final_hostlist.push(temp_host);
                        }
                    }
                }
            }
            None => {}
        }

        if final_hostlist.is_empty() {
            HostList { hosts: None }
        } else {
            HostList {
                hosts: Some(final_hostlist),
            }
        }
    }
}

// TODO : So far, we assume the hostlist file is in YAML format. More formats will come later.
pub fn hostlist_parser(hostlistfilecontent: &str) -> Result<HostList, Error> {
    // First we parse the content as YAML, host vars not parsed yet (unproper YAML syntax)
    match serde_yaml::from_str::<HostListVarsUnparsed>(&hostlistfilecontent) {
        Ok(yaml_parsed_result) => {
            // Second we parse the host vars
            let host_vars_parsed_result = yaml_parsed_result.parse_host_vars();
            // Finally, we generate a HostList out of the HostListFile
            return Ok(host_vars_parsed_result.generate_hostlist());
        }
        Err(error) => {
            return Err(Error::FailedInitialization(format!("{}", error)));
        }
    };
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_hostlist_parsing() {
        let hostlist = hostlist_parser("").unwrap();
        assert!(hostlist.hosts.is_none());
    }

    #[test]
    fn varless_hostlist_parsing() {
        let hostlist = hostlist_parser(
"---
hosts:
- 10.20.30.51
- 10.20.30.52
- 10.20.30.53
"
        ).unwrap();

        assert!(hostlist.hosts.is_some());

        let vec_hosts = hostlist.hosts.unwrap();
        assert_eq!(vec_hosts.len(), 3);

        let mut address_list: Vec<String> = Vec::new();
        address_list.push(vec_hosts[0].address.clone());
        address_list.push(vec_hosts[1].address.clone());
        address_list.push(vec_hosts[2].address.clone());
        assert!(address_list.binary_search(&"10.20.30.51".into()).is_ok());
        assert!(address_list.binary_search(&"10.20.30.52".into()).is_ok());
        assert!(address_list.binary_search(&"10.20.30.53".into()).is_ok());
        assert!(address_list.binary_search(&"192.168.10.25".into()).is_err());
    }
}
