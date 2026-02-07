use crate::error::Error;
use crate::inventory::hosts::Host;
use crate::inventory::parsing::hostlist_parser;
use serde::Deserialize;
use std::collections::HashMap;

#[derive(Debug, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct Inventory {
    pub hosts: HashMap<String, Host>, // <host_id, Host>
    pub global_vars: HashMap<String, String>,
    pub groups: HashMap<String, Vec<String>> // <group_id, Vec<host_id>>
}

impl Inventory {
    pub fn from_str(raw_content: &str) -> Result<Inventory, Error> {
        // First we parse the content as YAML, host vars not parsed yet (unproper YAML syntax)
        match serde_yaml::from_str::<HostList>(raw_content) {
            Ok(host_list) => {
                Ok(host_list)
            }
            Err(error) => {
                Err(Error::FailedInitialization(format!("{}", error)))
            }
        }
    }

    pub fn from_file(file_path: &str) -> Result<HostList, Error> {
        match std::fs::read_to_string(file_path) {
            Ok(file_content) => {
                return HostList::from_str(&file_content);
            }
            Err(error) => {
                return Err(Error::FailedInitialization(format!(
                    "{} : {}",
                    file_path, error
                )));
            }
        }
    }

    pub fn is_empty(&self) -> bool {
        match &self.hosts {
            Some(host_list) => {
                if host_list.len() == 0 {
                    true
                } else {
                    false
                }
            }
            None => true
        }
    }
}

pub fn hostlist_get_all_hosts(hostlist: &HostList) -> Option<Vec<String>> {
    match &hostlist.hosts {
        Some(host_list) => {
            let mut all_hosts_addresses: Vec<String> = Vec::new();
            for host in host_list {
                all_hosts_addresses.push(host.address.clone());
            }
            Some(all_hosts_addresses)
        }
        None => None,
    }
}

pub fn hostlist_get_from_file(file_path: &str) -> String {
    std::fs::read_to_string(file_path).unwrap() // Placeholder : error handling required here
}

pub fn hostlist_get_from_interactive_mode() -> String {
    // Placeholder : we might want a mode where the TaskList is already set and we can add
    // manually / pipe from some other source in real time some more hosts to run the TaskList
    // on and, as soon as the hosts are entered, the TaskList is run on them. Interest ?
    String::new()
}

// If the host is already in the list, the index is returned. Otherwise, None is returned.
pub fn find_host_in_list(hosts_list: &Vec<Host>, host_name: &String) -> Option<usize> {
    for (index, host) in hosts_list.iter().enumerate() {
        if host.address.eq(host_name) {
            return Some(index);
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hostlist_from_str() {
        let yaml_content = r#"
vars:
    global_key: global_value

hosts:
    - address: host1.example.com
      vars:
        key1: value1
      groups:
        - webserver
    - address: host2.example.com
      vars:
        key2: value2
      groups:
        - database
"#;
        let hostlist = HostList::from_str(yaml_content).unwrap();
        assert!(hostlist.hosts.is_some());

        let hosts = hostlist.hosts.unwrap();
        assert_eq!(hosts.len(), 2);
        assert_eq!(hosts[0].address, "host1.example.com");
        assert_eq!(hosts[1].address, "host2.example.com");
    }

    #[test]
    fn finding_hosts_in_given_list() {
        let hosts_list: Vec<Host> = vec![
            Host::from_string("10.20.30.51".into()),
            Host::from_string("10.20.30.52".into()),
            Host::from_string("10.20.30.53".into()),
        ];

        assert!(find_host_in_list(&hosts_list, &"10.20.30.51".to_string()).is_some());
        assert!(find_host_in_list(&hosts_list, &"192.168.10.25".to_string()).is_none());
    }
}

