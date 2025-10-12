use crate::error::Error;
use crate::host::hosts::Host;
use crate::host::parser::hostlist_parser;
use serde::Deserialize;

#[derive(Debug, Deserialize, Clone)]
pub struct HostList {
    pub hosts: Option<Vec<Host>>,
}

impl HostList {
    pub fn from_str(raw_content: &str) -> Result<HostList, Error> {
        hostlist_parser(raw_content)
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
