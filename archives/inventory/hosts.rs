use serde::{Deserialize, Serialize};
use std::collections::HashMap;

// TODO : add a connection mode field
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Host {
    pub address: String,
    pub vars: Option<HashMap<String, String>>,
    pub groups: Option<Vec<String>>,
}

impl Host {
    pub fn new() -> Host {
        Host {
            address: String::new(),
            vars: None,
            groups: None,
        }
    }

    pub fn from_string(address: String) -> Host {
        Host {
            address,
            vars: None,
            groups: None,
        }
    }

    pub fn add_to_group(&mut self, groupname: &String) {
        match &self.groups {
            Some(group_list) => {
                let mut new_group_list = group_list.clone();
                new_group_list.push(groupname.clone());
                self.groups = Some(new_group_list);
            }
            None => {
                self.groups = Some(vec![groupname.clone()]);
            }
        }
    }

    pub fn add_vars(&mut self, newvars: &HashMap<String, String>) {
        match &self.vars {
            Some(oldvars) => {
                let mut new_vars_list = oldvars.clone();
                new_vars_list.extend(newvars.clone());
                self.vars = Some(new_vars_list);
            }
            None => {
                self.vars = Some(newvars.clone());
            }
        }
    }

    pub fn add_var(&mut self, key: &str, value: &str) {
        match &self.vars {
            Some(oldvars) => {
                let mut new_vars_list = oldvars.clone();
                new_vars_list.insert(key.into(), value.into());
                self.vars = Some(new_vars_list);
            }
            None => {
                let mut new_vars = HashMap::new();
                new_vars.insert(key.into(), value.into());
                self.vars = Some(new_vars);
            }
        }
    }
}

#[derive(Debug, Deserialize, Clone)]
pub struct Group {
    pub name: String,
    pub vars: Option<HashMap<String, String>>,
    pub hosts: Option<Vec<String>>,
}
