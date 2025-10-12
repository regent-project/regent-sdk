use crate::connection::host_connection::HostConnectionInfo;
use crate::connection::hosthandler::HostHandler;
use crate::error::Error;
use crate::host::hosts::Host;
use crate::output::job_output::JobOutput;
use crate::task::tasklist::TaskList;
use crate::task::tasklist::TaskListFileType;
use crate::workflow::hostworkflow::HostWorkFlow;
use crate::workflow::hostworkflow::HostWorkFlowStatus;
use chrono::Utc;
use machineid_rs::{Encryption, HWIDComponent, IdBuilder};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::time::SystemTime;

/// The Job is the key type around which the whole automation revolves. A Job is about one host only. If you want to handle multiple hosts, you will need to have multiple Jobs (in a vec or anything else).
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Job {
    pub host: Host,
    pub host_connection_info: HostConnectionInfo,
    pub correlation_id: Option<String>,
    pub tasklist: Option<TaskList>,
    pub vars: Option<serde_json::Value>,
    pub timestamp_start: Option<String>,
    pub timestamp_end: Option<String>,
    pub hostworkflow: Option<HostWorkFlow>,
    pub final_status: HostWorkFlowStatus,
}

impl Job {
    pub fn new() -> Job {
        Job {
            host: Host::new(),
            host_connection_info: HostConnectionInfo::Unset,
            correlation_id: None,
            tasklist: None,
            vars: None,
            timestamp_start: None,
            timestamp_end: None,
            hostworkflow: None,
            final_status: HostWorkFlowStatus::NotRunYet,
        }
    }

    pub fn from_host(host: Host) -> Job {
        let mut job = Job::new();
        job.set_address(&host.address);

        let temp_tera_context_value = match &host.vars {
            Some(vars_list) => Some(
                tera::Context::from_serialize(vars_list)
                    .unwrap()
                    .into_json(),
            ),
            None => None,
        };
        job.set_vars(temp_tera_context_value);
        job
    }

    pub fn get_address(&self) -> String {
        self.host.address.clone()
    }

    /// Set host address
    pub fn set_address(&mut self, address: &str) -> &mut Self {
        // TODO : Add controls on address content (invalid address with spaces or else...)
        self.host.address = address.to_string();

        self
    }

    /// Using a correlation id can be required in a distributed environment. If a machine is building Jobs and sending it to worker nodes, then the results will probably arrive in a random order, meaning it will hard to identify which results belong to which Job unless we use correlation ids.
    pub fn with_correlation_id(&mut self, with_correlation_id: bool) -> Result<&mut Self, Error> {
        if with_correlation_id {
            match IdBuilder::new(Encryption::MD5)
                .add_component(HWIDComponent::CPUID)
                .add_component(HWIDComponent::MacAddress)
                .add_component(HWIDComponent::MachineName)
                .add_component(HWIDComponent::Username)
                .build("dux")
            {
                Ok(salt) => {
                    let now = SystemTime::now();
                    let value = Sha256::digest(format!("{}{:?}", salt, now));
                    self.correlation_id = Some(format!("{:X}", value));
                    Ok(self)
                }
                Err(e) => {
                    return Err(Error::FailedInitialization(format!("{}", e)));
                }
            }
        } else {
            self.correlation_id = None;
            Ok(self)
        }
    }

    /// How do we connect to the target host ?
    pub fn set_connection(
        &mut self,
        host_connection_info: HostConnectionInfo,
    ) -> Result<&mut Self, Error> {
        if let HostConnectionInfo::Unset = host_connection_info {
            Err(Error::WrongInitialization(format!(
                "No point in initializing connection info to HostConnectionInfo::Unset"
            )))
        } else {
            self.host_connection_info = host_connection_info;
            Ok(self)
        }
    }

    /// Define the task list from a TaskList
    pub fn set_tasklist(
        &mut self,
        task_list: TaskList
    ) -> &mut Self {
        self.tasklist = Some(task_list);
        self
    }

    /// Define the task list from a str
    pub fn set_tasklist_from_str(
        &mut self,
        raw_content: &str,
        content_type: TaskListFileType,
    ) -> Result<&mut Self, Error> {
        match TaskList::from_str(raw_content, content_type) {
            Ok(task_list) => {
                self.tasklist = Some(task_list);
                Ok(self)
            }
            Err(error) => Err(error),
        }
    }

    /// Define the task list from a given file path
    pub fn set_tasklist_from_file(
        &mut self,
        file_path: &str,
        content_type: TaskListFileType,
    ) -> Result<&mut Self, Error> {
        match TaskList::from_file(file_path, content_type) {
            Ok(task_list) => {
                self.tasklist = Some(task_list);
                Ok(self)
            }
            Err(error) => Err(error),
        }
    }

    pub fn add_var(&mut self, key: &str, value: &str) -> &mut Self {
        match &self.vars {
            Some(old_tera_context_value) => {
                let mut tera_context_temp =
                    tera::Context::from_value(old_tera_context_value.clone()).unwrap();
                tera_context_temp.insert(key, value);
                self.vars = Some(tera_context_temp.into_json());
            }
            None => {
                let mut tera_context_temp = tera::Context::new();
                tera_context_temp.insert(key, value);
                self.vars = Some(tera_context_temp.into_json());
            }
        }
        self
    }

    pub fn set_vars(&mut self, vars: Option<serde_json::Value>) -> &mut Self {
        self.vars = vars;
        self
    }

    /// "DRY_RUN" this job -> evaluate the difference between the expected state and the actual state of the given host
    pub fn dry_run(&mut self) {
        // Build a HostHandler
        let mut host_handler =
            HostHandler::from(self.host.address.clone(), self.host_connection_info.clone())
                .unwrap();
        if let Err(error) = host_handler.init() {
            self.final_status = HostWorkFlowStatus::ConnectionInitFailed(
                format!("{:?}", error)
            );
            return;
        }

        // Build a context
        let mut temp_tera_context = match &self.vars {
            Some(context_value) => tera::Context::from_value(context_value.clone()).unwrap(),
            None => tera::Context::new(),
        };

        self.timestamp_start = Some(format!("{}", Utc::now().format("%+").to_string()));

        match &mut self.hostworkflow {
            Some(host_work_flow) => {
                match host_work_flow.dry_run(&mut host_handler, &mut temp_tera_context) {
                    Ok(()) => {
                        self.final_status = host_work_flow.final_status.clone();
                    }
                    Err(_error) => {
                        self.final_status = HostWorkFlowStatus::DryRunFailed;
                    }
                }
            }
            None => {
                let mut host_work_flow = HostWorkFlow::from(&self.tasklist.as_mut().unwrap());
                match host_work_flow.dry_run(&mut host_handler, &mut temp_tera_context) {
                    Ok(()) => {
                        self.final_status = host_work_flow.final_status.clone();
                        self.hostworkflow = Some(host_work_flow);
                    }
                    Err(_error) => {
                        self.final_status = HostWorkFlowStatus::ApplyFailed;
                    }
                }
            }
        }

        self.timestamp_end = Some(format!("{}", Utc::now().format("%+").to_string()));
        match temp_tera_context.clone().into_json() {
            serde_json::Value::Null => {
                self.vars = None;
            }
            _ => self.vars = Some(temp_tera_context.into_json()),
        }
    }

    /// "APPLY" this job -> evaluate what needs to be done to reach the expected state, then do it
    pub fn apply(&mut self) {
        // Build a HostHandler
        let mut host_handler =
            HostHandler::from(self.host.address.clone(), self.host_connection_info.clone())
                .unwrap();
        if let Err(error) = host_handler.init() {
            self.final_status = HostWorkFlowStatus::ConnectionInitFailed(
                format!("{:?}", error)
            );
            return;
        }

        // Build a context
        let mut temp_tera_context = match &self.vars {
            Some(context_value) => tera::Context::from_value(context_value.clone()).unwrap(),
            None => tera::Context::new(),
        };

        self.timestamp_start = Some(format!("{}", Utc::now().format("%+").to_string()));

        match &mut self.hostworkflow {
            Some(host_work_flow) => {
                match host_work_flow.apply(&mut host_handler, &mut temp_tera_context) {
                    Ok(()) => {
                        self.final_status = host_work_flow.final_status.clone();
                    }
                    Err(_error) => {
                        self.final_status = HostWorkFlowStatus::ApplyFailed;
                    }
                }
            }
            None => {
                let mut host_work_flow = HostWorkFlow::from(&self.tasklist.as_mut().unwrap());
                match host_work_flow.apply(&mut host_handler, &mut temp_tera_context) {
                    Ok(()) => {
                        self.final_status = host_work_flow.final_status.clone();
                        self.hostworkflow = Some(host_work_flow);
                    }
                    Err(_error) => {
                        self.final_status = HostWorkFlowStatus::ApplyFailed;
                    }
                }
            }
        }

        self.timestamp_end = Some(format!("{}", Utc::now().format("%+").to_string()));

        match temp_tera_context.into_json() {
            serde_json::Value::Null => {
                self.vars = None;
            }
            any_other_value => self.vars = Some(any_other_value),
        }
    }

    pub fn display(&mut self) -> String {
        let job_output = JobOutput::from_job(self);
        serde_json::to_string(&job_output).unwrap()
    }

    pub fn display_pretty(&mut self) -> String {
        let job_output = JobOutput::from_job(self);
        serde_json::to_string_pretty(&job_output).unwrap()
    }
}

#[derive(PartialEq, Debug, Clone, Serialize, Deserialize)]
pub enum RunningMode {
    DryRun, // Only check what needs to be done to match the expected situation
    Apply,  // Actually apply the changes required to match the expected situation
    Unset,
}

#[derive(PartialEq, Debug, Clone, Serialize, Deserialize)]
pub enum JobFinalStatus {
    Unset,
    AlreadyMatched,
    FailedDryRun(String),
    Changed,
    ChangedWithFailures,
    FailedChange,
    GenericFailed(String),
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub enum HostAddress {
    Unset,
    LocalHost,
    RemoteHost(String), // IP/hostname
}
