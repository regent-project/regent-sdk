use crate::error::Error;
use crate::task::contentformat::json::json_tasklist_parser;
use crate::task::contentformat::yaml::yaml_tasklist_parser;
use crate::task::taskblock::TaskBlock;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaskList {
    pub tasks: Vec<TaskBlock>,
}

impl TaskList {
    pub fn new() -> TaskList {
        TaskList {
            tasks: Vec::<TaskBlock>::new(),
        }
    }
    pub fn from(tasks: Vec<TaskBlock>) -> TaskList {
        TaskList { tasks }
    }
    pub fn from_str(raw_content: &str, content_type: TaskListFileType) -> Result<TaskList, Error> {
        match content_type {
            TaskListFileType::Yaml => yaml_tasklist_parser(raw_content),
            TaskListFileType::Json => json_tasklist_parser(raw_content),
            TaskListFileType::Unknown => {
                // Unknown format -> Try YAML -> Try JSON -> Failed
                match yaml_tasklist_parser(raw_content) {
                    Ok(task_list) => {
                        return Ok(task_list);
                    }
                    Err(yaml_try_error) => match json_tasklist_parser(raw_content) {
                        Ok(task_list) => {
                            return Ok(task_list);
                        }
                        Err(json_try_error) => {
                            return Err(Error::FailedInitialization(format!(
                                "Unable to parse file. YAML : {:?}, JSON : {:?}",
                                yaml_try_error, json_try_error
                            )));
                        }
                    },
                }
            }
        }
    }
    pub fn from_file(file_path: &str, file_type: TaskListFileType) -> Result<TaskList, Error> {
        match std::fs::read_to_string(file_path) {
            Ok(file_content) => {
                return TaskList::from_str(&file_content, file_type);
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

#[derive(PartialEq, Debug, Clone, Serialize, Deserialize)]
pub enum RunningMode {
    DryRun, // Only check what needs to be done to match the expected situation
    Apply,  // Actually apply the changes required to match the expected situation
}

pub enum TaskListFileType {
    Yaml,
    Json,
    Unknown,
}
