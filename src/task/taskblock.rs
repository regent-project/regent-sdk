use crate::error::Error;
use crate::task::step::{ParsingStep, Step};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaskBlock {
    pub name: Option<String>,
    pub steps: Vec<Step>,
    pub with_sudo: Option<bool>,
}

impl TaskBlock {
    pub fn new() -> TaskBlock {
        TaskBlock {
            name: None,
            steps: Vec::new(),
            with_sudo: None,
        }
    }

    pub fn from(name: Option<String>, steps: Vec<Step>, with_sudo: Option<bool>) -> TaskBlock {
        TaskBlock {
            name,
            steps,
            with_sudo,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ParsingTaskBlock {
    pub name: Option<String>,
    pub steps: Vec<ParsingStep>,
    pub with_sudo: Option<bool>,
}

impl ParsingTaskBlock {
    pub fn parse_task_block(&self) -> Result<TaskBlock, Error> {
        let mut steps: Vec<Step> = Vec::new();
        for parsing_step in self.steps.iter() {
            match parsing_step.parsemodule() {
                Ok(step) => {
                    steps.push(step);
                }
                Err(error) => {
                    return Err(error);
                }
            }
        }

        Ok(TaskBlock {
            name: self.name.clone(),
            steps: steps,
            with_sudo: self.with_sudo.clone(),
        })
    }
}
