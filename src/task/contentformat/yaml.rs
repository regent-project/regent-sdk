use crate::error::Error;
use crate::task::taskblock::{ParsingTaskBlock, TaskBlock};
use crate::task::tasklist::TaskList;
use serde_yaml;

pub fn yaml_tasklist_parser(tasklistcontent: &str) -> Result<TaskList, Error> {
    match serde_yaml::from_str::<Vec<ParsingTaskBlock>>(tasklistcontent) {
        Ok(parsed_content) => {
            let mut tasks: Vec<TaskBlock> = Vec::new();
            for parsed_task in parsed_content.iter() {
                match parsed_task.parse_task_block() {
                    Ok(task_block) => {
                        tasks.push(task_block);
                    }
                    Err(error) => {
                        return Err(error);
                    }
                }
            }
            return Ok(TaskList::from(tasks));
        }
        Err(e) => return Err(Error::FailureToParseContent(format!("{:?}", e))),
    }
}
