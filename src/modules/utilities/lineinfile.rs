// LineInFile module : manipulate lines in a file (add, delete)
use crate::connection::hosthandler::HostHandler;
use crate::connection::specification::Privilege;
use crate::error::Error;
use crate::result::apicallresult::{ApiCallResult, ApiCallStatus};
use crate::step::stepchange::StepChange;
use crate::task::moduleblock::ModuleApiCall;
use crate::task::moduleblock::{Apply, DryRun};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
enum LineInFileModuleInternalApiCall {
    Add(LineExpectedPosition),
    Delete(Vec<u64>)
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
enum LineExpectedState {
    Present,
    Absent
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
enum LineExpectedPosition {
    Top,
    Bottom,
    Anywhere,
    #[serde(untagged)]
    SpecificLineNumber(u64)
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct LineInFileBlockExpectedState {
    filepath: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    line: Option<String>,
    state: LineExpectedState,
    #[serde(skip_serializing_if = "Option::is_none")]
    position: Option<LineExpectedPosition>, // "top" | "bottom" | "anywhere" (default) | "45" (specific line number)

                              // ****** To be implemented ********
                              // beforeline: Option<String>, // Insert before this line
                              // afterline: Option<String>, // Insert after this line
                              // replace: Option<String>, // Replace this line...
                              // with: Option<String> // ... with this one.
}

impl DryRun for LineInFileBlockExpectedState {
    fn dry_run_block(
        &self,
        hosthandler: &mut HostHandler,
        privilege: Privilege,
    ) -> Result<StepChange, Error> {
        if !hosthandler.is_this_cmd_available("sed").unwrap() {
            return Err(Error::FailedDryRunEvaluation(
                "Sed command not available on this host".to_string(),
            ));
        }

        let file_exists_check = hosthandler
            .run_cmd(
                format!("test -f {}", self.filepath).as_str(),
                privilege.clone(),
            )
            .unwrap();

        if file_exists_check.rc != 0 {
            return Err(Error::FailedDryRunEvaluation(format!(
                "{} not found or not a regular file",
                self.filepath
            )));
        }

        let change = match &self.state {
            LineExpectedState::Present => {

                let filenumberoflines = hosthandler
                    .run_cmd(
                        format!("wc -l {} | cut -f 1 -d ' '", self.filepath).as_str(),
                        privilege.clone(),
                    )
                    .unwrap()
                    .stdout
                    .trim()
                    .parse::<u64>()
                    .unwrap();

                // Precheck
                if let Some(LineExpectedPosition::SpecificLineNumber(expected_line_number)) = self.position {
                    if expected_line_number > filenumberoflines {
                        return Err(Error::FailedDryRunEvaluation(
                            "Position value out of range (use \"bottom\" instead)".to_string()
                        ));
                    }
                }

                let file_actual_compliance = is_line_present(
                    hosthandler,
                    &self.line.as_ref().unwrap(),
                    &self.filepath,
                    &privilege,
                );

                match file_actual_compliance {
                    Some(actual_line_numbers) => {
                        // Line is already there but we need to make sure it is at the expected place
                        match &self.position {
                            Some(expected_position) => {
                                match expected_position {
                                    LineExpectedPosition::Top => {
                                        if actual_line_numbers.contains(&1) {
                                            // Line is already at the right place, nothing to do
                                            ModuleApiCall::None(String::from(
                                                "Line already present at expected place",
                                            ))
                                        } else {
                                            ModuleApiCall::LineInFile(LineInFileApiCall {
                                                api_call: LineInFileModuleInternalApiCall::Add(LineExpectedPosition::Top),
                                                line_content: self.line.as_ref().unwrap().clone(),
                                                file_path: self.filepath.clone(),
                                                privilege,
                                            })
                                        }
                                    }
                                    LineExpectedPosition::Bottom => {
                                        if actual_line_numbers.contains(&filenumberoflines) {
                                            // Line is already at the right place, nothing to do
                                            ModuleApiCall::None(String::from(
                                                "Line already present at expected place",
                                            ))
                                        } else {
                                            ModuleApiCall::LineInFile(LineInFileApiCall {
                                                api_call: LineInFileModuleInternalApiCall::Add(LineExpectedPosition::Bottom),
                                                line_content: self.line.as_ref().unwrap().clone(),
                                                file_path: self.filepath.clone(),
                                                privilege,
                                            })
                                        }
                                    }
                                    LineExpectedPosition::SpecificLineNumber(specific_line_number) => {
                                        if actual_line_numbers.contains(&specific_line_number) {
                                            // Line is already at the right place, nothing to do
                                            ModuleApiCall::None(String::from(
                                                "Line already present at expected place",
                                            ))
                                        } else {
                                            ModuleApiCall::LineInFile(LineInFileApiCall {
                                                api_call: LineInFileModuleInternalApiCall::Add(LineExpectedPosition::SpecificLineNumber(*specific_line_number)),
                                                line_content: self.line.as_ref().unwrap().clone(),
                                                file_path: self.filepath.clone(),
                                                privilege,
                                            })
                                        }
                                    }
                                    LineExpectedPosition::Anywhere => {
                                        if actual_line_numbers.len() != 0 {
                                            // Line is already present somewhere in the file, nothing to do
                                            ModuleApiCall::None(String::from(
                                                "Line already present in the file",
                                            ))
                                        } else {
                                            ModuleApiCall::LineInFile(LineInFileApiCall {
                                                api_call: LineInFileModuleInternalApiCall::Add(LineExpectedPosition::Bottom),
                                                line_content: self.line.as_ref().unwrap().clone(),
                                                file_path: self.filepath.clone(),
                                                privilege,
                                            })
                                        }
                                    }
                                }
                            }
                            None => {
                                // Line is already present but position is not specified (aka "anywhere"), nothing to do
                                ModuleApiCall::None(format!(
                                    "Line already present {:?}",
                                    actual_line_numbers
                                ))
                            }
                        }
                    }
                    None => {
                        // Line is absent and needs to be added
                        match &self.position {
                            Some(expected_position) => {
                                ModuleApiCall::LineInFile(LineInFileApiCall {
                                    api_call: LineInFileModuleInternalApiCall::Add(expected_position.clone()),
                                    line_content: self.line.as_ref().unwrap().clone(),
                                    file_path: self.filepath.clone(),
                                    privilege,
                                })
                            }
                            None => {
                                // Defaults to bottom
                                ModuleApiCall::LineInFile(LineInFileApiCall {
                                    api_call: LineInFileModuleInternalApiCall::Add(LineExpectedPosition::Bottom),
                                    line_content: self.line.as_ref().unwrap().clone(),
                                    file_path: self.filepath.clone(),
                                    privilege,
                                })
                            }
                        }
                    }
                }
            }
            LineExpectedState::Absent => {
                // Check if line is already present
                match is_line_present(
                    hosthandler,
                    self.line.as_ref().unwrap(),
                    &self.filepath,
                    &privilege,
                ) {
                    Some(line_numbers) => ModuleApiCall::LineInFile(LineInFileApiCall {
                        api_call: LineInFileModuleInternalApiCall::Delete(line_numbers),
                        line_content: self.line.as_ref().unwrap().clone(),
                        file_path: self.filepath.clone(),
                        privilege,
                    }),
                    None => {
                        // Line is already absent
                        ModuleApiCall::None(String::from("Line already absent"))
                    }
                }
            }
        };

        return Ok(StepChange::changes([change].to_vec()));
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct LineInFileApiCall {
    file_path: String,
    line_content: String,
    api_call: LineInFileModuleInternalApiCall,
    privilege: Privilege,
}

impl Apply for LineInFileApiCall {
    fn display(&self) -> String {
        match &self.api_call {
            LineInFileModuleInternalApiCall::Add(line_expected_position) => {
                return format!("Line missing -> needs to be added here {:?}", line_expected_position);
            }
            LineInFileModuleInternalApiCall::Delete(line_numbers) => {
                return format!(
                    "Line present {:?} -> needs to be removed",
                    line_numbers
                );
            }
        }
    }

    fn apply_moduleblock_change(&self, hosthandler: &mut HostHandler) -> ApiCallResult {
        match &self.api_call {
            LineInFileModuleInternalApiCall::Add(line_expected_position) => {

                let filenumberoflines = hosthandler
                    .run_cmd(
                        format!("wc -l {} | cut -f 1 -d ' '", self.file_path).as_str(),
                        self.privilege.clone(),
                    )
                    .unwrap()
                    .stdout
                    .trim()
                    .parse::<u64>()
                    .unwrap();

                // let future_line_number: u64 = match line_expected_position {
                //     LineExpectedPosition::Top => 1,
                //     LineExpectedPosition::SpecificLineNumber(specific_line_number) => specific_line_number,
                //     LineExpectedPosition::Bottom | LineExpectedPosition::Anywhere => filelinenumbers
                // };

                // If the file is empty, the sed command won't work.
                let cmd: String;
                if filenumberoflines == 0 {
                    // File is empty -> matches top|bottom|anywhere|given=1
                    match line_expected_position {
                        LineExpectedPosition::Top | LineExpectedPosition::Bottom | LineExpectedPosition::Anywhere => {
                            cmd = format!("echo \'{}\' >> {}", self.line_content, self.file_path);
                        }
                        LineExpectedPosition::SpecificLineNumber(1) => {
                            cmd = format!("echo \'{}\' >> {}", self.line_content, self.file_path);
                        }
                        LineExpectedPosition::SpecificLineNumber(_any_other_line_number) => {
                            // Position = <any other value> which is out of range anyway
                            return ApiCallResult::from(
                                None,
                                None,
                                ApiCallStatus::Failure(String::from(
                                    "Position value out of range (use \"bottom\" instead)",
                                )),
                            );
                        }
                    }
                } else {
                    // File not empty
                    let future_line_number = match line_expected_position {
                        LineExpectedPosition::Top => 1,
                        LineExpectedPosition::Bottom | LineExpectedPosition::Anywhere => filenumberoflines,
                        LineExpectedPosition::SpecificLineNumber(specific_line_number) => *specific_line_number
                    };
                    cmd = format!("sed -i \'{} i {}\' {}", future_line_number, self.line_content, self.file_path);
                }

                let cmd_result = hosthandler
                    .run_cmd(cmd.as_str(), self.privilege.clone())
                    .unwrap();

                if cmd_result.rc == 0 {
                    return ApiCallResult::from(
                        Some(cmd_result.rc),
                        Some(cmd_result.stdout),
                        ApiCallStatus::ChangeSuccessful(String::from("Line added")),
                    );
                } else {
                    return ApiCallResult::from(
                        Some(cmd_result.rc),
                        Some(cmd_result.stdout),
                        ApiCallStatus::Failure(String::from("Failed to add line")),
                    );
                }
            }
            LineInFileModuleInternalApiCall::Delete(line_numbers) => {
                // We need a final command like this : sed -i '7d;12d;16d' input.txt
                // It implies a little formatting first.
                let formatted_line_numbers = line_numbers.clone()
                    .into_iter()
                    .map(|i| format!("{}d;", i))
                    .collect::<String>();
                let formatted_line_numbers = formatted_line_numbers
                    .split_at(formatted_line_numbers.len() - 1)
                    .0; // Delete the last ';

                let cmd = format!("sed -i \'{}\' {}", formatted_line_numbers, self.file_path);
                let cmd_result = hosthandler
                    .run_cmd(cmd.as_str(), self.privilege.clone())
                    .unwrap();

                if cmd_result.rc == 0 {
                    return ApiCallResult::from(
                        Some(cmd_result.rc),
                        Some(cmd_result.stdout),
                        ApiCallStatus::ChangeSuccessful(format!(
                            "Line {:?} removed",
                            line_numbers
                        )),
                    );
                } else {
                    return ApiCallResult::from(
                        Some(cmd_result.rc),
                        Some(cmd_result.stdout),
                        ApiCallStatus::Failure(String::from("Failed to remove line")),
                    );
                }
            }
        }
    }
}

// Returns a Some(Vec<u64>) representing the line numbers of each occurrence of the line if present, and None if absent
fn is_line_present(
    hosthandler: &mut HostHandler,
    line: &String,
    filepath: &String,
    privilege: &Privilege,
) -> Option<Vec<u64>> {
    let test = hosthandler
        .run_cmd(
            format!("grep -n -F -w \'{}\' {}", line, filepath).as_str(), //  Output looks like 4:my line content
            privilege.clone(),
        )
        .unwrap();

    if test.rc == 0 {
        let mut line_numbers: Vec<u64> = Vec::new();
        for line in test.stdout.lines() {
            line_numbers.push(line.split(':').next().unwrap().parse::<u64>().unwrap());
        }
        return Some(line_numbers);
    } else {
        return None;
    }
}


#[cfg(test)]
mod tests {
    use crate::prelude::*;

    #[test]
    fn parsing_lineinfile_module_block_from_yaml_str() {
        let raw_tasklist_description = "---
- name: Dummy steps to test deserialization and syntax of this module
  steps:
    - name: Add a line at the top
      lineinfile:
        filepath: /path/to/my/file
        line: the first line
        state: present
        position: top

    - name: Add a line at the 2nd place
      lineinfile:
        filepath: /path/to/my/file
        line: 2nd line
        state: present
        position: 2
        
    - name: Add a line at the bottom
      lineinfile:
        filepath: /path/to/my/file
        line: the last line
        state: present
        position: bottom

    - name: Remove all occurences of a line based on its content
      lineinfile:
        filepath: /path/to/my/file
        line: the content expected not to be present at all
        state: absent
        ";

        let parsed_tasklist = TaskList::from_str(raw_tasklist_description, TaskListFileType::Yaml);

        assert!(parsed_tasklist.is_ok());
        
    }
}