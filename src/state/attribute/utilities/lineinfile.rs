use crate::error::Error;
use crate::managed_host::InternalApiCallOutcome;
use crate::managed_host::{AssessCompliance, ReachCompliance};
use crate::state::attribute::HostHandler;
use crate::state::attribute::Privilege;
use crate::state::attribute::Remediation;
use crate::state::compliance::AttributeComplianceAssessment;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum LineInFileModuleInternalApiCall {
    Add(LineExpectedPosition),
    Delete(Vec<u64>),
}

impl std::fmt::Display for LineInFileModuleInternalApiCall {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LineInFileModuleInternalApiCall::Add(position) => {
                write!(f, "add line at position {:?}", position)
            }
            LineInFileModuleInternalApiCall::Delete(line_numbers) => {
                write!(f, "delete lines {:?}", line_numbers)
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
enum LineExpectedState {
    Present,
    Absent,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum LineExpectedPosition {
    Top,
    Bottom,
    Anywhere,
    #[serde(untagged)]
    SpecificLineNumber(u64),
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LineInFileBlockExpectedState {
    filepath: String,
    line: Option<String>,
    state: LineExpectedState,
    position: Option<LineExpectedPosition>, // "top" | "bottom" | "anywhere" (default) | "45" (specific line number)

                                            // ****** To be implemented ********
                                            // beforeline: Option<String>, // Insert before this line
                                            // afterline: Option<String>, // Insert after this line
                                            // replace: Option<String>, // Replace this line...
                                            // with: Option<String> // ... with this one.
}

// impl Check for LineInFileBlockExpectedState {
//     fn check(&self) -> Result<(), Error> {
//         if let (None, None) = (&self.line, &self.position) {
//             return Err(Error::IncoherentExpectedState(format!(
//                 "Both 'line' and 'position' are unset. What is the expected state of this file ({}) ?",
//                 self.filepath
//             )));
//         }
//         Ok(())
//     }
// }

impl<Handler: HostHandler> AssessCompliance<Handler> for LineInFileBlockExpectedState {
    fn assess_compliance(
        &self,
        host_handler: &mut Handler,
        privilege: &Privilege,
    ) -> Result<AttributeComplianceAssessment, Error> {
        if !host_handler
            .is_this_command_available("sed", &privilege)
            .unwrap()
        {
            return Err(Error::FailedDryRunEvaluation(
                "Sed command not available on this host".to_string(),
            ));
        }

        let privilege = privilege.clone();

        let file_exists_check = host_handler
            .run_command(format!("test -f {}", self.filepath).as_str(), &privilege)
            .unwrap();

        if file_exists_check.return_code != 0 {
            return Err(Error::FailedDryRunEvaluation(format!(
                "{} not found or not a regular file",
                self.filepath
            )));
        }

        let remediation = match &self.state {
            LineExpectedState::Present => {
                let filenumberoflines = host_handler
                    .run_command(
                        format!("wc -l {} | cut -f 1 -d ' '", self.filepath).as_str(),
                        &privilege,
                    )
                    .unwrap()
                    .stdout
                    .trim()
                    .parse::<u64>()
                    .unwrap();

                // Precheck
                if let Some(LineExpectedPosition::SpecificLineNumber(expected_line_number)) =
                    self.position
                {
                    if expected_line_number > filenumberoflines {
                        return Err(Error::FailedDryRunEvaluation(
                            "Position value out of range (use \"bottom\" instead)".to_string(),
                        ));
                    }
                }

                let file_actual_compliance = is_line_present(
                    host_handler,
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
                                            Remediation::None(String::from(
                                                "Line already present at expected place",
                                            ))
                                        } else {
                                            Remediation::LineInFile(LineInFileApiCall {
                                                api_call: LineInFileModuleInternalApiCall::Add(
                                                    LineExpectedPosition::Top,
                                                ),
                                                line_content: self.line.as_ref().unwrap().clone(),
                                                file_path: self.filepath.clone(),
                                                privilege,
                                            })
                                        }
                                    }
                                    LineExpectedPosition::Bottom => {
                                        if actual_line_numbers.contains(&filenumberoflines) {
                                            // Line is already at the right place, nothing to do
                                            Remediation::None(String::from(
                                                "Line already present at expected place",
                                            ))
                                        } else {
                                            Remediation::LineInFile(LineInFileApiCall {
                                                api_call: LineInFileModuleInternalApiCall::Add(
                                                    LineExpectedPosition::Bottom,
                                                ),
                                                line_content: self.line.as_ref().unwrap().clone(),
                                                file_path: self.filepath.clone(),
                                                privilege,
                                            })
                                        }
                                    }
                                    LineExpectedPosition::SpecificLineNumber(
                                        specific_line_number,
                                    ) => {
                                        if actual_line_numbers.contains(&specific_line_number) {
                                            // Line is already at the right place, nothing to do
                                            Remediation::None(String::from(
                                                "Line already present at expected place",
                                            ))
                                        } else {
                                            Remediation::LineInFile(LineInFileApiCall {
                                                api_call: LineInFileModuleInternalApiCall::Add(
                                                    LineExpectedPosition::SpecificLineNumber(
                                                        *specific_line_number,
                                                    ),
                                                ),
                                                line_content: self.line.as_ref().unwrap().clone(),
                                                file_path: self.filepath.clone(),
                                                privilege,
                                            })
                                        }
                                    }
                                    LineExpectedPosition::Anywhere => {
                                        if actual_line_numbers.len() != 0 {
                                            // Line is already present somewhere in the file, nothing to do
                                            Remediation::None(String::from(
                                                "Line already present in the file",
                                            ))
                                        } else {
                                            Remediation::LineInFile(LineInFileApiCall {
                                                api_call: LineInFileModuleInternalApiCall::Add(
                                                    LineExpectedPosition::Bottom,
                                                ),
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
                                Remediation::None(format!(
                                    "Line already present {:?}",
                                    actual_line_numbers
                                ))
                            }
                        }
                    }
                    None => {
                        // Line is absent and needs to be added
                        match &self.position {
                            Some(expected_position) => Remediation::LineInFile(LineInFileApiCall {
                                api_call: LineInFileModuleInternalApiCall::Add(
                                    expected_position.clone(),
                                ),
                                line_content: self.line.as_ref().unwrap().clone(),
                                file_path: self.filepath.clone(),
                                privilege,
                            }),
                            None => {
                                // Defaults to bottom
                                Remediation::LineInFile(LineInFileApiCall {
                                    api_call: LineInFileModuleInternalApiCall::Add(
                                        LineExpectedPosition::Bottom,
                                    ),
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
                    host_handler,
                    self.line.as_ref().unwrap(),
                    &self.filepath,
                    &privilege,
                ) {
                    Some(line_numbers) => Remediation::LineInFile(LineInFileApiCall {
                        api_call: LineInFileModuleInternalApiCall::Delete(line_numbers),
                        line_content: self.line.as_ref().unwrap().clone(),
                        file_path: self.filepath.clone(),
                        privilege,
                    }),
                    None => {
                        // Line is already absent
                        Remediation::None(String::from("Line already absent"))
                    }
                }
            }
        };

        if let Remediation::None(_message) = remediation {
            Ok(AttributeComplianceAssessment::Compliant)
        } else {
            Ok(AttributeComplianceAssessment::NonCompliant(Vec::from([
                remediation,
            ])))
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct LineInFileApiCall {
    file_path: String,
    line_content: String,
    pub api_call: LineInFileModuleInternalApiCall,
    privilege: Privilege,
}

impl<Handler: HostHandler> ReachCompliance<Handler> for LineInFileApiCall {
    // fn display(&self) -> String {
    //     match &self.api_call {
    //         LineInFileModuleInternalApiCall::Add(line_expected_position) => {
    //             return format!(
    //                 "Line missing -> needs to be added here {:?}",
    //                 line_expected_position
    //             );
    //         }
    //         LineInFileModuleInternalApiCall::Delete(line_numbers) => {
    //             return format!("Line present {:?} -> needs to be removed", line_numbers);
    //         }
    //     }
    // }

    fn call(&self, host_handler: &mut Handler) -> Result<InternalApiCallOutcome, Error> {
        match &self.api_call {
            LineInFileModuleInternalApiCall::Add(line_expected_position) => {
                let filenumberoflines = host_handler
                    .run_command(
                        format!("wc -l {} | cut -f 1 -d ' '", self.file_path).as_str(),
                        &self.privilege,
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
                        LineExpectedPosition::Top
                        | LineExpectedPosition::Bottom
                        | LineExpectedPosition::Anywhere => {
                            cmd = format!("echo \'{}\' >> {}", self.line_content, self.file_path);
                        }
                        LineExpectedPosition::SpecificLineNumber(1) => {
                            cmd = format!("echo \'{}\' >> {}", self.line_content, self.file_path);
                        }
                        LineExpectedPosition::SpecificLineNumber(_any_other_line_number) => {
                            // Position = <any other value> which is out of range anyway
                            return Ok(InternalApiCallOutcome::Failure(String::from(
                                "Position value out of range (use \"bottom\" instead)",
                            )));
                        }
                    }
                } else {
                    // File not empty
                    let future_line_number = match line_expected_position {
                        LineExpectedPosition::Top => 1,
                        LineExpectedPosition::Bottom | LineExpectedPosition::Anywhere => {
                            filenumberoflines
                        }
                        LineExpectedPosition::SpecificLineNumber(specific_line_number) => {
                            *specific_line_number
                        }
                    };
                    cmd = format!(
                        "sed -i \'{} i {}\' {}",
                        future_line_number, self.line_content, self.file_path
                    );
                }

                let cmd_result = host_handler
                    .run_command(cmd.as_str(), &self.privilege)
                    .unwrap();

                if cmd_result.return_code == 0 {
                    return Ok(InternalApiCallOutcome::Success);
                } else {
                    return Ok(InternalApiCallOutcome::Failure(format!(
                        "Failed to add line. RC : {}, STDOUT : {}, STDERR : {}",
                        cmd_result.return_code, cmd_result.stdout, cmd_result.stderr
                    )));
                }
            }
            LineInFileModuleInternalApiCall::Delete(line_numbers) => {
                // We need a final command like this : sed -i '7d;12d;16d' input.txt
                // It implies a little formatting first.
                let formatted_line_numbers = line_numbers
                    .clone()
                    .into_iter()
                    .map(|i| format!("{}d;", i))
                    .collect::<String>();
                let formatted_line_numbers = formatted_line_numbers
                    .split_at(formatted_line_numbers.len() - 1)
                    .0; // Delete the last ';

                let cmd = format!("sed -i \'{}\' {}", formatted_line_numbers, self.file_path);
                let cmd_result = host_handler
                    .run_command(cmd.as_str(), &self.privilege)
                    .unwrap();

                if cmd_result.return_code == 0 {
                    return Ok(InternalApiCallOutcome::Success);
                } else {
                    return Ok(InternalApiCallOutcome::Failure(format!(
                        "Failed to remove line. RC : {}, STDOUT : {}, STDERR : {}",
                        cmd_result.return_code, cmd_result.stdout, cmd_result.stderr
                    )));
                }
            }
        }
    }
}

// Returns a Some(Vec<u64>) representing the line numbers of each occurrence of the line if present, and None if absent
fn is_line_present<Handler: HostHandler>(
    host_handler: &mut Handler,
    line: &String,
    filepath: &String,
    privilege: &Privilege,
) -> Option<Vec<u64>> {
    let test = host_handler
        .run_command(
            format!("grep -n -F -w \'{}\' {}", line, filepath).as_str(), //  Output looks like 4:my line content
            &privilege,
        )
        .unwrap();

    if test.return_code == 0 {
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
    use super::*;

    #[test]
    fn parsing_lineinfile_module_block_from_yaml_str() {
        let raw_attributes = "---

- filepath: /path/to/my/file
  line: the first line
  state: present
  position: top

- filepath: /path/to/my/file
  line: 2nd line
  state: present
  position: 2

- filepath: /path/to/my/file
  line: the last line
  state: present
  position: bottom

- filepath: /path/to/my/file
  line: the content expected not to be present at all
  state: absent
    ";

        let attributes: Vec<LineInFileBlockExpectedState> =
            serde_yaml::from_str(raw_attributes).unwrap();
    }
}
