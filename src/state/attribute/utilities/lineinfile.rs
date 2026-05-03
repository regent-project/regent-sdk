use crate::error::RegentError;
use crate::hosts::managed_host::InternalApiCallOutcome;
use crate::hosts::managed_host::{AssessCompliance, ReachCompliance};
use crate::hosts::properties::HostProperties;
use crate::secrets::SecretProvider;
use crate::state::Check;
use crate::state::attribute::HostHandler;
use crate::state::attribute::Privilege;
use crate::state::attribute::Remediation;
use crate::state::compliance::AttributeComplianceAssessment;
use crate::state::expected_state::Parameter;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
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
#[serde(rename_all = "PascalCase")]
enum LineExpectedState {
    Present,
    Absent,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub enum LineExpectedPosition {
    Top,
    Bottom,
    Anywhere,
    // #[serde(untagged)]
    LineNumber(u64),
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[serde(rename_all = "PascalCase")]
pub struct LineInFileBlockExpectedState {
    file_path: String,
    line: Option<Parameter<String>>,
    state: LineExpectedState,
    position: Option<LineExpectedPosition>, // "top" | "bottom" | "anywhere" (default) | "45" (specific line number)
    line_number: Option<u64>, // Exists to avoid weird YAML writing for LineExpectedPosition::LineNumber(u64)

                              // ****** To be implemented ********
                              // beforeline: Option<String>, // Insert before this line
                              // afterline: Option<String>, // Insert after this line
                              // replace: Option<String>, // Replace this line...
                              // with: Option<String> // ... with this one.
}

impl Check for LineInFileBlockExpectedState {
    fn check(&self) -> Result<(), RegentError> {
        if let (None, None) = (&self.line, &self.position) {
            return Err(RegentError::IncoherentExpectedState(format!(
                "Both 'line' and 'position' are unset. What is the expected state of this file ({}) ?",
                self.file_path
            )));
        }
        Ok(())
    }
}

impl<Handler: HostHandler> AssessCompliance<Handler> for LineInFileBlockExpectedState {
    fn assess_compliance(
        &self,
        host_handler: &mut Handler,
        _host_properties: &Option<HostProperties>,
        privilege: &Privilege,
        optional_secret_provider: &Option<SecretProvider>,
    ) -> Result<AttributeComplianceAssessment, RegentError> {
        if !host_handler
            .is_this_command_available("sed", &privilege)
            .unwrap()
        {
            return Err(RegentError::FailedDryRunEvaluation(
                "Sed command not available on this host".to_string(),
            ));
        }

        let privilege = privilege.clone();

        let file_exists_check = host_handler
            .run_command(format!("test -f {}", self.file_path).as_str(), &privilege)
            .unwrap();

        if file_exists_check.return_code != 0 {
            return Err(RegentError::FailedDryRunEvaluation(format!(
                "{} not found, access denied or not a regular file (directory or device ?)",
                self.file_path
            )));
        }

        let line_content: Option<String> = match self.line.clone() {
            Some(parameter) => Some(parameter.inner_raw(optional_secret_provider).unwrap()),
            None => None,
        };

        let remediation = match &self.state {
            LineExpectedState::Present => {
                let filenumberoflines = host_handler
                    .run_command(
                        format!("wc -l {} | cut -f 1 -d ' '", self.file_path).as_str(),
                        &privilege,
                    )
                    .unwrap()
                    .stdout
                    .trim()
                    .parse::<u64>()
                    .unwrap();

                // Precheck
                let parsed_expected_position = match self.line_number {
                    Some(line_number) => Some(LineExpectedPosition::LineNumber(line_number)),
                    None => self.position.clone(),
                };

                if let Some(LineExpectedPosition::LineNumber(expected_line_number)) =
                    parsed_expected_position
                {
                    if expected_line_number > filenumberoflines {
                        return Err(RegentError::FailedDryRunEvaluation(
                            "Position value out of range (use \"bottom\" instead)".to_string(),
                        ));
                    }
                }

                let file_actual_compliance = is_line_present(
                    host_handler,
                    &line_content.clone().unwrap(),
                    &self.file_path,
                    &privilege,
                );

                match file_actual_compliance {
                    Some(actual_line_numbers) => {
                        // Line is already there but we need to make sure it is at the expected place
                        match &parsed_expected_position {
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
                                                line_content: self.line.clone(),
                                                file_path: self.file_path.clone(),
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
                                                line_content: self.line.clone(),
                                                file_path: self.file_path.clone(),
                                                privilege,
                                            })
                                        }
                                    }
                                    LineExpectedPosition::LineNumber(specific_line_number) => {
                                        if actual_line_numbers.contains(&specific_line_number) {
                                            // Line is already at the right place, nothing to do
                                            Remediation::None(String::from(
                                                "Line already present at expected place",
                                            ))
                                        } else {
                                            Remediation::LineInFile(LineInFileApiCall {
                                                api_call: LineInFileModuleInternalApiCall::Add(
                                                    LineExpectedPosition::LineNumber(
                                                        *specific_line_number,
                                                    ),
                                                ),
                                                line_content: self.line.clone(),
                                                file_path: self.file_path.clone(),
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
                                                line_content: self.line.clone(),
                                                file_path: self.file_path.clone(),
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
                        match &parsed_expected_position {
                            Some(expected_position) => Remediation::LineInFile(LineInFileApiCall {
                                api_call: LineInFileModuleInternalApiCall::Add(
                                    expected_position.clone(),
                                ),
                                line_content: self.line.clone(),
                                file_path: self.file_path.clone(),
                                privilege,
                            }),
                            None => {
                                // Defaults to bottom
                                Remediation::LineInFile(LineInFileApiCall {
                                    api_call: LineInFileModuleInternalApiCall::Add(
                                        LineExpectedPosition::Bottom,
                                    ),
                                    line_content: self.line.clone(),
                                    file_path: self.file_path.clone(),
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
                    &line_content.clone().unwrap(),
                    &self.file_path,
                    &privilege,
                ) {
                    Some(line_numbers) => Remediation::LineInFile(LineInFileApiCall {
                        api_call: LineInFileModuleInternalApiCall::Delete(line_numbers),
                        line_content: self.line.clone(),
                        file_path: self.file_path.clone(),
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
    line_content: Option<Parameter<String>>,
    pub api_call: LineInFileModuleInternalApiCall,
    privilege: Privilege,
}

impl LineInFileApiCall {
    pub fn display(&self) -> String {
        match &self.api_call {
            LineInFileModuleInternalApiCall::Add(line_expected_position) => {
                return format!(
                    "Line missing -> needs to be added here {:?}",
                    line_expected_position
                );
            }
            LineInFileModuleInternalApiCall::Delete(line_numbers) => {
                return format!("Line present {:?} -> needs to be removed", line_numbers);
            }
        }
    }
}

impl<Handler: HostHandler> ReachCompliance<Handler> for LineInFileApiCall {
    fn call(
        &self,
        host_handler: &mut Handler,
        _host_properties: &Option<HostProperties>,
        optional_secret_provider: &Option<SecretProvider>,
    ) -> Result<InternalApiCallOutcome, RegentError> {
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
                //     LineExpectedPosition::LineNumber(specific_line_number) => specific_line_number,
                //     LineExpectedPosition::Bottom | LineExpectedPosition::Anywhere => filelinenumbers
                // };

                let line_content: Option<String> = match self.line_content.clone() {
                    Some(parameter) => Some(parameter.inner_raw(optional_secret_provider).unwrap()),
                    None => None,
                };

                // If the file is empty, the sed command won't work.
                let cmd: String;
                if filenumberoflines == 0 {
                    // File is empty -> matches top|bottom|anywhere|given=1
                    match line_expected_position {
                        LineExpectedPosition::Top
                        | LineExpectedPosition::Bottom
                        | LineExpectedPosition::Anywhere => {
                            cmd =
                                format!("echo \'{}\' >> {}", line_content.unwrap(), self.file_path);
                        }
                        LineExpectedPosition::LineNumber(1) => {
                            cmd =
                                format!("echo \'{}\' >> {}", line_content.unwrap(), self.file_path);
                        }
                        LineExpectedPosition::LineNumber(_any_other_line_number) => {
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
                        LineExpectedPosition::LineNumber(specific_line_number) => {
                            *specific_line_number
                        }
                    };
                    cmd = format!(
                        "sed -i \'{} i {}\' {}",
                        future_line_number,
                        line_content.unwrap(),
                        self.file_path
                    );
                }

                let cmd_result = host_handler
                    .run_command(cmd.as_str(), &self.privilege)
                    .unwrap();

                if cmd_result.return_code == 0 {
                    return Ok(InternalApiCallOutcome::Success(None));
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
                    return Ok(InternalApiCallOutcome::Success(None));
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
    file_path: &String,
    privilege: &Privilege,
) -> Option<Vec<u64>> {
    let test = host_handler
        .run_command(
            format!("grep -n -F -w \'{}\' {}", line, file_path).as_str(), //  Output looks like 4:my line content
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

- FilePath: /path/to/my/file
  Line: the first line
  State: !Present
  Position: !Top

- FilePath: /path/to/my/file
  Line: 2nd line
  State: !Present
  LineNumber: 2

- FilePath: /path/to/my/file
  Line: the last line
  State: !Present
  Position: !Bottom

- FilePath: /path/to/my/file
  Line: the content expected not to be present at all
  State: !Absent
    ";

        let _attributes: Vec<LineInFileBlockExpectedState> =
            yaml_serde::from_str(raw_attributes).unwrap();
    }
}
