use crate::result::apicallresult::ApiCallResult;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StepResult {
    pub rc: Option<i32>,        // Last RC of last ApiCallResult
    pub output: Option<String>, // Concatenation of all ApiCallResult outputs
    pub apicallresults: Vec<ApiCallResult>,
}

impl StepResult {
    pub fn new() -> StepResult {
        StepResult {
            rc: None,
            output: None,
            apicallresults: Vec::new(),
        }
    }

    pub fn none() -> StepResult {
        StepResult {
            rc: None,
            output: None,
            apicallresults: Vec::from([ApiCallResult::none()]),
        }
    }

    pub fn from(apicallresults: &Vec<ApiCallResult>) -> StepResult {
        let mut final_rc: i32 = 0;
        let mut output_list = String::new();

        for api_call_result in apicallresults.clone().iter() {
            if let Some(api_call_result_output) = &api_call_result.output {
                output_list.push_str(
                    format!(
                        "{}",
                        api_call_result_output
                            .replace('\n', "\\n")
                            .chars()
                            .filter(|c| !c.is_control())
                            .collect::<String>()
                    )
                    .as_str(),
                );
            }
            match api_call_result.rc {
                None | Some(0) => {}
                Some(failure_rc) => {
                    final_rc = failure_rc;
                    break;
                }
            }
        }

        StepResult {
            rc: Some(final_rc),
            output: Some(output_list),
            apicallresults: apicallresults.clone(),
        }
    }
}
