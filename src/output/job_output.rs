use crate::job::job::Job;
use crate::task::moduleblock::ModuleBlockExpectedState;
use crate::workflow::stepflow::StepFlow;
use crate::workflow::stepflow::StepStatus;
use crate::workflow::taskflow::TaskFlow;
use serde::{Deserialize, Serialize};

/// This type is dedicated to being displayed as JSON output of a Job.
#[derive(Serialize, Deserialize)]
pub struct JobOutput {
    host: String,
    timestamp_start: String,
    timestamp_end: String,
    final_status: String,
    tasks: Vec<TaskOutput>,
}

impl JobOutput {
    pub fn new() -> JobOutput {
        JobOutput {
            host: String::new(),
            timestamp_start: String::new(),
            timestamp_end: String::new(),
            final_status: String::new(),
            tasks: Vec::new(),
        }
    }

    pub fn from_job(job: &mut Job) -> JobOutput {
        let mut job_output = JobOutput::new();

        job_output.host = job.get_address();
        job_output.timestamp_start = job.timestamp_start.as_ref().unwrap_or(&"".into()).to_string();
        job_output.timestamp_end = job.timestamp_end.as_ref().unwrap_or(&"".into()).to_string();
        job_output.final_status = format!("{:?}", job.final_status);

        let mut tasks_output: Vec<TaskOutput> = Vec::new();

        if job.hostworkflow.is_some() {
            for task_flow in job.hostworkflow.as_ref().unwrap().clone().task_flows {
                tasks_output.push(TaskOutput::from_taskflow(&task_flow, &job.vars));
            }
        }
        job_output.tasks = tasks_output;

        job_output
    }
}

#[derive(Serialize, Deserialize)]
pub struct TaskOutput {
    name: String,
    steps: Vec<StepOutput>,
}

impl TaskOutput {
    pub fn from_taskflow(task_flow: &TaskFlow, vars: &Option<serde_json::Value>) -> TaskOutput {
        let mut steps_output: Vec<StepOutput> = Vec::new();
        for step_flow in task_flow.step_flows.clone() {
            steps_output.push(StepOutput::from_stepflow(&step_flow, vars));
        }

        TaskOutput {
            name: task_flow.name.as_ref().unwrap().to_string(),
            steps: steps_output,
        }
    }
}

#[derive(Serialize, Deserialize)]
pub struct StepOutput {
    name: String,
    expected_state: ModuleBlockExpectedState,
    status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    raw_output: Option<String>,
}

impl StepOutput {
    pub fn from_stepflow(step_flow: &StepFlow, vars: &Option<serde_json::Value>) -> StepOutput {
        let raw_output = match step_flow.step_status {
            StepStatus::ApplyFailed => {
                let mut api_call_results_output = String::new();
                for api_call_result in step_flow.step_result.clone().unwrap().apicallresults {
                    api_call_results_output
                        .push_str(format!("{}\n", api_call_result.output.unwrap()).as_str());
                }
                Some(api_call_results_output)
            }
            _ => None,
        };

        StepOutput {
            name: step_flow.step_expected.name.as_ref().unwrap().to_string(),
            expected_state: step_flow
                .step_expected
                .moduleblock
                .clone()
                .consider_vars(vars)
                .unwrap(),
            status: format!("{:?}", step_flow.step_status),
            raw_output,
        }
    }
}
