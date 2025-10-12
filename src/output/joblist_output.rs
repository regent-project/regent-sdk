use crate::job::joblist::JobList;
use crate::output::job_output::JobOutput;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
pub struct JobListOutput {
    jobs: Vec<JobOutput>,
}

impl JobListOutput {
    pub fn from_joblist(job_list: &mut JobList) -> JobListOutput {
        let mut jobs_output: Vec<JobOutput> = Vec::new();

        if let Some(jobs) = &mut job_list.job_list {
            for job in jobs {
                jobs_output.push(JobOutput::from_job(job));
            }
        }

        JobListOutput { jobs: jobs_output }
    }
}
