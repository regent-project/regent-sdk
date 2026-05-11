use std::error::Error;

#[derive(Debug)]
pub enum RegentError {
    FailureToFindGroupContent,
    FailureToParseContent(String),
    FailureToRunCommand(String),
    FailureToEstablishConnection(String),
    FailedInitialization(String),
    FailedTcpBinding(String),
    FailedTaskDryRun(String),
    FailedDryRunEvaluation(String),
    FailedToApplyExpectedState(String),
    FailedToGetSecret(String),
    FailureToConsiderContext(String),
    MissingInitialization(String),
    GroupNotFound,
    MissingGroupsList,
    WorkFlowNotFollowed(String),
    WrongInitialization(String),
    AnyOtherError(String),
    IncoherentExpectedState(String),
    InternalLogicError(String),
    NotConnectedToHost,
    ConnectionLevel(String),
    ProblemWithHostConnection(String),
    SecretsIssue(String),
}

impl std::fmt::Display for RegentError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RegentError::FailureToFindGroupContent => write!(f, "Failure to find group content"),
            RegentError::FailureToParseContent(e) => write!(f, "Failure to parse content: {}", e),
            RegentError::FailureToRunCommand(e) => write!(f, "Failure to run command: {}", e),
            RegentError::FailureToEstablishConnection(e) => {
                write!(f, "Failure to establish connection: {}", e)
            }
            RegentError::FailedInitialization(e) => write!(f, "Failed initialization: {}", e),
            RegentError::FailedTcpBinding(e) => write!(f, "Failed TCP binding: {}", e),
            RegentError::FailedTaskDryRun(e) => write!(f, "Failed task dry run: {}", e),
            RegentError::FailedDryRunEvaluation(e) => write!(f, "Failed dry run evaluation: {}", e),
            RegentError::FailedToApplyExpectedState(e) => {
                write!(f, "Failed to apply expected state: {}", e)
            }
            RegentError::FailedToGetSecret(e) => write!(f, "Failed to get secret: {}", e),
            RegentError::FailureToConsiderContext(e) => {
                write!(f, "Failure to consider context: {}", e)
            }
            RegentError::MissingInitialization(e) => write!(f, "Missing initialization: {}", e),
            RegentError::GroupNotFound => write!(f, "Group not found"),
            RegentError::MissingGroupsList => write!(f, "Missing groups list"),
            RegentError::WorkFlowNotFollowed(e) => write!(f, "Workflow not followed: {}", e),
            RegentError::WrongInitialization(e) => write!(f, "Wrong initialization: {}", e),
            RegentError::AnyOtherError(e) => write!(f, "Any other error: {}", e),
            RegentError::IncoherentExpectedState(e) => {
                write!(f, "Incoherent expected state: {}", e)
            }
            RegentError::InternalLogicError(e) => write!(f, "Internal logic error: {}", e),
            RegentError::NotConnectedToHost => write!(f, "Not connected to host"),
            RegentError::ConnectionLevel(e) => write!(f, "Connection level: {}", e),
            RegentError::ProblemWithHostConnection(e) => {
                write!(f, "Problem with host connection: {}", e)
            }
            RegentError::SecretsIssue(e) => write!(f, "Issue related to secrets: {}", e),
        }
    }
}

impl Error for RegentError {}
