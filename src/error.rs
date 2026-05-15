use thiserror::Error;

#[derive(Debug, Error)]
pub enum RegentError {
    #[error("Failure to find group content")]
    FailureToFindGroupContent,

    #[error("Failure to parse content: '{0}'")]
    FailureToParseContent(String),

    #[error("Failure to run command: '{0}'")]
    FailureToRunCommand(String),

    #[error("Failure to establish connection: '{0}'")]
    FailureToEstablishConnection(String),

    #[error("Failed initialization: '{0}'")]
    FailedInitialization(String),

    #[error("Failed TCP binding: '{0}'")]
    FailedTcpBinding(String),

    #[error("Failed task dry run: '{0}'")]
    FailedTaskDryRun(String),

    #[error("Failed dry run evaluation: '{0}'")]
    FailedDryRunEvaluation(String),

    #[error("Failed to apply expected state: '{0}'")]
    FailedToApplyExpectedState(String),

    #[error("Failed to get secret: '{0}'")]
    FailedToGetSecret(String),

    #[error("Failure to consider context: '{0}'")]
    FailureToConsiderContext(String),
    #[error("Missing initialization: '{0}'")]
    MissingInitialization(String),

    #[error("Group not found")]
    GroupNotFound,

    #[error("Missing groups list")]
    MissingGroupsList,

    #[error("Workflow not followed: '{0}'")]
    WorkFlowNotFollowed(String),

    #[error("Wrong initialization: '{0}'")]
    WrongInitialization(String),

    #[error("Any other error: '{0}'")]
    AnyOtherError(String),
    #[error("Incoherent expected state: '{0}'")]
    IncoherentExpectedState(String),

    #[error("Internal logic error: '{0}'")]
    InternalLogicError(String),

    #[error("Not connected to host")]
    NotConnectedToHost,

    #[error("Problem with host connection: '{0}'")]
    ProblemWithHostConnection(String),

    #[error("Secrets issue: '{0}'")]
    SecretsIssue(String),
}
