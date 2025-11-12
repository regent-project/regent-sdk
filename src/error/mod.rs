//! Regent-sdk specific errors

// Definition of all possible errors for the whole crate
// FIXME : relevant to subdivide this into multiple enums ?

#[derive(Debug)]
pub enum Error {
    FailureToFindGroupContent,
    FailureToParseContent(String),
    FailureToRunCommand(String),
    FailureToEstablishConnection(String),
    FailedInitialization(String),
    FailedTcpBinding(String),
    FailedTaskDryRun(String),
    FailedDryRunEvaluation(String),
    MissingInitialization(String),
    GroupNotFound,
    MissingGroupsList,
    WorkFlowNotFollowed(String),
    WrongInitialization(String),
    AnyOtherError(String),
    IncoherentExpectedState(String)
}
