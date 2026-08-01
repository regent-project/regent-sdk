//! Error types for Regent SDK
//!
//! This module provides comprehensive error handling for all operations
//! within the Regent SDK. All errors implement `std::error::Error` and
//! provide detailed context for troubleshooting.

use thiserror::Error;

/// The primary error type for Regent SDK operations.
///
/// All operations in Regent SDK return this error type, which provides
/// detailed information about what went wrong during execution.
///
/// # Error Variants
///
/// - `FailureToFindGroupContent`: Could not locate group information
/// - `FailureToParseContent`: Parsing errors (YAML, JSON, etc.)
/// - `FailureToRunCommand`: Command execution failed
/// - `FailureToEstablishConnection`: Connection to host failed
/// - `FailedInitialization`: Initialization or setup error
/// - `FailedTcpBinding`: TCP binding failed
/// - `FailedTaskDryRun`: Dry run of a task failed
/// - `FailedDryRunEvaluation`: Evaluation during dry run failed
/// - `FailedToApplyExpectedState`: Could not apply the expected state
/// - `FailedToGetSecret`: Secret retrieval failed
/// - `FailureToConsiderContext`: Template context rendering failed
/// - `MissingInitialization`: Required initialization was missing
/// - `GroupNotFound`: Requested group does not exist
/// - `MissingGroupsList`: Groups list was not provided
/// - `WorkFlowNotFollowed`: Required workflow was not followed
/// - `WrongInitialization`: Initialization was incorrect
/// - `AnyOtherError`: Generic error wrapper
/// - `IncoherentExpectedState`: Expected state definition was inconsistent
/// - `InternalLogicError`: Internal library error (please report)
/// - `NotConnectedToHost`: Operation attempted without active connection
/// - `ProblemWithHostConnection`: Connection issue with host
/// - `SecretsIssue`: Problem with secret management
/// - `AttributeError`: Issue with an attribute definition or execution
/// - `TimeOutReached`: Operation timed out
///
/// # Example
///
/// ```no_run
/// use regent_sdk::RegentError;
///
/// fn handle_error(e: RegentError) {
///     match e {
///         RegentError::NotConnectedToHost => {
///             eprintln!("Please connect to the host first");
///         }
///         RegentError::TimeOutReached(msg) => {
///             eprintln!("Operation timed out: {}", msg);
///         }
///         RegentError::FailedToGetSecret(msg) => {
///             eprintln!("Secret retrieval failed: {}", msg);
///         }
///         _ => {
///             eprintln!("An error occurred: {:?}", e);
///         }
///     }
/// }
/// ```
#[derive(Debug, Error, Clone)]
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

    #[error("Attribute error: '{0}'")]
    AttributeError(String),

    #[error("TimeOut reached: '{0}'")]
    TimeOutReached(String),

    #[error("Failed to get file: '{0}'")]
    FailedToGetFile(String),

    #[error("Incompatible host: '{0}'")]
    IncompatibleHost(String),
}
