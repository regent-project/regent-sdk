//! Command execution results
//!
//! This module provides types for handling command execution output.

/// Result of executing a command on a host.
///
/// Contains the return code, standard output, and standard error streams
/// from command execution.
///
/// # Example
///
/// ```no_run
/// use regent_sdk::command::CommandResult;
///
/// let result = CommandResult {
///     return_code: 0,
///     stdout: "Command executed successfully".to_string(),
///     stderr: "".to_string(),
/// };
///
/// assert!(result.return_code == 0);
/// ```
#[derive(Debug)]
pub struct CommandResult {
    /// The exit code returned by the command.
    ///
    /// A value of 0 typically indicates success, while non-zero values indicate errors.
    pub return_code: i64,

    /// The standard output captured from the command execution.
    pub stdout: String,

    /// The standard error captured from the command execution.
    pub stderr: String,
}
