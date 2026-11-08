//! Windows hosts (feature `windows`): PowerShell scripts and file transfer
//! over [`HostHandler::run_windows_command`] (`cmd /C` on the host).
//!
//! Scripts are passed with `-EncodedCommand` (UTF-16LE, base64), so no
//! quoting of the script itself is needed; values inside a script are quoted
//! with [`ps_quote`]. Files are read as base64 on stdout and written in
//! base64 chunks to a temporary file, then moved into place.

use base64::Engine;
use base64::engine::general_purpose::STANDARD;

use crate::error::RegentError;
use crate::hosts::command::CommandResult;
use crate::hosts::handlers::HostHandler;

/// `cmd /C` limits a command line to 8191 characters: chunks stay well below.
const CHUNK_BYTES: usize = 2048;

/// A PowerShell single-quoted string literal.
pub fn ps_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "''"))
}

/// The `cmd` command line running `script` in PowerShell.
pub fn powershell_command(script: &str) -> String {
    let utf16: Vec<u8> = script
        .encode_utf16()
        .flat_map(|unit| unit.to_le_bytes())
        .collect();
    format!(
        "powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -EncodedCommand {}",
        STANDARD.encode(utf16)
    )
}

/// Run a PowerShell script on the host. Errors stop the script
/// (`$ErrorActionPreference = 'Stop'`) with a non-zero exit code.
pub async fn run_powershell<Handler: HostHandler>(
    host_handler: &mut Handler,
    script: &str,
) -> Result<CommandResult, RegentError> {
    let script = format!(
        "$ErrorActionPreference = 'Stop'\n$ProgressPreference = 'SilentlyContinue'\ntry {{\n{script}\n}} catch {{ [Console]::Error.WriteLine($_.Exception.Message); exit 1 }}"
    );
    host_handler
        .run_windows_command(&powershell_command(&script))
        .await
}

/// A file's content, or `None` when it does not exist.
pub async fn read_file<Handler: HostHandler>(
    host_handler: &mut Handler,
    path: &str,
) -> Result<Option<Vec<u8>>, RegentError> {
    let script = format!(
        "$p = {path}\nif (-not (Test-Path -LiteralPath $p -PathType Leaf)) {{ exit 3 }}\n[Convert]::ToBase64String([IO.File]::ReadAllBytes($p))",
        path = ps_quote(path)
    );
    let result = run_powershell(host_handler, &script).await?;
    match result.return_code {
        0 => {
            let encoded: String = result.stdout.split_whitespace().collect();
            STANDARD
                .decode(encoded)
                .map(Some)
                .map_err(|e| RegentError::FailedToGetFile(format!("{path}: invalid base64: {e}")))
        }
        3 => Ok(None),
        code => Err(RegentError::FailedToGetFile(format!(
            "{path}: exit code {code}: {}",
            result.stderr.trim()
        ))),
    }
}

/// Write `content` to `path` (created or replaced): chunks go to a temporary
/// file next to it, which then replaces the target in one move.
pub async fn write_file<Handler: HostHandler>(
    host_handler: &mut Handler,
    path: &str,
    content: &[u8],
) -> Result<(), String> {
    let temp = format!("{path}.regent-tmp");
    let chunks: Vec<&[u8]> = if content.is_empty() {
        vec![&[][..]]
    } else {
        content.chunks(CHUNK_BYTES).collect()
    };
    for (index, chunk) in chunks.iter().enumerate() {
        let mode = if index == 0 { "Create" } else { "Append" };
        let script = format!(
            "$b = [Convert]::FromBase64String('{data}')\n$f = [IO.File]::Open({temp}, [IO.FileMode]::{mode}, [IO.FileAccess]::Write)\ntry {{ $f.Write($b, 0, $b.Length) }} finally {{ $f.Close() }}",
            data = STANDARD.encode(chunk),
            temp = ps_quote(&temp),
        );
        check(run_powershell(host_handler, &script).await, &temp)?;
    }
    let script = format!(
        "Move-Item -LiteralPath {temp} -Destination {path} -Force",
        temp = ps_quote(&temp),
        path = ps_quote(path)
    );
    check(run_powershell(host_handler, &script).await, path)
}

fn check(result: Result<CommandResult, RegentError>, path: &str) -> Result<(), String> {
    match result {
        Ok(result) if result.return_code == 0 => Ok(()),
        Ok(result) => Err(format!(
            "{path}: exit code {}: {}",
            result.return_code,
            result.stderr.trim()
        )),
        Err(e) => Err(format!("{path}: {e:?}")),
    }
}

/// Text lines of a file and the line ending it uses (`\r\n` when the file
/// has any, else `\n`), so edits keep the file's convention.
pub fn split_lines(content: &str) -> (Vec<String>, &'static str) {
    let ending = if content.contains("\r\n") {
        "\r\n"
    } else {
        "\n"
    };
    let lines = content
        .lines()
        .map(|line| line.trim_end_matches('\r').to_string())
        .collect();
    (lines, ending)
}

/// Lines joined back, with a final line ending (like `printf '%s\n'`).
pub fn join_lines(lines: &[String], ending: &str) -> String {
    let mut out = String::new();
    for line in lines {
        out.push_str(line);
        out.push_str(ending);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quoting_and_encoding() {
        assert_eq!(ps_quote("it's"), "'it''s'");
        let command = powershell_command("Write-Output 'é'");
        let encoded = command.rsplit(' ').next().unwrap();
        let bytes = STANDARD.decode(encoded).unwrap();
        let units: Vec<u16> = bytes
            .chunks(2)
            .map(|c| u16::from_le_bytes([c[0], c[1]]))
            .collect();
        assert_eq!(String::from_utf16(&units).unwrap(), "Write-Output 'é'");
        assert!(command.len() < 8191);
    }

    #[test]
    fn lines_keep_their_ending() {
        let (lines, ending) = split_lines("a\r\nb\r\n");
        assert_eq!(lines, vec!["a", "b"]);
        assert_eq!(join_lines(&lines, ending), "a\r\nb\r\n");
        let (lines, ending) = split_lines("a\nb");
        assert_eq!(join_lines(&lines, ending), "a\nb\n");
    }

    #[test]
    fn a_chunk_fits_in_a_command_line() {
        let chunk = vec![0u8; CHUNK_BYTES];
        let script = format!(
            "$ErrorActionPreference = 'Stop'\n$b = [Convert]::FromBase64String('{}')\n$f = [IO.File]::Open('C:\\some\\long\\path\\to\\a\\file.regent-tmp', [IO.FileMode]::Append, [IO.FileAccess]::Write)\ntry {{ $f.Write($b, 0, $b.Length) }} finally {{ $f.Close() }} catch {{}}",
            STANDARD.encode(chunk)
        );
        assert!(powershell_command(&script).len() < 8191);
    }
}
