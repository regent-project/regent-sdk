//! Host-side lock
//!
//! Serializes Regent operations on a host, whichever process runs them (a
//! remote runner over SSH/SSHOQ, a local agent such as regops):
//!
//! - assessments take a **shared** lock: any number of them may run in parallel;
//! - remediations ([`ManagedHost::reach_compliance`]) take an **exclusive** lock for their
//!   whole run: no other remediation and no assessment meanwhile, since the host is
//!   in a transitional state.
//!
//! The lock is a `flock(2)` lock on a directory **on the host**. Remotely, it is held
//! by a process attached to the very connection used for the work, so a dead
//! connection releases it, and a caller cannot lose the lock while still being
//! able to act on the host. Locking a directory (rather than a file) lets every
//! user share it without privilege escalation, even in a world-writable directory
//! protected by `fs.protected_regular`.
//!
//! Remote hosts need util-linux's `flock(1)`.
//!
//! [`ManagedHost::reach_compliance`]: crate::hosts::managed_host::ManagedHost::reach_compliance

use serde::{Deserialize, Serialize};
use std::time::Duration;
#[allow(unused)]
use tracing::{debug, error, info, trace, warn};

use crate::error::RegentError;
use crate::hosts::handlers::shell_quote;

/// Default location of the lock directory. `/dev/shm` is world-writable on every
/// Linux host, so any user can create it.
pub const DEFAULT_HOST_LOCK_PATH: &str = "/dev/shm/regent.lock";

/// Printed by the remote lock holder once the lock is acquired.
const LOCKED_MARKER: &str = "REGENT_LOCKED";

/// Exit code of `flock(1)` when the lock could not be acquired in time.
const CONFLICT_EXIT_CODE: i64 = 75;

/// Extra time granted, on top of the lock wait, before the caller gives up on
/// the remote lock holder answering.
const REMOTE_GRACE: Duration = Duration::from_secs(15);

/// How long a release waits for the remote lock holder to exit.
const RELEASE_TIMEOUT: Duration = Duration::from_secs(10);

/// Interval between two attempts of the local lock.
const LOCAL_RETRY_INTERVAL: Duration = Duration::from_millis(100);

/// Kind of host lock.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HostLockMode {
    /// Shared with other assessments (read-only operations).
    Shared,
    /// Exclusive (remediation).
    Exclusive,
}

/// Host lock settings, part of a [`ManagedHostBuilder`].
///
/// Every process working on a host must use the same `Path` for the lock to be
/// effective. Setting the builder's `HostLock` to `null` disables locking.
///
/// [`ManagedHostBuilder`]: crate::hosts::managed_host::ManagedHostBuilder
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "PascalCase")]
#[serde(deny_unknown_fields)]
pub struct HostLockSettings {
    /// Lock directory on the host, created (mode 0755) when missing.
    #[serde(default = "default_path")]
    pub path: String,
    /// Maximum wait for a shared lock (assessment).
    #[serde(default = "default_shared_timeout", with = "humantime_serde")]
    pub shared_timeout: Duration,
    /// Maximum wait for an exclusive lock (remediation).
    #[serde(default = "default_exclusive_timeout", with = "humantime_serde")]
    pub exclusive_timeout: Duration,
}

fn default_path() -> String {
    DEFAULT_HOST_LOCK_PATH.to_string()
}

fn default_shared_timeout() -> Duration {
    Duration::from_secs(60)
}

fn default_exclusive_timeout() -> Duration {
    Duration::from_secs(300)
}

impl Default for HostLockSettings {
    fn default() -> Self {
        Self {
            path: default_path(),
            shared_timeout: default_shared_timeout(),
            exclusive_timeout: default_exclusive_timeout(),
        }
    }
}

impl HostLockSettings {
    /// Maximum wait for a lock of the given mode.
    pub fn timeout(&self, mode: HostLockMode) -> Duration {
        match mode {
            HostLockMode::Shared => self.shared_timeout,
            HostLockMode::Exclusive => self.exclusive_timeout,
        }
    }
}

/// A held host lock. Released by [`HostLock::release`], or on drop.
pub struct HostLock {
    inner: Option<HostLockInner>,
}

enum HostLockInner {
    LocalHost(std::fs::File),
    Ssh2(russh::Channel<russh::client::Msg>),
    Sshoq(shhoq::Session),
}

impl HostLock {
    /// A lock that holds nothing (locking disabled).
    pub(crate) fn disabled() -> Self {
        Self { inner: None }
    }

    pub(crate) fn local(file: std::fs::File) -> Self {
        Self {
            inner: Some(HostLockInner::LocalHost(file)),
        }
    }

    pub(crate) fn ssh2(channel: russh::Channel<russh::client::Msg>) -> Self {
        Self {
            inner: Some(HostLockInner::Ssh2(channel)),
        }
    }

    pub(crate) fn sshoq(session: shhoq::Session) -> Self {
        Self {
            inner: Some(HostLockInner::Sshoq(session)),
        }
    }

    /// Release the lock.
    pub async fn release(mut self) {
        if let Some(inner) = self.inner.take() {
            release_inner(inner).await;
        }
    }
}

impl Drop for HostLock {
    // Covers early returns and cancelled futures. Locally, closing the file
    // releases the lock. Remotely, the release is asynchronous: spawn it if a
    // runtime is available; otherwise the lock lasts until the connection closes.
    fn drop(&mut self) {
        match self.inner.take() {
            None => {}
            Some(HostLockInner::LocalHost(file)) => drop(file),
            Some(remote) => match tokio::runtime::Handle::try_current() {
                Ok(runtime) => {
                    runtime.spawn(release_inner(remote));
                }
                Err(_) => {
                    warn!("Host lock dropped outside a runtime: held until the connection closes")
                }
            },
        }
    }
}

// The remote holder exits as soon as it reads a line (or its stdin closes, when the
// connection dies). The channel is not closed explicitly: SSHOQ ends the whole
// conversation when a session channel's stream ends.
async fn release_inner(inner: HostLockInner) {
    match inner {
        HostLockInner::LocalHost(file) => drop(file),
        HostLockInner::Ssh2(mut channel) => {
            if let Err(details) = channel.data(&b"\n"[..]).await {
                warn!(?details, "Failed to release host lock");
                return;
            }
            let wait_exit = async {
                while let Some(msg) = channel.wait().await {
                    if let russh::ChannelMsg::ExitStatus { .. } = msg {
                        break;
                    }
                }
            };
            if tokio::time::timeout(RELEASE_TIMEOUT, wait_exit)
                .await
                .is_err()
            {
                warn!("Host lock holder did not exit after release");
            }
            let _ = channel.close().await;
        }
        HostLockInner::Sshoq(session) => {
            if let Err(details) = session.write_stdin(b"\n").await {
                warn!(?details, "Failed to release host lock");
                return;
            }
            if tokio::time::timeout(RELEASE_TIMEOUT, session.wait())
                .await
                .is_err()
            {
                warn!("Host lock holder did not exit after release");
            }
        }
    }
}

/// Shell command acquiring the lock on a remote host. On success, it prints
/// [`LOCKED_MARKER`] and keeps the lock until it reads a line or its stdin closes.
/// Run as the login user: no privilege escalation is needed.
pub(crate) fn remote_lock_command(settings: &HostLockSettings, mode: HostLockMode) -> String {
    let path = shell_quote(&settings.path);
    let script = format!(
        "mkdir -p -m 0755 {path} 2>/dev/null; \
exec flock {flag} -w {wait} -E {conflict} {path} sh -c 'echo {marker}; read _regent_release'",
        flag = match mode {
            HostLockMode::Shared => "-s",
            HostLockMode::Exclusive => "-x",
        },
        wait = settings.timeout(mode).as_secs_f64(),
        conflict = CONFLICT_EXIT_CODE,
        marker = LOCKED_MARKER,
    );
    format!("sh -c {} 2>&1", shell_quote(&script))
}

/// Maximum time to wait for the remote lock holder's answer.
pub(crate) fn remote_answer_timeout(settings: &HostLockSettings, mode: HostLockMode) -> Duration {
    settings.timeout(mode) + REMOTE_GRACE
}

/// Outcome of reading the remote lock holder's output so far.
pub(crate) enum RemoteLockProgress {
    Pending,
    Locked,
}

/// Whether the output received so far shows the lock as acquired.
pub(crate) fn remote_progress(output: &str) -> RemoteLockProgress {
    if output.contains(LOCKED_MARKER) {
        RemoteLockProgress::Locked
    } else {
        RemoteLockProgress::Pending
    }
}

/// Error for a remote lock holder that exited without acquiring the lock.
pub(crate) fn remote_exit_error(
    settings: &HostLockSettings,
    mode: HostLockMode,
    exit_code: i64,
    output: &str,
) -> RegentError {
    if exit_code == CONFLICT_EXIT_CODE {
        busy_error(settings, mode)
    } else {
        RegentError::HostLockUnavailable(format!(
            "lock command exited with code {}: {}",
            exit_code,
            output.trim()
        ))
    }
}

fn busy_error(settings: &HostLockSettings, mode: HostLockMode) -> RegentError {
    RegentError::HostBusy(format!(
        "no {} lock on {} within {:?}",
        match mode {
            HostLockMode::Shared => "shared",
            HostLockMode::Exclusive => "exclusive",
        },
        settings.path,
        settings.timeout(mode)
    ))
}

/// Acquire the lock on the local machine, in process.
#[cfg(unix)]
pub(crate) async fn acquire_local(
    settings: &HostLockSettings,
    mode: HostLockMode,
) -> Result<HostLock, RegentError> {
    use std::fs::{DirBuilder, File, Permissions, TryLockError};
    use std::os::unix::fs::{DirBuilderExt, PermissionsExt};

    let path = std::path::Path::new(&settings.path);
    if !path.exists() {
        // The umask may restrict the mode given to mkdir: other users must be able
        // to open the directory, so set it explicitly.
        if DirBuilder::new()
            .recursive(true)
            .mode(0o755)
            .create(path)
            .is_ok()
        {
            let _ = std::fs::set_permissions(path, Permissions::from_mode(0o755));
        }
    }

    let file = File::open(path).map_err(|details| {
        RegentError::HostLockUnavailable(format!("cannot open {}: {}", settings.path, details))
    })?;

    let deadline = tokio::time::Instant::now() + settings.timeout(mode);
    loop {
        let attempt = match mode {
            HostLockMode::Shared => file.try_lock_shared(),
            HostLockMode::Exclusive => file.try_lock(),
        };
        match attempt {
            Ok(()) => return Ok(HostLock::local(file)),
            Err(TryLockError::WouldBlock) => {
                if tokio::time::Instant::now() >= deadline {
                    return Err(busy_error(settings, mode));
                }
                tokio::time::sleep(LOCAL_RETRY_INTERVAL).await;
            }
            Err(TryLockError::Error(details)) => {
                return Err(RegentError::HostLockUnavailable(format!(
                    "cannot lock {}: {}",
                    settings.path, details
                )));
            }
        }
    }
}

/// Windows: a lock **file** (`LockFileEx` through `File::try_lock*`; a
/// directory cannot be locked there). The Unix default path maps to
/// `%ProgramData%\regent\regent.lock`; every process on the machine must use
/// the same path.
#[cfg(windows)]
pub(crate) async fn acquire_local(
    settings: &HostLockSettings,
    mode: HostLockMode,
) -> Result<HostLock, RegentError> {
    use std::fs::{OpenOptions, TryLockError};

    let path = windows_lock_path(&settings.path);
    if let Some(parent) = path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(&path)
        .map_err(|details| {
            RegentError::HostLockUnavailable(format!("cannot open {}: {}", path.display(), details))
        })?;

    let deadline = tokio::time::Instant::now() + settings.timeout(mode);
    loop {
        let attempt = match mode {
            HostLockMode::Shared => file.try_lock_shared(),
            HostLockMode::Exclusive => file.try_lock(),
        };
        match attempt {
            Ok(()) => return Ok(HostLock::local(file)),
            Err(TryLockError::WouldBlock) => {
                if tokio::time::Instant::now() >= deadline {
                    return Err(busy_error(settings, mode));
                }
                tokio::time::sleep(LOCAL_RETRY_INTERVAL).await;
            }
            Err(TryLockError::Error(details)) => {
                return Err(RegentError::HostLockUnavailable(format!(
                    "cannot lock {}: {}",
                    path.display(),
                    details
                )));
            }
        }
    }
}

/// The lock file used on Windows for a configured path.
#[cfg_attr(not(windows), allow(dead_code))]
fn windows_lock_path(configured: &str) -> std::path::PathBuf {
    if configured == DEFAULT_HOST_LOCK_PATH {
        let base = std::env::var("ProgramData").unwrap_or_else(|_| r"C:\ProgramData".to_string());
        std::path::Path::new(&base)
            .join("regent")
            .join("regent.lock")
    } else {
        std::path::PathBuf::from(configured)
    }
}

#[cfg(not(any(unix, windows)))]
pub(crate) async fn acquire_local(
    _settings: &HostLockSettings,
    _mode: HostLockMode,
) -> Result<HostLock, RegentError> {
    Err(RegentError::HostLockUnavailable(
        "host lock is only supported on Unix and Windows".to_string(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn windows_lock_path_maps_the_unix_default() {
        let mapped = windows_lock_path(DEFAULT_HOST_LOCK_PATH);
        assert!(mapped.ends_with(std::path::Path::new("regent").join("regent.lock")));
        assert_eq!(
            windows_lock_path("D:/locks/regent.lock"),
            std::path::PathBuf::from("D:/locks/regent.lock")
        );
    }

    fn settings_in(dir: &std::path::Path) -> HostLockSettings {
        HostLockSettings {
            path: dir.join("regent.lock").to_string_lossy().to_string(),
            shared_timeout: Duration::from_millis(300),
            exclusive_timeout: Duration::from_millis(300),
        }
    }

    fn temp_dir(name: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("regent-lock-{}-{}", name, nanoid::nanoid!()));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[tokio::test]
    async fn shared_locks_coexist() {
        let settings = settings_in(&temp_dir("shared"));
        let first = acquire_local(&settings, HostLockMode::Shared)
            .await
            .unwrap();
        let second = acquire_local(&settings, HostLockMode::Shared)
            .await
            .unwrap();
        first.release().await;
        second.release().await;
    }

    #[tokio::test]
    async fn exclusive_excludes_shared_and_exclusive() {
        let settings = settings_in(&temp_dir("exclusive"));
        let exclusive = acquire_local(&settings, HostLockMode::Exclusive)
            .await
            .unwrap();
        assert!(matches!(
            acquire_local(&settings, HostLockMode::Shared).await,
            Err(RegentError::HostBusy(_))
        ));
        assert!(matches!(
            acquire_local(&settings, HostLockMode::Exclusive).await,
            Err(RegentError::HostBusy(_))
        ));
        exclusive.release().await;
        acquire_local(&settings, HostLockMode::Shared)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn shared_excludes_exclusive_until_dropped() {
        let settings = settings_in(&temp_dir("drop"));
        let shared = acquire_local(&settings, HostLockMode::Shared)
            .await
            .unwrap();
        assert!(matches!(
            acquire_local(&settings, HostLockMode::Exclusive).await,
            Err(RegentError::HostBusy(_))
        ));
        drop(shared);
        acquire_local(&settings, HostLockMode::Exclusive)
            .await
            .unwrap();
    }

    #[test]
    fn settings_defaults_and_serde() {
        let parsed: HostLockSettings = yaml_serde::from_str("Path: /run/regent.lock").unwrap();
        assert_eq!(parsed.path, "/run/regent.lock");
        assert_eq!(parsed.shared_timeout, Duration::from_secs(60));
        assert_eq!(parsed.exclusive_timeout, Duration::from_secs(300));

        let parsed: HostLockSettings =
            yaml_serde::from_str("SharedTimeout: 10s\nExclusiveTimeout: 2m").unwrap();
        assert_eq!(parsed.path, DEFAULT_HOST_LOCK_PATH);
        assert_eq!(parsed.shared_timeout, Duration::from_secs(10));
        assert_eq!(parsed.exclusive_timeout, Duration::from_secs(120));
    }

    // Runs the remote command locally, as sshd would, against the local lock.
    // Skipped when util-linux's flock(1) is missing.
    #[tokio::test]
    async fn remote_command_locks_and_releases() {
        use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

        if std::process::Command::new("flock")
            .arg("--version")
            .output()
            .is_err()
        {
            return;
        }
        let dir = temp_dir("remote with 'quote'");
        let settings = settings_in(&dir);

        let mut holder = tokio::process::Command::new("sh")
            .arg("-c")
            .arg(remote_lock_command(&settings, HostLockMode::Exclusive))
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .kill_on_drop(true)
            .spawn()
            .unwrap();
        let mut stdout = BufReader::new(holder.stdout.take().unwrap()).lines();
        let first_line = stdout.next_line().await.unwrap().unwrap();
        assert!(matches!(
            remote_progress(&first_line),
            RemoteLockProgress::Locked
        ));

        // The remote holder excludes the local lock, and vice versa
        assert!(matches!(
            acquire_local(&settings, HostLockMode::Shared).await,
            Err(RegentError::HostBusy(_))
        ));
        let busy = tokio::process::Command::new("sh")
            .arg("-c")
            .arg(remote_lock_command(&settings, HostLockMode::Shared))
            .output()
            .await
            .unwrap();
        let output = String::from_utf8_lossy(&busy.stdout);
        assert!(matches!(
            remote_exit_error(
                &settings,
                HostLockMode::Shared,
                busy.status.code().unwrap().into(),
                &output
            ),
            RegentError::HostBusy(_)
        ));

        // Release: one line on stdin
        holder.stdin.take().unwrap().write_all(b"\n").await.unwrap();
        assert!(holder.wait().await.unwrap().success());
        acquire_local(&settings, HostLockMode::Exclusive)
            .await
            .unwrap();
    }

    #[test]
    fn remote_command_quotes_path_and_mode() {
        let settings = HostLockSettings {
            path: "/tmp/it's here".to_string(),
            ..Default::default()
        };
        let command = remote_lock_command(&settings, HostLockMode::Exclusive);
        assert!(command.starts_with("sh -c "));
        assert!(command.contains("flock -x -w 300"));
        assert!(command.contains("-E 75"));
    }
}
