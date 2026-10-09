//! Package-manager attributes (`apt`, `pacman`, `yumdnf`) and package
//! repository management (`apt_repo`, `dnf_repo`).
//!
//! Value types that carry the same semantics across the attributes of this
//! category are defined here, at category level, and imported by the
//! attribute modules.

pub mod apt;
pub mod apt_repo;
pub mod dnf_repo;
pub mod pacman;
pub mod yumdnf;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub enum PackageExpectedState {
    Present,
    Absent,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub enum RepoExpectedStatus {
    Present,
    Absent,
}
