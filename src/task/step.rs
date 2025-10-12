use crate::error::Error;
use crate::modules::prelude::*;
use crate::task::moduleblock::ModuleBlockExpectedState;
use serde::{Deserialize, Deserializer, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Step {
    pub name: Option<String>,
    pub run_as: Option<String>,
    pub with_sudo: Option<bool>,
    pub allowed_to_fail: Option<bool>,
    pub register: Option<String>,
    // pub prelogic -> TODO
    // pub postlogic -> TODO
    pub moduleblock: ModuleBlockExpectedState,
}

impl Step {
    pub fn from_parsed_step(parsed_step: ParsingStep) -> Result<Step, Error> {
        parsed_step.parsemodule()
    }
}

// Any value that is present is considered Some value, including null. This way, we can use
// argument-less modules like Ping by writing "ping:" and Serde won't confuse it with a missing field.
fn deserialize_argumentlessmodule<'a, T, D>(deserializer: D) -> Result<Option<T>, D::Error>
where
    T: Deserialize<'a>,
    D: Deserializer<'a>,
{
    Deserialize::deserialize(deserializer).map(Some)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ParsingStep {
    pub name: Option<String>,
    pub run_as: Option<String>,
    pub with_sudo: Option<bool>,
    pub allowed_to_fail: Option<bool>,
    pub register: Option<String>,
    // pub prelogic -> TODO
    // pub postlogic -> TODO

    // FIXME: Having an attribute per module is at the moment the only way found to be able to write "apt:" and not "!apt".
    // It requires parsemodule() method to check that only one attribute per step is filled.
    // **BEACON_1**
    pub service: Option<ServiceBlockExpectedState>,
    pub debug: Option<DebugBlockExpectedState>,
    pub lineinfile: Option<LineInFileBlockExpectedState>,
    pub command: Option<CommandBlockExpectedState>,
    pub apt: Option<AptBlockExpectedState>,
    pub dnf: Option<YumDnfBlockExpectedState>,
    #[serde(default, deserialize_with = "deserialize_argumentlessmodule")]
    pub ping: Option<Option<PingBlockExpectedState>>, // Double wrapping in order to have Serde distinguish between missing field and None value
    pub yum: Option<YumDnfBlockExpectedState>,
}

impl ParsingStep {
    pub fn parsemodule(&self) -> Result<Step, Error> {
        let mut counter: u8 = 0;
        let mut moduleblock: Option<ModuleBlockExpectedState> = None;

        // **BEACON_2**
        if let Some(content) = self.service.clone() {
            counter += 1;
            moduleblock = Some(ModuleBlockExpectedState::Service(content));
        }
        if let Some(content) = self.debug.clone() {
            counter += 1;
            moduleblock = Some(ModuleBlockExpectedState::Debug(content));
        }
        if let Some(content) = self.lineinfile.clone() {
            counter += 1;
            moduleblock = Some(ModuleBlockExpectedState::LineInFile(content));
        }
        if let Some(content) = self.command.clone() {
            counter += 1;
            moduleblock = Some(ModuleBlockExpectedState::Command(content));
        }
        if let Some(content) = self.apt.clone() {
            counter += 1;
            moduleblock = Some(ModuleBlockExpectedState::Apt(content));
        }
        if let Some(content) = self.dnf.clone() {
            counter += 1;
            moduleblock = Some(ModuleBlockExpectedState::Dnf(content));
        }
        if let Some(_content) = self.ping.clone() {
            // Ping "content" is always null at the moment
            counter += 1;
            moduleblock = Some(ModuleBlockExpectedState::Ping(PingBlockExpectedState {}));
        }
        if let Some(content) = self.yum.clone() {
            counter += 1;
            moduleblock = Some(ModuleBlockExpectedState::Yum(content));
        }

        if counter > 1 {
            return Err(Error::FailedInitialization(
                "Too much modules defined in this step. Only one module per step please.".into(),
            ));
        } else {
            match moduleblock {
                Some(module_block_expected_state) => {
                    return Ok(Step {
                        name: self.name.clone(),
                        run_as: self.run_as.clone(),
                        with_sudo: self.with_sudo.clone(),
                        allowed_to_fail: self.allowed_to_fail.clone(),
                        register: self.register.clone(),
                        // prelogic -> TODO
                        // postlogic -> TODO
                        moduleblock: module_block_expected_state,
                    });
                }
                None => {
                    return Err(Error::FailedInitialization(
                        "No module found in this step".into(),
                    ));
                }
            }
        }
    }
}
