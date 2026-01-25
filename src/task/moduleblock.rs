use crate::connection::hosthandler::ConnectionHandler;
use crate::connection::specification::Privilege;
use crate::error::Error;
use crate::modules::prelude::*;
use crate::result::apicallresult::ApiCallResult;
use crate::step::stepchange::StepChange;
use serde::{Deserialize, Serialize};
use tera::{Context, Tera};
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ModuleBlockExpectedState {
    None, // Used for new() methods, initializations and errors
    // **BEACON_2**
    Service(ServiceBlockExpectedState),
    Debug(DebugBlockExpectedState),
    LineInFile(LineInFileBlockExpectedState),
    Command(CommandBlockExpectedState),
    Apt(AptBlockExpectedState),
    Dnf(YumDnfBlockExpectedState),
    Ping(PingBlockExpectedState),
    Yum(YumDnfBlockExpectedState),
}

impl ModuleBlockExpectedState {
    pub fn new() -> ModuleBlockExpectedState {
        ModuleBlockExpectedState::None
    }

    pub fn consider_context(
        &mut self,
        tera_context: &mut tera::Context,
    ) -> Result<ModuleBlockExpectedState, Error> {
        // TODO : is this the best way to do this ?

        let serialized_self = serde_json::to_string(self).unwrap();
        let context_wise_serialized_self =
            Tera::one_off(serialized_self.as_str(), tera_context, true).unwrap();
        match serde_json::from_str::<ModuleBlockExpectedState>(&context_wise_serialized_self) {
            Ok(context_wise_moduleblock) => Ok(context_wise_moduleblock),
            Err(error) => Err(Error::FailureToParseContent(format!("{}", error))),
        }
    }

    pub fn consider_vars(
        &mut self,
        vars: &Option<serde_json::Value>,
    ) -> Result<ModuleBlockExpectedState, Error> {
        // TODO : is this the best way to do this ?
        let serialized_self = serde_json::to_string(self).unwrap();

        let temp_tera_context = match vars {
            Some(var_list) => Context::from_value(var_list.clone()).unwrap(),
            None => Context::new(),
        };

        let context_wise_serialized_self =
            Tera::one_off(serialized_self.as_str(), &temp_tera_context, true).unwrap();

        match serde_json::from_str::<ModuleBlockExpectedState>(&context_wise_serialized_self) {
            Ok(context_wise_moduleblock) => Ok(context_wise_moduleblock),
            Err(error) => Err(Error::FailureToParseContent(format!("{}", error))),
        }
    }

    pub fn dry_run_moduleblock(
        &self,
        connection_handler: &mut ConnectionHandler,
        privilege: &Privilege,
    ) -> Result<StepChange, Error> {
        let mbchange_result: Result<StepChange, Error> = match &self {
            ModuleBlockExpectedState::None => Ok(StepChange::matched("none")),
            // **BEACON_3**
            ModuleBlockExpectedState::Service(block) => {
                block.dry_run_block(connection_handler, privilege)
            }
            ModuleBlockExpectedState::Debug(block) => {
                block.dry_run_block(connection_handler, privilege)
            }
            ModuleBlockExpectedState::LineInFile(block) => {
                block.dry_run_block(connection_handler, privilege)
            }
            ModuleBlockExpectedState::Command(block) => {
                block.dry_run_block(connection_handler, privilege)
            }
            ModuleBlockExpectedState::Apt(block) => {
                block.dry_run_block(connection_handler, privilege)
            }
            ModuleBlockExpectedState::Dnf(block) => {
                block.dry_run_block(connection_handler, privilege)
            }
            ModuleBlockExpectedState::Ping(block) => {
                block.dry_run_block(connection_handler, privilege)
            }
            ModuleBlockExpectedState::Yum(block) => {
                block.dry_run_block(connection_handler, privilege)
            }
        };

        mbchange_result
    }

    pub fn check(&self) -> Result<(), Error> {
        match &self {
            ModuleBlockExpectedState::Service(block) => block.check(),
            ModuleBlockExpectedState::Debug(block) => block.check(),
            ModuleBlockExpectedState::LineInFile(block) => block.check(),
            ModuleBlockExpectedState::Command(block) => block.check(),
            ModuleBlockExpectedState::Apt(block) => block.check(),
            ModuleBlockExpectedState::Dnf(block) => block.check(),
            ModuleBlockExpectedState::Ping(block) => block.check(),
            ModuleBlockExpectedState::Yum(block) => block.check(),
            _ => Ok(()),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ModuleApiCall {
    None(String),
    // **BEACON_4**
    Debug(DebugApiCall),
    Service(ServiceApiCall),
    LineInFile(LineInFileApiCall),
    Command(CommandApiCall),
    Apt(AptApiCall),
    Ping(PingApiCall),
    YumDnf(YumDnfApiCall),
}

pub trait Check {
    fn check(&self) -> Result<(), Error>;
}

pub trait DryRun {
    fn dry_run_block(
        &self,
        connection_handler: &mut ConnectionHandler,
        privilege: &Privilege,
    ) -> Result<StepChange, Error>;
}

pub trait Apply {
    fn display(&self) -> String;
    fn apply_moduleblock_change(&self, connection_handler: &mut ConnectionHandler)
    -> ApiCallResult;
}
