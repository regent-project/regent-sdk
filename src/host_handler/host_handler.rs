use crate::error::Error;
use crate::host_handler::localhost::WhichUser;
use crate::{command::CommandResult, host_handler::privilege::Privilege};

use serde::{Deserialize, Serialize};
pub trait HostHandler: Sized {
    fn connect(&mut self, endpoint: &str) -> Result<(), Error>;

    fn is_connected(&mut self) -> bool;

    fn disconnect(&mut self) -> Result<(), Error>;

    fn is_this_command_available(
        &mut self,
        command: &str,
        privilege: &Privilege,
    ) -> Result<bool, Error>;

    fn run_command(&mut self, command: &str, privilege: &Privilege)
    -> Result<CommandResult, Error>;
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ConnectionDetails {
    // LocalHost(WhichUser),
    // Ssh2(NewSsh2ConnectionDetails),
}

// TODO : add some syntax checks
pub fn final_command(cmd: &str, privilege: &Privilege, user: &WhichUser) -> String {
    match user {
        WhichUser::CurrentUser => match privilege {
            Privilege::None => format!("{} 2>&1", cmd),
            Privilege::WithSudo => format!("sudo {} 2>&1", cmd),
            Privilege::WithSudoRs => format!("sudo-rs {} 2>&1", cmd),
        },
        WhichUser::PasswordLessUser(username) => match privilege {
            Privilege::None | Privilege::WithSudo => format!("sudo -u {} {} 2>&1", username, cmd),
            Privilege::WithSudoRs => format!("sudo-rs -u {} {} 2>&1", username, cmd),
        },
        WhichUser::UsernamePassword(credentials) => match privilege {
            Privilege::None | Privilege::WithSudo => format!(
                "echo {} | sudo -S -u {} {} 2>&1",
                credentials.password(),
                credentials.username(),
                cmd
            ),
            Privilege::WithSudoRs => format!(
                "echo {} | sudo-rs -S -u {} {} 2>&1",
                credentials.password(),
                credentials.username(),
                cmd
            ),
        },
    }

    // match privilege {
    //     Privilege::None => {
    //         let final_cmd = format!("{} 2>&1", cmd);
    //         return final_cmd;
    //     }
    //     // Privilege::WithSuAsUser(credentials) => {
    //     //     let final_cmd = format!("echo {} | su - {} -c {} 2>&1", credentials.password(), credentials.username(), cmd);
    //     //     return final_cmd;
    //     // }
    //     Privilege::WithSudo => {
    //         let final_cmd = format!("sudo {} 2>&1", cmd);
    //         return final_cmd;
    //     }
    //     // Privilege::WithSudoAsUser(credentials) => {
    //     //     let final_cmd = format!("echo {} | sudo -S -u {} {} 2>&1", credentials.password(), credentials.username(), cmd);
    //     //     return final_cmd;
    //     // }
    //     Privilege::WithSudoRs => {
    //         let final_cmd = format!("sudo-rs {} 2>&1", cmd);
    //         return final_cmd;
    //     }
    //     // Privilege::WithSudoRsAsUser(credentials) => {
    //     //     let final_cmd = format!("echo {} | sudo-rs -u {} {} 2>&1", credentials.password(), credentials.username(), cmd);
    //     //     return final_cmd;
    //     // }
    // }
}
