//! # Regent-sdk
//!
//! # Most basic example : install a web server
//! ```rust
//!use regent-sdk::prelude::*;
//!
//!fn main() {
//!
//!    // First we need to define what the expected state of the target host is.
//!    let my_tasklist = "---
//!- name: Let's install a web server !
//!  steps:
//!    - name: First, we test the connectivity and authentication with the host.
//!      ping:
//!      
//!    - name: Then we can install the package...
//!      with_sudo: true
//!      apt:
//!        package: '{{ package_name }}'
//!        state: present
//!        
//!    - name: ... and start & enable the service.
//!      with_sudo: true
//!      service:
//!        name: '{{ service_name }}'
//!        state: started
//!        enabled: true
//!        ";
//!
//!    // Then we create a 'Job'.
//!    let mut my_job = Job::new();
//!
//!    // We set who the target host of this Job is, and how to connect to it.
//!    my_job
//!        .set_address("10.20.0.203").unwrap()
//!        .set_connection(ConnectionInfo::ssh2_with_key_file("dux", "controller_key")).unwrap();
//!    
//!    // We give it some context and the task list.
//!    my_job
//!        .set_var("package_name", "apache2")
//!        .set_var("service_name", "apache2")
//!        .set_tasklist_from_str(my_tasklist, TaskListFormat::Yaml).unwrap()
//!    ;
//!    // We can finally apply the task list to this host.
//!    my_job.apply();
//!
//!    // Let's see the result.
//!    println!("{}", my_job.display_pretty());
//!}
//! ```

pub mod connection;
pub mod error;
pub mod exitcode;
pub mod expected_state;
pub mod host;
pub mod job;
pub mod modules;
pub mod output;
pub mod prelude;
pub mod result;
pub mod step;
pub mod task;
pub mod workflow;

pub use crate::connection::connectionmode::ssh2mode::Ssh2AuthMode;
pub use crate::connection::host_connection::HostConnectionInfo;
pub use crate::host::host::ManagedHost;
pub use crate::job::job::Job;
pub use crate::task::moduleblock::ModuleBlockExpectedState as Attribute;
pub use crate::task::tasklist::TaskListFormat;

pub use crate::modules::packages::apt as Apt;
pub use crate::modules::packages::yumdnf as YumDnf;
pub use crate::modules::shell::command as Command;
pub use crate::modules::system::service as Service;
pub use crate::modules::utilities::debug as Debug;
pub use crate::modules::utilities::lineinfile as LineInFile;
pub use crate::modules::utilities::ping as Ping;

pub use crate::connection::connectionmode::ssh2mode::NewSsh2ConnectionDetails;
pub use crate::connection::specification::Privilege;
pub use connection::hosthandler::NewConnectionDetails;
