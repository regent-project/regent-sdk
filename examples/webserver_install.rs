use regent_sdk::{HostConnectionInfo, Job, TaskListFormat};

fn main() {
    let my_tasklist = r#"---
- name: Let's install a web server !
  steps:
    - name: check connectivity and authentication with host.
      ping:
    
    - name: install apache2 package
      with_sudo: true
      apt:
        package: apache2
        state: present

    - name: start apache2 service
      with_sudo: true
      service:
        name: apache2
        current_status: active
        "#;
    let mut my_job = Job::new();

    my_job
        .set_address("<target-host-endpoint>:<port>") // port is optional (22 if unspecified)
        .set_connection(HostConnectionInfo::ssh2_with_key_file(
            "regent-user",
            "/path/to/private/key",
        ))
        .unwrap();

    my_job
        .set_tasklist_from_str(my_tasklist, TaskListFormat::Yaml)
        .unwrap();

    my_job.apply();

    println!("{}", my_job.display_pretty());
}
