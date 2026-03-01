use regent_sdk::{LocalHostHandler, ManagedHost};

fn main() {
    // Describe the ManagedHost
    let mut managed_host = ManagedHost::new(
        "localhost",
        LocalHostHandler::new(regent_sdk::WhichUser::CurrentUser),
    );

    // Open connection with this ManageHost
    managed_host.connect().unwrap();

    // What kind of Os are we dealing with ?
    match managed_host.collect_properties() {
        Ok(()) => {
            println!("Host properties : {:?}", managed_host.get_host_properties());
        }
        Err(error_detail) => {
            println!("Unable to collect host properties : {:?}", error_detail);
        }
    }
}
