#[derive(Debug)]
pub struct CmdResult {
    pub rc: i32,
    pub stdout: String,
}

impl CmdResult {
    pub fn new() -> CmdResult {
        CmdResult {
            rc: 0,
            stdout: String::new(),
        }
    }
}
