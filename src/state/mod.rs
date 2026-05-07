pub mod attribute;
pub mod compliance;
pub mod expected_state;

use crate::error::RegentError;
pub use expected_state::ExpectedState;

pub trait Check {
    fn check(&self) -> Result<(), RegentError>;
}
