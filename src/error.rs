/// Configuration faults are operator errors; backend faults are runtime routing-plane failures.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("{0}")]
    Config(String),
    #[error("{0}")]
    Backend(String),
    #[error("{0}")]
    Io(#[from] std::io::Error),
}

pub type Result<T, E = Error> = std::result::Result<T, E>;

pub fn config_err<T>(message: impl Into<String>) -> Result<T> {
    Err(Error::Config(message.into()))
}

pub fn backend_err<T>(message: impl Into<String>) -> Result<T> {
    Err(Error::Backend(message.into()))
}
