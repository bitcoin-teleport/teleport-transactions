use std::{error, fmt, io};

// error enum for the whole project
// try to make functions return this
#[derive(Debug)]
pub enum Error {
    Network(Box<dyn error::Error + Send>),
    Disk(io::Error),
    Protocol(&'static str),
    Rpc(bitcoincore_rpc::Error),
    Socks(tokio_socks::Error),
}

impl From<Box<dyn error::Error + Send>> for Error {
    fn from(e: Box<dyn error::Error + Send>) -> Error {
        Error::Network(e)
    }
}

impl From<io::Error> for Error {
    fn from(e: io::Error) -> Error {
        Error::Disk(e)
    }
}

impl From<bitcoincore_rpc::Error> for Error {
    fn from(e: bitcoincore_rpc::Error) -> Error {
        Error::Rpc(e)
    }
}

impl From<tokio_socks::Error> for Error {
    fn from(e: tokio_socks::Error) -> Error {
        Error::Socks(e)
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Error::Network(ref e) => write!(f, "Network error: {}", e),
            Error::Disk(ref e) => write!(f, "File system error: {}", e),
            Error::Protocol(ref e) => write!(f, "Protocol error: {}", e),
            Error::Rpc(ref e) => write!(f, "RPC error: {}", e),
            Error::Socks(ref e) => write!(f, "SOCKS error: {}", e),
        }
    }
}
