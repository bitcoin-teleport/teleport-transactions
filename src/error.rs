use std::error;
use std::io;

use bitcoincore_rpc;

use crate::serialization::NetSerializationError;

// error enum for the whole project
// try to make functions return this
#[derive(Debug)]
pub enum Error {
    Network(Box<dyn error::Error + Send>),
    Disk(io::Error),
    Protocol(&'static str),
    Rpc(bitcoincore_rpc::Error),
    Serialisation(NetSerializationError),
}

impl From<Box<dyn error::Error + Send>> for Error {
    fn from(e: Box<dyn error::Error + Send>) -> Error {
        Error::Network(e)
    }
}

impl From<NetSerializationError> for Error {
    fn from(e: NetSerializationError) -> Error {
        Error::Serialisation(e)
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
