use std::error;
use std::io;

use bitcoincore_rpc;

// error enum for the whole project
// try to make functions return this
#[derive(Debug)]
pub enum Error {
    Network(Box<dyn error::Error>),
    Disk(io::Error),
    Protocol(&'static str),
    Rpc(bitcoincore_rpc::Error),
}

impl From<Box<dyn error::Error>> for Error {
    fn from(e: Box<dyn error::Error>) -> Error {
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
