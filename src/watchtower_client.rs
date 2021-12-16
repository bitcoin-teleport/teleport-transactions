use tokio::io::BufReader;
use tokio::net::TcpStream;
use tokio::prelude::*;

use serde::{Deserialize, Serialize};

use bitcoin::Transaction;

use crate::error::Error;
use crate::watchtower_protocol::{
    MakerToWatchtowerMessage, WatchContractTxes, WatchtowerToMakerMessage,
};

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ContractInfo {
    pub contract_tx: Transaction,
}

#[tokio::main]
pub async fn test_watchtower_client(contracts_to_watch: Vec<ContractInfo>) {
    register_coinswap_with_watchtowers(contracts_to_watch)
        .await
        .unwrap();
}

fn parse_message(line: &str) -> Result<WatchtowerToMakerMessage, Error> {
    serde_json::from_str::<WatchtowerToMakerMessage>(line)
        .map_err(|_| Error::Protocol("watchtower sent invalid message"))
}

pub async fn register_coinswap_with_watchtowers(
    contracts_to_watch: Vec<ContractInfo>,
) -> Result<(), Error> {
    //TODO add support for registering with multiple watchtowers concurrently
    //TODO add timeouts to deal with indefinite hangs

    let host = "localhost:6103";
    let mut socket = TcpStream::connect(host).await?;

    let (socket_reader, mut socket_writer) = socket.split();
    let mut socket_reader = BufReader::new(socket_reader);

    let mut message_packet = serde_json::to_vec(&MakerToWatchtowerMessage::WatchContractTxes(
        WatchContractTxes {
            protocol_version_min: 0,
            protocol_version_max: 0,
            contracts_to_watch,
        },
    ))
    .unwrap();
    message_packet.push(b'\n');
    socket_writer.write_all(&message_packet).await?;

    let mut line1 = String::new();
    if socket_reader.read_line(&mut line1).await? == 0 {
        return Err(Error::Protocol("watchtower eof"));
    }
    let _watchtower_hello =
        if let WatchtowerToMakerMessage::WatchtowerHello(h) = parse_message(&line1)? {
            h
        } else {
            log::trace!(target: "watchtower_client", "wrong protocol message");
            return Err(Error::Protocol("wrong protocol message from watchtower"));
        };
    log::trace!(target: "watchtower_client", "watchtower hello = {:?}", _watchtower_hello);

    let mut line2 = String::new();
    if socket_reader.read_line(&mut line2).await? == 0 {
        return Err(Error::Protocol("watchtower eof"));
    }
    let _success = if let WatchtowerToMakerMessage::Success(s) = parse_message(&line2)? {
        s
    } else {
        log::trace!(target: "watchtower_client", "wrong protocol message2");
        return Err(Error::Protocol("wrong protocol message2 from watchtower"));
    };
    log::info!("Successfully registered contract txes with watchtower");

    Ok(())
}
