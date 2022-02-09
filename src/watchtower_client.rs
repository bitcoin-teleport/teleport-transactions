use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;

use crate::error::Error;
use crate::watchtower_protocol::{
    ContractsInfo, MakerToWatchtowerMessage, Ping, WatchContractTxes, WatchtowerToMakerMessage,
};

#[tokio::main]
pub async fn test_watchtower_client(contracts_to_watch: ContractsInfo) {
    ping_watchtowers().await.unwrap();
    register_coinswap_with_watchtowers(contracts_to_watch)
        .await
        .unwrap();
}

fn parse_message(line: &str) -> Result<WatchtowerToMakerMessage, Error> {
    serde_json::from_str::<WatchtowerToMakerMessage>(line)
        .map_err(|_| Error::Protocol("watchtower sent invalid message"))
}

pub async fn register_coinswap_with_watchtowers(
    contracts_to_watch: ContractsInfo,
) -> Result<(), Error> {
    send_message_to_watchtowers(&MakerToWatchtowerMessage::WatchContractTxes(
        WatchContractTxes {
            protocol_version_min: 0,
            protocol_version_max: 0,
            contracts_to_watch,
        },
    ))
    .await?;
    log::info!("Successfully registered contract txes with watchtower");
    Ok(())
}

pub async fn ping_watchtowers() -> Result<(), Error> {
    log::debug!("pinging watchtowers");
    send_message_to_watchtowers(&MakerToWatchtowerMessage::Ping(Ping {
        protocol_version_min: 0,
        protocol_version_max: 0,
    }))
    .await
}

async fn send_message_to_watchtowers(message: &MakerToWatchtowerMessage) -> Result<(), Error> {
    //TODO add support for registering with multiple watchtowers concurrently
    //TODO add timeouts to deal with indefinite hangs

    let host = "localhost:6103";
    let mut socket = TcpStream::connect(host).await?;

    let (socket_reader, mut socket_writer) = socket.split();
    let mut socket_reader = BufReader::new(socket_reader);

    let mut message_packet = serde_json::to_vec(message).unwrap();
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

    Ok(())
}
