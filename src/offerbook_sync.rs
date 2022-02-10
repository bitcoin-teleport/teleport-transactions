use std::fmt;

use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;
use tokio::sync::mpsc;

use crate::messages::{GiveOffer, MakerToTakerMessage, Offer, TakerHello, TakerToMakerMessage};

const TOR_ADDR: &str = "127.0.0.1:9150";

#[derive(Debug, Clone)]
pub enum MakerAddress {
    Clearnet { address: String },
    Tor { address: String },
}

#[derive(Debug, Clone)]
pub struct OfferAndAddress {
    pub offer: Offer,
    pub address: MakerAddress,
}

const MAKER_HOSTS: [&str; 5] = [
    "localhost:6102",
    "localhost:16102",
    "localhost:26102",
    "localhost:36102",
    "localhost:46102",
];

impl MakerAddress {
    pub fn get_tcpstream_address(&self) -> String {
        match &self {
            MakerAddress::Clearnet { address } => address.to_string(),
            MakerAddress::Tor { address: _ } => String::from(TOR_ADDR),
        }
    }
}

impl fmt::Display for MakerAddress {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match &self {
            MakerAddress::Clearnet { address } => write!(f, "{}", address),
            MakerAddress::Tor { address } => write!(f, "{}", address),
        }
    }
}

fn parse_message(line: &str) -> Option<MakerToTakerMessage> {
    let message: MakerToTakerMessage = match serde_json::from_str(line) {
        Ok(r) => r,
        Err(_e) => return None,
    };
    Some(message)
}

async fn download_maker_offer(host: &str) -> Option<OfferAndAddress> {
    //TODO add timeouts to deal with indefinite hangs
    let mut socket = match TcpStream::connect(host).await {
        Ok(s) => s,
        Err(_e) => {
            log::trace!(target: "offer_book", "failed to connect to: {}", host);
            return None;
        }
    };

    let (socket_reader, mut socket_writer) = socket.split();
    let mut socket_reader = BufReader::new(socket_reader);

    let mut message_packet = serde_json::to_vec(&TakerToMakerMessage::TakerHello(TakerHello {
        protocol_version_min: 0,
        protocol_version_max: 0,
    }))
    .unwrap();
    message_packet.push(b'\n');
    message_packet
        .append(&mut serde_json::to_vec(&TakerToMakerMessage::GiveOffer(GiveOffer)).unwrap());
    message_packet.push(b'\n');
    //TODO error handling here
    socket_writer.write_all(&message_packet).await.unwrap();

    let mut line1 = String::new();
    match socket_reader.read_line(&mut line1).await {
        Ok(0) | Err(_) => {
            log::trace!(target: "offer_book", "failed to read line");
            return None;
        }
        Ok(_n) => (),
    };
    let _makerhello = if let MakerToTakerMessage::MakerHello(m) = parse_message(&line1)? {
        m
    } else {
        log::trace!(target: "offer_book", "wrong protocol message");
        return None;
    };
    log::trace!(target: "offer_book", "maker hello = {:?}", _makerhello);

    let mut line2 = String::new();
    match socket_reader.read_line(&mut line2).await {
        Ok(0) | Err(_) => {
            log::trace!(target: "oofer_book", "failed to read line2");
            return None;
        }
        Ok(_n) => (),
    };
    let offer = if let MakerToTakerMessage::Offer(o) = parse_message(&line2)? {
        o
    } else {
        log::trace!(target: "offer_book", "wrong protocol message2");
        return None;
    };

    Some(OfferAndAddress {
        offer,
        address: MakerAddress::Clearnet {
            address: String::from(host),
        },
    })
}

pub async fn sync_offerbook() -> Vec<OfferAndAddress> {
    let (offers_writer_m, mut offers_reader) = mpsc::channel::<Option<OfferAndAddress>>(100);
    //unbounded_channel makes more sense here, but results in a compile
    //error i cant figure out

    for host in &MAKER_HOSTS {
        let offers_writer = offers_writer_m.clone();
        tokio::spawn(async move {
            if let Err(_e) = offers_writer.send(download_maker_offer(host).await).await {
                panic!("mpsc failed");
            }
        });
    }

    let mut result = Vec::<OfferAndAddress>::new();
    for _ in 0..MAKER_HOSTS.len() {
        if let Some(offer_addr) = offers_reader.recv().await.unwrap() {
            result.push(offer_addr);
        }
    }
    result
}
