use std::fmt;
use std::time::Duration;

use tokio::net::TcpStream;
use tokio::select;
use tokio::sync::mpsc;
use tokio::time::sleep;

use crate::error::Error;
use crate::messages::{GiveOffer, MakerToTakerMessage, Offer, TakerToMakerMessage};
use crate::taker_protocol::{
    handshake_maker, read_message, send_message, FIRST_CONNECT_ATTEMPTS,
    FIRST_CONNECT_ATTEMPT_TIMEOUT_SEC, FIRST_CONNECT_SLEEP_DELAY_SEC,
};

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

async fn download_maker_offer_attempt_once(addr: &MakerAddress) -> Result<Offer, Error> {
    log::debug!(target: "offerbook", "Connecting to {}", addr);
    let mut socket = TcpStream::connect(addr.get_tcpstream_address()).await?;
    let (mut socket_reader, mut socket_writer) = handshake_maker(&mut socket, addr).await?;

    send_message(
        &mut socket_writer,
        TakerToMakerMessage::GiveOffer(GiveOffer),
    )
    .await?;

    let offer = if let MakerToTakerMessage::Offer(o) = read_message(&mut socket_reader).await? {
        o
    } else {
        return Err(Error::Protocol("expected method offer"));
    };

    log::debug!(target: "offerbook", "Obtained offer from {}", addr);
    Ok(offer)
}

async fn download_maker_offer(address: MakerAddress) -> Option<OfferAndAddress> {
    let mut ii = 0;
    loop {
        ii += 1;
        select! {
            ret = download_maker_offer_attempt_once(&address) => {
                match ret {
                    Ok(offer) => return Some(OfferAndAddress { offer, address }),
                    Err(e) => {
                        log::debug!(target: "offerbook",
                            "Failed to request offer from maker {}, \
                            reattempting... error={:?}",
                            address,
                            e
                        );
                        if ii <= FIRST_CONNECT_ATTEMPTS {
                            sleep(Duration::from_secs(FIRST_CONNECT_SLEEP_DELAY_SEC)).await;
                            continue;
                        } else {
                            return None;
                        }
                    }
                }
            },
            _ = sleep(Duration::from_secs(FIRST_CONNECT_ATTEMPT_TIMEOUT_SEC)) => {
                log::debug!(target: "offerbook",
                    "Timeout for request offer from maker {}, reattempting...",
                    address
                );
                if ii <= FIRST_CONNECT_ATTEMPTS {
                    continue;
                } else {
                    return None;
                }
            },
        }
    }
}

pub async fn sync_offerbook() -> Vec<OfferAndAddress> {
    let (offers_writer_m, mut offers_reader) = mpsc::channel::<Option<OfferAndAddress>>(100);
    //unbounded_channel makes more sense here, but results in a compile
    //error i cant figure out

    for host in &MAKER_HOSTS {
        let offers_writer = offers_writer_m.clone();
        tokio::spawn(async move {
            let addr = MakerAddress::Clearnet {
                address: host.to_string(),
            };
            if let Err(_e) = offers_writer.send(download_maker_offer(addr).await).await {
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
