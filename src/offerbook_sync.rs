use tokio::io::BufReader;
use tokio::net::TcpStream;
use tokio::sync::mpsc;

use crate::messages::{GiveOffer, MakerToTakerMessage, Offer, TakerHello, TakerToMakerMessage};

use crate::taker_protocol::{read_message, send_message};

#[derive(Debug, Clone)]
pub struct OfferAddress {
    pub offer: Offer,
    pub address: String, //string for now when its "localhost:port"
}

const MAKER_HOSTS: [&str; 4] = [
    "localhost:6102",
    "localhost:16102",
    "localhost:26102",
    "localhost:36102",
];

async fn download_maker_offer(host: &str) -> Option<OfferAddress> {
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

    let hello = TakerToMakerMessage::TakerHello(TakerHello {
        protocol_version_max: 0,
        protocol_version_min: 0,
    });

    if let Err(_) = send_message(&mut socket_writer, hello).await {
        log::trace!("Can't send Hello");
    } else {
        let give_offer = TakerToMakerMessage::GiveOffer(GiveOffer);
        if let Err(_) = send_message(&mut socket_writer, give_offer).await {
            log::trace!("Can't send offer request");
            return None;
        }
    }

    if let Ok(MakerToTakerMessage::MakerHello(_)) = read_message(&mut socket_reader).await {
        if let Ok(MakerToTakerMessage::Offer(offer)) = read_message(&mut socket_reader).await {
            return Some(OfferAddress {
                offer,
                address: String::from(host),
            });
        } else {
            log::trace!("Didn't recieve Offer");
            return None;
        }
    } else {
        log::trace!("Didn't recieve Hello");
        return None;
    }
}

pub async fn sync_offerbook() -> Vec<OfferAddress> {
    let (offers_writer_m, mut offers_reader) = mpsc::channel::<Option<OfferAddress>>(100);
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

    let mut result = Vec::<OfferAddress>::new();
    for _ in 0..MAKER_HOSTS.len() {
        if let Some(offer_addr) = offers_reader.recv().await.unwrap() {
            result.push(offer_addr);
        }
    }
    result
}
