use tokio::io::BufReader;
use tokio::net::TcpStream;
use tokio::prelude::*;
use tokio::sync::mpsc;

use serde_json;

use crate::messages::{GiveOffer, MakerToTakerMessage, Offer, TakerHello, TakerToMakerMessage};

#[derive(Debug)]
pub struct OfferAddress {
    pub offer: Offer,
    pub socket_address: String, //string for now when its "localhost:port"
}

const MAKER_HOSTS: [&str; 2] = ["localhost:6102", "localhost:16102"];

fn parse_message(line: &str) -> Option<MakerToTakerMessage> {
    let message: MakerToTakerMessage = match serde_json::from_str(line) {
        Ok(r) => r,
        Err(_e) => return None,
    };
    Some(message)
}

async fn download_maker_offer(host: &str) -> Option<OfferAddress> {
    //TODO add timeouts to deal with indefinite hangs
    let mut socket = match TcpStream::connect(host).await {
        Ok(s) => s,
        Err(_e) => {
            println!("failed to connect to: {}", host);
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
            println!("failed to read line");
            return None;
        }
        Ok(_n) => (),
    };
    let _makerhello = if let MakerToTakerMessage::MakerHello(m) = parse_message(&line1)? {
        m
    } else {
        println!("wrong protocol message");
        return None;
    };
    println!("maker hello = {:?}", _makerhello);

    let mut line2 = String::new();
    match socket_reader.read_line(&mut line2).await {
        Ok(0) | Err(_) => {
            println!("failed to read line2");
            return None;
        }
        Ok(_n) => (),
    };
    let offer = if let MakerToTakerMessage::Offer(o) = parse_message(&line2)? {
        o
    } else {
        println!("wrong protocol message2");
        return None;
    };

    Some(OfferAddress {
        offer,
        socket_address: String::from(host),
    })
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
