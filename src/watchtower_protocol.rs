use std::collections::HashSet;
use std::iter::FromIterator;
use std::net::Ipv4Addr;
use std::time::Duration;

use tokio::io::BufReader;
use tokio::net::tcp::WriteHalf;
use tokio::net::TcpListener;
use tokio::prelude::*;
use tokio::select;
use tokio::sync::mpsc;
use tokio::time::sleep;

use serde::{Deserialize, Serialize};

use bitcoin::Txid;
use bitcoincore_rpc::{json::GetBlockResult, Client, RpcApi};

use crate::error::Error;
use crate::watchtower_client::ContractInfo;

//needed things for each contract: contract_redeemscript, fully signed contract_tx
// tx which spends from the hashlock branch minus the preimage
//for now only coding the part which broadcasts all txes when one is broadcast,
// we dont even need separate incoming/outgoing variables, we could just send a list
// of all contract_tx
//later will add part about

#[derive(Debug, Serialize, Deserialize)]
pub struct WatchContractTxes {
    pub protocol_version_min: u32,
    pub protocol_version_max: u32,
    pub contracts_to_watch: Vec<ContractInfo>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Ping {
    pub protocol_version_min: u32,
    pub protocol_version_max: u32,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "method", rename_all = "lowercase")]
pub enum MakerToWatchtowerMessage {
    Ping(Ping),
    WatchContractTxes(WatchContractTxes),
}

#[derive(Debug, Serialize, Deserialize)]
pub struct WatchtowerHello {
    pub protocol_version_min: u32,
    pub protocol_version_max: u32,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Success;

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "method", rename_all = "lowercase")]
pub enum WatchtowerToMakerMessage {
    WatchtowerHello(WatchtowerHello),
    Success(Success),
}

//pub async fn

#[tokio::main]
pub async fn start_watchtower(rpc: &Client) {
    match run(rpc).await {
        Ok(_o) => log::info!("watchtower ended without error"),
        Err(e) => log::info!("watchtower ended with err {:?}", e),
    };
}

//TODO i think rpc doesnt need to be wrapped in Arc, because its not used in the spawned task
async fn run(rpc: &Client) -> Result<(), Error> {
    //TODO port number in config file
    let port = 6103;
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, port)).await?;
    log::info!("Starting teleport watchtower. Listening On Port {}", port);

    let (watched_txes_comms_tx, mut watched_txes_comms_rx) =
        mpsc::channel::<Vec<ContractInfo>>(100);

    //TODO these kind of things should be persisted to file rather than in memory
    //so that if theres a crash or power cut, the watchtower can be restarted and continue watching
    //the same transactions
    let mut watched_contracts = Vec::<Vec<ContractInfo>>::new();
    let mut last_checked_block_height: Option<u64> = None;

    let (server_loop_err_comms_tx, mut server_loop_err_comms_rx) = mpsc::channel::<Error>(100);
    let mut accepting_clients = true;

    loop {
        let (mut socket, addr) = select! {
            new_client = listener.accept() => new_client?,
            client_err = server_loop_err_comms_rx.recv() => {
                //unwrap the option here because we'll never close the mscp so it will always work
                match client_err.as_ref().unwrap() {
                    Error::Rpc(_e) => {
                        log::warn!("lost connection with bitcoin node, temporarily shutting \
                                  down watchtower until connection reestablished");
                        accepting_clients = false;
                        continue;
                    },
                    _ => log::error!("ending watchtower"),
                }
                break Err(client_err.unwrap());
            },
            new_watched_txes = watched_txes_comms_rx.recv() => {
                //unwrap the option here because we'll never close the mscp so it will always work
                let new_watched_contracts = new_watched_txes.as_ref().unwrap().to_vec();
                log::info!("new_watched_contracts = {:?}", new_watched_contracts);
                watched_contracts.push(new_watched_contracts);
                continue;
            },
            //TODO make a const for this magic number of how often to poll, see similar
            // comment in maker_protocol.rs
            _ = sleep(Duration::from_secs(10)) => {
                let r = check_for_broadcasted_contract_txes(&rpc, &watched_contracts,
                    &mut last_checked_block_height);
                accepting_clients = r.is_ok();
                log::info!("Timeout Branch, Accepting Clients @ {}", port);
                continue;
            },
        };

        if !accepting_clients {
            log::warn!("Rejecting Connection From {:?}", addr);
            continue;
        }

        log::info!("<=== [{}] | Accepted Connection From", addr.port());
        let server_loop_err_comms_tx = server_loop_err_comms_tx.clone();
        let watched_txes_comms_tx = watched_txes_comms_tx.clone();

        tokio::spawn(async move {
            let (socket_reader, mut socket_writer) = socket.split();
            let mut reader = BufReader::new(socket_reader);

            if let Err(e) = send_message(
                &mut socket_writer,
                &WatchtowerToMakerMessage::WatchtowerHello(WatchtowerHello {
                    protocol_version_min: 0,
                    protocol_version_max: 0,
                }),
            )
            .await
            {
                log::error!("io error sending first message: {:?}", e);
                return;
            }

            loop {
                let mut line = String::new();
                match reader.read_line(&mut line).await {
                    Ok(n) if n == 0 => {
                        log::info!("Reached EOF");
                        break;
                    }
                    Ok(_n) => (),
                    Err(e) => {
                        log::error!("error reading from socket: {:?}", e);
                        break;
                    }
                };
                #[cfg(test)]
                if line == "kill".to_string() {
                    server_loop_err_comms_tx
                        .send(Error::Protocol("kill signal"))
                        .await
                        .unwrap();
                    log::info!("Kill signal received, stopping watchtower....");
                    break;
                }

                line = line.trim_end().to_string();
                let message_result = handle_message(line, &watched_txes_comms_tx).await;
                match message_result {
                    Ok(()) => {
                        let success_message = WatchtowerToMakerMessage::Success(Success);
                        if let Err(e) = send_message(&mut socket_writer, &success_message).await {
                            log::error!("closing due to io error sending message: {:?}", e);
                            break;
                        }
                    }
                    Err(err) => {
                        log::error!("error handling request: {:?}", err);
                        match err {
                            Error::Network(_e) => (),
                            Error::Protocol(_e) => (),
                            Error::Disk(e) => {
                                server_loop_err_comms_tx.send(Error::Disk(e)).await.unwrap()
                            }
                            Error::Rpc(e) => {
                                server_loop_err_comms_tx.send(Error::Rpc(e)).await.unwrap()
                            }
                        };
                        break;
                    }
                };
            }
        });
    }
}

async fn send_message(
    socket_writer: &mut WriteHalf<'_>,
    message: &WatchtowerToMakerMessage,
) -> Result<(), Error> {
    let mut message_bytes = serde_json::to_vec(message).map_err(|e| io::Error::from(e))?;
    message_bytes.push(b'\n');
    socket_writer.write_all(&message_bytes).await?;
    Ok(())
}

async fn handle_message(
    line: String,
    watched_txes_comms_tx: &mpsc::Sender<Vec<ContractInfo>>,
) -> Result<(), Error> {
    let request: MakerToWatchtowerMessage = match serde_json::from_str(&line) {
        Ok(r) => r,
        Err(_e) => return Err(Error::Protocol("message parsing error")),
    };
    log::debug!("request = {:?}", request);
    match request {
        MakerToWatchtowerMessage::Ping(_ping) => {}
        MakerToWatchtowerMessage::WatchContractTxes(watch_contract_txes_message) => {
            watched_txes_comms_tx
                .send(watch_contract_txes_message.contracts_to_watch)
                .await
                .unwrap(); //TODO can someone crash the watchtower by maxing out this list?
        }
    }
    Ok(())
}

//the point of this enum is to store whether the transaction is from mempool or from a block
//the watchtower needs to know that because obtaining the full transaction differs depending
// if a tx is already in a block you use `getrawtransaction <txid> <blockhash>`
// if a tx is in mempool use another way
enum TxidListType {
    FromMempool(Vec<Txid>),
    FromBlock(GetBlockResult),
}

pub fn check_for_broadcasted_contract_txes(
    rpc: &Client,
    all_contracts_to_watch: &[Vec<ContractInfo>],
    last_checked_block_height: &mut Option<u64>,
) -> Result<bool, bitcoincore_rpc::Error> {
    let mut network_txids = Vec::<TxidListType>::new();

    let mempool_txids = rpc.get_raw_mempool()?;
    network_txids.push(TxidListType::FromMempool(mempool_txids));

    if last_checked_block_height.is_none() {
        log::debug!("initial setting of last_checked_block_height");
        *last_checked_block_height = Some(rpc.get_block_count()?);
    }
    let blockchain_tip_height = rpc.get_block_count()?;
    log::debug!(
        "blockchain_tip_height = {}, last_checked_block_height = {:?}",
        blockchain_tip_height,
        last_checked_block_height
    );
    log::debug!(
        "all_contracts_to_watch = {:?}",
        all_contracts_to_watch
            .iter()
            .map(|vec_contract_info| vec_contract_info
                .iter()
                .map(|c| c.contract_tx.txid())
                .collect::<Vec<Txid>>())
            .collect::<Vec<Vec<Txid>>>()
    );
    //note the plus one here
    for height in (last_checked_block_height.unwrap() + 1)..(blockchain_tip_height + 1) {
        let block_info = rpc.get_block_info(&rpc.get_block_hash(height)?)?;
        log::debug!("height = {}, tx = {:?}", height, block_info.tx);
        network_txids.push(TxidListType::FromBlock(block_info));
    }
    *last_checked_block_height = Some(blockchain_tip_height);

    let mut contract_broadcasted = false;
    for txid_list_type in network_txids {
        let txid_list = match txid_list_type {
            TxidListType::FromMempool(txids) => {
                log::debug!("mempool txids = {:?}", txids);
                txids
            }
            TxidListType::FromBlock(block_info) => {
                log::debug!(
                    "height = {}, block txids = {:?}",
                    block_info.height,
                    block_info.tx
                );
                block_info.tx
            }
        };
        let network_txids = txid_list.into_iter().collect::<HashSet<Txid>>();

        for contracts_to_watch in all_contracts_to_watch {
            let contracts_txids =
                HashSet::from_iter(contracts_to_watch.iter().map(|ci| ci.contract_tx.txid()));

            let contract_txids_on_network = network_txids
                .intersection(&contracts_txids)
                .collect::<Vec<&Txid>>();
            log::debug!(
                "contract_txids_on_network = {:?}",
                contract_txids_on_network
            );
            if !contract_txids_on_network.is_empty() {
                contract_broadcasted = true;
            }
            if contract_txids_on_network.is_empty()
                || contract_txids_on_network.len() == contracts_to_watch.len()
            {
                continue;
            }
            //at this point some but not all the contract txes of a coinswap are visible on network
            //so then broadcast the remaining unbroadcasted ones
            let unbroadcasted_contracts = contracts_to_watch
                .iter()
                .filter(|ci| {
                    contract_txids_on_network
                        .iter()
                        .find(|&&&txid| txid == ci.contract_tx.txid())
                        .is_none()
                })
                .collect::<Vec<&ContractInfo>>();
            log::info!("broadcasting contracts = {:?}", unbroadcasted_contracts);
            for ub_c in unbroadcasted_contracts {
                log::debug!(
                    "broadcasting txid = {:?} tx = {:?}",
                    ub_c.contract_tx.txid(),
                    ub_c.contract_tx
                );
                let txid = rpc.send_raw_transaction(&ub_c.contract_tx)?;
                assert_eq!(txid, ub_c.contract_tx.txid());
            }
        }
    }

    Ok(contract_broadcasted)
}
