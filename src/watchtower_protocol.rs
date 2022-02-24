use std::collections::HashSet;
use std::iter::FromIterator;
use std::net::Ipv4Addr;
use std::sync::{Arc, RwLock};
use std::time::Duration;

use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::tcp::WriteHalf;
use tokio::net::TcpListener;
use tokio::select;
use tokio::sync::mpsc;
use tokio::time::sleep;

use serde::{Deserialize, Serialize};

use bitcoin::hashes::{hash160::Hash as Hash160, Hash};
use bitcoin::{Address, Network, Script, Transaction, Txid};
use bitcoincore_rpc::{
    json::{GetBlockResult, ListTransactionResult},
    Client, RpcApi,
};

use crate::contracts::{
    create_contract_redeemscript, read_hashlock_pubkey_from_contract, read_hashvalue_from_contract,
    read_locktime_from_contract, read_timelock_pubkey_from_contract,
};
use crate::error::Error;
use crate::wallet_sync::import_redeemscript;

//TODO these two structs below are used for two different purposes
//one purpose is as a message format for messages sent down the wire
//the other is as internal data stores for this watchtower application
//thats subpar, it requires the users of the watchtower to send spurious fields
//like timelock_spend_broadcasted = false
//these structs should be split up into another two structs for the different uses
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
pub struct ContractTransaction {
    pub tx: Transaction,
    pub redeemscript: Script,
    pub hashlock_spend_without_preimage: Option<Transaction>,
    pub timelock_spend: Option<Transaction>,
    pub timelock_spend_broadcasted: bool,
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
pub struct ContractsInfo {
    pub contract_txes: Vec<ContractTransaction>,
    pub wallet_label: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct WatchContractTxes {
    pub protocol_version_min: u32,
    pub protocol_version_max: u32,
    pub contracts_to_watch: ContractsInfo,
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

//the point of these Display structs is so that ContractsInfo can be printed
//with {:?} to look nice for debugging
#[derive(Debug)]
struct ContractTransactionDisplay {
    _tx: Txid,
    _redeemscript: Address,
    _hashlock_spend_without_preimage: Option<Txid>,
    _timelock_spend: Option<Txid>,
}

#[derive(Debug)]
struct ContractsInfoDisplay {
    _contract_txes: Vec<ContractTransactionDisplay>,
    _wallet_label: String,
}

impl ContractsInfoDisplay {
    fn from(contracts_info: &ContractsInfo) -> ContractsInfoDisplay {
        ContractsInfoDisplay {
            _contract_txes: contracts_info
                .contract_txes
                .iter()
                .map(|ctx| ContractTransactionDisplay {
                    _tx: ctx.tx.txid(),
                    _redeemscript: Address::p2wsh(&ctx.redeemscript, Network::Regtest),
                    _hashlock_spend_without_preimage: ctx
                        .hashlock_spend_without_preimage
                        .as_ref()
                        .map(|t| t.txid()),
                    _timelock_spend: ctx.timelock_spend.as_ref().map(|t| t.txid()),
                })
                .collect::<Vec<ContractTransactionDisplay>>(),
            _wallet_label: contracts_info.wallet_label.clone(),
        }
    }
}

#[tokio::main]
pub async fn start_watchtower(rpc: &Client, network: Network, kill_flag: Arc<RwLock<bool>>) {
    match run(rpc, network, kill_flag).await {
        Ok(_o) => log::info!("watchtower ended without error"),
        Err(e) => log::info!("watchtower ended with err {:?}", e),
    };
}

async fn run(rpc: &Client, network: Network, kill_flag: Arc<RwLock<bool>>) -> Result<(), Error> {
    //TODO port number in config file
    let port = 6103;
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, port)).await?;
    log::info!("Starting teleport watchtower. Listening On Port {}", port);

    let (watched_txes_comms_tx, mut watched_txes_comms_rx) = mpsc::channel::<ContractsInfo>(100);

    //TODO these kind of things should be persisted to file rather than in memory
    //so that if theres a crash or power cut, the watchtower can be restarted and continue watching
    //the same transactions
    let mut coinswap_in_progress_contracts = Vec::<ContractsInfo>::new();
    let mut last_checked_block_height: Option<u64> = None;
    let mut live_contracts = Vec::<ContractsInfo>::new();
    let mut last_checked_txid: Option<Txid> = None;

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
                let new_watched_contracts = new_watched_txes.as_ref().unwrap();
                log::info!("new_watched_contracts = {:?}", new_watched_contracts); //TODO much spam, print txids instead
                coinswap_in_progress_contracts.push(new_watched_contracts.clone());
                continue;
            },
            //TODO make a const for this magic number of how often to poll, see similar
            // comment in maker_protocol.rs
            _ = sleep(Duration::from_secs(10)) => {
                accepting_clients = run_contract_checks(
                    &rpc,
                    network,
                    &mut coinswap_in_progress_contracts,
                    &mut last_checked_block_height,
                    &mut live_contracts,
                    &mut last_checked_txid
                ).is_ok();

                log::info!("Heartbeat, accepting clients on port {}", port);
                if *kill_flag.read().unwrap() {
                    break Err(Error::Protocol("kill flag is true"));
                }
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
                            Error::Socks(e) => server_loop_err_comms_tx
                                .send(Error::Socks(e))
                                .await
                                .unwrap(),
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
    let mut message_bytes = serde_json::to_vec(message).map_err(|e| std::io::Error::from(e))?;
    message_bytes.push(b'\n');
    socket_writer.write_all(&message_bytes).await?;
    Ok(())
}

async fn handle_message(
    line: String,
    watched_txes_comms_tx: &mpsc::Sender<ContractsInfo>,
) -> Result<(), Error> {
    let request: MakerToWatchtowerMessage = match serde_json::from_str(&line) {
        Ok(r) => r,
        Err(_e) => return Err(Error::Protocol("message parsing error")),
    };
    log::debug!("request = {:?}", request);
    match request {
        MakerToWatchtowerMessage::Ping(_ping) => {}
        MakerToWatchtowerMessage::WatchContractTxes(watch_contract_txes_message) => {
            //TODO check that all the hashvalues are the same
            watched_txes_comms_tx
                .send(watch_contract_txes_message.contracts_to_watch)
                .await
                .unwrap(); //TODO can someone crash the watchtower by maxing out this list?
        }
    }
    Ok(())
}

fn run_contract_checks(
    rpc: &Client,
    network: Network,
    coinswap_in_progress_contracts: &mut Vec<ContractsInfo>,
    last_checked_block_height: &mut Option<u64>,
    live_contracts: &mut Vec<ContractsInfo>,
    last_checked_txid: &mut Option<Txid>,
) -> Result<(), bitcoincore_rpc::Error> {
    log::debug!(
        "coinswap_in_progress_contracts = {:?}",
        coinswap_in_progress_contracts
            .iter()
            .map(|c| ContractsInfoDisplay::from(c))
            .collect::<Vec<ContractsInfoDisplay>>()
    );
    log::debug!(
        "live_contracts = {:?}",
        live_contracts
            .iter()
            .map(|c| ContractsInfoDisplay::from(c))
            .collect::<Vec<ContractsInfoDisplay>>()
    );

    let broadcasted_contracts = check_for_broadcasted_contract_txes(
        rpc,
        coinswap_in_progress_contracts,
        last_checked_block_height,
    )?;
    if !broadcasted_contracts.is_empty() {
        import_broadcasted_contract_redeemscripts(rpc, network, &broadcasted_contracts)?;
        //remove broadcasted_contracts from the vec coinswap_in_progress_contracts
        coinswap_in_progress_contracts.retain(|cipc| {
            broadcasted_contracts
                .iter()
                .find(|&bc| bc == cipc)
                .is_none()
        });
        live_contracts.extend(broadcasted_contracts);
    }

    if !live_contracts.is_empty() {
        let mut closed_contracts =
            check_for_hashlock_spends(rpc, live_contracts, last_checked_txid)?;
        let closed_contracts2 = check_for_timelock_maturity(rpc, live_contracts)?;
        closed_contracts.extend(closed_contracts2);
        if !closed_contracts.is_empty() {
            //remove closed_contracts from the vec coinswap_in_progress_contracts
            live_contracts.retain(|cipc| closed_contracts.iter().find(|&c| c == cipc).is_none());
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
    coinswap_in_progress_contracts: &[ContractsInfo],
    last_checked_block_height: &mut Option<u64>,
) -> Result<Vec<ContractsInfo>, bitcoincore_rpc::Error> {
    let mut network_txs = Vec::<TxidListType>::new();

    let mempool_txids = rpc.get_raw_mempool()?;
    network_txs.push(TxidListType::FromMempool(mempool_txids));

    if last_checked_block_height.is_none() {
        log::debug!("initial setting of last_checked_block_height");
        *last_checked_block_height = Some(rpc.get_block_count()?);
    }
    let blockchain_tip_height = rpc.get_block_count()?;
    //note the plus one here
    for height in (last_checked_block_height.unwrap() + 1)..(blockchain_tip_height + 1) {
        let block_info = rpc.get_block_info(&rpc.get_block_hash(height)?)?;
        log::debug!("height = {}, txes.len = {}", height, block_info.tx.len());
        network_txs.push(TxidListType::FromBlock(block_info));
    }
    *last_checked_block_height = Some(blockchain_tip_height);

    let mut broadcasted_contracts = Vec::<ContractsInfo>::new();
    for txid_list_type in network_txs {
        let txid_list = match txid_list_type {
            TxidListType::FromMempool(txids) => {
                log::debug!("mempool_txids.len = {}", txids.len());
                txids
            }
            TxidListType::FromBlock(block_info) => {
                log::debug!(
                    "height = {}, block_txes.len = {}",
                    block_info.height,
                    block_info.tx.len()
                );
                block_info.tx
            }
        };
        let network_txids = txid_list.into_iter().collect::<HashSet<Txid>>();
        for coinswap_in_progress_contract in coinswap_in_progress_contracts {
            let contracts_txids = HashSet::from_iter(
                coinswap_in_progress_contract
                    .contract_txes
                    .iter()
                    .map(|ctx| ctx.tx.txid()),
            );
            let contract_txids_on_network = network_txids
                .intersection(&contracts_txids)
                .collect::<Vec<&Txid>>();
            log::debug!(
                "contract_txids_on_network = {:?}",
                contract_txids_on_network
            );
            if !contract_txids_on_network.is_empty() {
                broadcasted_contracts.push(coinswap_in_progress_contract.clone());
            }
            if contract_txids_on_network.is_empty()
                || contract_txids_on_network.len()
                    == coinswap_in_progress_contract.contract_txes.len()
            {
                continue;
            }
            //at this point some but not all the contract txes of a coinswap are visible on network
            //so then broadcast the remaining unbroadcasted ones
            let unbroadcasted_contract_txes = coinswap_in_progress_contract
                .contract_txes
                .iter()
                .filter(|ctx| {
                    contract_txids_on_network
                        .iter()
                        .find(|&&&txid| txid == ctx.tx.txid())
                        .is_none()
                })
                .map(|ctx| &ctx.tx)
                .collect::<Vec<&Transaction>>();
            log::info!(
                "broadcasting contract txes = {:?}",
                unbroadcasted_contract_txes
                    .iter()
                    .map(|tx| tx.txid())
                    .collect::<Vec<Txid>>()
            );
            for tx in unbroadcasted_contract_txes {
                log::debug!("broadcasting txid = {:?}", tx.txid());
                let ret_txid = rpc.send_raw_transaction(tx);
                if ret_txid.is_err() {
                    log::debug!("broadcast failed = {:?}", ret_txid);
                }
            }
        }
    }
    Ok(broadcasted_contracts)
}

fn import_broadcasted_contract_redeemscripts(
    rpc: &Client,
    network: Network,
    broadcasted_contracts: &[ContractsInfo],
) -> Result<(), bitcoincore_rpc::Error> {
    log::debug!(
        "broadcasted transactions, now importing their redeemscripts = {:?}",
        broadcasted_contracts
            .iter()
            .map(|ci| ci
                .contract_txes
                .iter()
                .map(|ctx| Address::p2wsh(&ctx.redeemscript, network))
                .collect::<Vec<Address>>())
            .collect::<Vec<Vec<Address>>>()
    );

    for contracts_info in broadcasted_contracts {
        for contract_tx in &contracts_info.contract_txes {
            if contract_tx.redeemscript.is_empty() {
                log::debug!(
                    "not importing redeemscript associated with txid={}",
                    contract_tx.tx.txid()
                );
                continue;
            }
            import_redeemscript(rpc, &contract_tx.redeemscript, &contracts_info.wallet_label)?;
        }
    }
    Ok(())
}

fn check_for_hashlock_spends(
    rpc: &Client,
    live_contracts: &[ContractsInfo],
    last_checked_txid: &mut Option<Txid>,
) -> Result<Vec<ContractsInfo>, bitcoincore_rpc::Error> {
    if last_checked_txid.is_none() {
        *last_checked_txid = Some(
            rpc.list_transactions(None, Some(1), Some(0), Some(true))?[0]
                .info
                .txid,
        );
        log::debug!(
            "initial setting of last_checked_txid = {:?}",
            last_checked_txid.unwrap()
        );
    }
    const BATCH_SIZE: usize = 100;
    let mut wallet_transactions = Vec::<ListTransactionResult>::new();
    for batch in 0..1000 {
        let skip = batch * BATCH_SIZE as usize;
        let mut txes = rpc.list_transactions(None, Some(BATCH_SIZE), Some(skip), Some(true))?;
        if txes.is_empty() {
            break;
        }
        txes.reverse(); //txes from listtransactions come in reverse order
        let found_txid = if let Some((position, _txid)) = txes
            .iter()
            .enumerate()
            .find(|(_i, tx)| tx.info.txid == last_checked_txid.unwrap())
        {
            txes.truncate(position);
            true
        } else {
            false
        };
        wallet_transactions.extend(txes);
        if found_txid {
            break;
        }
    }
    log::debug!(
        "wallet_transactions = {:?}",
        wallet_transactions
            .iter()
            .map(|ltr| ltr.info.txid)
            .collect::<Vec<Txid>>()
    );
    if !wallet_transactions.is_empty() {
        *last_checked_txid = Some(wallet_transactions[0].info.txid);
        log::debug!("updating last_checked_txid to: {:?}", last_checked_txid);
    } else {
        log::debug!(
            "last_checked_txid remaining unchanged: {:?}",
            last_checked_txid
        );
    }
    let mut closed_contracts = Vec::<ContractsInfo>::new();
    let mut already_checked_txids = HashSet::<Txid>::new();
    for wallet_tx in wallet_transactions {
        if already_checked_txids.contains(&wallet_tx.info.txid) {
            continue;
        }
        let tx = rpc
            .get_transaction(&wallet_tx.info.txid, Some(true))?
            .transaction()
            .unwrap();
        for input in tx.input {
            //TODO most of this below for checking whether a tx spends using a preimage we're
            //interested in should be in its own function so its easier to test
            if input.witness.len() < 3 {
                log::debug!(
                    "txid={} not hashlock spend, witness not enough elements",
                    wallet_tx.info.txid
                );
                continue;
            }
            let contract_redeemscript = Script::from(input.witness[2].clone());
            let pub_hashlock =
                if let Ok(phl) = read_hashlock_pubkey_from_contract(&contract_redeemscript) {
                    phl
                } else {
                    log::debug!(
                        "txid={} not hashlock spend, unable to obtain pub_hashlock",
                        wallet_tx.info.txid
                    );
                    continue;
                };
            let pub_timelock =
                if let Ok(ptl) = read_timelock_pubkey_from_contract(&contract_redeemscript) {
                    ptl
                } else {
                    log::debug!(
                        "txid={} not hashlock spend, unable to obtain pub_hashlock",
                        wallet_tx.info.txid
                    );
                    continue;
                };
            let locktime = if let Some(lt) = read_locktime_from_contract(&contract_redeemscript) {
                lt
            } else {
                log::debug!(
                    "txid={} not hashlock spend, unable to obtain locktime",
                    wallet_tx.info.txid
                );
                continue;
            };
            let hashvalue = if let Ok(hv) = read_hashvalue_from_contract(&contract_redeemscript) {
                hv
            } else {
                log::debug!(
                    "txid={} not hashlock spend, unable to obtain hashvalue",
                    wallet_tx.info.txid
                );
                continue;
            };
            if create_contract_redeemscript(&pub_hashlock, &pub_timelock, hashvalue, locktime)
                != contract_redeemscript
            {
                log::debug!(
                    "txid={} not hashlock spend, tx not in contract_redeemscript form",
                    wallet_tx.info.txid
                );
                continue;
            }
            let preimage = &input.witness[1];
            if Hash160::hash(&preimage) != hashvalue {
                log::debug!(
                    "txid={} not hashlock spend, preimage does not match",
                    wallet_tx.info.txid
                );
                continue;
            }

            //check if any of the live contracts we're monitoring have this hashvalue
            for live_contract in live_contracts {
                let contract_hashvalue =
                    read_hashvalue_from_contract(&live_contract.contract_txes[0].redeemscript)
                        .unwrap();
                if contract_hashvalue != hashvalue {
                    log::debug!(
                        "txid={} not hashlock spend, hashvalue doesnt match contract being monitored",
                        wallet_tx.info.txid
                    );
                    continue;
                }
                //time to add the found preimage and broadcast the spend txes

                closed_contracts.push(live_contract.clone());
                log::info!(
                    "Found hashlock spend (txid={}) for one of our contracts, hashvalue={}",
                    wallet_tx.info.txid,
                    hashvalue
                );
                for contract_transaction in &live_contract.contract_txes {
                    if contract_transaction
                        .hashlock_spend_without_preimage
                        .is_none()
                    {
                        continue;
                    }
                    let mut spend_tx = contract_transaction
                        .hashlock_spend_without_preimage
                        .as_ref()
                        .unwrap()
                        .clone();
                    //assumes the spend tx is one-input-one-output
                    spend_tx.input[0].witness[1] = preimage.clone();
                    log::info!("Broadcasting hashlock spend tx: {}", spend_tx.txid());
                    let txid = rpc.send_raw_transaction(&spend_tx)?;
                    assert_eq!(txid, spend_tx.txid());
                }
            }
        }
        already_checked_txids.insert(wallet_tx.info.txid);
    }
    Ok(closed_contracts)
}

fn check_for_timelock_maturity(
    rpc: &Client,
    live_contracts: &mut [ContractsInfo],
) -> Result<Vec<ContractsInfo>, bitcoincore_rpc::Error> {
    let mut closed_contracts = Vec::<ContractsInfo>::new();
    for live_contract in live_contracts {
        for contract_transaction in &mut live_contract.contract_txes {
            if contract_transaction.timelock_spend.is_none() {
                continue;
            }
            let timelock_spend = contract_transaction.timelock_spend.as_ref().unwrap();
            let gettx = rpc.get_transaction(&contract_transaction.tx.txid(), Some(true))?;
            if gettx.info.confirmations < (timelock_spend.input[0].sequence as i32) {
                log::debug!(
                    "timelock txout (txid={}) maturing in {} blocks",
                    contract_transaction.tx.txid(),
                    ((timelock_spend.input[0].sequence as i32) - gettx.info.confirmations)
                );
                continue;
            }
            if contract_transaction.timelock_spend_broadcasted {
                log::debug!(
                    "not broadcasting timelock spend ({}) again, already broadcasted",
                    timelock_spend.txid()
                );
            } else {
                log::info!("Broadcasting timelock spend tx: {}", timelock_spend.txid());
                let _txid = rpc.send_raw_transaction(timelock_spend)?;
                contract_transaction.timelock_spend_broadcasted = true;
            }
        }

        let timelock_spends_broadcasted = live_contract
            .contract_txes
            .iter()
            .filter(|ct| ct.timelock_spend_broadcasted)
            .count();
        let total_timelock_spends = live_contract
            .contract_txes
            .iter()
            .filter(|ct| ct.timelock_spend.is_some())
            .count();
        log::debug!(
            "timelock_spends_broadcasted = {}, total_timelock_spends = {}",
            timelock_spends_broadcasted,
            total_timelock_spends
        );
        if timelock_spends_broadcasted == total_timelock_spends {
            log::debug!(
                "live contract {:?} has all timelock spends broadcast",
                live_contract
                    .contract_txes
                    .iter()
                    .map(|ct| ct.tx.txid())
                    .collect::<Vec<Txid>>()
            );
            closed_contracts.push(live_contract.clone());
        }
    }
    Ok(closed_contracts)
}
