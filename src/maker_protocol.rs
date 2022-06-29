//put your onion address and port here
const MAKER_ONION_ADDR: &str = "myhiddenserviceaddress.onion:6102";
const ABSOLUTE_FEE_SAT: u64 = 1000;
const AMOUNT_RELATIVE_FEE_PPB: u64 = 10_000_000;
const TIME_RELATIVE_FEE_PPB: u64 = 100_000;
const REQUIRED_CONFIRMS: i32 = 1;
const MINIMUM_LOCKTIME: u16 = 48;
const MIN_SIZE: u64 = 10000;

//TODO this goes in the config file

use std::net::{Ipv4Addr, SocketAddr};
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::tcp::WriteHalf;
use tokio::net::TcpListener;
use tokio::select;
use tokio::sync::mpsc;
use tokio::time::sleep;

use bitcoin::hashes::{hash160::Hash as Hash160, Hash};
use bitcoin::secp256k1::{SecretKey, Signature};
use bitcoin::{Amount, Network, OutPoint, PublicKey, Transaction, TxOut, Txid};
use bitcoincore_rpc::{Client, RpcApi};

use itertools::izip;

use crate::contracts;
use crate::contracts::SwapCoin;
use crate::contracts::{
    calculate_coinswap_fee, find_funding_output, read_hashvalue_from_contract,
    read_locktime_from_contract, read_pubkeys_from_multisig_redeemscript,
    MAKER_FUNDING_TX_VBYTE_SIZE,
};
use crate::directory_servers::post_maker_address_to_directory_servers;
use crate::error::Error;
use crate::messages::{
    HashPreimage, MakerHello, MakerToTakerMessage, Offer, PrivateKeyHandover, ProofOfFunding,
    ReceiversContractSig, SenderContractTxInfo, SendersAndReceiversContractSigs,
    SendersContractSig, SignReceiversContractTx, SignSendersAndReceiversContractTxes,
    SignSendersContractTx, SwapCoinPrivateKey, TakerToMakerMessage,
};
use crate::wallet_sync::{IncomingSwapCoin, OutgoingSwapCoin, Wallet, WalletSwapCoin};
use crate::watchtower_client::{ping_watchtowers, register_coinswap_with_watchtowers};
use crate::watchtower_protocol::{ContractTransaction, ContractsInfo};

//used to configure the maker do weird things for testing
#[derive(Debug, Clone, Copy)]
pub enum MakerBehavior {
    Normal,
    CloseOnSignSendersContractTx,
}

#[derive(Debug, Clone)]
pub struct MakerConfig {
    pub port: u16,
    pub rpc_ping_interval_secs: u64,
    pub watchtower_ping_interval_secs: u64,
    pub directory_servers_refresh_interval_secs: u64,
    pub maker_behavior: MakerBehavior,
    pub kill_flag: Arc<RwLock<bool>>,
    pub idle_connection_timeout: u64,
}

#[tokio::main]
pub async fn start_maker(rpc: Arc<Client>, wallet: Arc<RwLock<Wallet>>, config: MakerConfig) {
    match run(rpc, wallet, config).await {
        Ok(_o) => log::info!("maker ended without error"),
        Err(e) => log::info!("maker ended with err: {:?}", e),
    };
}

// A structure denoting expectation of type of taker message.
// Used in the [ConnectionState] structure.
//
// If the recieved message doesn't match expected method,
// protocol error will be returned.
#[derive(Debug)]
enum ExpectedMessage {
    TakerHello,
    NewlyConnectedTaker,
    SignSendersContractTx,
    ProofOfFunding,
    ProofOfFundingORSendersAndReceiversContractSigs,
    SignReceiversContractTx,
    HashPreimage,
    PrivateKeyHandover,
}

struct ConnectionState {
    allowed_message: ExpectedMessage,
    incoming_swapcoins: Option<Vec<IncomingSwapCoin>>,
    outgoing_swapcoins: Option<Vec<OutgoingSwapCoin>>,
    pending_funding_txes: Option<Vec<Transaction>>,
}

async fn run(
    rpc: Arc<Client>,
    wallet: Arc<RwLock<Wallet>>,
    config: MakerConfig,
) -> Result<(), Error> {
    log::debug!(
        "Running maker with special behavior = {:?}",
        config.maker_behavior
    );
    wallet
        .write()
        .unwrap()
        .refresh_offer_maxsize_cache(Arc::clone(&rpc))?;

    log::info!("Pinging watchtowers. . .");
    ping_watchtowers().await?;

    if wallet.read().unwrap().network != Network::Regtest {
        if MAKER_ONION_ADDR == "myhiddenserviceaddress.onion:6102" {
            panic!("You must set config variable MAKER_ONION_ADDR in file src/maker_protocol.rs");
        }
        log::info!(
            "Adding my address ({}) to the directory servers. . .",
            MAKER_ONION_ADDR
        );
        post_maker_address_to_directory_servers(wallet.read().unwrap().network, MAKER_ONION_ADDR)
            .await
            .expect("unable to add my address to the directory servers, is tor reachable?");
    }

    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, config.port)).await?;
    log::info!("Listening On Port {}", config.port);

    let (server_loop_comms_tx, mut server_loop_comms_rx) = mpsc::channel::<Error>(100);
    let mut accepting_clients = true;
    let mut last_watchtowers_ping = Instant::now();
    let mut last_directory_servers_refresh = Instant::now();

    let my_kill_flag = config.kill_flag.clone();

    loop {
        let (mut socket, addr) = select! {
            new_client = listener.accept() => new_client?,
            client_err = server_loop_comms_rx.recv() => {
                //unwrap the option here because we'll never close the mscp so it will always work
                match client_err.as_ref().unwrap() {
                    Error::Rpc(e) => {
                        //doublecheck the rpc connection here because sometimes the rpc error
                        //will be unrelated to the connection itself e.g. "insufficent funds"
                        let rpc_connection_success = rpc.get_best_block_hash().is_ok();
                        if !rpc_connection_success {
                            log::warn!("lost connection with bitcoin node, temporarily shutting \
                                      down server until connection reestablished, error={:?}", e);
                            accepting_clients = false;
                        }
                        continue;
                    },
                    _ => log::error!("ending server"),
                }
                break Err(client_err.unwrap());
            },
            _ = sleep(Duration::from_secs(config.rpc_ping_interval_secs)) => {
                let rpc_ping_success = wallet
                    .write()
                    .unwrap()
                    .refresh_offer_maxsize_cache(Arc::clone(&rpc))
                    .is_ok();
                let watchtowers_ping_interval
                    = Duration::from_secs(config.watchtower_ping_interval_secs);
                let (watchtowers_ping_success, debug_msg) = if Instant::now()
                        .saturating_duration_since(last_watchtowers_ping)
                        > watchtowers_ping_interval {
                    last_watchtowers_ping = Instant::now();
                    let w = ping_watchtowers().await;
                    (w.is_ok(), format!(", watchtowers = {}", w.is_ok()))
                } else {
                    (true, String::from(""))
                };
                log::debug!("Ping: RPC = {}{}", rpc_ping_success, debug_msg);
                accepting_clients = rpc_ping_success && watchtowers_ping_success;
                if !accepting_clients {
                    log::warn!("not accepting clients, rpc_ping_success={} \
                        watchtowers_ping_success={}", rpc_ping_success, watchtowers_ping_success);
                }
                if *my_kill_flag.read().unwrap() {
                    break Err(Error::Protocol("kill flag is true"));
                }

                let directory_servers_refresh_interval = Duration::from_secs(
                    config.directory_servers_refresh_interval_secs
                );
                if wallet.read().unwrap().network != Network::Regtest
                        && Instant::now().saturating_duration_since(last_directory_servers_refresh)
                        > directory_servers_refresh_interval {
                    last_directory_servers_refresh = Instant::now();
                    let result_expiry_time = post_maker_address_to_directory_servers(
                        wallet.read().unwrap().network,
                        MAKER_ONION_ADDR
                    ).await;
                    log::info!("Refreshing my address at the directory servers = {:?}",
                        result_expiry_time);
                }
                continue;
            },
        };

        if !accepting_clients {
            log::warn!("Rejecting Connection From {:?}", addr);
            continue;
        }

        log::info!(
            "[{}] ===> Accepted Connection on port={}",
            addr.port(),
            addr.port()
        );
        let client_rpc = Arc::clone(&rpc);
        let client_wallet = Arc::clone(&wallet);
        let server_loop_comms_tx = server_loop_comms_tx.clone();
        let maker_behavior = config.maker_behavior;
        let idle_connection_timeout = config.idle_connection_timeout;

        tokio::spawn(async move {
            let (socket_reader, mut socket_writer) = socket.split();
            let mut reader = BufReader::new(socket_reader);

            let mut connection_state = ConnectionState {
                allowed_message: ExpectedMessage::TakerHello,
                incoming_swapcoins: None,
                outgoing_swapcoins: None,
                pending_funding_txes: None,
            };

            if let Err(e) = send_message(
                &mut socket_writer,
                &MakerToTakerMessage::MakerHello(MakerHello {
                    protocol_version_min: 0,
                    protocol_version_max: 0,
                }),
            )
            .await
            {
                log::error!("io error sending first message: {:?}", e);
                return;
            }
            log::info!("[{}] <=== MakerHello", addr.port());

            loop {
                let mut line = String::new();
                select! {
                    readline_ret = reader.read_line(&mut line) => {
                        match readline_ret {
                            Ok(n) if n == 0 => {
                                log::info!("[{}] Connection closed by peer", addr.port());
                                break;
                            }
                            Ok(_n) => (),
                            Err(e) => {
                                log::error!("error reading from socket: {:?}", e);
                                break;
                            }
                        }
                    },
                    _ = sleep(Duration::from_secs(idle_connection_timeout)) => {
                        log::info!("[{}] Idle connection closed", addr.port());
                        break;
                    },
                };

                line = line.trim_end().to_string();
                let message_result = handle_message(
                    line,
                    &mut connection_state,
                    Arc::clone(&client_rpc),
                    Arc::clone(&client_wallet),
                    addr,
                    maker_behavior,
                )
                .await;
                match message_result {
                    Ok(reply) => {
                        if let Some(message) = reply {
                            if let Err(e) = send_message(&mut socket_writer, &message).await {
                                log::error!("closing due to io error sending message: {:?}", e);
                                break;
                            }
                        }
                        //if reply is None then dont send anything to client
                    }
                    Err(err) => {
                        log::error!("error handling client request: {:?}", err);
                        match err {
                            Error::Network(_e) => (),
                            Error::Protocol(_e) => (),
                            Error::Disk(e) => {
                                server_loop_comms_tx.send(Error::Disk(e)).await.unwrap()
                            }
                            Error::Rpc(e) => {
                                server_loop_comms_tx.send(Error::Rpc(e)).await.unwrap()
                            }
                            Error::Socks(e) => {
                                server_loop_comms_tx.send(Error::Socks(e)).await.unwrap()
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
    first_message: &MakerToTakerMessage,
) -> Result<(), Error> {
    let mut message_bytes =
        serde_json::to_vec(first_message).map_err(|e| std::io::Error::from(e))?;
    message_bytes.push(b'\n');
    socket_writer.write_all(&message_bytes).await?;
    Ok(())
}

async fn handle_message(
    line: String,
    connection_state: &mut ConnectionState,
    rpc: Arc<Client>,
    wallet: Arc<RwLock<Wallet>>,
    from_addrs: SocketAddr,
    maker_behavior: MakerBehavior,
) -> Result<Option<MakerToTakerMessage>, Error> {
    let request: TakerToMakerMessage = match serde_json::from_str(&line) {
        Ok(r) => r,
        Err(_e) => return Err(Error::Protocol("message parsing error")),
    };

    log::info!(
        "[{}] ===> {} ",
        from_addrs.port(),
        match request {
            TakerToMakerMessage::TakerHello(_) => "TakerHello",
            TakerToMakerMessage::GiveOffer(_) => "GiveOffer",
            TakerToMakerMessage::SignSendersContractTx(_) => "SignSendersContractTx",
            TakerToMakerMessage::ProofOfFunding(_) => "ProofOfFunding",
            TakerToMakerMessage::SendersAndReceiversContractSigs(_) =>
                "SendersAndReceiversContractSigs",
            TakerToMakerMessage::SignReceiversContractTx(_) => "SignReceiversContractTx",
            TakerToMakerMessage::HashPreimage(_) => "HashPreimage",
            TakerToMakerMessage::PrivateKeyHandover(_) => "PrivateKeyHandover",
        }
    );
    log::debug!("{:#?}", request);

    let outgoing_message = match connection_state.allowed_message {
        ExpectedMessage::TakerHello => {
            if let TakerToMakerMessage::TakerHello(_) = request {
                connection_state.allowed_message = ExpectedMessage::NewlyConnectedTaker;
                None
            } else {
                return Err(Error::Protocol("Expected Taker Hello Message"));
            }
        }
        ExpectedMessage::NewlyConnectedTaker => match request {
            TakerToMakerMessage::GiveOffer(_) => {
                let max_size = wallet.read().unwrap().get_offer_maxsize_cache();
                let tweakable_point = wallet.read().unwrap().get_tweakable_keypair().1;
                connection_state.allowed_message = ExpectedMessage::SignSendersContractTx;
                Some(MakerToTakerMessage::Offer(Offer {
                    absolute_fee_sat: ABSOLUTE_FEE_SAT,
                    amount_relative_fee_ppb: AMOUNT_RELATIVE_FEE_PPB,
                    time_relative_fee_ppb: TIME_RELATIVE_FEE_PPB,
                    required_confirms: REQUIRED_CONFIRMS,
                    minimum_locktime: MINIMUM_LOCKTIME,
                    max_size,
                    min_size: MIN_SIZE,
                    tweakable_point,
                }))
            }
            TakerToMakerMessage::SignSendersContractTx(message) => {
                connection_state.allowed_message = ExpectedMessage::ProofOfFunding;
                handle_sign_senders_contract_tx(wallet, message, maker_behavior)?
            }
            TakerToMakerMessage::ProofOfFunding(proof) => {
                connection_state.allowed_message =
                    ExpectedMessage::ProofOfFundingORSendersAndReceiversContractSigs;
                handle_proof_of_funding(connection_state, rpc, wallet, &proof)?
            }
            TakerToMakerMessage::SignReceiversContractTx(message) => {
                connection_state.allowed_message = ExpectedMessage::HashPreimage;
                handle_sign_receivers_contract_tx(wallet, message)?
            }
            TakerToMakerMessage::HashPreimage(message) => {
                connection_state.allowed_message = ExpectedMessage::PrivateKeyHandover;
                handle_hash_preimage(wallet, message)?
            }
            _ => {
                return Err(Error::Protocol("Unexpected Newly Connected Taker message"));
            }
        },
        ExpectedMessage::SignSendersContractTx => {
            if let TakerToMakerMessage::SignSendersContractTx(message) = request {
                connection_state.allowed_message = ExpectedMessage::ProofOfFunding;
                handle_sign_senders_contract_tx(wallet, message, maker_behavior)?
            } else {
                return Err(Error::Protocol(
                    "Expected Sign sender's contract transaction message",
                ));
            }
        }
        ExpectedMessage::ProofOfFunding => {
            if let TakerToMakerMessage::ProofOfFunding(proof) = request {
                connection_state.allowed_message =
                    ExpectedMessage::ProofOfFundingORSendersAndReceiversContractSigs;
                handle_proof_of_funding(connection_state, rpc, wallet, &proof)?
            } else {
                return Err(Error::Protocol("Expected proof of funding message"));
            }
        }
        ExpectedMessage::ProofOfFundingORSendersAndReceiversContractSigs => {
            match request {
                TakerToMakerMessage::ProofOfFunding(proof) => {
                    connection_state.allowed_message =
                        ExpectedMessage::ProofOfFundingORSendersAndReceiversContractSigs;
                    handle_proof_of_funding(connection_state, rpc, wallet, &proof)?
                }
                TakerToMakerMessage::SendersAndReceiversContractSigs(message) => {
                    // Nothing to send. Maker now creates and broadcasts his funding Txs
                    connection_state.allowed_message = ExpectedMessage::SignReceiversContractTx;
                    handle_senders_and_receivers_contract_sigs(
                        connection_state,
                        rpc,
                        wallet,
                        message,
                    )
                    .await?
                }
                _ => {
                    return Err(Error::Protocol(
                        "Expected proof of funding or sender's and reciever's contract signatures",
                    ));
                }
            }
        }
        ExpectedMessage::SignReceiversContractTx => {
            if let TakerToMakerMessage::SignReceiversContractTx(message) = request {
                connection_state.allowed_message = ExpectedMessage::HashPreimage;
                handle_sign_receivers_contract_tx(wallet, message)?
            } else {
                return Err(Error::Protocol("Expected reciever's contract transaction"));
            }
        }
        ExpectedMessage::HashPreimage => {
            if let TakerToMakerMessage::HashPreimage(message) = request {
                connection_state.allowed_message = ExpectedMessage::PrivateKeyHandover;
                handle_hash_preimage(wallet, message)?
            } else {
                return Err(Error::Protocol("Expected hash preimgae"));
            }
        }
        ExpectedMessage::PrivateKeyHandover => {
            if let TakerToMakerMessage::PrivateKeyHandover(message) = request {
                // Nothing to send. Succesfully completed swap
                handle_private_key_handover(wallet, message)?
            } else {
                return Err(Error::Protocol("expected privatekey handover"));
            }
        }
    };

    match outgoing_message {
        Some(reply_message) => {
            log::info!(
                "[{}] <=== {} ",
                from_addrs.port(),
                match reply_message {
                    MakerToTakerMessage::MakerHello(_) => "MakerHello",
                    MakerToTakerMessage::Offer(_) => "Offer",
                    MakerToTakerMessage::SendersContractSig(_) => "SendersContractSig",
                    MakerToTakerMessage::SignSendersAndReceiversContractTxes(_) =>
                        "SignSendersAndReceiversContractTxes",
                    MakerToTakerMessage::ReceiversContractSig(_) => "ReceiversContractSig",
                    MakerToTakerMessage::PrivateKeyHandover(_) => "PrivateKeyHandover",
                }
            );
            log::debug!("{:#?}", reply_message);
            Ok(Some(reply_message))
        }
        None => Ok(None),
    }
}

fn handle_sign_senders_contract_tx(
    wallet: Arc<RwLock<Wallet>>,
    message: SignSendersContractTx,
    maker_behavior: MakerBehavior,
) -> Result<Option<MakerToTakerMessage>, Error> {
    if let MakerBehavior::CloseOnSignSendersContractTx = maker_behavior {
        return Err(Error::Protocol(
            "closing connection early due to special maker behavior",
        ));
    }
    let tweakable_privkey = wallet.read().unwrap().get_tweakable_keypair().0;
    //TODO this for loop could be replaced with an iterator and map
    //see that other example where Result<> inside an iterator is used
    let mut sigs = Vec::<Signature>::new();
    let mut funding_txids = Vec::<Txid>::new();
    let mut total_amount = 0;
    for txinfo in message.txes_info {
        let sig = contracts::validate_and_sign_senders_contract_tx(
            &txinfo.multisig_key_nonce,
            &txinfo.hashlock_key_nonce,
            &txinfo.timelock_pubkey,
            &txinfo.senders_contract_tx,
            &txinfo.multisig_redeemscript,
            txinfo.funding_input_value,
            message.hashvalue,
            message.locktime,
            MINIMUM_LOCKTIME,
            &tweakable_privkey,
            &mut wallet.write().unwrap(),
        )?;
        sigs.push(sig);
        funding_txids.push(txinfo.senders_contract_tx.input[0].previous_output.txid);
        total_amount += txinfo.funding_input_value;
    }
    if total_amount >= MIN_SIZE && total_amount < wallet.read().unwrap().get_offer_maxsize_cache() {
        log::info!(
            "requested contracts amount={}, for funding txids = {:?}",
            Amount::from_sat(total_amount),
            funding_txids
        );
        Ok(Some(MakerToTakerMessage::SendersContractSig(
            SendersContractSig { sigs },
        )))
    } else {
        log::info!(
            "rejecting contracts for amount={} because not enough funds",
            Amount::from_sat(total_amount)
        );
        Err(Error::Protocol("not enough funds"))
    }
}

fn handle_proof_of_funding(
    connection_state: &mut ConnectionState,
    rpc: Arc<Client>,
    wallet: Arc<RwLock<Wallet>>,
    proof: &ProofOfFunding,
) -> Result<Option<MakerToTakerMessage>, Error> {
    let mut funding_output_indexes = Vec::<u32>::new();
    let mut funding_outputs = Vec::<&TxOut>::new();
    let mut incoming_swapcoin_keys = Vec::<(SecretKey, PublicKey, SecretKey)>::new();
    if proof.confirmed_funding_txes.len() == 0 {
        return Err(Error::Protocol("zero funding txes provided"));
    }
    for funding_info in &proof.confirmed_funding_txes {
        //check that the claimed multisig redeemscript is in the transaction
        log::debug!(
            "Proof of Funding: \ntx = {:#?}\nMultisig_Reedimscript = {:x}",
            funding_info.funding_tx,
            funding_info.multisig_redeemscript
        );
        let (funding_output_index, funding_output) = match find_funding_output(
            &funding_info.funding_tx,
            &funding_info.multisig_redeemscript,
        ) {
            Some(fo) => fo,
            None => return Err(Error::Protocol("funding tx doesnt pay to multisig")),
        };
        funding_output_indexes.push(funding_output_index);
        funding_outputs.push(funding_output);
        let verify_result = contracts::verify_proof_of_funding(
            Arc::clone(&rpc),
            &mut wallet.write().unwrap(),
            &funding_info,
            funding_output_index,
            proof.next_locktime,
            MINIMUM_LOCKTIME,
        )?;
        incoming_swapcoin_keys.push(verify_result);
    }

    //check that all the contract redeemscripts involve the same hashvalue
    let mut confirmed_funding_txes_hashvalue_check_iter = proof.confirmed_funding_txes.iter();
    let hashvalue = read_hashvalue_from_contract(
        &confirmed_funding_txes_hashvalue_check_iter
            .next()
            .unwrap()
            .contract_redeemscript,
    )
    .map_err(|_| Error::Protocol("unable to read hashvalue from contract"))?;
    for hv in confirmed_funding_txes_hashvalue_check_iter
        .map(|info| read_hashvalue_from_contract(&info.contract_redeemscript))
    {
        if hv.map_err(|_| Error::Protocol("unable to read hashvalue from contract"))? != hashvalue {
            return Err(Error::Protocol(
                "contract redeemscripts dont all use the same hashvalue",
            ));
        }
    }

    log::debug!("proof of funding valid, creating own funding txes");

    connection_state.incoming_swapcoins = Some(Vec::<IncomingSwapCoin>::new());
    for (funding_info, &funding_output_index, &funding_output, &incoming_swapcoin_keys) in izip!(
        proof.confirmed_funding_txes.iter(),
        funding_output_indexes.iter(),
        funding_outputs.iter(),
        incoming_swapcoin_keys.iter()
    ) {
        let (pubkey1, pubkey2) =
            read_pubkeys_from_multisig_redeemscript(&funding_info.multisig_redeemscript)
                .ok_or(Error::Protocol("invalid multisig redeemscript"))?;
        wallet
            .read()
            .unwrap()
            .import_wallet_multisig_redeemscript(&rpc, &pubkey1, &pubkey2)?;
        wallet.read().unwrap().import_tx_with_merkleproof(
            &rpc,
            &funding_info.funding_tx,
            funding_info.funding_tx_merkleproof.clone(),
        )?;
        wallet
            .read()
            .unwrap()
            .import_wallet_contract_redeemscript(&rpc, &funding_info.contract_redeemscript)?;
        let my_receivers_contract_tx = contracts::create_receivers_contract_tx(
            OutPoint {
                txid: funding_info.funding_tx.txid(),
                vout: funding_output_index,
            },
            funding_output.value,
            &funding_info.contract_redeemscript,
        );
        let (coin_privkey, coin_other_pubkey, hashlock_privkey) = incoming_swapcoin_keys;
        log::debug!(
            "Adding incoming_swapcoin contract_tx = {:?} fo = {:?}",
            my_receivers_contract_tx.clone(),
            funding_output
        );
        connection_state
            .incoming_swapcoins
            .as_mut()
            .unwrap()
            .push(IncomingSwapCoin::new(
                coin_privkey,
                coin_other_pubkey,
                my_receivers_contract_tx.clone(),
                funding_info.contract_redeemscript.clone(),
                hashlock_privkey,
                funding_output.value,
            ));
    }

    //set up the next coinswap in the route
    let incoming_amount = funding_outputs.iter().map(|o| o.value).sum::<u64>();
    let coinswap_fees = calculate_coinswap_fee(
        ABSOLUTE_FEE_SAT,
        AMOUNT_RELATIVE_FEE_PPB,
        TIME_RELATIVE_FEE_PPB,
        incoming_amount,
        1, //time_in_blocks just 1 for now
    );
    let miner_fees_paid_by_taker =
        MAKER_FUNDING_TX_VBYTE_SIZE * proof.next_fee_rate * (proof.next_coinswap_info.len() as u64)
            / 1000;
    let outgoing_amount = incoming_amount - coinswap_fees - miner_fees_paid_by_taker;

    let (my_funding_txes, outgoing_swapcoins, total_miner_fee) =
        wallet.write().unwrap().initalize_coinswap(
            &rpc,
            outgoing_amount,
            &proof
                .next_coinswap_info
                .iter()
                .map(|nci| nci.next_coinswap_multisig_pubkey)
                .collect::<Vec<PublicKey>>(),
            &proof
                .next_coinswap_info
                .iter()
                .map(|nci| nci.next_hashlock_pubkey)
                .collect::<Vec<PublicKey>>(),
            hashvalue,
            proof.next_locktime,
            proof.next_fee_rate,
        )?;

    log::info!(
        "Proof of funding valid. Incoming funding txes, txids = {:?}",
        proof
            .confirmed_funding_txes
            .iter()
            .map(|cft| cft.funding_tx.txid())
            .collect::<Vec<Txid>>()
    );
    log::info!(
        "incoming_amount={}, incoming_locktime={}, hashvalue={}",
        Amount::from_sat(incoming_amount),
        read_locktime_from_contract(&proof.confirmed_funding_txes[0].contract_redeemscript)
            .unwrap(),
        //unwrap() as format of contract_redeemscript already checked in verify_proof_of_funding
        hashvalue
    );
    log::info!(
        concat!(
            "outgoing_amount={}, outgoing_locktime={}, miner fees paid by taker={}, ",
            "actual miner fee={}, coinswap_fees={}, POTENTIALLY EARNED={}"
        ),
        Amount::from_sat(outgoing_amount),
        proof.next_locktime,
        Amount::from_sat(miner_fees_paid_by_taker),
        Amount::from_sat(total_miner_fee),
        Amount::from_sat(coinswap_fees),
        Amount::from_sat(incoming_amount - outgoing_amount - total_miner_fee)
    );

    connection_state.pending_funding_txes = Some(my_funding_txes);
    connection_state.outgoing_swapcoins = Some(outgoing_swapcoins);
    log::debug!(
        "Incoming_swapcoins = {:#?}\nOutgoing_swapcoins = {:#?}",
        connection_state.incoming_swapcoins,
        connection_state.outgoing_swapcoins,
    );
    Ok(Some(
        MakerToTakerMessage::SignSendersAndReceiversContractTxes(
            SignSendersAndReceiversContractTxes {
                receivers_contract_txes: connection_state
                    .incoming_swapcoins
                    .as_ref()
                    .unwrap()
                    .iter()
                    .map(|isc| isc.contract_tx.clone())
                    .collect::<Vec<Transaction>>(),
                senders_contract_txes_info: connection_state
                    .outgoing_swapcoins
                    .as_ref()
                    .unwrap()
                    .iter()
                    .map(|outgoing_swapcoin| SenderContractTxInfo {
                        contract_tx: outgoing_swapcoin.contract_tx.clone(),
                        timelock_pubkey: outgoing_swapcoin.get_timelock_pubkey(),
                        multisig_redeemscript: outgoing_swapcoin.get_multisig_redeemscript(),
                        funding_amount: outgoing_swapcoin.funding_amount,
                    })
                    .collect::<Vec<SenderContractTxInfo>>(),
            },
        ),
    ))
}

async fn handle_senders_and_receivers_contract_sigs(
    connection_state: &mut ConnectionState,
    rpc: Arc<Client>,
    wallet: Arc<RwLock<Wallet>>,
    sigs: SendersAndReceiversContractSigs,
) -> Result<Option<MakerToTakerMessage>, Error> {
    //if incoming/outgoing_swapcoin are None then the app should crash because
    //its a logic error, so no error handling, just use unwrap()

    let incoming_swapcoins = connection_state.incoming_swapcoins.as_mut().unwrap();
    if sigs.receivers_sigs.len() != incoming_swapcoins.len() {
        return Err(Error::Protocol("invalid number of recv signatures"));
    }
    for (receivers_sig, incoming_swapcoin) in
        sigs.receivers_sigs.iter().zip(incoming_swapcoins.iter())
    {
        if !incoming_swapcoin.verify_contract_tx_sig(receivers_sig) {
            return Err(Error::Protocol("invalid recv signature"));
        }
    }
    sigs.receivers_sigs
        .iter()
        .zip(incoming_swapcoins.iter_mut())
        .for_each(|(&receivers_sig, incoming_swapcoin)| {
            incoming_swapcoin.others_contract_sig = Some(receivers_sig)
        });

    let outgoing_swapcoins = connection_state.outgoing_swapcoins.as_mut().unwrap();
    if sigs.senders_sigs.len() != outgoing_swapcoins.len() {
        return Err(Error::Protocol("invalid number of send signatures"));
    }
    for (senders_sig, outgoing_swapcoin) in sigs.senders_sigs.iter().zip(outgoing_swapcoins.iter())
    {
        if !outgoing_swapcoin.verify_contract_tx_sig(senders_sig) {
            return Err(Error::Protocol("invalid send signature"));
        }
    }
    sigs.senders_sigs
        .iter()
        .zip(outgoing_swapcoins.iter_mut())
        .for_each(|(&senders_sig, outgoing_swapcoin)| {
            outgoing_swapcoin.others_contract_sig = Some(senders_sig)
        });

    let wallet_label = wallet.read().unwrap().get_core_wallet_label();
    let internal_addresses = wallet
        .read()
        .unwrap()
        .get_next_internal_addresses(&rpc, incoming_swapcoins.len() as u32)?;
    register_coinswap_with_watchtowers(ContractsInfo {
        contract_txes: incoming_swapcoins
            .iter()
            .zip(internal_addresses.iter())
            .map(|(isc, addr)| ContractTransaction {
                tx: isc.get_fully_signed_contract_tx(),
                redeemscript: isc.contract_redeemscript.clone(),
                hashlock_spend_without_preimage: Some(
                    isc.create_hashlock_spend_without_preimage(addr),
                ),
                timelock_spend: None,
                timelock_spend_broadcasted: false,
            })
            .chain(
                outgoing_swapcoins
                    .iter()
                    .zip(internal_addresses.iter())
                    .map(|(osc, addr)| ContractTransaction {
                        tx: osc.get_fully_signed_contract_tx(),
                        redeemscript: osc.contract_redeemscript.clone(),
                        hashlock_spend_without_preimage: None,
                        timelock_spend: Some(osc.create_timelock_spend(addr)),
                        timelock_spend_broadcasted: false,
                    }),
            )
            .collect::<Vec<ContractTransaction>>(),
        wallet_label,
    })
    .await?;

    let mut w = wallet.write().unwrap();
    incoming_swapcoins
        .iter()
        .for_each(|incoming_swapcoin| w.add_incoming_swapcoin(incoming_swapcoin.clone()));
    outgoing_swapcoins
        .iter()
        .for_each(|outgoing_swapcoin| w.add_outgoing_swapcoin(outgoing_swapcoin.clone()));
    w.update_swapcoins_list()?;

    let mut my_funding_txids = Vec::<Txid>::new();
    for my_funding_tx in connection_state.pending_funding_txes.as_ref().unwrap() {
        log::debug!("Broadcasting My Funding Tx : {:#?}", my_funding_tx);
        let txid = rpc.send_raw_transaction(my_funding_tx)?;
        assert_eq!(txid, my_funding_tx.txid());
        my_funding_txids.push(txid);
    }
    log::info!("Broadcasted My Funding Txes: {:?}", my_funding_txids);

    //set these to None which might be helpful in picking up logic errors later
    connection_state.incoming_swapcoins = None;
    connection_state.outgoing_swapcoins = None;
    connection_state.pending_funding_txes = None;

    Ok(None)
}

fn handle_sign_receivers_contract_tx(
    wallet: Arc<RwLock<Wallet>>,
    message: SignReceiversContractTx,
) -> Result<Option<MakerToTakerMessage>, Error> {
    let mut sigs = Vec::<Signature>::new();
    for receivers_contract_tx_info in message.txes {
        sigs.push(
            //the fact that the peer knows the correct multisig_redeemscript is what ensures
            //security here, a random peer out there who isnt involved in a coinswap wont know
            //what the multisig_redeemscript is
            wallet
                .read()
                .unwrap()
                .find_outgoing_swapcoin(&receivers_contract_tx_info.multisig_redeemscript)
                .ok_or(Error::Protocol("multisig_redeemscript not found"))?
                .sign_contract_tx_with_my_privkey(&receivers_contract_tx_info.contract_tx)?,
        );
    }
    Ok(Some(MakerToTakerMessage::ReceiversContractSig(
        ReceiversContractSig { sigs },
    )))
}

fn handle_hash_preimage(
    wallet: Arc<RwLock<Wallet>>,
    message: HashPreimage,
) -> Result<Option<MakerToTakerMessage>, Error> {
    let hashvalue = Hash160::hash(&message.preimage);
    {
        let mut wallet_mref = wallet.write().unwrap();
        for multisig_redeemscript in message.senders_multisig_redeemscripts {
            let mut incoming_swapcoin = wallet_mref
                .find_incoming_swapcoin_mut(&multisig_redeemscript)
                .ok_or(Error::Protocol("senders multisig_redeemscript not found"))?;
            if read_hashvalue_from_contract(&incoming_swapcoin.contract_redeemscript)
                .map_err(|_| Error::Protocol("unable to read hashvalue from contract"))?
                != hashvalue
            {
                return Err(Error::Protocol("not correct hash preimage"));
            }
            incoming_swapcoin.hash_preimage = Some(message.preimage);
        }
        //TODO tell preimage to watchtowers
    }
    log::info!("received preimage for hashvalue={}", hashvalue);
    let wallet_ref = wallet.read().unwrap();
    let mut swapcoin_private_keys = Vec::<SwapCoinPrivateKey>::new();
    for multisig_redeemscript in message.receivers_multisig_redeemscripts {
        let outgoing_swapcoin = wallet_ref
            .find_outgoing_swapcoin(&multisig_redeemscript)
            .ok_or(Error::Protocol("receivers multisig_redeemscript not found"))?;
        if read_hashvalue_from_contract(&outgoing_swapcoin.contract_redeemscript)
            .map_err(|_| Error::Protocol("unable to read hashvalue from contract"))?
            != hashvalue
        {
            return Err(Error::Protocol("not correct hash preimage"));
        }
        swapcoin_private_keys.push(SwapCoinPrivateKey {
            multisig_redeemscript,
            key: outgoing_swapcoin.my_privkey,
        });
    }

    wallet_ref.update_swapcoins_list()?;
    Ok(Some(MakerToTakerMessage::PrivateKeyHandover(
        PrivateKeyHandover {
            swapcoin_private_keys,
        },
    )))
}

fn handle_private_key_handover(
    wallet: Arc<RwLock<Wallet>>,
    message: PrivateKeyHandover,
) -> Result<Option<MakerToTakerMessage>, Error> {
    let mut wallet_ref = wallet.write().unwrap();
    for swapcoin_private_key in message.swapcoin_private_keys {
        wallet_ref
            .find_incoming_swapcoin_mut(&swapcoin_private_key.multisig_redeemscript)
            .ok_or(Error::Protocol("multisig_redeemscript not found"))?
            .apply_privkey(swapcoin_private_key.key)?
    }
    wallet_ref.update_swapcoins_list()?;
    log::info!("Successfully Completed Coinswap");
    Ok(None)
}
