use std::net::{Ipv4Addr, SocketAddr};
use std::sync::{Arc, RwLock};
use std::time::Duration;

use tokio::io::BufReader;
use tokio::net::tcp::WriteHalf;
use tokio::net::TcpListener;
use tokio::prelude::*;
use tokio::select;
use tokio::sync::mpsc;
use tokio::time::sleep;

use bitcoin::hashes::{hash160::Hash as Hash160, Hash};
use bitcoin::secp256k1::{SecretKey, Signature};
use bitcoin::{OutPoint, PublicKey, Transaction, TxOut};
use bitcoincore_rpc::{Client, RpcApi};

use itertools::izip;

use crate::contracts;
use crate::contracts::SwapCoin;
use crate::contracts::{find_funding_output, read_hashvalue_from_contract};
use crate::error::Error;
use crate::messages::{
    HashPreimage, MakerHello, MakerToTakerMessage, Offer, PrivateKeyHandover, ProofOfFunding,
    ReceiversContractSig, SenderContractTxInfo, SendersAndReceiversContractSigs,
    SendersContractSig, SignReceiversContractTx, SignSendersAndReceiversContractTxes,
    SignSendersContractTx, SwapCoinPrivateKey, TakerToMakerMessage,
};
use crate::wallet_sync::{CoreAddressLabelType, IncomingSwapCoin, OutgoingSwapCoin, Wallet};
use crate::watchtower_client::{register_coinswap_with_watchtowers, ContractInfo};

// A structure denoting expectation of type of taker message.
// Used in the [ConnectionState] structure.
//
// If the recieved message doesn't match expected method,
// protocol error will be returned.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
enum ExpectedMessage {
    TakerHello,
    NewlyConnectedTaker,
    SignSendersContractTx,
    ProofOfFunding,
    SendersAndReceiversContractSigs,
    SignReceiversContractTx,
    HashPreimage,
    PrivateKeyHandover,
}

#[tokio::main]
pub async fn start_maker(rpc: Arc<Client>, wallet: Arc<RwLock<Wallet>>, port: u16) {
    match run(rpc, wallet, port).await {
        Ok(_o) => log::info!("maker ended without error"),
        Err(e) => log::info!("maker ended with err {:?}", e),
    };
}

struct ConnectionState {
    allowed_message: ExpectedMessage,
    incoming_swapcoins: Option<Vec<IncomingSwapCoin>>,
    outgoing_swapcoins: Option<Vec<OutgoingSwapCoin>>,
    pending_funding_txes: Option<Vec<Transaction>>,
}

async fn run(rpc: Arc<Client>, wallet: Arc<RwLock<Wallet>>, port: u16) -> Result<(), Error> {
    //TODO port number in config file
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, port)).await?;
    log::info!("Listening On Port {}", port);

    let (server_loop_comms_tx, mut server_loop_comms_rx) = mpsc::channel::<Error>(100);
    let mut accepting_clients = true;
    loop {
        let (mut socket, addr) = select! {
            new_client = listener.accept() => new_client?,
            client_err = server_loop_comms_rx.recv() => {
                //unwrap the option here because we'll never close the mscp so it will always work
                match client_err.as_ref().unwrap() {
                    Error::Rpc(_e) => {
                        log::warn!("lost connection with bitcoin node, temporarily shutting \
                                  down server until connection reestablished");
                        accepting_clients = false;
                        continue;
                    },
                    _ => log::error!("ending server"),
                }
                break Err(client_err.unwrap());
            },
            //TODO make a const for this magic number of how often to poll the rpc
            _ = sleep(Duration::from_secs(60)) => {
                let r = rpc.get_best_block_hash();
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
        let client_rpc = Arc::clone(&rpc);
        let client_wallet = Arc::clone(&wallet);
        let server_loop_comms_tx = server_loop_comms_tx.clone();

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
                    server_loop_comms_tx
                        .send(Error::Protocol("kill signal"))
                        .await
                        .unwrap();
                    log::info!("Kill signal received, stopping maker....");
                    break;
                }

                line = line.trim_end().to_string();
                let message_result = handle_message(
                    line,
                    &mut connection_state,
                    Arc::clone(&client_rpc),
                    Arc::clone(&client_wallet),
                    addr,
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
    let mut message_bytes = serde_json::to_vec(first_message).map_err(|e| io::Error::from(e))?;
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
) -> Result<Option<MakerToTakerMessage>, Error> {
    let request: TakerToMakerMessage = match serde_json::from_str(&line) {
        Ok(r) => r,
        Err(_e) => return Err(Error::Protocol("message parsing error")),
    };

    let outgoing_message = match connection_state.allowed_message {
        ExpectedMessage::TakerHello => {
            if let TakerToMakerMessage::TakerHello(_) = request {
                log::debug!("{:#?}", request);
                connection_state.allowed_message = ExpectedMessage::NewlyConnectedTaker;
                None
            } else {
                return Err(Error::Protocol("Expected Taker Hello Message"));
            }
        }
        ExpectedMessage::NewlyConnectedTaker => match request {
            TakerToMakerMessage::GiveOffer(_) => {
                log::info!("<=== [{}] | Recieved GiveOffer", from_addrs.port());
                log::info!("===> [{}] | Sending Offer Data", from_addrs.port());
                let max_size = wallet.read().unwrap().get_offer_maxsize(rpc)?;
                let tweakable_point = wallet.read().unwrap().get_tweakable_keypair().1;
                connection_state.allowed_message = ExpectedMessage::SignSendersContractTx;
                Some(MakerToTakerMessage::Offer(Offer {
                    absolute_fee: 1000,
                    amount_relative_fee: 0.005,
                    max_size,
                    min_size: 10000,
                    tweakable_point,
                }))
            }
            TakerToMakerMessage::SignSendersContractTx(message) => {
                log::info!(
                    "<=== [{}] | Recieved SignSendersContractTx ",
                    from_addrs.port()
                );
                log::info!("===> [{}] | Sending SendersContractSig", from_addrs.port());
                log::debug!("{:#?}", message);
                connection_state.allowed_message = ExpectedMessage::ProofOfFunding;
                handle_sign_senders_contract_tx(wallet, message)?
            }
            TakerToMakerMessage::ProofOfFunding(proof) => {
                log::info!("<=== [{}] | Recieved ProofOfFunding", from_addrs.port());
                log::info!(
                    "===> [{}] | Sending SignSendersAndReceiversContractTxes",
                    from_addrs.port()
                );
                log::debug!("{:#?}", proof);
                connection_state.allowed_message = ExpectedMessage::SendersAndReceiversContractSigs;
                handle_proof_of_funding(connection_state, rpc, wallet, &proof)?
            }
            TakerToMakerMessage::SignReceiversContractTx(message) => {
                log::info!(
                    "<=== [{}] | Recieved SignReceiversContractTx",
                    from_addrs.port()
                );
                log::info!(
                    "===> [{}] | Sending ReceiversContractSig",
                    from_addrs.port()
                );
                log::debug!("{:#?}", message);
                connection_state.allowed_message = ExpectedMessage::HashPreimage;
                handle_sign_receivers_contract_tx(wallet, message)?
            }
            TakerToMakerMessage::HashPreimage(message) => {
                log::info!("<=== [{}] | Recieved HashPreimage", from_addrs.port());
                log::info!("===> [{}] | Sending Private Keys", from_addrs.port());
                log::debug!("{:#?}", message);
                connection_state.allowed_message = ExpectedMessage::PrivateKeyHandover;
                handle_hash_preimage(wallet, message)?
            }
            _ => {
                return Err(Error::Protocol("Unexpected Newly Connected Taker message"));
            }
        },
        ExpectedMessage::SignSendersContractTx => {
            if let TakerToMakerMessage::SignSendersContractTx(message) = request {
                log::info!(
                    "<=== [{}] | Recieved SignSendersContractTx ",
                    from_addrs.port()
                );
                log::info!("===> [{}] | Sending SendersContractSig", from_addrs.port());
                log::debug!("{:#?}", message);
                connection_state.allowed_message = ExpectedMessage::ProofOfFunding;
                handle_sign_senders_contract_tx(wallet, message)?
            } else {
                return Err(Error::Protocol(
                    "Expected Sign sender's contract transaction message",
                ));
            }
        }
        ExpectedMessage::ProofOfFunding => {
            if let TakerToMakerMessage::ProofOfFunding(proof) = request {
                log::info!("<=== [{}] | Recieved ProofOfFunding", from_addrs.port());
                log::info!(
                    "===> [{}] | Sending SignSendersAndReceiversContractTxes",
                    from_addrs.port()
                );
                log::debug!("{:#?}", proof);
                connection_state.allowed_message = ExpectedMessage::SendersAndReceiversContractSigs;
                handle_proof_of_funding(connection_state, rpc, wallet, &proof)?
            } else {
                return Err(Error::Protocol("Expected proof of funding message"));
            }
        }
        ExpectedMessage::SendersAndReceiversContractSigs => {
            if let TakerToMakerMessage::SendersAndReceiversContractSigs(message) = request {
                log::info!(
                    "<=== [{}] | Recieved SendersAndReceiversContractSigs",
                    from_addrs.port()
                );
                // Nothing to send. Maker now creates and broadcasts his funding Txs
                log::debug!("{:#?}", message);
                connection_state.allowed_message = ExpectedMessage::SignReceiversContractTx;
                handle_senders_and_receivers_contract_sigs(connection_state, rpc, wallet, message)
                    .await?
            } else {
                return Err(Error::Protocol(
                    "Expected sender's and reciever's contract signatures",
                ));
            }
        }
        ExpectedMessage::SignReceiversContractTx => {
            if let TakerToMakerMessage::SignReceiversContractTx(message) = request {
                log::info!(
                    "<=== [{}] | Recieved SignReceiversContractTx",
                    from_addrs.port()
                );
                log::info!(
                    "===> [{}] | Sending ReceiversContractSig",
                    from_addrs.port()
                );
                log::debug!("{:#?}", message);
                connection_state.allowed_message = ExpectedMessage::HashPreimage;
                handle_sign_receivers_contract_tx(wallet, message)?
            } else {
                return Err(Error::Protocol("Expected reciever's contract transaction"));
            }
        }
        ExpectedMessage::HashPreimage => {
            if let TakerToMakerMessage::HashPreimage(message) = request {
                log::info!("<=== [{}] | Recieved HashPreimage", from_addrs.port());
                log::info!("===> [{}] | Sending Private Keys", from_addrs.port());
                log::debug!("{:#?}", message);
                connection_state.allowed_message = ExpectedMessage::PrivateKeyHandover;
                handle_hash_preimage(wallet, message)?
            } else {
                return Err(Error::Protocol("Expected hash preimgae"));
            }
        }
        ExpectedMessage::PrivateKeyHandover => {
            if let TakerToMakerMessage::PrivateKeyHandover(message) = request {
                log::info!("<=== [{}] | Recieved Private Keys", from_addrs.port());
                // Nothing to send. Succesfully completed swap
                log::debug!("{:#?}", message);
                handle_private_key_handover(wallet, message)?
            } else {
                return Err(Error::Protocol("expected privatekey handover"));
            }
        }
    };

    match outgoing_message {
        Some(result) => {
            log::debug!("{:#?}", result);
            Ok(Some(result))
        }
        None => Ok(None),
    }
}

fn handle_sign_senders_contract_tx(
    wallet: Arc<RwLock<Wallet>>,
    message: SignSendersContractTx,
) -> Result<Option<MakerToTakerMessage>, Error> {
    let tweakable_privkey = wallet.read().unwrap().get_tweakable_keypair().0;
    //TODO this for loop could be replaced with an iterator and map
    //see that other example where Result<> inside an iterator is used
    let mut sigs = Vec::<Signature>::new();
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
            &tweakable_privkey,
            &mut wallet.write().unwrap(),
        )?;
        sigs.push(sig);
    }
    Ok(Some(MakerToTakerMessage::SendersContractSig(
        SendersContractSig { sigs },
    )))
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
        wallet.read().unwrap().import_redeemscript(
            &rpc,
            &funding_info.multisig_redeemscript,
            CoreAddressLabelType::Wallet,
        )?;
        wallet.read().unwrap().import_tx_with_merkleproof(
            &rpc,
            &funding_info.funding_tx,
            funding_info.funding_tx_merkleproof.clone(),
        )?;
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

    //set up the next coinswap address in the route
    let coinswap_fees = 10000; //TODO calculate them properly
    let incoming_amount = funding_outputs.iter().map(|o| o.value).sum::<u64>();
    log::debug!("incoming amount = {}", incoming_amount);
    let amount = incoming_amount - coinswap_fees;

    let (my_funding_txes, outgoing_swapcoins, timelock_pubkeys) =
        wallet.write().unwrap().initalize_coinswap(
            &rpc,
            amount,
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
        )?;

    log::debug!("My Funding Transactions = {:#?}", my_funding_txes);

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
                    .zip(timelock_pubkeys.iter())
                    .map(
                        |(outgoing_swapcoin, &timelock_pubkey)| SenderContractTxInfo {
                            contract_tx: outgoing_swapcoin.contract_tx.clone(),
                            timelock_pubkey,
                            multisig_redeemscript: outgoing_swapcoin.get_multisig_redeemscript(),
                            funding_amount: outgoing_swapcoin.funding_amount,
                        },
                    )
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

    register_coinswap_with_watchtowers(
        incoming_swapcoins
            .iter()
            .map(|isc| ContractInfo {
                contract_tx: isc.contract_tx.clone(),
            })
            .chain(outgoing_swapcoins.iter().map(|osc| ContractInfo {
                contract_tx: osc.contract_tx.clone(),
            }))
            .collect::<Vec<ContractInfo>>(),
    )
    .await?;

    let mut w = wallet.write().unwrap();
    incoming_swapcoins
        .iter()
        .for_each(|incoming_swapcoin| w.add_incoming_swapcoin(incoming_swapcoin.clone()));
    outgoing_swapcoins
        .iter()
        .for_each(|outgoing_swapcoin| w.add_outgoing_swapcoin(outgoing_swapcoin.clone()));
    w.update_swap_coins_list()?;

    for my_funding_tx in connection_state.pending_funding_txes.as_ref().unwrap() {
        log::debug!("Broadcasting My Funding Tx : {:#?}", my_funding_tx);
        let txid = rpc.send_raw_transaction(my_funding_tx)?;
        assert_eq!(txid, my_funding_tx.txid());
        log::info!("Broadcasted My Funding Tx: {}", txid);
    }

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
            if let Some(c) = wallet
                .read()
                .unwrap()
                .find_incoming_swapcoin(&receivers_contract_tx_info.multisig_redeemscript)
            {
                c.sign_contract_tx_with_my_privkey(&receivers_contract_tx_info.contract_tx)?
            } else {
                wallet
                    .read()
                    .unwrap()
                    .find_outgoing_swapcoin(&receivers_contract_tx_info.multisig_redeemscript)
                    .ok_or(Error::Protocol("multisig_redeemscript not found"))?
                    .sign_contract_tx_with_my_privkey(&receivers_contract_tx_info.contract_tx)?
            },
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

    wallet_ref.update_swap_coins_list()?;
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
        if let Some(c) =
            wallet_ref.find_incoming_swapcoin_mut(&swapcoin_private_key.multisig_redeemscript)
        {
            c.apply_privkey(swapcoin_private_key.key)?
        } else {
            wallet_ref
                .find_outgoing_swapcoin_mut(&swapcoin_private_key.multisig_redeemscript)
                .ok_or(Error::Protocol("multisig_redeemscript not found"))?
                .apply_privkey(swapcoin_private_key.key)?
        }
    }
    wallet_ref.update_swap_coins_list()?;
    log::info!("Successfully Completed Coinswap");
    Ok(None)
}
