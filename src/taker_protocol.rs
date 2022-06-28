use std::collections::{HashMap, HashSet};
use std::io::ErrorKind;
use std::iter::once;
use std::time::Duration;

use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::tcp::{ReadHalf, WriteHalf};
use tokio::net::TcpStream;
use tokio::select;
use tokio::time::sleep;

use tokio_socks::tcp::Socks5Stream;

use bitcoin::consensus::encode::deserialize;
use bitcoin::hashes::hash160::Hash as Hash160;
use bitcoin::hashes::{hex::ToHex, Hash};
use bitcoin::secp256k1::{SecretKey, Signature};
use bitcoin::util::ecdsa::PublicKey;
use bitcoin::{BlockHash, OutPoint, Script, Transaction, Txid};
use bitcoincore_rpc::{Client, RpcApi};

use rand::rngs::OsRng;
use rand::RngCore;

use itertools::izip;

use crate::contracts;
use crate::contracts::SwapCoin;
use crate::contracts::{
    calculate_coinswap_fee, create_contract_redeemscript, create_receivers_contract_tx,
    find_funding_output, read_pubkeys_from_multisig_redeemscript, sign_contract_tx,
    validate_contract_tx, WatchOnlySwapCoin, MAKER_FUNDING_TX_VBYTE_SIZE,
};
use crate::error::Error;
use crate::messages::{
    ConfirmedCoinSwapTxInfo, HashPreimage, MakerToTakerMessage, NextCoinSwapTxInfo, Preimage,
    PrivateKeyHandover, ProofOfFunding, ReceiversContractTxInfo, SenderContractTxNoncesInfo,
    SendersAndReceiversContractSigs, SignReceiversContractTx, SignSendersAndReceiversContractTxes,
    SignSendersContractTx, SwapCoinPrivateKey, TakerHello, TakerToMakerMessage, PREIMAGE_LEN,
};

use crate::offerbook_sync::{sync_offerbook, MakerAddress, OfferAndAddress};
use crate::wallet_sync::{
    generate_keypair, import_watchonly_redeemscript, IncomingSwapCoin, OutgoingSwapCoin, Wallet,
};

use crate::watchtower_protocol::{
    check_for_broadcasted_contract_txes, ContractTransaction, ContractsInfo,
};

//relatively low value for now so that its easier to test without having to wait too much
//right now only the very brave will try coinswap out on mainnet with non-trivial amounts
pub const REFUND_LOCKTIME: u16 = 48; //in blocks
pub const REFUND_LOCKTIME_STEP: u16 = 48; //in blocks

//first connect means the first time you're ever connecting, without having gotten any txes
// confirmed yet, so the taker will not be very persistent since there should be plenty of other
// makers out there
//but also it should allow for flaky connections, otherwise you exclude raspberry pi nodes running
// in people's closets, which are very important for decentralization
pub const FIRST_CONNECT_ATTEMPTS: u32 = 5;
pub const FIRST_CONNECT_SLEEP_DELAY_SEC: u64 = 1;
pub const FIRST_CONNECT_ATTEMPT_TIMEOUT_SEC: u64 = 20;

//reconnect means when connecting to a maker again after having already gotten txes confirmed
// as it would be a waste of miner fees to give up, the taker is coded to be very persistent
//taker will first attempt to connect with a short delay between attempts
// after that will attempt to connect with a longer delay between attempts
//these figures imply that taker will attempt to connect for just over 48 hours
// of course the user can ctrl+c before then if they give up themselves
const RECONNECT_ATTEMPTS: u32 = 3200;
const RECONNECT_SHORT_SLEEP_DELAY_SEC: u64 = 10;
const RECONNECT_LONG_SLEEP_DELAY_SEC: u64 = 60;
const SHORT_LONG_SLEEP_DELAY_TRANSITION: u32 = 60; //after this many attempts, switch to sleeping longer
const RECONNECT_ATTEMPT_TIMEOUT_SEC: u64 = 60 * 5;

#[derive(Debug, Clone, Copy)]
pub struct TakerConfig {
    pub send_amount: u64,
    pub maker_count: u16,
    pub tx_count: u32,
    pub required_confirms: i32,
    pub fee_rate: u64,
}

#[tokio::main]
pub async fn start_taker(rpc: &Client, wallet: &mut Wallet, config: TakerConfig) {
    match run(rpc, wallet, config).await {
        Ok(_o) => (),
        Err(e) => log::error!("err {:?}", e),
    };
}

async fn run(rpc: &Client, wallet: &mut Wallet, config: TakerConfig) -> Result<(), Error> {
    let offers_addresses = sync_offerbook(wallet.network)
        .await
        .expect("unable to sync maker addresses from directory servers");
    log::info!("<=== Got Offers ({} offers)", offers_addresses.len());
    log::debug!("Offers : {:#?}", offers_addresses);
    send_coinswap(rpc, wallet, config, &offers_addresses).await?;
    Ok(())
}

async fn send_coinswap(
    rpc: &Client,
    wallet: &mut Wallet,
    config: TakerConfig,
    all_maker_offers_addresses: &Vec<OfferAndAddress>,
) -> Result<(), Error> {
    let mut preimage = [0u8; PREIMAGE_LEN];
    OsRng.fill_bytes(&mut preimage);
    let hashvalue = Hash160::hash(&preimage);

    let first_swap_locktime = REFUND_LOCKTIME + REFUND_LOCKTIME_STEP * config.maker_count;

    let mut maker_offers_addresses = all_maker_offers_addresses
        .iter()
        .collect::<Vec<&OfferAndAddress>>();

    let (
        first_maker,
        mut this_maker_multisig_privkeys,
        mut this_maker_hashlock_privkeys,
        my_funding_txes,
        mut outgoing_swapcoins,
        first_maker_senders_contract_sigs,
    ) = loop {
        //loop to help error handling, loop ends if we run out of makers to try
        let first_maker = choose_next_maker(&mut maker_offers_addresses, config.send_amount)
            .expect("not enough offers");
        let (
            first_maker_multisig_pubkeys,
            this_maker_multisig_privkeys,
            first_maker_hashlock_pubkeys,
            this_maker_hashlock_privkeys,
        ) = generate_maker_multisig_and_hashlock_keys(
            &first_maker.offer.tweakable_point,
            config.tx_count,
        );
        let (my_funding_txes, outgoing_swapcoins, _my_total_miner_fee) = wallet
            .initalize_coinswap(
                rpc,
                config.send_amount,
                &first_maker_multisig_pubkeys,
                &first_maker_hashlock_pubkeys,
                hashvalue,
                first_swap_locktime,
                config.fee_rate,
            )
            .unwrap();
        let first_maker_senders_contract_sigs = match request_senders_contract_tx_signatures(
            &first_maker.address,
            &outgoing_swapcoins,
            &this_maker_multisig_privkeys,
            &this_maker_hashlock_privkeys,
            first_swap_locktime,
        )
        .await
        {
            Ok(r) => r,
            Err(e) => {
                log::debug!(
                    "Failed to obtain senders contract tx signature from first_maker {}: {:?}",
                    first_maker.address,
                    e
                );
                continue; //go back to the start and try another maker
            }
        };
        break (
            first_maker,
            this_maker_multisig_privkeys,
            this_maker_hashlock_privkeys,
            my_funding_txes,
            outgoing_swapcoins,
            first_maker_senders_contract_sigs,
        );
    };
    first_maker_senders_contract_sigs
        .iter()
        .zip(outgoing_swapcoins.iter_mut())
        .for_each(|(sig, outgoing_swapcoin)| outgoing_swapcoin.others_contract_sig = Some(*sig));
    for outgoing_swapcoin in &outgoing_swapcoins {
        wallet.add_outgoing_swapcoin(outgoing_swapcoin.clone());
    }
    wallet.update_swapcoins_list().unwrap();

    log::debug!("My Funding Tx:  {:#?}", my_funding_txes);
    log::debug!("Outgoing SwapCoins: {:#?}", outgoing_swapcoins);
    for my_funding_tx in my_funding_txes.iter() {
        let txid = rpc.send_raw_transaction(my_funding_tx)?;
        log::info!("Broadcasting My Funding Tx: {}", txid);
        assert_eq!(txid, my_funding_tx.txid());
    }
    let (mut funding_txes, mut funding_tx_merkleproofs) = wait_for_funding_tx_confirmation(
        rpc,
        &my_funding_txes
            .iter()
            .map(|tx| tx.txid())
            .collect::<Vec<Txid>>(),
        first_maker.offer.required_confirms,
        &[],
        &mut None,
    )
    .await?
    .unwrap();
    //unwrap the option without checking for Option::None because we passed no contract txes
    //to watch and therefore they cant be broadcast

    let mut active_maker_addresses = Vec::<&MakerAddress>::new();
    let mut next_maker = first_maker;
    let mut previous_maker: Option<&OfferAndAddress> = None;

    let mut watchonly_swapcoins = Vec::<Vec<WatchOnlySwapCoin>>::new();
    let mut incoming_swapcoins = Vec::<IncomingSwapCoin>::new();

    let mut last_checked_block_height: Option<u64> = None;

    for maker_index in 0..config.maker_count {
        let is_taker_next_peer = maker_index == config.maker_count - 1;
        let is_taker_previous_peer = maker_index == 0;

        let maker_refund_locktime =
            REFUND_LOCKTIME + REFUND_LOCKTIME_STEP * (config.maker_count - maker_index - 1);
        let (
            this_maker_multisig_redeemscripts,
            this_maker_contract_redeemscripts,
            this_maker_contract_txes,
        ) = if is_taker_previous_peer {
            get_swapcoin_multisig_contract_redeemscripts_txes(&outgoing_swapcoins)
        } else {
            get_swapcoin_multisig_contract_redeemscripts_txes(watchonly_swapcoins.last().unwrap())
        };

        let this_maker = next_maker;
        let (
            next_peer_multisig_pubkeys,
            next_peer_multisig_keys_or_nonces,
            next_peer_hashlock_keys_or_nonces,
            maker_sign_sender_and_receiver_contracts,
            next_swap_contract_redeemscripts,
            found_next_maker,
        ) = exchange_signatures_and_find_next_maker(
            rpc,
            &config,
            &mut maker_offers_addresses,
            &this_maker,
            previous_maker,
            is_taker_previous_peer,
            is_taker_next_peer,
            &funding_txes,
            &funding_tx_merkleproofs,
            &this_maker_multisig_redeemscripts,
            &this_maker_multisig_privkeys,
            &this_maker_contract_redeemscripts,
            &this_maker_hashlock_privkeys,
            &this_maker_contract_txes,
            maker_refund_locktime,
            hashvalue,
            &outgoing_swapcoins,
            &mut watchonly_swapcoins,
        )
        .await?;
        next_maker = found_next_maker;
        active_maker_addresses.push(&this_maker.address);

        let wait_for_confirm_result = wait_for_funding_tx_confirmation(
            rpc,
            &maker_sign_sender_and_receiver_contracts
                .senders_contract_txes_info
                .iter()
                .map(|senders_contract_tx_info| {
                    senders_contract_tx_info.contract_tx.input[0]
                        .previous_output
                        .txid
                })
                .collect::<Vec<Txid>>(),
            if is_taker_next_peer {
                config.required_confirms
            } else {
                next_maker.offer.required_confirms
            },
            &watchonly_swapcoins
                .iter()
                .map(|watchonly_swapcoin_list| {
                    watchonly_swapcoin_list
                        .iter()
                        .map(|watchonly_swapcoin| watchonly_swapcoin.contract_tx.clone())
                        .collect::<Vec<Transaction>>()
                })
                .chain(once(
                    outgoing_swapcoins
                        .iter()
                        .map(|osc| osc.contract_tx.clone())
                        .collect::<Vec<Transaction>>(),
                ))
                .collect::<Vec<Vec<Transaction>>>(),
            &mut last_checked_block_height,
        )
        .await?;
        if wait_for_confirm_result.is_none() {
            log::info!(concat!(
                "Somebody deviated from the protocol by broadcasting one or more contract",
                " transactions! Use main method `recover-from-incomplete-coinswap` to recover",
                " coins"
            ));
            panic!("ending");
        }
        let (next_funding_txes, next_funding_tx_merkleproofs) = wait_for_confirm_result.unwrap();
        funding_txes = next_funding_txes;
        funding_tx_merkleproofs = next_funding_tx_merkleproofs;

        if is_taker_next_peer {
            incoming_swapcoins = create_incoming_swapcoins(
                rpc,
                &wallet,
                &maker_sign_sender_and_receiver_contracts,
                &funding_txes,
                &funding_tx_merkleproofs,
                &next_swap_contract_redeemscripts,
                &next_peer_hashlock_keys_or_nonces,
                &next_peer_multisig_pubkeys,
                &next_peer_multisig_keys_or_nonces,
                preimage,
            )
            .unwrap();
            //TODO reason about why this unwrap is here without any error handling
            //do we expect this to never error? are the conditions checked earlier?
        }
        this_maker_multisig_privkeys = next_peer_multisig_keys_or_nonces;
        this_maker_hashlock_privkeys = next_peer_hashlock_keys_or_nonces;
        previous_maker = Some(this_maker);
    }

    let last_maker = previous_maker.unwrap();
    log::info!(
        "===> Sending SignReceiversContractTx to {}",
        last_maker.address
    );
    let last_receiver_contract_sig = request_receivers_contract_tx_signatures(
        &last_maker.address,
        &incoming_swapcoins,
        &incoming_swapcoins
            .iter()
            .map(|swapcoin| swapcoin.contract_tx.clone())
            .collect::<Vec<Transaction>>(),
    )
    .await?;
    for (incoming_swapcoin, &receiver_contract_sig) in incoming_swapcoins
        .iter_mut()
        .zip(last_receiver_contract_sig.iter())
    {
        incoming_swapcoin.others_contract_sig = Some(receiver_contract_sig);
    }
    for incoming_swapcoin in &incoming_swapcoins {
        wallet.add_incoming_swapcoin(incoming_swapcoin.clone());
    }
    wallet.update_swapcoins_list().unwrap();

    settle_all_coinswaps_send_hash_preimage_and_privkeys(
        &config,
        preimage,
        &active_maker_addresses,
        &outgoing_swapcoins,
        &mut watchonly_swapcoins,
        &mut incoming_swapcoins,
    )
    .await?;

    for (index, watchonly_swapcoin) in watchonly_swapcoins.iter().enumerate() {
        log::debug!(
            "maker[{}] funding txes = {:#?}",
            index,
            watchonly_swapcoin
                .iter()
                .map(|w| w.contract_tx.input[0].previous_output.txid)
                .collect::<Vec<_>>()
        );
    }
    log::debug!(
        "my incoming txes = {:#?}",
        incoming_swapcoins
            .iter()
            .map(|w| w.contract_tx.input[0].previous_output.txid)
            .collect::<Vec<_>>()
    );

    //update incoming_swapcoins with privkey on disk here
    for incoming_swapcoin in &incoming_swapcoins {
        wallet
            .find_incoming_swapcoin_mut(&incoming_swapcoin.get_multisig_redeemscript())
            .unwrap()
            .other_privkey = incoming_swapcoin.other_privkey;
    }
    wallet.update_swapcoins_list().unwrap();

    log::info!("Successfully Completed Coinswap");
    Ok(())
}

fn choose_next_maker<'a>(
    maker_offers_addresses: &mut Vec<&'a OfferAndAddress>,
    amount: u64,
) -> Option<&'a OfferAndAddress> {
    loop {
        let m = maker_offers_addresses.pop()?;
        if amount < m.offer.min_size || amount > m.offer.max_size {
            log::debug!("amount out of range for maker = {:?}", m);
            continue;
        }
        log::debug!("next maker = {:?}", m);
        break Some(m);
    }
}

pub async fn send_message(
    socket_writer: &mut WriteHalf<'_>,
    message: TakerToMakerMessage,
) -> Result<(), Error> {
    log::debug!("==> {:#?}", message);
    let mut result_bytes = serde_json::to_vec(&message).map_err(|e| std::io::Error::from(e))?;
    result_bytes.push(b'\n');
    socket_writer.write_all(&result_bytes).await?;
    Ok(())
}

pub async fn read_message(
    reader: &mut BufReader<ReadHalf<'_>>,
) -> Result<MakerToTakerMessage, Error> {
    let mut line = String::new();
    let n = reader.read_line(&mut line).await?;
    if n == 0 {
        return Err(Error::Network(Box::new(std::io::Error::new(
            ErrorKind::ConnectionReset,
            "EOF",
        ))));
    }
    let message: MakerToTakerMessage = match serde_json::from_str(&line) {
        Ok(r) => r,
        Err(_e) => return Err(Error::Protocol("json parsing error")),
    };
    log::debug!("<== {:#?}", message);
    Ok(message)
}

pub async fn handshake_maker<'a>(
    socket: &'a mut TcpStream,
    maker_address: &MakerAddress,
) -> Result<(BufReader<ReadHalf<'a>>, WriteHalf<'a>), Error> {
    let socket = match maker_address {
        MakerAddress::Clearnet { address: _ } => socket,
        MakerAddress::Tor { address } => Socks5Stream::connect_with_socket(socket, address.clone())
            .await?
            .into_inner(),
    };
    let (reader, mut socket_writer) = socket.split();
    let mut socket_reader = BufReader::new(reader);
    send_message(
        &mut socket_writer,
        TakerToMakerMessage::TakerHello(TakerHello {
            protocol_version_min: 0,
            protocol_version_max: 0,
        }),
    )
    .await?;
    let makerhello =
        if let MakerToTakerMessage::MakerHello(m) = read_message(&mut socket_reader).await? {
            m
        } else {
            return Err(Error::Protocol("expected method makerhello"));
        };
    log::debug!("{:#?}", makerhello);
    Ok((socket_reader, socket_writer))
}

fn generate_maker_multisig_and_hashlock_keys(
    tweakable_point: &PublicKey,
    count: u32,
) -> (
    Vec<PublicKey>,
    Vec<SecretKey>,
    Vec<PublicKey>,
    Vec<SecretKey>,
) {
    let (multisig_pubkeys, multisig_keys_or_nonces): (Vec<_>, Vec<_>) = (0..count)
        .map(|_| contracts::derive_maker_pubkey_and_nonce(*tweakable_point).unwrap())
        .unzip();
    let (hashlock_pubkeys, hashlock_keys_or_nonces): (Vec<_>, Vec<_>) = (0..count)
        .map(|_| contracts::derive_maker_pubkey_and_nonce(*tweakable_point).unwrap())
        .unzip();
    (
        multisig_pubkeys,
        multisig_keys_or_nonces,
        hashlock_pubkeys,
        hashlock_keys_or_nonces,
    )
}

fn generate_my_multisig_and_hashlock_keys(
    count: u32,
) -> (
    Vec<PublicKey>,
    Vec<SecretKey>,
    Vec<PublicKey>,
    Vec<SecretKey>,
) {
    let (my_receiving_multisig_pubkeys, my_receiving_multisig_privkeys): (Vec<_>, Vec<_>) =
        (0..count).map(|_| generate_keypair()).unzip();
    let (my_receiving_hashlock_pubkeys, my_receiving_hashlock_privkeys): (Vec<_>, Vec<_>) =
        (0..count).map(|_| generate_keypair()).unzip();
    (
        my_receiving_multisig_pubkeys,
        my_receiving_multisig_privkeys,
        my_receiving_hashlock_pubkeys,
        my_receiving_hashlock_privkeys,
    )
}

async fn request_senders_contract_tx_signatures<S: SwapCoin>(
    maker_address: &MakerAddress,
    outgoing_swapcoins: &[S],
    maker_multisig_nonces: &[SecretKey],
    maker_hashlock_nonces: &[SecretKey],
    locktime: u16,
) -> Result<Vec<Signature>, Error> {
    let mut ii = 0;
    loop {
        ii += 1;
        select! {
            ret = request_senders_contract_tx_signatures_attempt_once(
                maker_address,
                outgoing_swapcoins,
                maker_multisig_nonces,
                maker_hashlock_nonces,
                locktime,
            ) => {
                match ret {
                    Ok(sigs) => return Ok(sigs),
                    Err(e) => {
                        log::warn!(
                            "Failed to request senders contract tx sigs from maker {}, \
                            reattempting... error={:?}",
                            maker_address,
                            e
                        );
                        if ii <= FIRST_CONNECT_ATTEMPTS {
                            sleep(Duration::from_secs(FIRST_CONNECT_SLEEP_DELAY_SEC)).await;
                            continue;
                        } else {
                            return Err(e);
                        }
                    }
                }
            },
            _ = sleep(Duration::from_secs(FIRST_CONNECT_ATTEMPT_TIMEOUT_SEC)) => {
                log::warn!(
                    "Timeout for request senders contract tx sig from maker {}, reattempting...",
                    maker_address
                );
                if ii <= FIRST_CONNECT_ATTEMPTS {
                    continue;
                } else {
                    return Err(Error::Protocol(
                        "Timed out of request_senders_contract_tx_signatures attempt"));
                }
            },
        }
    }
}

async fn request_senders_contract_tx_signatures_attempt_once<S: SwapCoin>(
    maker_address: &MakerAddress,
    outgoing_swapcoins: &[S],
    maker_multisig_nonces: &[SecretKey],
    maker_hashlock_nonces: &[SecretKey],
    locktime: u16,
) -> Result<Vec<Signature>, Error> {
    log::info!("Connecting to {}", maker_address);
    let mut socket = TcpStream::connect(maker_address.get_tcpstream_address()).await?;
    let (mut socket_reader, mut socket_writer) =
        handshake_maker(&mut socket, maker_address).await?;
    log::info!("===> Sending SignSendersContractTx to {}", maker_address);
    send_message(
        &mut socket_writer,
        TakerToMakerMessage::SignSendersContractTx(SignSendersContractTx {
            txes_info: izip!(
                maker_multisig_nonces.iter(),
                maker_hashlock_nonces.iter(),
                outgoing_swapcoins.iter()
            )
            .map(
                |(&multisig_key_nonce, &hashlock_key_nonce, outgoing_swapcoin)| {
                    SenderContractTxNoncesInfo {
                        multisig_key_nonce,
                        hashlock_key_nonce,
                        timelock_pubkey: outgoing_swapcoin.get_timelock_pubkey(),
                        senders_contract_tx: outgoing_swapcoin.get_contract_tx(),
                        multisig_redeemscript: outgoing_swapcoin.get_multisig_redeemscript(),
                        funding_input_value: outgoing_swapcoin.get_funding_amount(),
                    }
                },
            )
            .collect::<Vec<SenderContractTxNoncesInfo>>(),
            hashvalue: outgoing_swapcoins[0].get_hashvalue(),
            locktime,
        }),
    )
    .await?;
    let maker_senders_contract_sig = if let MakerToTakerMessage::SendersContractSig(m) =
        read_message(&mut socket_reader).await?
    {
        m
    } else {
        return Err(Error::Protocol("expected method senderscontractsig"));
    };
    if maker_senders_contract_sig.sigs.len() != outgoing_swapcoins.len() {
        return Err(Error::Protocol("wrong number of signatures from maker"));
    }
    if maker_senders_contract_sig
        .sigs
        .iter()
        .zip(outgoing_swapcoins.iter())
        .any(|(sig, outgoing_swapcoin)| !outgoing_swapcoin.verify_contract_tx_sender_sig(&sig))
    {
        return Err(Error::Protocol("invalid signature from maker"));
    }
    log::info!("<=== Received SendersContractSig from {}", maker_address);
    Ok(maker_senders_contract_sig.sigs)
}

async fn request_receivers_contract_tx_signatures<S: SwapCoin>(
    maker_address: &MakerAddress,
    incoming_swapcoins: &[S],
    receivers_contract_txes: &[Transaction],
) -> Result<Vec<Signature>, Error> {
    let mut ii = 0;
    loop {
        ii += 1;
        select! {
            ret = request_receivers_contract_tx_signatures_attempt_once(
                maker_address,
                incoming_swapcoins,
                receivers_contract_txes,
            ) => {
                match ret {
                    Ok(sigs) => return Ok(sigs),
                    Err(e) => {
                        log::warn!(
                            "Failed to request receivers contract tx sigs from maker {}, \
                            reattempting... error={:?}",
                            maker_address,
                            e
                        );
                        if ii <= RECONNECT_ATTEMPTS {
                            sleep(Duration::from_secs(
                                if ii <= SHORT_LONG_SLEEP_DELAY_TRANSITION {
                                    RECONNECT_SHORT_SLEEP_DELAY_SEC
                                } else {
                                    RECONNECT_LONG_SLEEP_DELAY_SEC
                                },
                            ))
                            .await;
                            continue;
                        } else {
                            return Err(e);
                        }
                    }
                }
            },
            _ = sleep(Duration::from_secs(RECONNECT_ATTEMPT_TIMEOUT_SEC)) => {
                log::warn!(
                    "Timeout for request receivers contract tx sig from maker {}, reattempting...",
                    maker_address
                );
                if ii <= RECONNECT_ATTEMPTS {
                    continue;
                } else {
                    return Err(Error::Protocol(
                        "Timed out of request_receivers_contract_tx_signatures attempt"));
                }
            },
        }
    }
}

async fn request_receivers_contract_tx_signatures_attempt_once<S: SwapCoin>(
    maker_address: &MakerAddress,
    incoming_swapcoins: &[S],
    receivers_contract_txes: &[Transaction],
) -> Result<Vec<Signature>, Error> {
    log::info!("Connecting to {}", maker_address);
    let mut socket = TcpStream::connect(maker_address.get_tcpstream_address()).await?;
    let (mut socket_reader, mut socket_writer) =
        handshake_maker(&mut socket, maker_address).await?;
    send_message(
        &mut socket_writer,
        TakerToMakerMessage::SignReceiversContractTx(SignReceiversContractTx {
            txes: incoming_swapcoins
                .iter()
                .zip(receivers_contract_txes.iter())
                .map(
                    |(swapcoin, receivers_contract_tx)| ReceiversContractTxInfo {
                        multisig_redeemscript: swapcoin.get_multisig_redeemscript(),
                        contract_tx: receivers_contract_tx.clone(),
                    },
                )
                .collect::<Vec<ReceiversContractTxInfo>>(),
        }),
    )
    .await?;
    let maker_receiver_contract_sig = if let MakerToTakerMessage::ReceiversContractSig(m) =
        read_message(&mut socket_reader).await?
    {
        m
    } else {
        return Err(Error::Protocol("expected method receiverscontractsig"));
    };
    if maker_receiver_contract_sig.sigs.len() != incoming_swapcoins.len() {
        return Err(Error::Protocol("wrong number of signatures from maker"));
    }
    if maker_receiver_contract_sig
        .sigs
        .iter()
        .zip(incoming_swapcoins.iter())
        .any(|(sig, swapcoin)| !swapcoin.verify_contract_tx_receiver_sig(&sig))
    {
        return Err(Error::Protocol("invalid signature from maker"));
    }

    log::info!("<=== Received ReceiversContractSig from {}", maker_address);
    Ok(maker_receiver_contract_sig.sigs)
}

//return a list of the transactions and merkleproofs if the funding txes confirmed
//return None if any of the contract transactions were seen on the network
// if it turns out i want to return data in the contract tx broadcast case, then maybe use an enum
async fn wait_for_funding_tx_confirmation(
    rpc: &Client,
    funding_txids: &[Txid],
    required_confirmations: i32,
    contract_to_watch: &[Vec<Transaction>],
    last_checked_block_height: &mut Option<u64>,
) -> Result<Option<(Vec<Transaction>, Vec<String>)>, Error> {
    let mut txid_tx_map = HashMap::<Txid, Transaction>::new();
    let mut txid_blockhash_map = HashMap::<Txid, BlockHash>::new();
    log::info!(
        "Waiting for funding transaction confirmations ({} conf required)",
        required_confirmations
    );
    let mut txids_seen_once = HashSet::<Txid>::new();
    loop {
        for txid in funding_txids {
            if txid_tx_map.contains_key(txid) {
                continue;
            }
            let gettx = match rpc.get_transaction(txid, Some(true)) {
                Ok(r) => r,
                //if we lose connection to the node, just try again, no point returning an error
                Err(_e) => continue,
            };
            if !txids_seen_once.contains(txid) {
                txids_seen_once.insert(*txid);
                if gettx.info.confirmations == 0 {
                    let mempool_tx = match rpc.get_mempool_entry(txid) {
                        Ok(m) => m,
                        Err(_e) => continue,
                    };
                    log::info!(
                        "Seen in mempool: {} [{:.1} sat/vbyte]",
                        txid,
                        mempool_tx.fees.base.as_sat() as f32 / mempool_tx.vsize as f32
                    );
                }
            }
            //TODO handle confirm<0
            if gettx.info.confirmations >= required_confirmations {
                txid_tx_map.insert(*txid, deserialize::<Transaction>(&gettx.hex).unwrap());
                txid_blockhash_map.insert(*txid, gettx.info.blockhash.unwrap());
                log::debug!(
                    "funding tx {} reached {} confirmation(s)",
                    txid,
                    required_confirmations
                );
            }
        }
        if txid_tx_map.len() == funding_txids.len() {
            log::info!("Funding Transactions confirmed");
            let txes = funding_txids
                .iter()
                .map(|txid| txid_tx_map.get(txid).unwrap().clone())
                .collect::<Vec<Transaction>>();
            let merkleproofs = funding_txids
                .iter()
                .map(|&txid| {
                    rpc.get_tx_out_proof(&[txid], Some(&txid_blockhash_map.get(&txid).unwrap()))
                        .map(|gettxoutproof_result| gettxoutproof_result.to_hex())
                })
                .collect::<Result<Vec<String>, bitcoincore_rpc::Error>>()?;
            return Ok(Some((txes, merkleproofs)));
        }
        if !contract_to_watch.is_empty() {
            let contracts_broadcasted = check_for_broadcasted_contract_txes(
                rpc,
                &contract_to_watch
                    .iter()
                    .map(|txes| ContractsInfo {
                        contract_txes: txes
                            .iter()
                            .map(|tx| ContractTransaction {
                                tx: tx.clone(),
                                redeemscript: Script::new(),
                                hashlock_spend_without_preimage: None,
                                timelock_spend: None,
                                timelock_spend_broadcasted: false,
                            })
                            .collect::<Vec<ContractTransaction>>(),
                        wallet_label: String::new(),
                    })
                    .collect::<Vec<ContractsInfo>>(),
                last_checked_block_height,
            )?;
            if !contracts_broadcasted.is_empty() {
                log::info!("Contract transactions were broadcasted! Aborting");
                return Ok(None);
            }
        }
        sleep(Duration::from_millis(1000)).await;
    }
}

fn get_swapcoin_multisig_contract_redeemscripts_txes<S: SwapCoin>(
    swapcoins: &[S],
) -> (Vec<Script>, Vec<Script>, Vec<Transaction>) {
    //TODO is there a more concise way to write this? with some kind of 3-parameter unzip()
    (
        swapcoins
            .iter()
            .map(|s| s.get_multisig_redeemscript())
            .collect::<Vec<Script>>(),
        swapcoins
            .iter()
            .map(|s| s.get_contract_redeemscript())
            .collect::<Vec<Script>>(),
        swapcoins
            .iter()
            .map(|s| s.get_contract_tx())
            .collect::<Vec<Transaction>>(),
    )
}

async fn exchange_signatures_and_find_next_maker<'a>(
    rpc: &Client,
    config: &TakerConfig,
    maker_offers_addresses: &mut Vec<&'a OfferAndAddress>,
    this_maker: &'a OfferAndAddress,
    previous_maker: Option<&'a OfferAndAddress>,
    is_taker_previous_peer: bool,
    is_taker_next_peer: bool,
    funding_txes: &[Transaction],
    funding_tx_merkleproofs: &[String],
    this_maker_multisig_redeemscripts: &[Script],
    this_maker_multisig_privkeys: &[SecretKey],
    this_maker_contract_redeemscripts: &[Script],
    this_maker_hashlock_privkeys: &[SecretKey],
    this_maker_contract_txes: &[Transaction],
    maker_refund_locktime: u16,
    hashvalue: Hash160,
    outgoing_swapcoins: &Vec<OutgoingSwapCoin>,
    watchonly_swapcoins: &mut Vec<Vec<WatchOnlySwapCoin>>,
) -> Result<
    (
        Vec<PublicKey>,
        Vec<SecretKey>,
        Vec<SecretKey>,
        SignSendersAndReceiversContractTxes,
        Vec<Script>,
        &'a OfferAndAddress,
    ),
    Error,
> {
    let mut ii = 0;
    loop {
        ii += 1;
        select! {
            ret = exchange_signatures_and_find_next_maker_attempt_once(
                rpc,
                config,
                maker_offers_addresses,
                this_maker,
                previous_maker,
                is_taker_previous_peer,
                is_taker_next_peer,
                funding_txes,
                funding_tx_merkleproofs,
                this_maker_multisig_redeemscripts,
                this_maker_multisig_privkeys,
                this_maker_contract_redeemscripts,
                this_maker_hashlock_privkeys,
                this_maker_contract_txes,
                maker_refund_locktime,
                hashvalue,
                outgoing_swapcoins,
                watchonly_swapcoins,
            ) => {
                match ret {
                    Ok(return_value) => return Ok(return_value),
                    Err(e) => {
                        log::warn!(
                            "Failed to exchange signatures with maker {}, \
                            reattempting... error={:?}",
                            this_maker.address,
                            e
                        );
                        if ii <= RECONNECT_ATTEMPTS {
                            sleep(Duration::from_secs(
                                if ii <= SHORT_LONG_SLEEP_DELAY_TRANSITION {
                                    RECONNECT_SHORT_SLEEP_DELAY_SEC
                                } else {
                                    RECONNECT_LONG_SLEEP_DELAY_SEC
                                },
                            ))
                            .await;
                            continue;
                        } else {
                            return Err(e);
                        }
                    }
                }
            },
            _ = sleep(Duration::from_secs(RECONNECT_ATTEMPT_TIMEOUT_SEC)) => {
                log::warn!(
                    "Timeout for exchange signatures with maker {}, reattempting...",
                    this_maker.address
                );
                if ii <= RECONNECT_ATTEMPTS {
                    continue;
                } else {
                    return Err(Error::Protocol(
                        "Timed out of exchange_signatures_and_find_next_maker attempt"));
                }
            },
        }
    }
}

async fn exchange_signatures_and_find_next_maker_attempt_once<'a>(
    rpc: &Client,
    config: &TakerConfig,
    maker_offers_addresses: &mut Vec<&'a OfferAndAddress>,
    this_maker: &'a OfferAndAddress,
    previous_maker: Option<&'a OfferAndAddress>,
    is_taker_previous_peer: bool,
    is_taker_next_peer: bool,
    funding_txes: &[Transaction],
    funding_tx_merkleproofs: &[String],
    this_maker_multisig_redeemscripts: &[Script],
    this_maker_multisig_privkeys: &[SecretKey],
    this_maker_contract_redeemscripts: &[Script],
    this_maker_hashlock_privkeys: &[SecretKey],
    this_maker_contract_txes: &[Transaction],
    maker_refund_locktime: u16,
    hashvalue: Hash160,
    outgoing_swapcoins: &Vec<OutgoingSwapCoin>,
    watchonly_swapcoins: &mut Vec<Vec<WatchOnlySwapCoin>>,
) -> Result<
    (
        Vec<PublicKey>,
        Vec<SecretKey>,
        Vec<SecretKey>,
        SignSendersAndReceiversContractTxes,
        Vec<Script>,
        &'a OfferAndAddress,
    ),
    Error,
> {
    //return next_peer_multisig_pubkeys, next_peer_multisig_keys_or_nonces,
    //    next_peer_hashlock_keys_or_nonces, (), next_swap_contract_redeemscripts, found_next_maker

    log::info!("Connecting to {}", this_maker.address);
    let mut socket = TcpStream::connect(this_maker.address.get_tcpstream_address()).await?;
    let (mut socket_reader, mut socket_writer) =
        handshake_maker(&mut socket, &this_maker.address).await?;
    let mut next_maker = this_maker;
    let (
        next_peer_multisig_pubkeys,
        next_peer_multisig_keys_or_nonces,
        next_peer_hashlock_keys_or_nonces,
        maker_sign_sender_and_receiver_contracts,
        next_swap_contract_redeemscripts,
        senders_sigs,
    ) = loop {
        //loop to help error handling, allowing us to keep trying new makers until
        //we find one for which our request is successful, or until we run out of makers
        let (
            next_peer_multisig_pubkeys,
            next_peer_multisig_keys_or_nonces,
            next_peer_hashlock_pubkeys,
            next_peer_hashlock_keys_or_nonces,
        ) = if is_taker_next_peer {
            generate_my_multisig_and_hashlock_keys(config.tx_count)
        } else {
            next_maker = choose_next_maker(maker_offers_addresses, config.send_amount)
                .expect("not enough offers");
            //next_maker is only ever accessed when the next peer is a maker, not a taker
            //i.e. if its ever used when is_taker_next_peer == true, then thats a bug
            generate_maker_multisig_and_hashlock_keys(
                &next_maker.offer.tweakable_point,
                config.tx_count,
            )
        };
        log::info!("===> Sending ProofOfFunding to {}", this_maker.address);
        let (maker_sign_sender_and_receiver_contracts, next_swap_contract_redeemscripts) =
            send_proof_of_funding_and_check_reply(
                &mut socket_reader,
                &mut socket_writer,
                this_maker,
                funding_txes,
                funding_tx_merkleproofs,
                this_maker_multisig_redeemscripts,
                this_maker_multisig_privkeys,
                this_maker_contract_redeemscripts,
                this_maker_hashlock_privkeys,
                &next_peer_multisig_pubkeys,
                &next_peer_hashlock_pubkeys,
                maker_refund_locktime,
                config.fee_rate,
                this_maker_contract_txes,
                hashvalue,
            )
            .await?;
        log::info!(
            "<=== Recieved SignSendersAndReceiversContractTxes from {}",
            this_maker.address
        );

        let senders_sigs = if is_taker_next_peer {
            log::info!("Taker is next peer. Signing Sender's Contract Txs",);
            sign_senders_contract_txes(
                &next_peer_multisig_keys_or_nonces,
                &maker_sign_sender_and_receiver_contracts,
            )?
        } else {
            let next_swapcoins = create_watch_only_swapcoins(
                rpc,
                &maker_sign_sender_and_receiver_contracts,
                &next_peer_multisig_pubkeys,
                &next_swap_contract_redeemscripts,
            )?;
            let sigs = match request_senders_contract_tx_signatures(
                &next_maker.address,
                &next_swapcoins,
                &next_peer_multisig_keys_or_nonces,
                &next_peer_hashlock_keys_or_nonces,
                maker_refund_locktime,
            )
            .await
            {
                Ok(r) => r,
                Err(e) => {
                    log::debug!(
                        "Fail to obtain senders contract tx signature from next_maker {}: {:?}",
                        next_maker.address,
                        e
                    );
                    continue; //go back to the start of the loop and try another maker
                }
            };
            watchonly_swapcoins.push(next_swapcoins);
            sigs
        };
        break (
            next_peer_multisig_pubkeys,
            next_peer_multisig_keys_or_nonces,
            next_peer_hashlock_keys_or_nonces,
            maker_sign_sender_and_receiver_contracts,
            next_swap_contract_redeemscripts,
            senders_sigs,
        );
    };

    let receivers_sigs = if is_taker_previous_peer {
        log::info!("Taker is previous peer. Signing Receivers Contract Txs",);
        sign_receivers_contract_txes(
            &maker_sign_sender_and_receiver_contracts.receivers_contract_txes,
            outgoing_swapcoins,
        )?
    } else {
        assert!(previous_maker.is_some());
        let previous_maker_addr = &previous_maker.unwrap().address;
        log::info!(
            "===> Sending SignReceiversContractTx, previous maker is {}",
            previous_maker_addr,
        );
        let previous_maker_watchonly_swapcoins = if is_taker_next_peer {
            watchonly_swapcoins.last().unwrap()
        } else {
            //if the next peer is a maker not a taker, then that maker's swapcoins are last
            &watchonly_swapcoins[watchonly_swapcoins.len() - 2]
        };
        request_receivers_contract_tx_signatures(
            &previous_maker_addr,
            previous_maker_watchonly_swapcoins,
            &maker_sign_sender_and_receiver_contracts.receivers_contract_txes,
        )
        .await?
    };
    log::info!(
        "===> Sending SendersAndReceiversContractSigs to {}",
        this_maker.address
    );
    send_message(
        &mut socket_writer,
        TakerToMakerMessage::SendersAndReceiversContractSigs(SendersAndReceiversContractSigs {
            receivers_sigs,
            senders_sigs,
        }),
    )
    .await?;
    Ok((
        next_peer_multisig_pubkeys,
        next_peer_multisig_keys_or_nonces,
        next_peer_hashlock_keys_or_nonces,
        maker_sign_sender_and_receiver_contracts,
        next_swap_contract_redeemscripts,
        next_maker,
    ))
}

async fn send_proof_of_funding_and_check_reply(
    socket_reader: &mut BufReader<ReadHalf<'_>>,
    socket_writer: &mut WriteHalf<'_>,
    this_maker: &OfferAndAddress,
    funding_txes: &[Transaction],
    funding_tx_merkleproofs: &[String],
    this_maker_multisig_redeemscripts: &[Script],
    this_maker_multisig_nonces: &[SecretKey],
    this_maker_contract_redeemscripts: &[Script],
    this_maker_hashlock_nonces: &[SecretKey],
    next_peer_multisig_pubkeys: &[PublicKey],
    next_peer_hashlock_pubkeys: &[PublicKey],
    next_maker_refund_locktime: u16,
    next_maker_fee_rate: u64,
    this_maker_contract_txes: &[Transaction],
    hashvalue: Hash160,
) -> Result<(SignSendersAndReceiversContractTxes, Vec<Script>), Error> {
    send_message(
        socket_writer,
        TakerToMakerMessage::ProofOfFunding(ProofOfFunding {
            confirmed_funding_txes: izip!(
                funding_txes.iter(),
                funding_tx_merkleproofs.iter(),
                this_maker_multisig_redeemscripts.iter(),
                this_maker_multisig_nonces,
                this_maker_contract_redeemscripts.iter(),
                this_maker_hashlock_nonces
            )
            .map(
                |(
                    funding_tx,
                    funding_tx_merkleproof,
                    multisig_redeemscript,
                    &multisig_key_nonce,
                    contract_redeemscript,
                    &hashlock_key_nonce,
                )| ConfirmedCoinSwapTxInfo {
                    funding_tx: funding_tx.clone(),
                    funding_tx_merkleproof: funding_tx_merkleproof.clone(),
                    multisig_redeemscript: multisig_redeemscript.clone(),
                    multisig_key_nonce,
                    contract_redeemscript: contract_redeemscript.clone(),
                    hashlock_key_nonce,
                },
            )
            .collect::<Vec<ConfirmedCoinSwapTxInfo>>(),
            next_coinswap_info: next_peer_multisig_pubkeys
                .iter()
                .zip(next_peer_hashlock_pubkeys.iter())
                .map(
                    |(&next_coinswap_multisig_pubkey, &next_hashlock_pubkey)| NextCoinSwapTxInfo {
                        next_coinswap_multisig_pubkey,
                        next_hashlock_pubkey,
                    },
                )
                .collect::<Vec<NextCoinSwapTxInfo>>(),
            next_locktime: next_maker_refund_locktime,
            next_fee_rate: next_maker_fee_rate,
        }),
    )
    .await?;
    let maker_sign_sender_and_receiver_contracts =
        if let MakerToTakerMessage::SignSendersAndReceiversContractTxes(m) =
            read_message(socket_reader).await?
        {
            m
        } else {
            return Err(Error::Protocol(
                "expected method signsendersandreceiverscontracttxes",
            ));
        };
    if maker_sign_sender_and_receiver_contracts
        .receivers_contract_txes
        .len()
        != this_maker_multisig_redeemscripts.len()
    {
        return Err(Error::Protocol(
            "wrong number of receivers contracts tx from maker",
        ));
    }
    if maker_sign_sender_and_receiver_contracts
        .senders_contract_txes_info
        .len()
        != next_peer_multisig_pubkeys.len()
    {
        return Err(Error::Protocol(
            "wrong number of senders contract txes from maker",
        ));
    }

    let funding_tx_values = funding_txes
        .iter()
        .zip(this_maker_multisig_redeemscripts.iter())
        .map(|(makers_funding_tx, multisig_redeemscript)| {
            find_funding_output(&makers_funding_tx, &multisig_redeemscript)
                .ok_or(Error::Protocol(
                    "multisig redeemscript not found in funding tx",
                ))
                .map(|txout| txout.1.value)
        })
        .collect::<Result<Vec<u64>, Error>>()?;
    let this_amount = funding_tx_values.iter().sum::<u64>();

    let next_amount = maker_sign_sender_and_receiver_contracts
        .senders_contract_txes_info
        .iter()
        .map(|i| i.funding_amount)
        .sum::<u64>();
    let coinswap_fees = calculate_coinswap_fee(
        this_maker.offer.absolute_fee_sat,
        this_maker.offer.amount_relative_fee_ppb,
        this_maker.offer.time_relative_fee_ppb,
        this_amount,
        1, //time_in_blocks just 1 for now
    );
    let miner_fees_paid_by_taker = MAKER_FUNDING_TX_VBYTE_SIZE
        * next_maker_fee_rate
        * (next_peer_multisig_pubkeys.len() as u64)
        / 1000;
    let calculated_next_amount = this_amount - coinswap_fees - miner_fees_paid_by_taker;
    if calculated_next_amount != next_amount {
        return Err(Error::Protocol("next_amount incorrect"));
    }
    log::info!(
        "this_amount={} coinswap_fees={} miner_fees_paid_by_taker={} next_amount={}",
        this_amount,
        coinswap_fees,
        miner_fees_paid_by_taker,
        next_amount
    );

    for (receivers_contract_tx, contract_tx, contract_redeemscript) in izip!(
        maker_sign_sender_and_receiver_contracts
            .receivers_contract_txes
            .iter(),
        this_maker_contract_txes.iter(),
        this_maker_contract_redeemscripts.iter()
    ) {
        validate_contract_tx(
            &receivers_contract_tx,
            Some(&contract_tx.input[0].previous_output),
            &contract_redeemscript,
        )?;
    }
    let next_swap_contract_redeemscripts = next_peer_hashlock_pubkeys
        .iter()
        .zip(
            maker_sign_sender_and_receiver_contracts
                .senders_contract_txes_info
                .iter(),
        )
        .map(|(hashlock_pubkey, senders_contract_tx_info)| {
            create_contract_redeemscript(
                hashlock_pubkey,
                &senders_contract_tx_info.timelock_pubkey,
                hashvalue,
                next_maker_refund_locktime,
            )
        })
        .collect::<Vec<Script>>();
    Ok((
        maker_sign_sender_and_receiver_contracts,
        next_swap_contract_redeemscripts,
    ))
}

fn sign_receivers_contract_txes(
    receivers_contract_txes: &[Transaction],
    outgoing_swapcoins: &[OutgoingSwapCoin],
) -> Result<Vec<Signature>, Error> {
    receivers_contract_txes
        .iter()
        .zip(outgoing_swapcoins.iter())
        .map(|(receivers_contract_tx, outgoing_swapcoin)| {
            outgoing_swapcoin.sign_contract_tx_with_my_privkey(receivers_contract_tx)
        })
        .collect::<Result<Vec<Signature>, Error>>()
}

fn sign_senders_contract_txes(
    my_receiving_multisig_privkeys: &[SecretKey],
    maker_sign_sender_and_receiver_contracts: &SignSendersAndReceiversContractTxes,
) -> Result<Vec<Signature>, Error> {
    my_receiving_multisig_privkeys
        .iter()
        .zip(
            maker_sign_sender_and_receiver_contracts
                .senders_contract_txes_info
                .iter(),
        )
        .map(
            |(my_receiving_multisig_privkey, senders_contract_tx_info)| {
                sign_contract_tx(
                    &senders_contract_tx_info.contract_tx,
                    &senders_contract_tx_info.multisig_redeemscript,
                    senders_contract_tx_info.funding_amount,
                    my_receiving_multisig_privkey,
                )
            },
        )
        .collect::<Result<Vec<Signature>, bitcoin::secp256k1::Error>>()
        .map_err(|_| Error::Protocol("error with signing contract tx"))
}

fn create_watch_only_swapcoins(
    rpc: &Client,
    maker_sign_sender_and_receiver_contracts: &SignSendersAndReceiversContractTxes,
    next_peer_multisig_pubkeys: &[PublicKey],
    next_swap_contract_redeemscripts: &[Script],
) -> Result<Vec<WatchOnlySwapCoin>, Error> {
    let next_swapcoins = izip!(
        maker_sign_sender_and_receiver_contracts
            .senders_contract_txes_info
            .iter(),
        next_peer_multisig_pubkeys.iter(),
        next_swap_contract_redeemscripts.iter()
    )
    .map(
        |(senders_contract_tx_info, &maker_multisig_pubkey, contract_redeemscript)| {
            WatchOnlySwapCoin::new(
                &senders_contract_tx_info.multisig_redeemscript,
                maker_multisig_pubkey,
                senders_contract_tx_info.contract_tx.clone(),
                contract_redeemscript.clone(),
                senders_contract_tx_info.funding_amount,
            )
        },
    )
    .collect::<Result<Vec<WatchOnlySwapCoin>, Error>>()?;
    //TODO error handle here the case where next_swapcoin.contract_tx script pubkey
    // is not equal to p2wsh(next_swap_contract_redeemscripts)
    for swapcoin in &next_swapcoins {
        import_watchonly_redeemscript(rpc, &swapcoin.get_multisig_redeemscript())?
    }
    Ok(next_swapcoins)
}

fn create_incoming_swapcoins(
    rpc: &Client,
    wallet: &Wallet,
    maker_sign_sender_and_receiver_contracts: &SignSendersAndReceiversContractTxes,
    funding_txes: &[Transaction],
    funding_tx_merkleproofs: &[String],
    next_swap_contract_redeemscripts: &[Script],
    next_peer_hashlock_keys_or_nonces: &[SecretKey],
    next_peer_multisig_pubkeys: &[PublicKey],
    next_peer_multisig_keys_or_nonces: &[SecretKey],
    preimage: Preimage,
) -> Result<Vec<IncomingSwapCoin>, Error> {
    let next_swap_multisig_redeemscripts = maker_sign_sender_and_receiver_contracts
        .senders_contract_txes_info
        .iter()
        .map(|senders_contract_tx_info| senders_contract_tx_info.multisig_redeemscript.clone())
        .collect::<Vec<Script>>();
    let next_swap_funding_outpoints = maker_sign_sender_and_receiver_contracts
        .senders_contract_txes_info
        .iter()
        .map(|senders_contract_tx_info| {
            senders_contract_tx_info.contract_tx.input[0].previous_output
        })
        .collect::<Vec<OutPoint>>();

    let last_makers_funding_tx_values = funding_txes
        .iter()
        .zip(next_swap_multisig_redeemscripts.iter())
        .map(|(makers_funding_tx, multisig_redeemscript)| {
            find_funding_output(&makers_funding_tx, &multisig_redeemscript)
                .ok_or(Error::Protocol(
                    "multisig redeemscript not found in funding tx",
                ))
                .map(|txout| txout.1.value)
        })
        .collect::<Result<Vec<u64>, Error>>()?;
    let my_receivers_contract_txes = izip!(
        next_swap_funding_outpoints.iter(),
        last_makers_funding_tx_values.iter(),
        next_swap_contract_redeemscripts.iter()
    )
    .map(
        |(&previous_funding_output, &maker_funding_tx_value, next_contract_redeemscript)| {
            create_receivers_contract_tx(
                previous_funding_output,
                maker_funding_tx_value,
                next_contract_redeemscript,
            )
        },
    )
    .collect::<Vec<Transaction>>();

    let mut incoming_swapcoins = Vec::<IncomingSwapCoin>::new();
    for (
        multisig_redeemscript,
        &maker_funded_multisig_pubkey,
        &maker_funded_multisig_privkey,
        my_receivers_contract_tx,
        next_contract_redeemscript,
        &hashlock_privkey,
        &maker_funding_tx_value,
        funding_tx,
        funding_tx_merkleproof,
    ) in izip!(
        next_swap_multisig_redeemscripts.iter(),
        next_peer_multisig_pubkeys.iter(),
        next_peer_multisig_keys_or_nonces.iter(),
        my_receivers_contract_txes.iter(),
        next_swap_contract_redeemscripts.iter(),
        next_peer_hashlock_keys_or_nonces.iter(),
        last_makers_funding_tx_values.iter(),
        funding_txes.iter(),
        funding_tx_merkleproofs.iter(),
    ) {
        let (o_ms_pubkey1, o_ms_pubkey2) =
            read_pubkeys_from_multisig_redeemscript(multisig_redeemscript)
                .ok_or(Error::Protocol("invalid pubkeys in multisig redeemscript"))?;
        let maker_funded_other_multisig_pubkey = if o_ms_pubkey1 == maker_funded_multisig_pubkey {
            o_ms_pubkey2
        } else {
            if o_ms_pubkey2 != maker_funded_multisig_pubkey {
                return Err(Error::Protocol("maker-funded multisig doesnt match"));
            }
            o_ms_pubkey1
        };

        wallet.import_wallet_multisig_redeemscript(&rpc, &o_ms_pubkey1, &o_ms_pubkey2)?;
        wallet.import_tx_with_merkleproof(&rpc, funding_tx, funding_tx_merkleproof.clone())?;
        wallet.import_wallet_contract_redeemscript(rpc, &next_contract_redeemscript)?;

        let mut incoming_swapcoin = IncomingSwapCoin::new(
            maker_funded_multisig_privkey,
            maker_funded_other_multisig_pubkey,
            my_receivers_contract_tx.clone(),
            next_contract_redeemscript.clone(),
            hashlock_privkey,
            maker_funding_tx_value,
        );
        incoming_swapcoin.hash_preimage = Some(preimage);
        incoming_swapcoins.push(incoming_swapcoin);
    }

    Ok(incoming_swapcoins)
}

fn get_multisig_redeemscripts_from_swapcoins<S: SwapCoin>(swapcoins: &[S]) -> Vec<Script> {
    swapcoins
        .iter()
        .map(|swapcoin| swapcoin.get_multisig_redeemscript())
        .collect::<Vec<Script>>()
}

fn check_and_apply_maker_private_keys<S: SwapCoin>(
    swapcoins: &mut Vec<S>,
    swapcoin_private_keys: &[SwapCoinPrivateKey],
) -> Result<(), Error> {
    for (swapcoin, swapcoin_private_key) in swapcoins.iter_mut().zip(swapcoin_private_keys.iter()) {
        swapcoin
            .apply_privkey(swapcoin_private_key.key)
            .map_err(|_| Error::Protocol("wrong privkey"))?;
    }
    Ok(())
}

async fn settle_all_coinswaps_send_hash_preimage_and_privkeys(
    config: &TakerConfig,
    preimage: Preimage,
    active_maker_addresses: &Vec<&MakerAddress>,
    outgoing_swapcoins: &Vec<OutgoingSwapCoin>,
    watchonly_swapcoins: &mut Vec<Vec<WatchOnlySwapCoin>>,
    incoming_swapcoins: &mut Vec<IncomingSwapCoin>,
) -> Result<(), Error> {
    let mut outgoing_privkeys: Option<Vec<SwapCoinPrivateKey>> = None;
    for (index, maker_address) in active_maker_addresses.iter().enumerate() {
        let is_taker_previous_peer = index == 0;
        let is_taker_next_peer = (index as u16) == config.maker_count - 1;

        let senders_multisig_redeemscripts = if is_taker_previous_peer {
            get_multisig_redeemscripts_from_swapcoins(&outgoing_swapcoins)
        } else {
            get_multisig_redeemscripts_from_swapcoins(&watchonly_swapcoins[index - 1])
        };
        let receivers_multisig_redeemscripts = if is_taker_next_peer {
            get_multisig_redeemscripts_from_swapcoins(&incoming_swapcoins)
        } else {
            get_multisig_redeemscripts_from_swapcoins(&watchonly_swapcoins[index])
        };

        let mut ii = 0;
        loop {
            ii += 1;
            select! {
                ret = settle_one_coinswap(
                    maker_address,
                    index,
                    is_taker_previous_peer,
                    is_taker_next_peer,
                    &mut outgoing_privkeys,
                    outgoing_swapcoins,
                    watchonly_swapcoins,
                    incoming_swapcoins,
                    &senders_multisig_redeemscripts,
                    &receivers_multisig_redeemscripts,
                    preimage,
                ) => {
                    if let Err(e) = ret {
                        log::warn!(
                            "Failed to connect to maker {} to settle coinswap, \
                            reattempting... error={:?}",
                            maker_address,
                            e
                        );
                        if ii <= RECONNECT_ATTEMPTS {
                            sleep(Duration::from_secs(
                                if ii <= SHORT_LONG_SLEEP_DELAY_TRANSITION {
                                    RECONNECT_SHORT_SLEEP_DELAY_SEC
                                } else {
                                    RECONNECT_LONG_SLEEP_DELAY_SEC
                                },
                            ))
                            .await;
                            continue;
                        } else {
                            return Err(e);
                        }
                    }
                    break;
                },
                _ = sleep(Duration::from_secs(RECONNECT_ATTEMPT_TIMEOUT_SEC)) => {
                    log::warn!(
                        "Timeout for settling coinswap with maker {}, reattempting...",
                        maker_address
                    );
                    if ii <= RECONNECT_ATTEMPTS {
                        continue;
                    } else {
                        return Err(Error::Protocol(
                            "Timed out of settle_one_coinswap attempt"));
                    }
                },
            }
        }
    }
    Ok(())
}

async fn settle_one_coinswap(
    maker_address: &MakerAddress,
    index: usize,
    is_taker_previous_peer: bool,
    is_taker_next_peer: bool,
    outgoing_privkeys: &mut Option<Vec<SwapCoinPrivateKey>>,
    outgoing_swapcoins: &Vec<OutgoingSwapCoin>,
    watchonly_swapcoins: &mut Vec<Vec<WatchOnlySwapCoin>>,
    incoming_swapcoins: &mut Vec<IncomingSwapCoin>,
    senders_multisig_redeemscripts: &Vec<Script>,
    receivers_multisig_redeemscripts: &Vec<Script>,
    preimage: Preimage,
) -> Result<(), Error> {
    log::info!("Connecting to {}", maker_address);
    let mut socket = TcpStream::connect(maker_address.get_tcpstream_address()).await?;
    let (mut socket_reader, mut socket_writer) =
        handshake_maker(&mut socket, maker_address).await?;

    log::info!("===> Sending HashPreimage to {}", maker_address);
    let maker_private_key_handover = send_hash_preimage_and_get_private_keys(
        &mut socket_reader,
        &mut socket_writer,
        senders_multisig_redeemscripts,
        receivers_multisig_redeemscripts,
        preimage,
    )
    .await?;
    log::info!("<=== Received PrivateKeyHandover from {}", maker_address);

    let privkeys_reply = if is_taker_previous_peer {
        outgoing_swapcoins
            .iter()
            .map(|outgoing_swapcoin| SwapCoinPrivateKey {
                multisig_redeemscript: outgoing_swapcoin.get_multisig_redeemscript(),
                key: outgoing_swapcoin.my_privkey,
            })
            .collect::<Vec<SwapCoinPrivateKey>>()
    } else {
        assert!(outgoing_privkeys.is_some());
        let reply = outgoing_privkeys.as_ref().unwrap().to_vec();
        *outgoing_privkeys = None;
        reply
    };
    if is_taker_next_peer {
        check_and_apply_maker_private_keys(
            incoming_swapcoins,
            &maker_private_key_handover.swapcoin_private_keys,
        )
    } else {
        let ret = check_and_apply_maker_private_keys(
            &mut watchonly_swapcoins[index],
            &maker_private_key_handover.swapcoin_private_keys,
        );
        *outgoing_privkeys = Some(maker_private_key_handover.swapcoin_private_keys);
        ret
    }?;
    log::info!("===> Sending PrivateKeyHandover to {}", maker_address);
    send_message(
        &mut socket_writer,
        TakerToMakerMessage::PrivateKeyHandover(PrivateKeyHandover {
            swapcoin_private_keys: privkeys_reply,
        }),
    )
    .await?;
    Ok(())
}

async fn send_hash_preimage_and_get_private_keys(
    socket_reader: &mut BufReader<ReadHalf<'_>>,
    socket_writer: &mut WriteHalf<'_>,
    senders_multisig_redeemscripts: &Vec<Script>,
    receivers_multisig_redeemscripts: &Vec<Script>,
    preimage: Preimage,
) -> Result<PrivateKeyHandover, Error> {
    let receivers_multisig_redeemscripts_len = receivers_multisig_redeemscripts.len();
    send_message(
        socket_writer,
        TakerToMakerMessage::HashPreimage(HashPreimage {
            senders_multisig_redeemscripts: senders_multisig_redeemscripts.to_vec(),
            receivers_multisig_redeemscripts: receivers_multisig_redeemscripts.to_vec(),
            preimage,
        }),
    )
    .await?;
    let maker_private_key_handover =
        if let MakerToTakerMessage::PrivateKeyHandover(m) = read_message(socket_reader).await? {
            m
        } else {
            return Err(Error::Protocol("expected method privatekeyhandover"));
        };
    if maker_private_key_handover.swapcoin_private_keys.len()
        != receivers_multisig_redeemscripts_len
    {
        return Err(Error::Protocol("wrong number of private keys from maker"));
    }
    Ok(maker_private_key_handover)
}
