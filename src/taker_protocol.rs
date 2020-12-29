use std::collections::HashMap;
use std::error::Error;
use std::io::{Error as IOError, ErrorKind};
use std::time::Duration;

use tokio::io::BufReader;
use tokio::net::tcp::{ReadHalf, WriteHalf};
use tokio::net::TcpStream;
use tokio::prelude::*;
use tokio::time::sleep;

use bitcoin::consensus::encode::deserialize;
use bitcoin::hashes::hash160::Hash as Hash160;
use bitcoin::hashes::{hex::ToHex, Hash};
use bitcoin::secp256k1::Signature;
use bitcoin::{BlockHash, Script, Transaction, Txid};
use bitcoincore_rpc::{Client, RpcApi};

use rand::rngs::OsRng;
use rand::RngCore;

use itertools::izip;

use crate::contracts;
use crate::contracts::{
    create_contract_redeemscript, create_receivers_contract_tx, find_funding_output,
    read_pubkeys_from_multisig_redeemscript, sign_contract_tx, validate_contract_tx,
    WatchOnlySwapCoin, REFUND_LOCKTIME, REFUND_LOCKTIME_STEP,
};
use crate::messages::{
    ConfirmedCoinSwapTxInfo, HashPreimage, MakerToTakerMessage, NextCoinSwapTxInfo,
    PrivateKeyHandover, ProofOfFunding, ReceiversContractTxInfo, SenderContractTxNoncesInfo,
    SendersAndReceiversContractSigs, SignReceiversContractTx, SignSendersContractTx,
    SwapCoinPrivateKey, TakerHello, TakerToMakerMessage,
};
use crate::offerbook_sync::{sync_offerbook, OfferAddress};
use crate::wallet_sync::{generate_keypair, CoreAddressLabelType, SwapCoin, Wallet};

#[tokio::main]
pub async fn start_taker(rpc: &Client, wallet: &mut Wallet) {
    match run(rpc, wallet).await {
        Ok(_o) => (),
        Err(e) => println!("err {:?}", e),
    };
}

async fn run(rpc: &Client, wallet: &mut Wallet) -> Result<(), Box<dyn Error>> {
    let offers_addresses = sync_offerbook().await;
    println!("offers_addresses = {:?}", offers_addresses);

    send_coinswap(rpc, wallet, &offers_addresses).await?;
    Ok(())
}

async fn send_message(
    socket_writer: &mut WriteHalf<'_>,
    message: TakerToMakerMessage,
) -> Result<(), Box<dyn Error>> {
    println!("=> {:?}", message);
    let mut result_bytes = serde_json::to_vec(&message).unwrap();
    result_bytes.push(b'\n');
    //TODO error handling here
    socket_writer.write_all(&result_bytes).await.unwrap();
    Ok(())
}

async fn read_message(
    reader: &mut BufReader<ReadHalf<'_>>,
) -> Result<MakerToTakerMessage, Box<dyn Error>> {
    let mut line = String::new();
    let n = reader.read_line(&mut line).await?;
    if n == 0 {
        return Err(Box::new(IOError::new(ErrorKind::ConnectionReset, "EOF")));
    }
    println!("<== {}", line.trim_end().to_string());

    let message: MakerToTakerMessage = match serde_json::from_str(&line) {
        Ok(r) => r,
        Err(e) => return Err(Box::new(IOError::new(ErrorKind::InvalidData, e))),
    };

    //println!("<= {:?}", message);
    Ok(message)
}

async fn handshake_maker(
    socket: &mut TcpStream,
) -> Result<(BufReader<ReadHalf<'_>>, WriteHalf<'_>), Box<dyn Error>> {
    println!("connected to maker");

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
            return Err(Box::new(IOError::new(ErrorKind::InvalidData, "")));
        };
    println!(
        "protocol version min/max = {}/{}",
        makerhello.protocol_version_min, makerhello.protocol_version_max
    );
    Ok((socket_reader, socket_writer))
}

async fn send_coinswap(
    rpc: &Client,
    wallet: &mut Wallet,
    maker_offers_addresses: &[OfferAddress],
) -> Result<(), Box<dyn Error>> {
    let amount = 5000000;
    let my_tx_count: u32 = 3;
    let maker_tx_count: u32 = 3;

    let mut preimage = [0u8; 32];
    OsRng.fill_bytes(&mut preimage);
    let hashvalue = Hash160::hash(&preimage).into_inner();

    let swap1_locktime = REFUND_LOCKTIME + REFUND_LOCKTIME_STEP * 2;
    let swap2_locktime = REFUND_LOCKTIME + REFUND_LOCKTIME_STEP;
    let swap3_locktime = REFUND_LOCKTIME;

    let (maker1_multisig_pubkeys, maker1_multisig_key_nonces): (Vec<_>, Vec<_>) = (0..my_tx_count)
        .map(|_| {
            contracts::derive_maker_pubkey_and_nonce(
                maker_offers_addresses[0].offer.tweakable_point,
            )
        })
        .unzip();
    let (maker1_hashlock_pubkeys, maker1_hashlock_key_nonces): (Vec<_>, Vec<_>) = (0..my_tx_count)
        .map(|_| {
            contracts::derive_maker_pubkey_and_nonce(
                maker_offers_addresses[0].offer.tweakable_point,
            )
        })
        .unzip();

    let (my_funding_txes, mut outgoing_swapcoins, my_timelock_pubkeys, _my_timelock_privkeys) =
        wallet.initalize_coinswap(
            rpc,
            amount,
            &maker1_multisig_pubkeys,
            &maker1_hashlock_pubkeys,
            hashvalue,
            swap1_locktime,
        );

    println!(
        "connecting to maker1 = {}",
        maker_offers_addresses[0].address
    );
    let mut socket1 = TcpStream::connect(maker_offers_addresses[0].address.clone()).await?;
    let (mut socket1_reader, mut socket1_writer) = handshake_maker(&mut socket1).await?;
    send_message(
        &mut socket1_writer,
        TakerToMakerMessage::SignSendersContractTx(SignSendersContractTx {
            txes_info: izip!(
                maker1_multisig_key_nonces.iter(),
                maker1_hashlock_key_nonces.iter(),
                my_timelock_pubkeys.iter(),
                outgoing_swapcoins.iter()
            )
            .map(
                |(
                    &multisig_key_nonce,
                    &hashlock_key_nonce,
                    &timelock_pubkey,
                    outgoing_swapcoin,
                )| SenderContractTxNoncesInfo {
                    multisig_key_nonce,
                    hashlock_key_nonce,
                    timelock_pubkey,
                    senders_contract_tx: outgoing_swapcoin.contract_tx.clone(),
                    multisig_redeemscript: outgoing_swapcoin.get_multisig_redeemscript(),
                    funding_input_value: outgoing_swapcoin.funding_amount,
                },
            )
            .collect::<Vec<SenderContractTxNoncesInfo>>(),
            hashvalue,
            locktime: swap1_locktime,
        }),
    )
    .await?;
    //TODO this pattern of let = if let else err could probably be replaced by
    //one of the methods in Result, such as ok_or() or something
    let maker1_senders_contract_sig = if let MakerToTakerMessage::SendersContractSig(m) =
        read_message(&mut socket1_reader).await?
    {
        m
    } else {
        return Err(Box::new(IOError::new(ErrorKind::InvalidData, "")));
    };

    if maker1_senders_contract_sig.sigs.len() != outgoing_swapcoins.len() {
        panic!("wrong number of signatures from maker1, ending");
    }
    if maker1_senders_contract_sig
        .sigs
        .iter()
        .zip(outgoing_swapcoins.iter())
        .any(|(sig, outgoing_swapcoin)| !outgoing_swapcoin.verify_contract_tx_sig(&sig))
    {
        panic!("invalid signature from maker1, ending");
        //TODO go back to the start and try with another maker, in a loop
    }
    maker1_senders_contract_sig
        .sigs
        .iter()
        .zip(outgoing_swapcoins.iter_mut())
        .for_each(|(sig, outgoing_swapcoin)| outgoing_swapcoin.others_contract_sig = Some(*sig));
    for my_funding_tx in my_funding_txes.iter() {
        let txid = if let Ok(t) = rpc.send_raw_transaction(my_funding_tx) {
            t
        } else {
            return Err(Box::new(IOError::new(ErrorKind::Other, "")));
        };
        assert_eq!(txid, my_funding_tx.txid());
    }

    println!("waiting for my funding transaction to confirm");
    let mut txid_blockhash_map = HashMap::<Txid, BlockHash>::new();
    loop {
        for my_funding_tx in my_funding_txes.iter() {
            let txid = my_funding_tx.txid();
            if txid_blockhash_map.contains_key(&txid) {
                continue;
            }
            let gettx = match rpc.get_transaction(&txid, Some(true)) {
                Ok(r) => r,
                Err(_e) => continue,
            };
            //TODO handle confirm<0
            if gettx.info.confirmations >= 1 {
                txid_blockhash_map.insert(txid, gettx.info.blockhash.unwrap());
                println!("funding tx {} reached 1 confirmation(s)", txid);
            }
        }
        if txid_blockhash_map.len() == my_funding_txes.len() {
            break;
        }
        sleep(Duration::from_millis(1000)).await;
    }
    println!("funding transaction confirmed");

    //TODO error handling on the rpc call here, this probably will have to
    //be a for loop so that a potential rpc error can be propagated upwards
    let my_funding_tx_merkleproofs = my_funding_txes
        .iter()
        .map(|my_funding_tx| my_funding_tx.txid())
        .map(|txid| {
            rpc.get_tx_out_proof(&[txid], Some(&txid_blockhash_map.get(&txid).unwrap()))
                .unwrap()
                .to_hex()
        })
        .collect::<Vec<String>>();

    let (maker2_multisig_pubkeys, maker2_multisig_key_nonces): (Vec<_>, Vec<_>) = (0
        ..maker_tx_count)
        .map(|_| {
            contracts::derive_maker_pubkey_and_nonce(
                maker_offers_addresses[1].offer.tweakable_point,
            )
        })
        .unzip();
    let (maker2_hashlock_pubkeys, maker2_hashlock_key_nonces): (Vec<_>, Vec<_>) = (0
        ..maker_tx_count)
        .map(|_| {
            contracts::derive_maker_pubkey_and_nonce(
                maker_offers_addresses[1].offer.tweakable_point,
            )
        })
        .unzip();

    send_message(
        &mut socket1_writer,
        TakerToMakerMessage::ProofOfFunding(ProofOfFunding {
            confirmed_funding_txes: izip!(
                my_funding_txes.iter(),
                my_funding_tx_merkleproofs.iter(),
                outgoing_swapcoins.iter(),
                maker1_multisig_key_nonces.iter(),
                maker1_hashlock_key_nonces.iter()
            )
            .map(
                |(
                    funding_tx,
                    funding_tx_merkleproof,
                    outgoing_swapcoin,
                    &multisig_key_nonce,
                    &hashlock_key_nonce,
                )| ConfirmedCoinSwapTxInfo {
                    funding_tx: funding_tx.clone(),
                    funding_tx_merkleproof: funding_tx_merkleproof.clone(),
                    multisig_redeemscript: outgoing_swapcoin.get_multisig_redeemscript(),
                    multisig_key_nonce,
                    contract_redeemscript: outgoing_swapcoin.contract_redeemscript.clone(),
                    hashlock_key_nonce,
                },
            )
            .collect::<Vec<ConfirmedCoinSwapTxInfo>>(),
            next_coinswap_info: maker2_multisig_pubkeys
                .iter()
                .zip(maker2_hashlock_pubkeys.iter())
                .map(
                    |(&next_coinswap_multisig_pubkey, &next_hashlock_pubkey)| NextCoinSwapTxInfo {
                        next_coinswap_multisig_pubkey,
                        next_hashlock_pubkey,
                    },
                )
                .collect::<Vec<NextCoinSwapTxInfo>>(),
            next_locktime: swap2_locktime,
        }),
    )
    .await?;
    let maker1_sign_sender_and_receiver_contracts =
        if let MakerToTakerMessage::SignSendersAndReceiversContractTxes(m) =
            read_message(&mut socket1_reader).await?
        {
            m
        } else {
            return Err(Box::new(IOError::new(ErrorKind::InvalidData, "")));
        };
    if maker1_sign_sender_and_receiver_contracts
        .receivers_contract_txes
        .len()
        != outgoing_swapcoins.len()
    {
        panic!("wrong number of signatures from maker1, ending");
    }
    for (receivers_contract_tx, outgoing_swapcoin) in maker1_sign_sender_and_receiver_contracts
        .receivers_contract_txes
        .iter()
        .zip(outgoing_swapcoins.iter())
    {
        validate_contract_tx(
            &receivers_contract_tx,
            Some(&outgoing_swapcoin.contract_tx.input[0].previous_output),
            &outgoing_swapcoin.contract_redeemscript,
        )
        .unwrap(); //TODO make it not just crash if invalid contract tx
    }
    if maker2_multisig_pubkeys.len()
        != maker1_sign_sender_and_receiver_contracts
            .senders_contract_txes_info
            .len()
    {
        panic!("wrong number of senders contract txes from maker, ending");
    }

    let mut swap2_contract_redeemscripts = Vec::<Script>::new();
    for (maker2_hashlock_pubkey, senders_contract_tx_info) in maker2_hashlock_pubkeys.iter().zip(
        maker1_sign_sender_and_receiver_contracts
            .senders_contract_txes_info
            .iter(),
    ) {
        let expected_next_contract_redeemscript = create_contract_redeemscript(
            maker2_hashlock_pubkey,
            &senders_contract_tx_info.timelock_pubkey,
            hashvalue,
            swap2_locktime,
        );
        validate_contract_tx(
            &senders_contract_tx_info.contract_tx,
            None,
            &expected_next_contract_redeemscript,
        )
        .unwrap(); //TODO make it not just crash if invalid contract tx
        swap2_contract_redeemscripts.push(expected_next_contract_redeemscript);
    }

    println!(
        "connecting to maker2 = {}",
        maker_offers_addresses[1].address
    );
    let mut socket2 = TcpStream::connect(maker_offers_addresses[1].address.clone()).await?;
    let (mut socket2_reader, mut socket2_writer) = handshake_maker(&mut socket2).await?;
    send_message(
        &mut socket2_writer,
        TakerToMakerMessage::SignSendersContractTx(SignSendersContractTx {
            txes_info: izip!(
                maker2_multisig_key_nonces.iter(),
                maker2_hashlock_key_nonces.iter(),
                maker1_sign_sender_and_receiver_contracts
                    .senders_contract_txes_info
                    .iter(),
            )
            .map(
                |(&multisig_key_nonce, &hashlock_key_nonce, senders_contract_tx_info)| {
                    SenderContractTxNoncesInfo {
                        multisig_key_nonce,
                        hashlock_key_nonce,
                        timelock_pubkey: senders_contract_tx_info.timelock_pubkey,
                        senders_contract_tx: senders_contract_tx_info.contract_tx.clone(),
                        multisig_redeemscript: senders_contract_tx_info
                            .multisig_redeemscript
                            .clone(),
                        funding_input_value: senders_contract_tx_info.funding_amount,
                    }
                },
            )
            .collect::<Vec<SenderContractTxNoncesInfo>>(),
            hashvalue,
            locktime: swap2_locktime,
        }),
    )
    .await?;
    let maker2_senders_contract_sig = if let MakerToTakerMessage::SendersContractSig(m) =
        read_message(&mut socket2_reader).await?
    {
        m
    } else {
        return Err(Box::new(IOError::new(ErrorKind::InvalidData, "")));
    };
    if maker2_senders_contract_sig.sigs.len()
        != maker1_sign_sender_and_receiver_contracts
            .senders_contract_txes_info
            .len()
    {
        panic!("wrong number of signatures from maker2, ending");
    }

    let swap2_swapcoins = izip!(
        maker1_sign_sender_and_receiver_contracts
            .senders_contract_txes_info
            .iter(),
        maker2_multisig_pubkeys.iter(),
        swap2_contract_redeemscripts.iter()
    )
    .map(
        |(senders_contract_tx_info, &maker2_multisig_pubkey, swap2_contract_redeemscript)| {
            WatchOnlySwapCoin::new(
                &senders_contract_tx_info.multisig_redeemscript,
                maker2_multisig_pubkey,
                senders_contract_tx_info.contract_tx.clone(),
                swap2_contract_redeemscript.clone(),
                senders_contract_tx_info.funding_amount,
            )
            .unwrap()
        },
    )
    .collect::<Vec<WatchOnlySwapCoin>>();
    if maker2_senders_contract_sig
        .sigs
        .iter()
        .zip(swap2_swapcoins.iter())
        .any(|(sig, swap2_swapcoin)| !swap2_swapcoin.verify_contract_tx_receiver_sig(&sig))
    {
        panic!("invalid signature from maker2, ending");
        //TODO go back to the start and try with another maker, in a loop
    }
    maker1_sign_sender_and_receiver_contracts
        .senders_contract_txes_info
        .iter()
        .for_each(|senders_contract_tx_info| {
            wallet.import_redeemscript(
                rpc,
                &senders_contract_tx_info.multisig_redeemscript,
                CoreAddressLabelType::WatchOnlySwapCoin,
            )
        });

    send_message(
        &mut socket1_writer,
        TakerToMakerMessage::SendersAndReceiversContractSigs(SendersAndReceiversContractSigs {
            receivers_sigs: maker1_sign_sender_and_receiver_contracts
                .receivers_contract_txes
                .iter()
                .zip(outgoing_swapcoins.iter())
                .map(|(receivers_contract_tx, outgoing_swapcoin)| {
                    outgoing_swapcoin.sign_contract_tx_with_my_privkey(receivers_contract_tx)
                })
                .collect::<Vec<Signature>>(),
            senders_sigs: maker2_senders_contract_sig.sigs,
        }),
    )
    .await?;

    let maker1s_funding_txids = maker1_sign_sender_and_receiver_contracts
        .senders_contract_txes_info
        .iter()
        .map(|senders_contract_tx_info| {
            senders_contract_tx_info.contract_tx.input[0]
                .previous_output
                .txid
        })
        .collect::<Vec<Txid>>();
    println!(
        "waiting for maker1's funding transaction to confirm, txids={:?}",
        maker1s_funding_txids
    );
    let mut maker1_txid_tx_map = HashMap::<Txid, Transaction>::new();
    loop {
        for txid in &maker1s_funding_txids {
            if maker1_txid_tx_map.contains_key(txid) {
                continue;
            }
            let gettx = match rpc.get_transaction(txid, Some(true)) {
                Ok(r) => r,
                Err(_e) => continue,
            };
            //TODO handle confirm<0
            if gettx.info.confirmations >= 1 {
                maker1_txid_tx_map.insert(*txid, deserialize::<Transaction>(&gettx.hex).unwrap());
                txid_blockhash_map.insert(*txid, gettx.info.blockhash.unwrap());
                println!("funding tx {} reached 1 confirmation(s)", txid);
            }
        }
        if maker1_txid_tx_map.len() == maker1s_funding_txids.len() {
            break;
        }
        sleep(Duration::from_millis(1000)).await;
    }
    println!("maker1's funding transactions confirmed");

    let maker1_funding_tx_merkleproofs = maker1s_funding_txids
        .iter()
        .map(|&txid| {
            rpc.get_tx_out_proof(&[txid], Some(&txid_blockhash_map.get(&txid).unwrap()))
                .unwrap()
                .to_hex()
        })
        .collect::<Vec<String>>();

    let (my_receiving_multisig_pubkeys, my_receiving_multisig_privkeys): (Vec<_>, Vec<_>) =
        (0..maker_tx_count).map(|_| generate_keypair()).unzip();
    let (my_receiving_hashlock_pubkeys, _my_receiving_hashlock_privkeys): (Vec<_>, Vec<_>) =
        (0..maker_tx_count).map(|_| generate_keypair()).unzip();

    send_message(
        &mut socket2_writer,
        TakerToMakerMessage::ProofOfFunding(ProofOfFunding {
            confirmed_funding_txes: izip!(
                maker1s_funding_txids.iter(),
                maker1_funding_tx_merkleproofs.iter(),
                maker1_sign_sender_and_receiver_contracts
                    .senders_contract_txes_info
                    .iter(),
                maker2_multisig_key_nonces.iter(),
                swap2_contract_redeemscripts.iter(),
                maker2_hashlock_key_nonces.iter()
            )
            .map(
                |(
                    funding_txid,
                    funding_tx_merkleproof,
                    senders_contract_tx_info,
                    &multisig_key_nonce,
                    contract_redeemscript,
                    &hashlock_key_nonce,
                )| ConfirmedCoinSwapTxInfo {
                    funding_tx: maker1_txid_tx_map.get(funding_txid).unwrap().clone(),
                    funding_tx_merkleproof: funding_tx_merkleproof.clone(),
                    multisig_redeemscript: senders_contract_tx_info.multisig_redeemscript.clone(),
                    multisig_key_nonce,
                    contract_redeemscript: contract_redeemscript.clone(),
                    hashlock_key_nonce,
                },
            )
            .collect::<Vec<ConfirmedCoinSwapTxInfo>>(),
            next_coinswap_info: my_receiving_multisig_pubkeys
                .iter()
                .zip(my_receiving_hashlock_pubkeys.iter())
                .map(
                    |(&next_coinswap_multisig_pubkey, &next_hashlock_pubkey)| NextCoinSwapTxInfo {
                        next_coinswap_multisig_pubkey,
                        next_hashlock_pubkey,
                    },
                )
                .collect::<Vec<NextCoinSwapTxInfo>>(),
            next_locktime: swap3_locktime,
        }),
    )
    .await?;

    let maker2_sign_sender_and_receiver_contracts =
        if let MakerToTakerMessage::SignSendersAndReceiversContractTxes(m) =
            read_message(&mut socket2_reader).await?
        {
            m
        } else {
            return Err(Box::new(IOError::new(ErrorKind::InvalidData, "")));
        };
    if maker2_sign_sender_and_receiver_contracts
        .receivers_contract_txes
        .len()
        != maker1_sign_sender_and_receiver_contracts
            .senders_contract_txes_info
            .len()
    {
        panic!("wrong number of signatures from maker2, ending");
    }

    //verify those txes
    for (receivers_contract_tx, senders_contract_tx_info, contract_redeemscript) in izip!(
        maker2_sign_sender_and_receiver_contracts
            .receivers_contract_txes
            .iter(),
        maker1_sign_sender_and_receiver_contracts
            .senders_contract_txes_info
            .iter(),
        swap2_contract_redeemscripts.iter()
    ) {
        validate_contract_tx(
            receivers_contract_tx,
            Some(&senders_contract_tx_info.contract_tx.input[0].previous_output),
            contract_redeemscript,
        )
        .unwrap();
    }

    send_message(
        &mut socket1_writer,
        TakerToMakerMessage::SignReceiversContractTx(SignReceiversContractTx {
            txes: maker1_sign_sender_and_receiver_contracts
                .senders_contract_txes_info
                .iter()
                .zip(
                    maker2_sign_sender_and_receiver_contracts
                        .receivers_contract_txes
                        .iter(),
                )
                .map(
                    |(senders_contract_tx_info, receivers_contract_tx)| ReceiversContractTxInfo {
                        multisig_redeemscript: senders_contract_tx_info
                            .multisig_redeemscript
                            .clone(),
                        contract_tx: receivers_contract_tx.clone(),
                    },
                )
                .collect::<Vec<ReceiversContractTxInfo>>(),
        }),
    )
    .await?;
    let maker1_receiver_contract_sig = if let MakerToTakerMessage::ReceiversContractSig(m) =
        read_message(&mut socket1_reader).await?
    {
        m
    } else {
        return Err(Box::new(IOError::new(ErrorKind::InvalidData, "")));
    };
    if maker1_receiver_contract_sig.sigs.len()
        != maker1_sign_sender_and_receiver_contracts
            .senders_contract_txes_info
            .len()
    {
        panic!("wrong number of signatures from maker1, ending");
    }

    let swap2_senders_sigs = my_receiving_multisig_privkeys
        .iter()
        .zip(
            maker2_sign_sender_and_receiver_contracts
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
        .collect::<Vec<Signature>>();
    send_message(
        &mut socket2_writer,
        TakerToMakerMessage::SendersAndReceiversContractSigs(SendersAndReceiversContractSigs {
            receivers_sigs: maker1_receiver_contract_sig.sigs,
            senders_sigs: swap2_senders_sigs,
        }),
    )
    .await?;

    let maker2s_funding_txids = maker2_sign_sender_and_receiver_contracts
        .senders_contract_txes_info
        .iter()
        .map(|senders_contract_tx_info| {
            senders_contract_tx_info.contract_tx.input[0]
                .previous_output
                .txid
        })
        .collect::<Vec<Txid>>();
    println!(
        "waiting for maker2's funding transaction to confirm, txids={:?}",
        maker2s_funding_txids
    );
    let mut maker2_txid_tx_map = HashMap::<Txid, Transaction>::new();
    loop {
        for txid in &maker2s_funding_txids {
            if maker2_txid_tx_map.contains_key(txid) {
                continue;
            }
            let gettx = match rpc.get_transaction(txid, Some(true)) {
                Ok(r) => r,
                Err(_e) => continue,
            };
            //TODO handle confirm<0
            if gettx.info.confirmations >= 1 {
                maker2_txid_tx_map.insert(*txid, deserialize::<Transaction>(&gettx.hex).unwrap());
                println!("funding tx {} reached 1 confirmation(s)", txid);
            }
        }
        if maker2_txid_tx_map.len() == maker2s_funding_txids.len() {
            break;
        }
        sleep(Duration::from_millis(1000)).await;
    }
    println!("maker2's funding transactions confirmed");

    let maker2s_funding_tx_values = maker2s_funding_txids
        .iter()
        .zip(
            maker2_sign_sender_and_receiver_contracts
                .senders_contract_txes_info
                .iter(),
        )
        .map(|(makers_funding_txid, senders_contract_tx_info)| {
            find_funding_output(
                &maker2_txid_tx_map.get(makers_funding_txid).unwrap(),
                &senders_contract_tx_info.multisig_redeemscript,
            )
            .unwrap()
            .1
            .value
        })
        .collect::<Vec<u64>>();
    let my_receivers_contract_txes = izip!(
        maker2_sign_sender_and_receiver_contracts
            .senders_contract_txes_info
            .iter(),
        maker2s_funding_tx_values.iter(),
        swap2_contract_redeemscripts.iter()
    )
    .map(
        |(senders_contract_tx_info, &maker_funding_tx_value, next_contract_redeemscript)| {
            create_receivers_contract_tx(
                senders_contract_tx_info.contract_tx.input[0].previous_output,
                maker_funding_tx_value,
                next_contract_redeemscript,
            )
        },
    )
    .collect::<Vec<Transaction>>();

    send_message(
        &mut socket2_writer,
        TakerToMakerMessage::SignReceiversContractTx(SignReceiversContractTx {
            txes: maker2_sign_sender_and_receiver_contracts
                .senders_contract_txes_info
                .iter()
                .zip(my_receivers_contract_txes.iter())
                .map(|(senders_contract_tx_info, my_receivers_contract_tx)| {
                    ReceiversContractTxInfo {
                        multisig_redeemscript: senders_contract_tx_info
                            .multisig_redeemscript
                            .clone(),
                        contract_tx: my_receivers_contract_tx.clone(),
                    }
                })
                .collect::<Vec<ReceiversContractTxInfo>>(),
        }),
    )
    .await?;
    let maker2_receiver_contract_sig = if let MakerToTakerMessage::ReceiversContractSig(m) =
        read_message(&mut socket2_reader).await?
    {
        m
    } else {
        return Err(Box::new(IOError::new(ErrorKind::InvalidData, "")));
    };
    if maker2_receiver_contract_sig.sigs.len()
        != maker2_sign_sender_and_receiver_contracts
            .senders_contract_txes_info
            .len()
    {
        panic!("wrong number of signatures from maker2, ending");
    }
    //assert all these are equal length

    let mut incoming_swapcoins = Vec::<SwapCoin>::new();
    for (
        senders_contract_tx_info,
        &maker_funded_multisig_pubkey,
        &maker_funded_multisig_privkey,
        my_receivers_contract_tx,
        next_contract_redeemscript,
        &maker_funding_tx_value,
        &receiver_contract_sig,
    ) in izip!(
        maker2_sign_sender_and_receiver_contracts
            .senders_contract_txes_info
            .iter(),
        my_receiving_multisig_pubkeys.iter(),
        my_receiving_multisig_privkeys.iter(),
        my_receivers_contract_txes.iter(),
        swap2_contract_redeemscripts.iter(),
        maker2s_funding_tx_values.iter(),
        maker2_receiver_contract_sig.sigs.iter()
    ) {
        let (o_ms_pubkey1, o_ms_pubkey2) = read_pubkeys_from_multisig_redeemscript(
            &senders_contract_tx_info.multisig_redeemscript,
        )
        .unwrap();
        let maker_funded_other_multisig_pubkey = if o_ms_pubkey1 == maker_funded_multisig_pubkey {
            o_ms_pubkey2
        } else {
            assert_eq!(o_ms_pubkey2, maker_funded_multisig_pubkey);
            o_ms_pubkey1
        };

        let mut incoming_swapcoin = SwapCoin::new(
            maker_funded_multisig_privkey,
            maker_funded_other_multisig_pubkey,
            my_receivers_contract_tx.clone(),
            next_contract_redeemscript.clone(),
            maker_funding_tx_value,
        );
        incoming_swapcoin.hash_preimage = Some(preimage);
        incoming_swapcoin.others_contract_sig = Some(receiver_contract_sig);
        incoming_swapcoins.push(incoming_swapcoin);
    }

    //at this point we could wait both replies from both makers at the same time
    //with tokio::spawn()

    send_message(
        &mut socket2_writer,
        TakerToMakerMessage::HashPreimage(HashPreimage {
            senders_multisig_redeemscripts: swap2_swapcoins
                .iter()
                .map(|swapcoin| swapcoin.get_multisig_redeemscript())
                .collect::<Vec<Script>>(),
            receivers_multisig_redeemscripts: incoming_swapcoins
                .iter()
                .map(|swapcoin| swapcoin.get_multisig_redeemscript())
                .collect::<Vec<Script>>(),
            preimage,
        }),
    )
    .await?;
    let maker2_private_key_handover = if let MakerToTakerMessage::PrivateKeyHandover(m) =
        read_message(&mut socket2_reader).await?
    {
        m
    } else {
        return Err(Box::new(IOError::new(ErrorKind::InvalidData, "")));
    };
    if maker2_private_key_handover.swapcoin_private_keys.len() != incoming_swapcoins.len() {
        panic!("wrong number of private keys from maker2");
    }
    for (swapcoin_private_key, incoming_swapcoin) in maker2_private_key_handover
        .swapcoin_private_keys
        .iter()
        .zip(incoming_swapcoins.iter_mut())
    {
        if swapcoin_private_key.multisig_redeemscript
            != incoming_swapcoin.get_multisig_redeemscript()
        {
            panic!("invalid multisig");
        }
        incoming_swapcoin
            .add_other_privkey(swapcoin_private_key.key)
            .unwrap();
    }

    send_message(
        &mut socket1_writer,
        TakerToMakerMessage::HashPreimage(HashPreimage {
            senders_multisig_redeemscripts: outgoing_swapcoins
                .iter()
                .map(|swapcoin| swapcoin.get_multisig_redeemscript())
                .collect::<Vec<Script>>(),
            receivers_multisig_redeemscripts: swap2_swapcoins
                .iter()
                .map(|swapcoin| swapcoin.get_multisig_redeemscript())
                .collect::<Vec<Script>>(),
            preimage,
        }),
    )
    .await?;
    let maker1_private_key_handover = if let MakerToTakerMessage::PrivateKeyHandover(m) =
        read_message(&mut socket1_reader).await?
    {
        m
    } else {
        return Err(Box::new(IOError::new(ErrorKind::InvalidData, "")));
    };
    if maker1_private_key_handover.swapcoin_private_keys.len() != swap2_swapcoins.len() {
        panic!("wrong number of private keys from maker1");
    }

    if maker1_private_key_handover
        .swapcoin_private_keys
        .iter()
        .zip(swap2_swapcoins.iter())
        .any(|(sc_privkey, sc)| {
            sc_privkey.multisig_redeemscript != sc.get_multisig_redeemscript()
                || !sc.is_other_privkey_valid(sc_privkey.key)
        })
    {
        panic!("invalid privkey from maker1");
    }
    send_message(
        &mut socket2_writer,
        TakerToMakerMessage::PrivateKeyHandover(PrivateKeyHandover {
            swapcoin_private_keys: maker1_private_key_handover.swapcoin_private_keys,
        }),
    )
    .await?;
    send_message(
        &mut socket1_writer,
        TakerToMakerMessage::PrivateKeyHandover(PrivateKeyHandover {
            swapcoin_private_keys: outgoing_swapcoins
                .iter()
                .map(|outgoing_swapcoin| SwapCoinPrivateKey {
                    multisig_redeemscript: outgoing_swapcoin.get_multisig_redeemscript(),
                    key: outgoing_swapcoin.my_privkey,
                })
                .collect::<Vec<SwapCoinPrivateKey>>(),
        }),
    )
    .await?;

    for incoming_swapcoin in incoming_swapcoins {
        wallet.add_swapcoin(incoming_swapcoin).unwrap();
    }
    for outgoing_swapcoin in outgoing_swapcoins {
        wallet.add_swapcoin(outgoing_swapcoin).unwrap();
    }

    println!(
        "my funding txes = {:#?}",
        my_funding_txes.iter().map(|t| t.txid()).collect::<Vec<_>>()
    );
    println!("maker1 funding txes = {:#?}", maker1s_funding_txids);
    println!("maker2 funding txes = {:#?}", maker2s_funding_txids);

    println!("successfully completed coinswap");
    Ok(())
}
