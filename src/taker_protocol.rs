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
use bitcoin::secp256k1::{SecretKey, Signature};
use bitcoin::util::key::PublicKey;
use bitcoin::{BlockHash, Script, Transaction, Txid};
use bitcoincore_rpc::{Client, RpcApi};

use rand::rngs::OsRng;
use rand::RngCore;

use itertools::izip;

use crate::contracts;
use crate::contracts::{
    create_contract_redeemscript, create_receivers_contract_tx, find_funding_output,
    read_pubkeys_from_multisig_redeemscript, sign_contract_tx, validate_contract_tx,
    REFUND_LOCKTIME, REFUND_LOCKTIME_STEP,
};
use crate::messages::{
    ConfirmedCoinSwapTxInfo, HashPreimage, MakerToTakerMessage, NextCoinSwapTxInfo, Offer,
    PrivateKeyHandover, ProofOfFunding, ReceiversContractTxInfo, SenderContractTxNoncesInfo,
    SendersAndReceiversContractSigs, SignReceiversContractTx, SignSendersContractTx,
    SwapCoinPrivateKey, TakerHello, TakerToMakerMessage,
};
use crate::offerbook_sync;
use crate::wallet_sync::{generate_keypair, SwapCoin, Wallet};

#[tokio::main]
pub async fn start_taker(rpc: &Client, wallet: &mut Wallet) {
    match run(rpc, wallet).await {
        Ok(_o) => (),
        Err(e) => println!("err {:?}", e),
    };
}

async fn run(rpc: &Client, wallet: &mut Wallet) -> Result<(), Box<dyn Error>> {
    let offers_addresses = offerbook_sync::sync_offerbook().await;

    println!("offers_addresses = {:?}", offers_addresses);

    send_coinswap(rpc, wallet, &offers_addresses[0].offer).await?;
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

async fn connect_to_maker(
    socket: &mut TcpStream,
) -> Result<(BufReader<ReadHalf<'_>>, WriteHalf<'_>), Box<dyn Error>> {
    println!("connected to maker");

    let (socket_reader, mut socket_writer) = socket.split();
    let mut reader = BufReader::new(socket_reader);

    send_message(
        &mut socket_writer,
        TakerToMakerMessage::TakerHello(TakerHello {
            protocol_version_min: 0,
            protocol_version_max: 0,
        }),
    )
    .await?;

    let makerhello = if let MakerToTakerMessage::MakerHello(m) = read_message(&mut reader).await? {
        m
    } else {
        return Err(Box::new(IOError::new(ErrorKind::InvalidData, "")));
    };
    println!(
        "protocol version min/max = {}/{}",
        makerhello.protocol_version_min, makerhello.protocol_version_max
    );
    Ok((reader, socket_writer))
}

async fn send_coinswap(
    rpc: &Client,
    wallet: &mut Wallet,
    offer: &Offer,
) -> Result<(), Box<dyn Error>> {
    let amount = 5000000;
    let my_tx_count: u32 = 3;
    let maker_tx_count: u32 = 3;

    let mut socket = TcpStream::connect("localhost:6102").await?;
    let (mut reader, mut socket_writer) = connect_to_maker(&mut socket).await?;

    let mut preimage = [0u8; 32];
    OsRng.fill_bytes(&mut preimage);
    let hashvalue = Hash160::hash(&preimage).into_inner();
    let my_locktime = REFUND_LOCKTIME + REFUND_LOCKTIME_STEP;

    let mut maker_multisig_pubkeys = Vec::<PublicKey>::new();
    let mut maker_multisig_key_nonces = Vec::<SecretKey>::new();
    let mut maker_hashlock_pubkeys = Vec::<PublicKey>::new();
    let mut maker_hashlock_key_nonces = Vec::<SecretKey>::new();
    for _ in 0..my_tx_count {
        let (maker_multisig_pubkey, multisig_key_nonce) =
            contracts::derive_maker_pubkey_and_nonce(offer.tweakable_point);
        maker_multisig_pubkeys.push(maker_multisig_pubkey);
        maker_multisig_key_nonces.push(multisig_key_nonce);
        let (maker_hashlock_pubkey, hashlock_key_nonce) =
            contracts::derive_maker_pubkey_and_nonce(offer.tweakable_point);
        maker_hashlock_pubkeys.push(maker_hashlock_pubkey);
        maker_hashlock_key_nonces.push(hashlock_key_nonce);
    }

    let (my_funding_txes, mut outgoing_swapcoins, timelock_pubkeys, _timelock_privkeys) = wallet
        .initalize_coinswap(
            rpc,
            amount,
            &maker_multisig_pubkeys,
            &maker_hashlock_pubkeys,
            hashvalue,
            my_locktime,
        );

    send_message(
        &mut socket_writer,
        TakerToMakerMessage::SignSendersContractTx(SignSendersContractTx {
            txes_info: izip!(
                maker_multisig_key_nonces.iter(),
                maker_hashlock_key_nonces.iter(),
                timelock_pubkeys.iter(),
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
            locktime: my_locktime,
        }),
    )
    .await?;
    //TODO this pattern of let = if let else err could probably be replaced by
    //one of the methods in Result, such as ok_or() or something
    let senders_contract_sig =
        if let MakerToTakerMessage::SendersContractSig(m) = read_message(&mut reader).await? {
            m
        } else {
            return Err(Box::new(IOError::new(ErrorKind::InvalidData, "")));
        };

    if senders_contract_sig.sigs.len() != outgoing_swapcoins.len() {
        panic!("wrong number of signatures from maker, ending");
    }
    if senders_contract_sig
        .sigs
        .iter()
        .zip(outgoing_swapcoins.iter())
        .any(|(sig, outgoing_swapcoin)| !outgoing_swapcoin.verify_contract_tx_sig(&sig))
    {
        panic!("invalid signature from maker, ending");
        //TODO go back to the start and try with another maker, in a loop
    }
    senders_contract_sig
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

    println!("waiting for funding transaction to confirm");
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
    let funding_tx_merkleproofs = my_funding_txes
        .iter()
        .map(|my_funding_tx| my_funding_tx.txid())
        .map(|txid| {
            rpc.get_tx_out_proof(&[txid], Some(&txid_blockhash_map.get(&txid).unwrap()))
                .unwrap()
                .to_hex()
        })
        .collect::<Vec<String>>();

    let mut maker_funded_multisig_pubkeys = Vec::<PublicKey>::new();
    let mut maker_funded_multisig_privkeys = Vec::<SecretKey>::new();
    let mut my_receiving_hashlock_pubkeys = Vec::<PublicKey>::new();
    let mut my_receiving_hashlock_privkeys = Vec::<SecretKey>::new();
    for _ in 0..maker_tx_count {
        let (maker_funded_coinswap_pubkey, maker_funded_coinswap_privkey) = generate_keypair();
        let (my_receiving_hashlock_pubkey, my_receiving_hashlock_privkey) = generate_keypair();
        maker_funded_multisig_pubkeys.push(maker_funded_coinswap_pubkey);
        maker_funded_multisig_privkeys.push(maker_funded_coinswap_privkey);
        my_receiving_hashlock_pubkeys.push(my_receiving_hashlock_pubkey);
        my_receiving_hashlock_privkeys.push(my_receiving_hashlock_privkey);
    }
    send_message(
        &mut socket_writer,
        TakerToMakerMessage::ProofOfFunding(ProofOfFunding {
            confirmed_funding_txes: izip!(
                my_funding_txes.iter(),
                funding_tx_merkleproofs.iter(),
                outgoing_swapcoins.iter(),
                maker_multisig_key_nonces.iter(),
                maker_hashlock_key_nonces.iter()
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
            next_coinswap_info: maker_funded_multisig_pubkeys
                .iter()
                .zip(my_receiving_hashlock_pubkeys.iter())
                .map(
                    |(&next_coinswap_multisig_pubkey, &next_hashlock_pubkey)| NextCoinSwapTxInfo {
                        next_coinswap_multisig_pubkey,
                        next_hashlock_pubkey,
                    },
                )
                .collect::<Vec<NextCoinSwapTxInfo>>(),
            next_locktime: REFUND_LOCKTIME,
        }),
    )
    .await?;
    let sign_sender_and_receiver_contract =
        if let MakerToTakerMessage::SignSendersAndReceiversContractTxes(m) =
            read_message(&mut reader).await?
        {
            m
        } else {
            return Err(Box::new(IOError::new(ErrorKind::InvalidData, "")));
        };
    if sign_sender_and_receiver_contract
        .receivers_contract_txes
        .len()
        != outgoing_swapcoins.len()
    {
        panic!("wrong number of signatures from maker, ending");
    }
    for (receivers_contract_tx, outgoing_swapcoin) in sign_sender_and_receiver_contract
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
    let receivers_sigs = sign_sender_and_receiver_contract
        .receivers_contract_txes
        .iter()
        .zip(outgoing_swapcoins.iter())
        .map(|(receivers_contract_tx, outgoing_swapcoin)| {
            outgoing_swapcoin.sign_contract_tx_with_my_privkey(receivers_contract_tx)
        })
        .collect::<Vec<Signature>>();

    if my_receiving_hashlock_pubkeys.len()
        != sign_sender_and_receiver_contract
            .senders_contract_txes_info
            .len()
    {
        panic!("wrong number of senders contract txes from maker, ending");
    }
    let mut next_contract_redeemscripts = Vec::<Script>::new();
    for (my_receiving_hashlock_pubkey, senders_contract_tx_info) in
        my_receiving_hashlock_pubkeys.iter().zip(
            sign_sender_and_receiver_contract
                .senders_contract_txes_info
                .iter(),
        )
    {
        let expected_next_contract_redeemscript = create_contract_redeemscript(
            my_receiving_hashlock_pubkey,
            &senders_contract_tx_info.timelock_pubkey,
            hashvalue,
            REFUND_LOCKTIME,
        );
        validate_contract_tx(
            &senders_contract_tx_info.contract_tx,
            None,
            &expected_next_contract_redeemscript,
        )
        .unwrap(); //TODO make it not just crash if invalid contract tx
        next_contract_redeemscripts.push(expected_next_contract_redeemscript);
    }
    assert_eq!(
        maker_funded_multisig_privkeys.len(),
        my_receiving_hashlock_pubkeys.len()
    );
    let senders_sigs = maker_funded_multisig_privkeys
        .iter()
        .zip(
            sign_sender_and_receiver_contract
                .senders_contract_txes_info
                .iter(),
        )
        .map(
            |(maker_funded_multisig_privkey, senders_contract_tx_info)| {
                sign_contract_tx(
                    &senders_contract_tx_info.contract_tx,
                    &senders_contract_tx_info.multisig_redeemscript,
                    senders_contract_tx_info.funding_amount,
                    maker_funded_multisig_privkey,
                )
            },
        )
        .collect::<Vec<Signature>>();
    sign_sender_and_receiver_contract
        .senders_contract_txes_info
        .iter()
        .for_each(|senders_contract_tx_info| {
            wallet.import_redeemscript(rpc, &senders_contract_tx_info.multisig_redeemscript)
        });
    send_message(
        &mut socket_writer,
        TakerToMakerMessage::SendersAndReceiversContractSigs(SendersAndReceiversContractSigs {
            receivers_sigs,
            senders_sigs,
        }),
    )
    .await?;

    let makers_funding_txids = sign_sender_and_receiver_contract
        .senders_contract_txes_info
        .iter()
        .map(|senders_contract_tx_info| {
            senders_contract_tx_info.contract_tx.input[0]
                .previous_output
                .txid
        })
        .collect::<Vec<Txid>>();
    println!(
        "waiting for maker's funding transaction to confirm, txids={:?}",
        makers_funding_txids
    );
    let mut txid_hex_map = HashMap::<Txid, Vec<u8>>::new();
    loop {
        for txid in &makers_funding_txids {
            if txid_hex_map.contains_key(txid) {
                continue;
            }
            let gettx = match rpc.get_transaction(txid, Some(true)) {
                Ok(r) => r,
                Err(_e) => continue,
            };
            //TODO handle confirm<0
            if gettx.info.confirmations >= 1 {
                txid_hex_map.insert(*txid, gettx.hex);
                println!("funding tx {} reached 1 confirmation(s)", txid);
            }
        }
        if txid_hex_map.len() == makers_funding_txids.len() {
            break;
        }
        sleep(Duration::from_millis(1000)).await;
    }
    println!("makers funding transactions confirmed");

    let maker_funding_tx_values = makers_funding_txids
        .iter()
        .zip(
            sign_sender_and_receiver_contract
                .senders_contract_txes_info
                .iter(),
        )
        .map(|(makers_funding_txid, senders_contract_tx_info)| {
            find_funding_output(
                &deserialize::<Transaction>(&txid_hex_map.get(makers_funding_txid).unwrap())
                    .unwrap(),
                &senders_contract_tx_info.multisig_redeemscript,
            )
            .unwrap()
            .1
            .value
        })
        .collect::<Vec<u64>>();

    let my_receivers_contract_txes = izip!(
        sign_sender_and_receiver_contract
            .senders_contract_txes_info
            .iter(),
        maker_funding_tx_values.iter(),
        next_contract_redeemscripts.iter()
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
        &mut socket_writer,
        TakerToMakerMessage::SignReceiversContractTx(SignReceiversContractTx {
            txes: sign_sender_and_receiver_contract
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
    let receiver_contract_sig =
        if let MakerToTakerMessage::ReceiversContractSig(m) = read_message(&mut reader).await? {
            m
        } else {
            return Err(Box::new(IOError::new(ErrorKind::InvalidData, "")));
        };
    if receiver_contract_sig.sigs.len()
        != sign_sender_and_receiver_contract
            .senders_contract_txes_info
            .len()
    {
        panic!("wrong number of signatures from maker, ending");
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
        sign_sender_and_receiver_contract
            .senders_contract_txes_info
            .iter(),
        maker_funded_multisig_pubkeys.iter(),
        maker_funded_multisig_privkeys.iter(),
        my_receivers_contract_txes.iter(),
        next_contract_redeemscripts.iter(),
        maker_funding_tx_values.iter(),
        receiver_contract_sig.sigs.iter()
    ) {
        let (o_ms_pubkey1, o_ms_pubkey2) = read_pubkeys_from_multisig_redeemscript(
            &senders_contract_tx_info.multisig_redeemscript,
        )
        .unwrap();
        let maker_funded_other_multisig_pubkey = if o_ms_pubkey1 == maker_funded_multisig_pubkey {
            o_ms_pubkey2
        } else {
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

    send_message(
        &mut socket_writer,
        TakerToMakerMessage::HashPreimage(HashPreimage {
            senders_multisig_redeemscripts: outgoing_swapcoins
                .iter()
                .map(|outgoing_swapcoin| outgoing_swapcoin.get_multisig_redeemscript())
                .collect::<Vec<Script>>(),
            receivers_multisig_redeemscripts: sign_sender_and_receiver_contract
                .senders_contract_txes_info
                .iter()
                .map(|senders_contract_tx_info| {
                    senders_contract_tx_info.multisig_redeemscript.clone()
                })
                .collect::<Vec<Script>>(),
            preimage,
        }),
    )
    .await?;
    let private_key_handover =
        if let MakerToTakerMessage::PrivateKeyHandover(m) = read_message(&mut reader).await? {
            m
        } else {
            return Err(Box::new(IOError::new(ErrorKind::InvalidData, "")));
        };

    if private_key_handover.swapcoin_private_keys.len() != incoming_swapcoins.len() {
        panic!("wrong number of private keys");
    }
    for (swapcoin_private_key, incoming_swapcoin) in private_key_handover
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
        &mut socket_writer,
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
    println!("successfully completed coinswap");

    Ok(())
}
