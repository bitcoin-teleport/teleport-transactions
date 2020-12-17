use std::sync::Arc;

use std::convert::TryInto;

use bitcoin::{
    blockdata::{
        opcodes,
        script::{Builder, Script},
    },
    secp256k1,
    secp256k1::{Message, Secp256k1, SecretKey, Signature},
    util::bip143::SigHashCache,
    util::key::PublicKey,
    Address, OutPoint, SigHashType, Transaction, TxIn, TxOut,
};

use bitcoincore_rpc::{Client, RpcApi};

use rand::rngs::OsRng;
use rand::RngCore;

use crate::messages::ConfirmedCoinSwapTxInfo;
use crate::wallet_sync::{create_multisig_redeemscript, SwapCoin, Wallet, NETWORK};

//TODO should be configurable somehow
//relatively low value for now so that its easier to test on regtest
pub const REFUND_LOCKTIME: i64 = 80; //in blocks
pub const REFUND_LOCKTIME_STEP: i64 = 20; //in blocks

//like the SwapCoin struct but no privkey or signature information
//used by the taker to monitor coinswaps between two makers
#[derive(Debug, Clone)]
pub struct WatchOnlySwapCoin {
    pub sender_pubkey: PublicKey,
    pub receiver_pubkey: PublicKey,
    pub contract_tx: Transaction,
    pub contract_redeemscript: Script,
    pub funding_amount: u64,
}

pub fn calculate_maker_pubkey_from_nonce(
    tweakable_point: PublicKey,
    nonce: SecretKey,
) -> PublicKey {
    let secp = Secp256k1::new();

    let nonce_point = secp256k1::PublicKey::from_secret_key(&secp, &nonce);
    PublicKey {
        compressed: true,
        key: tweakable_point.key.combine(&nonce_point).unwrap(),
    }
}

pub fn derive_maker_pubkey_and_nonce(tweakable_point: PublicKey) -> (PublicKey, SecretKey) {
    let mut nonce_bytes = [0u8; 32];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = SecretKey::from_slice(&nonce_bytes).unwrap();
    let maker_pubkey = calculate_maker_pubkey_from_nonce(tweakable_point, nonce);

    (maker_pubkey, nonce)
}

#[rustfmt::skip]
pub fn create_contract_redeemscript(
    pub_hashlock: &PublicKey,
    pub_timelock: &PublicKey,
    hashvalue: [u8; 20],
    locktime: i64,
) -> Script {
    Builder::new()
        .push_opcode(opcodes::all::OP_SIZE)
        .push_opcode(opcodes::all::OP_SWAP)
        .push_opcode(opcodes::all::OP_HASH160)
        .push_slice(&hashvalue[..])
        .push_opcode(opcodes::all::OP_EQUAL)
        .push_opcode(opcodes::all::OP_IF)
            .push_key(&pub_hashlock)
            .push_int(32)
            .push_int(1)
        .push_opcode(opcodes::all::OP_ELSE)
            .push_key(&pub_timelock)
            .push_int(0)
            .push_int(locktime)
        .push_opcode(opcodes::all::OP_ENDIF)
        .push_opcode(opcodes::all::OP_CSV)
        .push_opcode(opcodes::all::OP_DROP)
        .push_opcode(opcodes::all::OP_ROT)
        .push_opcode(opcodes::all::OP_EQUALVERIFY)
        .push_opcode(opcodes::all::OP_CHECKSIG)
        .into_script()
}

//TODO put all these magic numbers in a const or something
pub fn read_hashvalue_from_contract(redeemscript: &Script) -> [u8; 20] {
    redeemscript.to_bytes()[4..24]
        .try_into()
        .expect("incorrect length")
}

pub fn read_locktime_from_contract(redeemscript: &Script) -> i64 {
    //note that locktimes in these contracts are always 2 bytes
    //so for example a locktime of 30 wont work, as the specific single opcode
    //will be used instead
    let rs = redeemscript.to_bytes();
    rs[100] as i64 | (rs[101] as i64) << 8
}

pub fn read_pubkeys_from_multisig_redeemscript(
    redeemscript: &Script,
) -> Result<(PublicKey, PublicKey), &'static str> {
    let ms_rs_bytes = redeemscript.to_bytes();
    //TODO put these magic numbers in consts, PUBKEY1_OFFSET maybe
    let pubkey1 = PublicKey::from_slice(&ms_rs_bytes[2..35]);
    let pubkey2 = PublicKey::from_slice(&ms_rs_bytes[36..69]);
    if pubkey1.is_err() || pubkey2.is_err() {
        return Err("invalid pubkeys");
    }
    Ok((pubkey1.unwrap(), pubkey2.unwrap()))
}

pub fn create_senders_contract_tx(
    input: OutPoint,
    input_value: u64,
    contract_redeemscript: &Script,
) -> Transaction {
    let contract_address = Address::p2wsh(&contract_redeemscript, NETWORK);

    Transaction {
        input: vec![TxIn {
            previous_output: input,
            sequence: 0,
            witness: Vec::new(),
            script_sig: Script::new(),
        }],
        output: vec![TxOut {
            script_pubkey: contract_address.script_pubkey(),
            value: input_value - 1000,
        }],
        lock_time: 0,
        version: 2,
    }
}

pub fn create_receivers_contract_tx(
    input: OutPoint,
    input_value: u64,
    contract_redeemscript: &Script,
) -> Transaction {
    //exactly the same thing as senders contract for now, until collateral
    //inputs are implemented
    create_senders_contract_tx(input, input_value, contract_redeemscript)
}

fn is_contract_out_valid(
    contract_output: &TxOut,
    hashlock_pubkey: &PublicKey,
    timelock_pubkey: &PublicKey,
    hashvalue: [u8; 20],
    locktime: i64,
) -> Result<(), &'static str> {
    let minimum_locktime = 50; //TODO should be in config file or something
    if minimum_locktime > locktime {
        return Err("locktime too short");
    }

    let redeemscript_from_request =
        create_contract_redeemscript(hashlock_pubkey, timelock_pubkey, hashvalue, locktime);
    let contract_spk_from_request =
        Address::p2wsh(&redeemscript_from_request, NETWORK).script_pubkey();
    if contract_output.script_pubkey != contract_spk_from_request {
        return Err("given transaction does not pay to requested contract");
    }
    Ok(())
}

//TODO perhaps rename this to include "_with_nonces"
//to match how "validate_and_sign_contract_tx" does it only with keys
pub fn validate_and_sign_senders_contract_tx(
    multisig_key_nonce: &SecretKey,
    hashlock_key_nonce: &SecretKey,
    timelock_pubkey: &PublicKey,
    senders_contract_tx: &Transaction,
    multisig_redeemscript: &Script,
    funding_input_value: u64,
    hashvalue: [u8; 20],
    locktime: i64,
    tweakable_privkey: &SecretKey,
    wallet: &mut Wallet,
) -> Result<Signature, &'static str> {
    if senders_contract_tx.input.len() != 1 || senders_contract_tx.output.len() != 1 {
        return Err("invalid number of inputs or outputs");
    }

    match wallet.does_prevout_match_cached_contract(
        &senders_contract_tx.input[0].previous_output,
        &senders_contract_tx.output[0].script_pubkey,
    ) {
        Ok(valid_from_cache) if !valid_from_cache => {
            return Err("taker attempting multiple contract attack, rejecting");
        }
        Err(_e) => return Err("wallet io error"),
        Ok(_valid_from_cache) => (),
    };

    let secp = Secp256k1::new();
    let mut hashlock_privkey_from_nonce = *tweakable_privkey;
    hashlock_privkey_from_nonce
        .add_assign(hashlock_key_nonce.as_ref())
        .unwrap(); //TODO malicious taker could use this to crash maker
    let hashlock_pubkey_from_nonce = PublicKey {
        compressed: true,
        key: secp256k1::PublicKey::from_secret_key(&secp, &hashlock_privkey_from_nonce),
    };

    is_contract_out_valid(
        &senders_contract_tx.output[0],
        &hashlock_pubkey_from_nonce,
        &timelock_pubkey,
        hashvalue,
        locktime,
    )?; //note question mark here propagating the error upwards

    wallet
        .add_prevout_and_contract_to_cache(
            senders_contract_tx.input[0].previous_output,
            senders_contract_tx.output[0].script_pubkey.clone(),
        )
        .unwrap();

    let mut multisig_privkey_from_nonce = *tweakable_privkey;
    multisig_privkey_from_nonce
        .add_assign(multisig_key_nonce.as_ref())
        .unwrap();

    Ok(sign_contract_tx(
        &senders_contract_tx,
        &multisig_redeemscript,
        funding_input_value,
        &multisig_privkey_from_nonce,
    ))
}

pub fn find_funding_output<'a>(
    funding_tx: &'a Transaction,
    multisig_redeemscript: &Script,
) -> Option<(u32, &'a TxOut)> {
    let multisig_spk = Address::p2wsh(&multisig_redeemscript, NETWORK).script_pubkey();
    funding_tx
        .output
        .iter()
        .enumerate()
        .map(|(i, o)| (i as u32, o))
        .find(|(_i, o)| o.script_pubkey == multisig_spk)
}

//returns the keys of the multisig, ready for importing
//or None if the proof is invalid for some reason
//or an error if the RPC connection fails
pub fn verify_proof_of_funding(
    rpc: Arc<Client>,
    wallet: &mut Wallet,
    funding_info: &ConfirmedCoinSwapTxInfo,
    funding_output_index: u32,
    next_locktime: i64,
) -> Result<Option<(SecretKey, PublicKey)>, bitcoincore_rpc::Error> {
    //check the funding_tx exists and was really confirmed
    if let Some(txout) =
        rpc.get_tx_out(&funding_info.funding_tx.txid(), funding_output_index, None)?
    {
        if txout.confirmations < 1 {
            return Ok(None);
        }
    } else {
        //output doesnt exist
        return Ok(None);
    }

    //pattern match to check redeemscript is really a 2of2 multisig
    let mut ms_rs_bytes = funding_info.multisig_redeemscript.to_bytes();
    const PUB_PLACEHOLDER: [u8; 33] = [0x02; 33];
    let pubkey_placeholder = PublicKey::from_slice(&PUB_PLACEHOLDER).unwrap();
    let template_ms_rs =
        create_multisig_redeemscript(&pubkey_placeholder, &pubkey_placeholder).into_bytes();
    if ms_rs_bytes.len() != template_ms_rs.len() {
        return Ok(None);
    }
    ms_rs_bytes.splice(2..35, PUB_PLACEHOLDER.iter().cloned());
    ms_rs_bytes.splice(36..69, PUB_PLACEHOLDER.iter().cloned());
    if ms_rs_bytes != template_ms_rs {
        return Ok(None);
    }

    //check my pubkey is one of the pubkeys in the redeemscript
    let (pubkey1, pubkey2) =
        read_pubkeys_from_multisig_redeemscript(&funding_info.multisig_redeemscript).unwrap();
    let (tweakable_privkey, tweakable_point) = wallet.get_tweakable_keypair();
    let my_pubkey =
        calculate_maker_pubkey_from_nonce(tweakable_point, funding_info.multisig_key_nonce);
    if pubkey1 != my_pubkey && pubkey2 != my_pubkey {
        return Ok(None);
    }

    //check that the new locktime is sufficently short enough compared to the
    //locktime in the provided funding tx
    let locktime = read_locktime_from_contract(&funding_info.contract_redeemscript);
    //this is the time the maker or his watchtowers have to be online, read
    // the hash preimage from the blockchain and broadcast their own tx
    //TODO put this in a config file perhaps, and have it advertised to takers
    const CONTRACT_REACT_TIME: i64 = 144;
    if locktime - next_locktime < CONTRACT_REACT_TIME {
        return Ok(None);
    }

    //check that the provided contract matches the scriptpubkey from the
    //cache which was populated when the signsendercontracttx message arrived
    let contract_spk = Address::p2wsh(&funding_info.contract_redeemscript, NETWORK).script_pubkey();
    match wallet.does_prevout_match_cached_contract(
        &OutPoint {
            txid: funding_info.funding_tx.txid(),
            vout: funding_output_index,
        },
        &contract_spk,
    ) {
        Ok(valid_from_cache) if !valid_from_cache => {
            //provided contract does not match sender contract tx, rejecting
            return Ok(None);
        }
        Err(_e) => {
            return Err(bitcoincore_rpc::Error::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "wallet file io",
            )))
        }
        Ok(_valid_from_cache) => (),
    };

    let mut my_privkey = tweakable_privkey;
    //TODO error handle
    my_privkey
        .add_assign(funding_info.multisig_key_nonce.as_ref())
        .unwrap();

    let other_pubkey = if pubkey1 == my_pubkey {
        pubkey2
    } else {
        pubkey1
    };
    Ok(Some((my_privkey, other_pubkey)))
}

pub fn validate_contract_tx(
    receivers_contract_tx: &Transaction,
    funding_outpoint: Option<&OutPoint>,
    contract_redeemscript: &Script,
) -> Result<(), &'static str> {
    if receivers_contract_tx.input.len() != 1 || receivers_contract_tx.output.len() != 1 {
        return Err("invalid number of inputs or outputs");
    }
    if funding_outpoint.is_some()
        && receivers_contract_tx.input[0].previous_output != *funding_outpoint.unwrap()
    {
        return Err("not spending the funding outpoint");
    }
    if receivers_contract_tx.output[0].script_pubkey
        != Address::p2wsh(&contract_redeemscript, NETWORK).script_pubkey()
    {
        return Err("doesnt pay to requested contract");
    }
    Ok(())
}

pub fn sign_contract_tx(
    contract_tx: &Transaction,
    multisig_redeemscript: &Script,
    funding_amount: u64,
    privkey: &SecretKey,
) -> Signature {
    let input_index = 0;
    let sighash = Message::from_slice(
        &SigHashCache::new(contract_tx).signature_hash(
            input_index,
            multisig_redeemscript,
            funding_amount,
            SigHashType::All,
        )[..],
    )
    .unwrap();
    let secp = Secp256k1::new();
    secp.sign(&sighash, privkey)
}

fn verify_contract_tx_sig(
    contract_tx: &Transaction,
    multisig_redeemscript: &Script,
    funding_amount: u64,
    pubkey: &PublicKey,
    sig: &Signature,
) -> bool {
    //TODO possible exploit here if this code accepts high-S signatures
    //but bitcoin doesnt
    //similar https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-26895

    let input_index = 0;
    let sighash = Message::from_slice(
        &SigHashCache::new(contract_tx).signature_hash(
            input_index,
            multisig_redeemscript,
            funding_amount,
            SigHashType::All,
        )[..],
    )
    .unwrap();
    let secp = Secp256k1::new();
    secp.verify(&sighash, sig, &pubkey.key).is_ok()
}

impl SwapCoin {
    pub fn get_multisig_redeemscript(&self) -> Script {
        let secp = Secp256k1::new();
        create_multisig_redeemscript(
            &self.other_pubkey,
            &PublicKey {
                compressed: true,
                key: secp256k1::PublicKey::from_secret_key(&secp, &self.my_privkey),
            },
        )
    }

    //"_with_my_privkey" as opposed to with other_privkey
    pub fn sign_contract_tx_with_my_privkey(&self, contract_tx: &Transaction) -> Signature {
        let multisig_redeemscript = self.get_multisig_redeemscript();
        sign_contract_tx(
            contract_tx,
            &multisig_redeemscript,
            self.funding_amount,
            &self.my_privkey,
        )
    }

    pub fn verify_contract_tx_sig(&self, sig: &Signature) -> bool {
        verify_contract_tx_sig(
            &self.contract_tx,
            &self.get_multisig_redeemscript(),
            self.funding_amount,
            &self.other_pubkey,
            sig,
        )
    }

    pub fn add_other_privkey(&mut self, privkey: SecretKey) -> Result<(), &'static str> {
        let secp = Secp256k1::new();
        let pubkey = PublicKey {
            compressed: true,
            key: secp256k1::PublicKey::from_secret_key(&secp, &privkey),
        };
        if pubkey != self.other_pubkey {
            return Err("not correct privkey");
        }
        self.other_privkey = Some(privkey);
        Ok(())
    }
}

impl WatchOnlySwapCoin {
    pub fn new(
        multisig_redeemscript: &Script,
        receiver_pubkey: PublicKey,
        contract_tx: Transaction,
        contract_redeemscript: Script,
        funding_amount: u64,
    ) -> Result<WatchOnlySwapCoin, &'static str> {
        let (pubkey1, pubkey2) = read_pubkeys_from_multisig_redeemscript(multisig_redeemscript)?;
        if pubkey1 != receiver_pubkey && pubkey2 != receiver_pubkey {
            return Err("given sender_pubkey not included in redeemscript");
        }
        let sender_pubkey = if pubkey1 == receiver_pubkey {
            pubkey2
        } else {
            pubkey1
        };
        Ok(WatchOnlySwapCoin {
            sender_pubkey,
            receiver_pubkey,
            contract_tx,
            contract_redeemscript,
            funding_amount,
        })
    }

    pub fn get_multisig_redeemscript(&self) -> Script {
        create_multisig_redeemscript(&self.sender_pubkey, &self.receiver_pubkey)
    }

    pub fn verify_contract_tx_sender_sig(&self, sig: &Signature) -> bool {
        verify_contract_tx_sig(
            &self.contract_tx,
            &self.get_multisig_redeemscript(),
            self.funding_amount,
            &self.sender_pubkey,
            sig,
        )
    }

    pub fn verify_contract_tx_receiver_sig(&self, sig: &Signature) -> bool {
        verify_contract_tx_sig(
            &self.contract_tx,
            &self.get_multisig_redeemscript(),
            self.funding_amount,
            &self.receiver_pubkey,
            sig,
        )
    }

    pub fn is_other_privkey_valid(&self, privkey: SecretKey) -> bool {
        let secp = Secp256k1::new();
        let pubkey = PublicKey {
            compressed: true,
            key: secp256k1::PublicKey::from_secret_key(&secp, &privkey),
        };
        pubkey == self.sender_pubkey || pubkey == self.receiver_pubkey
    }
}
