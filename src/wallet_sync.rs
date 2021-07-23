// this file contains code handling the wallet and sync'ing the wallet
// for now the wallet is only sync'd via bitcoin core's RPC
// makers will only ever sync this way, but one day takers may sync in other
// ways too such as a lightweight wallet method

use std::fs::File;
use std::io;
use std::io::Read;
use std::path::Path;
use std::str::FromStr;
use std::sync::Arc;

use std::collections::{HashMap, HashSet};

use itertools::izip;

use bitcoin_wallet::mnemonic;

use bitcoin::{
    blockdata::{
        opcodes::all,
        script::{Builder, Script},
    },
    hashes::hex::{FromHex, ToHex},
    secp256k1,
    secp256k1::{Secp256k1, SecretKey, Signature},
    util::{
        bip143::SigHashCache,
        bip32::{ChildNumber, DerivationPath, ExtendedPrivKey, ExtendedPubKey},
        key::PublicKey,
        psbt::serialize::Serialize,
    },
    Address, Amount, Network, OutPoint, SigHashType, Transaction, TxIn, TxOut, Txid,
};

use bitcoincore_rpc::json::{
    ImportMultiOptions, ImportMultiRequest, ImportMultiRequestScriptPubkey, ImportMultiRescanSince,
    ListUnspentResultEntry, WalletCreateFundedPsbtOptions,
};
use bitcoincore_rpc::{Client, RpcApi};

use serde_json::json;
use serde_json::Value;

use rand::rngs::OsRng;
use rand::RngCore;

use crate::contracts;
use crate::contracts::{read_hashvalue_from_contract, SwapCoin};
use crate::error::Error;

//these subroutines are coded so that as much as possible they keep all their
//data in the bitcoin core wallet
//for example which privkey corresponds to a scriptpubkey is stored in hd paths

//TODO this goes in the config file
pub const NETWORK: Network = Network::Regtest; //not configurable for now
const DERIVATION_PATH: &str = "m/84'/1'/0'";
const WALLET_FILE_VERSION: u32 = 0;

#[cfg(not(test))]
const INITIAL_ADDRESS_IMPORT_COUNT: usize = 5000;
#[cfg(test)]
const INITIAL_ADDRESS_IMPORT_COUNT: usize = 6;

//TODO the wallet file format is probably best handled with sqlite

#[derive(serde::Serialize, serde::Deserialize)]
struct WalletFileData {
    version: u32,
    seedphrase: String,
    extension: String,
    external_index: u32,
    swap_coins: Vec<WalletSwapCoin>,
    prevout_to_contract_map: HashMap<OutPoint, Script>,
}

pub struct Wallet {
    master_key: ExtendedPrivKey,
    wallet_file_name: String,
    external_index: u32,
    swap_coins: HashMap<Script, WalletSwapCoin>,
}

pub enum CoreAddressLabelType {
    Wallet,
    WatchOnlySwapCoin,
}
const WATCH_ONLY_SWAPCOIN_LABEL: &str = "watchonly_swapcoin_label";

//swapcoins are UTXOs + metadata which are not from the deterministic wallet
//they are made in the process of a coinswap
#[derive(serde::Serialize, serde::Deserialize, Debug, Clone)]
pub struct WalletSwapCoin {
    pub my_privkey: SecretKey,
    pub other_pubkey: PublicKey,
    pub other_privkey: Option<SecretKey>,
    pub contract_tx: Transaction,
    pub contract_redeemscript: Script,
    //either timelock_privkey for outgoing swapcoins or hashlock_privkey for incoming swapcoins
    pub contract_privkey: SecretKey,
    pub funding_amount: u64,
    pub others_contract_sig: Option<Signature>,
    pub hash_preimage: Option<[u8; 32]>,
}
//TODO split WalletSwapCoin into two structs, IncomingSwapCoin and OutgoingSwapCoin
//where Incoming has hashlock_privkey and Outgoing has timelock_privkey
//that is a much more rustic way of doing things, which uses the compiler to check for some bugs

impl WalletSwapCoin {
    pub fn new(
        my_privkey: SecretKey,
        other_pubkey: PublicKey,
        contract_tx: Transaction,
        contract_redeemscript: Script,
        contract_privkey: SecretKey,
        funding_amount: u64,
    ) -> WalletSwapCoin {
        let secp = Secp256k1::new();
        let contract_pubkey = PublicKey {
            compressed: true,
            key: secp256k1::PublicKey::from_secret_key(&secp, &contract_privkey),
        };
        assert!(
            contract_pubkey
                == contracts::read_hashlock_pubkey_from_contract(&contract_redeemscript).unwrap()
                || contract_pubkey
                    == contracts::read_timelock_pubkey_from_contract(&contract_redeemscript)
                        .unwrap()
        );
        WalletSwapCoin {
            my_privkey,
            other_pubkey,
            other_privkey: None,
            contract_tx,
            contract_redeemscript,
            contract_privkey,
            funding_amount,
            others_contract_sig: None,
            hash_preimage: None,
        }
    }

    fn get_my_pubkey(&self) -> PublicKey {
        let secp = Secp256k1::new();
        PublicKey {
            compressed: true,
            key: secp256k1::PublicKey::from_secret_key(&secp, &self.my_privkey),
        }
    }

    fn sign_transaction_input(
        &self,
        index: usize,
        tx: &Transaction,
        input: &mut TxIn,
        redeemscript: &Script,
    ) -> Result<(), &'static str> {
        if self.other_privkey.is_none() {
            return Err("unable to sign: incomplete coinswap for this input");
        }
        let secp = Secp256k1::new();
        let my_pubkey = self.get_my_pubkey();

        let sighash = secp256k1::Message::from_slice(
            &SigHashCache::new(tx).signature_hash(
                index,
                redeemscript,
                self.funding_amount,
                SigHashType::All,
            )[..],
        )
        .unwrap();

        let sig_mine = secp.sign(&sighash, &self.my_privkey);
        let sig_other = secp.sign(&sighash, &self.other_privkey.unwrap());

        let (sig_first, sig_second) =
            if my_pubkey.serialize()[..] < self.other_pubkey.serialize()[..] {
                (sig_mine, sig_other)
            } else {
                (sig_other, sig_mine)
            };

        input.witness.push(Vec::new()); //first is multisig dummy
        input.witness.push(sig_first.serialize_der().to_vec());
        input.witness.push(sig_second.serialize_der().to_vec());
        input.witness[1].push(SigHashType::All as u8);
        input.witness[2].push(SigHashType::All as u8);
        input.witness.push(redeemscript.to_bytes());
        Ok(())
    }
}

impl Wallet {
    pub fn print_wallet_key_data(&self) {
        println!(
            "master key = {}, external_index = {}",
            self.master_key, self.external_index
        );
        for (multisig_redeemscript, swapcoin) in &self.swap_coins {
            println!(
                "{} {}:{} {}",
                Address::p2wsh(multisig_redeemscript, NETWORK),
                swapcoin.contract_tx.input[0].previous_output.txid,
                swapcoin.contract_tx.input[0].previous_output.vout,
                if swapcoin.other_privkey.is_some() {
                    "  known"
                } else {
                    "unknown"
                }
            )
        }
        println!("swapcoin count = {}", self.swap_coins.len());
    }

    pub fn save_new_wallet_file<P: AsRef<Path>>(
        wallet_file_name: P,
        seedphrase: String,
        extension: String,
    ) -> Result<(), Error> {
        let wallet_file_data = WalletFileData {
            version: WALLET_FILE_VERSION,
            seedphrase,
            extension,
            external_index: 0,
            swap_coins: Vec::new(),
            prevout_to_contract_map: HashMap::<OutPoint, Script>::new(),
        };
        let wallet_file = File::create(wallet_file_name)?;
        serde_json::to_writer(wallet_file, &wallet_file_data).map_err(|e| io::Error::from(e))?;
        Ok(())
    }

    fn load_wallet_file_data<P: AsRef<Path>>(wallet_file_name: P) -> Result<WalletFileData, Error> {
        let mut wallet_file = File::open(wallet_file_name)?;
        let mut wallet_file_str = String::new();
        wallet_file.read_to_string(&mut wallet_file_str)?;
        Ok(serde_json::from_str::<WalletFileData>(&wallet_file_str)
            .map_err(|e| io::Error::from(e))?)
    }

    pub fn load_wallet_from_file<P: AsRef<Path>>(wallet_file_name: P) -> Result<Wallet, Error> {
        let wallet_file_name = wallet_file_name
            .as_ref()
            .as_os_str()
            .to_string_lossy()
            .to_string();
        let wallet_file_data = Wallet::load_wallet_file_data(&wallet_file_name)?;
        let mnemonic_ret = mnemonic::Mnemonic::from_str(&wallet_file_data.seedphrase);
        if mnemonic_ret.is_err() {
            return Err(Error::Disk(io::Error::new(
                io::ErrorKind::Other,
                "invalid seed phrase",
            )));
        }

        let seed = mnemonic_ret
            .unwrap()
            .to_seed(Some(&wallet_file_data.extension));
        let xprv = ExtendedPrivKey::new_master(NETWORK, &seed.0).unwrap();

        let wallet = Wallet {
            master_key: xprv,
            wallet_file_name,
            external_index: wallet_file_data.external_index,
            swap_coins: wallet_file_data
                .swap_coins
                .iter()
                .map(|sc| (sc.get_multisig_redeemscript(), sc.clone()))
                .collect::<HashMap<Script, WalletSwapCoin>>(),
        };
        Ok(wallet)
    }

    pub fn update_external_index(&mut self, new_external_index: u32) -> Result<(), Error> {
        self.external_index = new_external_index;
        let mut wallet_file_data = Wallet::load_wallet_file_data(&self.wallet_file_name)?;
        wallet_file_data.external_index = new_external_index;
        let wallet_file = File::create(&self.wallet_file_name[..])?;
        serde_json::to_writer(wallet_file, &wallet_file_data).map_err(|e| io::Error::from(e))?;
        Ok(())
    }

    #[cfg(test)]
    pub fn get_external_index(&self) -> u32 {
        self.external_index
    }

    pub fn update_swap_coins_list(&self) -> Result<(), Error> {
        let mut wallet_file_data = Wallet::load_wallet_file_data(&self.wallet_file_name)?;
        wallet_file_data.swap_coins = self
            .swap_coins
            .values()
            .cloned()
            .collect::<Vec<WalletSwapCoin>>();
        let wallet_file = File::create(&self.wallet_file_name[..])?;
        serde_json::to_writer(wallet_file, &wallet_file_data).map_err(|e| io::Error::from(e))?;
        Ok(())
    }

    pub fn find_swapcoin(&self, multisig_redeemscript: &Script) -> Option<&WalletSwapCoin> {
        self.swap_coins.get(multisig_redeemscript)
    }

    pub fn find_swapcoin_mut(
        &mut self,
        multisig_redeemscript: &Script,
    ) -> Option<&mut WalletSwapCoin> {
        self.swap_coins.get_mut(multisig_redeemscript)
    }

    pub fn add_swapcoin(&mut self, coin: WalletSwapCoin) {
        self.swap_coins
            .insert(coin.get_multisig_redeemscript(), coin);
    }

    #[cfg(test)]
    pub fn get_swap_coins_count(&self) -> usize {
        self.swap_coins.len()
    }

    //this function is used in two places
    //once when maker has received message signsendercontracttx
    //again when maker receives message proofoffunding
    //
    //cases when receiving signsendercontracttx
    //case 1: prevout in cache doesnt have any contract => ok
    //case 2: prevout has a contract and it matches given contract => ok
    //case 3: prevout has a contract and it doesnt match contract => reject
    //
    //cases when receiving proofoffunding
    //case 1: prevout doesnt have an entry => weird, how did they get a sig
    //case 2: prevout has an entry which matches contract => ok
    //case 3: prevout has an entry which doesnt match contract => reject
    //
    //so the two cases are the same except for case 1 for proofoffunding which
    //shouldnt happen at all
    //
    //only time it returns false is when prevout doesnt match cached contract
    pub fn does_prevout_match_cached_contract(
        &self,
        prevout: &OutPoint,
        contract_scriptpubkey: &Script,
    ) -> Result<bool, Error> {
        let wallet_file_data = Wallet::load_wallet_file_data(&self.wallet_file_name[..])?;
        Ok(
            match wallet_file_data.prevout_to_contract_map.get(prevout) {
                Some(c) => c == contract_scriptpubkey,
                None => true,
            },
        )
    }

    pub fn add_prevout_and_contract_to_cache(
        &mut self,
        prevout: OutPoint,
        contract: Script,
    ) -> Result<(), Error> {
        let mut wallet_file_data = Wallet::load_wallet_file_data(&self.wallet_file_name[..])?;
        wallet_file_data
            .prevout_to_contract_map
            .insert(prevout, contract);
        let wallet_file = File::create(&self.wallet_file_name[..])?;
        serde_json::to_writer(wallet_file, &wallet_file_data).map_err(|e| io::Error::from(e))?;
        Ok(())
    }

    //pub fn get_recovery_phrase_from_file()

    fn is_xpub_descriptor_imported(&self, rpc: &Client, descriptor: &str) -> Result<bool, Error> {
        let first_addr = rpc.derive_addresses(&descriptor, Some([0, 0]))?[0].clone();
        let last_index = (INITIAL_ADDRESS_IMPORT_COUNT - 1) as u32;
        let last_addr =
            rpc.derive_addresses(&descriptor, Some([last_index, last_index]))?[0].clone();

        //this issue
        // https://github.com/rust-bitcoin/rust-bitcoincore-rpc/issues/123
        //means that we cant use get_address_info() instead we have to
        // parse the json ourselves
        let first_addr_imported = rpc.call::<serde_json::Value>(
            "getaddressinfo",
            &[Value::String(first_addr.to_string())],
        )?["iswatchonly"]
            .as_bool()
            .unwrap();
        let last_addr_imported = rpc
            .call::<serde_json::Value>("getaddressinfo", &[Value::String(last_addr.to_string())])?
            ["iswatchonly"]
            .as_bool()
            .unwrap();

        Ok(first_addr_imported && last_addr_imported)
    }

    fn is_swapcoin_descriptor_imported(&self, rpc: &Client, descriptor: &str) -> bool {
        let addr = rpc.derive_addresses(&descriptor, None).unwrap()[0].clone();
        rpc.call::<serde_json::Value>("getaddressinfo", &[Value::String(addr.to_string())])
            .unwrap()["iswatchonly"]
            .as_bool()
            .unwrap()
    }

    pub fn get_hd_wallet_descriptors(&self, rpc: &Client) -> Result<Vec<String>, Error> {
        let secp = Secp256k1::new();
        let wallet_xpub = ExtendedPubKey::from_private(
            &secp,
            &self
                .master_key
                .derive_priv(&secp, &DerivationPath::from_str(DERIVATION_PATH).unwrap())
                .unwrap(),
        );
        let address_type = [0, 1];
        let descriptors: Result<Vec<String>, bitcoincore_rpc::Error> = address_type
            .iter()
            .map(|at| {
                rpc.get_descriptor_info(&format!("wpkh({}/{}/*)", wallet_xpub, at))
                    .map(|getdescriptorinfo_result| getdescriptorinfo_result.descriptor)
            })
            .collect();
        descriptors.map_err(|e| Error::Rpc(e))
    }

    fn get_core_wallet_label(&self) -> String {
        let secp = Secp256k1::new();
        let m_xpub = ExtendedPubKey::from_private(&secp, &self.master_key);
        m_xpub.fingerprint().to_string()
    }

    pub fn import_initial_addresses(
        &self,
        rpc: &Client,
        hd_descriptors_to_import: &[&String],
        swapcoin_descriptors_to_import: &[String],
    ) -> Result<(), Error> {
        let address_label = self.get_core_wallet_label();

        let import_requests = hd_descriptors_to_import
            .iter()
            .map(|desc| ImportMultiRequest {
                timestamp: ImportMultiRescanSince::Now,
                descriptor: Some(desc),
                range: Some((0, INITIAL_ADDRESS_IMPORT_COUNT - 1)),
                watchonly: Some(true),
                label: Some(&address_label),
                ..Default::default()
            })
            .chain(
                swapcoin_descriptors_to_import
                    .iter()
                    .map(|desc| ImportMultiRequest {
                        timestamp: ImportMultiRescanSince::Now,
                        descriptor: Some(desc),
                        watchonly: Some(true),
                        label: Some(&address_label),
                        ..Default::default()
                    }),
            )
            .collect::<Vec<ImportMultiRequest>>();

        let result = rpc.import_multi(
            &import_requests,
            Some(&ImportMultiOptions {
                rescan: Some(false),
            }),
        )?;
        for r in result {
            if !r.success {
                return Err(Error::Rpc(bitcoincore_rpc::Error::UnexpectedStructure));
            }
        }
        Ok(())
    }

    pub fn startup_sync(&mut self, rpc: &Client) -> Result<(), Error> {
        //TODO many of these unwraps to be replaced with proper error handling

        let hd_descriptors = self.get_hd_wallet_descriptors(rpc)?;
        let hd_descriptors_to_import = hd_descriptors
            .iter()
            .filter(|d| !self.is_xpub_descriptor_imported(rpc, &d).unwrap())
            .collect::<Vec<&String>>();

        let swapcoin_descriptors_to_import = self
            .swap_coins
            .values()
            .map(|sc| {
                format!(
                    "wsh(sortedmulti(2,{},{}))",
                    sc.other_pubkey,
                    sc.get_my_pubkey()
                )
            })
            .map(|d| rpc.get_descriptor_info(&d).unwrap().descriptor)
            .filter(|d| !self.is_swapcoin_descriptor_imported(rpc, &d))
            .collect::<Vec<String>>();

        if hd_descriptors_to_import.is_empty() && swapcoin_descriptors_to_import.is_empty() {
            return Ok(());
        }

        log::trace!(target: "wallet", "new wallet detected, synchronizing balance...");
        self.import_initial_addresses(
            rpc,
            &hd_descriptors_to_import,
            &swapcoin_descriptors_to_import,
        )?;

        rpc.call::<Value>("scantxoutset", &[json!("abort")])?;
        let desc_list = hd_descriptors_to_import
            .iter()
            .map(|d| {
                json!(
                {"desc": d,
                "range": INITIAL_ADDRESS_IMPORT_COUNT-1})
            })
            .chain(swapcoin_descriptors_to_import.iter().map(|d| json!(d)))
            .collect::<Vec<Value>>();

        let scantxoutset_result: Value =
            rpc.call("scantxoutset", &[json!("start"), json!(desc_list)])?;
        if !scantxoutset_result["success"].as_bool().unwrap() {
            return Err(Error::Rpc(bitcoincore_rpc::Error::UnexpectedStructure));
        }
        for unspent in scantxoutset_result["unspents"].as_array().unwrap() {
            let blockhash = rpc.get_block_hash(unspent["height"].as_u64().unwrap())?;
            let txid = Txid::from_hex(unspent["txid"].as_str().unwrap()).unwrap();
            let rawtx = rpc.get_raw_transaction_hex(&txid, Some(&blockhash));
            if let Ok(rawtx_hex) = rawtx {
                let merkleproof = rpc.get_tx_out_proof(&[txid], Some(&blockhash))?.to_hex();
                rpc.call(
                    "importprunedfunds",
                    &[Value::String(rawtx_hex), Value::String(merkleproof)],
                )?;
            } else {
                log::error!(target: "wallet", "block pruned, TODO add UTXO to wallet file");
                panic!("teleport doesnt work with pruning yet, try rescanning");
            }
        }

        let max_external_index = self.find_hd_next_index(rpc, 0)?;
        self.update_external_index(max_external_index)?;
        Ok(())
    }

    fn is_utxo_ours_and_spendable(&self, u: &ListUnspentResultEntry) -> bool {
        if u.descriptor.is_none() {
            return false;
        }
        let descriptor = u.descriptor.as_ref().unwrap();
        if let Some(ret) = self.get_hd_path_from_descriptor(&descriptor) {
            //utxo is in a hd wallet
            let (fingerprint, _, _) = ret;

            let secp = Secp256k1::new();
            let master_private_key = self
                .master_key
                .derive_priv(&secp, &DerivationPath::from_str(DERIVATION_PATH).unwrap())
                .unwrap();
            fingerprint == master_private_key.fingerprint(&secp).to_string()
        } else {
            //utxo might be one of our swapcoins
            self.find_swapcoin(
                u.witness_script
                    .as_ref()
                    .unwrap_or(&Script::from(Vec::from_hex("").unwrap())),
            )
            .map_or(false, |sc| sc.other_privkey.is_some())
        }
    }

    pub fn lock_all_nonwallet_unspents(&self, rpc: &Client) -> Result<(), Error> {
        //rpc.unlock_unspent(&[])?;
        //https://github.com/rust-bitcoin/rust-bitcoincore-rpc/issues/148
        rpc.call::<Value>("lockunspent", &[Value::Bool(true)])?;

        let all_unspents = rpc.list_unspent(None, None, None, None, None)?;
        let utxos_to_lock = &all_unspents
            .into_iter()
            .filter(|u| !self.is_utxo_ours_and_spendable(u))
            .map(|u| OutPoint {
                txid: u.txid,
                vout: u.vout,
            })
            .collect::<Vec<OutPoint>>();
        rpc.lock_unspent(utxos_to_lock)?;
        Ok(())
    }

    pub fn list_unspent_from_wallet(
        &self,
        rpc: &Client,
    ) -> Result<Vec<ListUnspentResultEntry>, Error> {
        rpc.call::<Value>("lockunspent", &[Value::Bool(true)])
            .map_err(|e| Error::Rpc(e))?;
        Ok(rpc
            .list_unspent(None, None, None, None, None)?
            .iter()
            .filter(|u| self.is_utxo_ours_and_spendable(u))
            .cloned()
            .collect::<Vec<ListUnspentResultEntry>>())
    }

    pub fn find_incomplete_coinswaps(
        &self,
        rpc: &Client,
    ) -> Result<HashMap<[u8; 20], Vec<(ListUnspentResultEntry, &WalletSwapCoin)>>, Error> {
        rpc.call::<Value>("lockunspent", &[Value::Bool(true)])
            .map_err(|e| Error::Rpc(e))?;

        let completed_coinswap_hashvalues = self
            .swap_coins
            .values()
            .filter(|sc| sc.other_privkey.is_some())
            .map(|sc| read_hashvalue_from_contract(&sc.contract_redeemscript).unwrap())
            .collect::<HashSet<[u8; 20]>>();
        //TODO make this read_hashvalue_from_contract() a struct function of WalletCoinSwap

        let mut incomplete_swapcoin_groups =
            HashMap::<[u8; 20], Vec<(ListUnspentResultEntry, &WalletSwapCoin)>>::new();
        for utxo in rpc.list_unspent(None, None, None, None, None)? {
            if utxo.descriptor.is_none() {
                continue;
            }
            let multisig_redeemscript = if let Some(rs) = utxo.witness_script.as_ref() {
                rs
            } else {
                continue;
            };
            let swapcoin = if let Some(s) = self.find_swapcoin(multisig_redeemscript) {
                s
            } else {
                continue;
            };
            if swapcoin.other_privkey.is_some() {
                continue;
            }
            let swapcoin_hashvalue = read_hashvalue_from_contract(&swapcoin.contract_redeemscript)
                .expect("unable to read hashvalue from contract_redeemscript");
            if completed_coinswap_hashvalues.contains(&swapcoin_hashvalue) {
                continue;
            }
            incomplete_swapcoin_groups
                .entry(swapcoin_hashvalue)
                .or_insert(Vec::<(ListUnspentResultEntry, &WalletSwapCoin)>::new())
                .push((utxo, swapcoin));
        }
        Ok(incomplete_swapcoin_groups)
    }

    // returns None if not a hd descriptor (but possibly a swapcoin (multisig) descriptor instead)
    fn get_hd_path_from_descriptor<'a>(&self, descriptor: &'a str) -> Option<(&'a str, u32, i32)> {
        //e.g
        //"desc": "wpkh([a945b5ca/1/1]029b77637989868dcd502dbc07d6304dc2150301693ae84a60b379c3b696b289ad)#aq759em9",
        let open = descriptor.find('[');
        let close = descriptor.find(']');
        if open.is_none() || close.is_none() {
            //unexpected, so printing it to stdout
            println!("unknown descriptor = {}", descriptor);
            return None;
        }
        let path = &descriptor[open.unwrap() + 1..close.unwrap()];
        let path_chunks: Vec<&str> = path.split('/').collect();
        if path_chunks.len() != 3 {
            return None;
            //unexpected descriptor = wsh(multi(2,[f67b69a3]0245ddf535f08a04fd86d794b76f8e3949f27f7ae039b641bf277c6a4552b4c387,[dbcd3c6e]030f781e9d2a6d3a823cee56be2d062ed4269f5a6294b20cb8817eb540c641d9a2))#8f70vn2q
        }
        let addr_type = path_chunks[1].parse::<u32>();
        if addr_type.is_err() {
            log::trace!(target: "wallet", "unexpected address_type = {}", path);
            return None;
        }
        let index = path_chunks[2].parse::<i32>();
        if index.is_err() {
            return None;
        }
        Some((path_chunks[0], addr_type.unwrap(), index.unwrap()))
    }

    fn find_hd_next_index(&self, rpc: &Client, address_type: u32) -> Result<u32, Error> {
        let mut max_index: i32 = -1;
        //TODO error handling
        let utxos = self.list_unspent_from_wallet(rpc)?;
        for utxo in utxos {
            if utxo.descriptor.is_none() {
                continue;
            }
            let descriptor = utxo.descriptor.unwrap();
            let ret = self.get_hd_path_from_descriptor(&descriptor);
            if ret.is_none() {
                continue;
            }
            let (_, addr_type, index) = ret.unwrap();
            if addr_type != address_type {
                continue;
            }
            max_index = std::cmp::max(max_index, index);
        }
        Ok((max_index + 1) as u32)
    }

    pub fn get_next_external_address(&mut self, rpc: &Client) -> Result<Address, Error> {
        let receive_branch_descriptor = &self.get_hd_wallet_descriptors(rpc)?[0];
        let receive_address = rpc.derive_addresses(
            receive_branch_descriptor,
            Some([self.external_index, self.external_index]),
        )?[0]
            .clone();
        self.update_external_index(self.external_index + 1)?;
        Ok(receive_address)
    }

    pub fn get_offer_maxsize(&self, rpc: Arc<Client>) -> Result<u64, Error> {
        let utxos = self.list_unspent_from_wallet(&rpc)?;
        let balance: Amount = utxos.iter().fold(Amount::ZERO, |acc, u| acc + u.amount);
        Ok(balance.as_sat())
    }

    pub fn get_tweakable_keypair(&self) -> (SecretKey, PublicKey) {
        let secp = Secp256k1::new();
        let privkey = self
            .master_key
            .ckd_priv(&secp, ChildNumber::from_hardened_idx(0).unwrap())
            .unwrap()
            .private_key;
        (privkey.key, privkey.public_key(&secp))
    }

    fn sign_transaction(&self, spending_tx: &mut Transaction, decoded_psbt: &Value) {
        let secp = Secp256k1::new();
        let master_private_key = self
            .master_key
            .derive_priv(&secp, &DerivationPath::from_str(DERIVATION_PATH).unwrap())
            .unwrap();
        let tx_clone = spending_tx.clone();

        for (ix, (mut input, input_info)) in spending_tx
            .input
            .iter_mut()
            .zip(decoded_psbt["inputs"].as_array().unwrap())
            .enumerate()
        {
            let bip32_info = &input_info["bip32_derivs"].as_array().unwrap();

            if bip32_info.len() == 2 {
                //signing multisig input
                let redeemscript = Builder::from(
                    Vec::from_hex(&input_info["witness_script"]["hex"].as_str().unwrap()).unwrap(),
                )
                .into_script();

                self.find_swapcoin(&redeemscript)
                    .unwrap()
                    .sign_transaction_input(ix, &tx_clone, &mut input, &redeemscript)
                    .unwrap();
            } else {
                //signing single sig input
                let path = bip32_info[0]["path"].as_str().unwrap();

                let privkey = master_private_key
                    .derive_priv(&secp, &DerivationPath::from_str(path).unwrap())
                    .unwrap()
                    .private_key;
                let pubkey = privkey.public_key(&secp);
                assert_eq!(pubkey.to_bytes().to_hex(), bip32_info[0]["pubkey"]);

                let input_value =
                    convert_json_rpc_bitcoin_to_satoshis(&input_info["witness_utxo"]["amount"]);
                let scriptcode = Script::new_p2pkh(&pubkey.pubkey_hash());
                let sighash = SigHashCache::new(&tx_clone).signature_hash(
                    ix,
                    &scriptcode,
                    input_value,
                    SigHashType::All,
                );
                //TODO use low-R value signatures for privacy
                //https://en.bitcoin.it/wiki/Privacy#Wallet_fingerprinting
                let signature = secp.sign(
                    &secp256k1::Message::from_slice(&sighash[..]).unwrap(),
                    &privkey.key,
                );
                input.witness.push(signature.serialize_der().to_vec());
                input.witness[0].push(SigHashType::All as u8);
                input.witness.push(pubkey.to_bytes());
            }
        }
    }

    fn generate_amount_fractions(count: usize, total_amount: u64, lower_limit: u64) -> Vec<f32> {
        loop {
            let mut knives = (1..count)
                .map(|_| OsRng.next_u32() as f32 / u32::MAX as f32)
                .collect::<Vec<f32>>();
            knives.sort_by(|a, b| b.partial_cmp(a).unwrap_or(std::cmp::Ordering::Equal));

            let mut fractions = Vec::<f32>::new();
            let mut last: f32 = 1.0;
            for k in knives {
                fractions.push(last - k);
                last = k;
            }
            fractions.push(last);

            if fractions
                .iter()
                .all(|f| *f * (total_amount as f32) > lower_limit as f32)
            {
                return fractions;
            }
        }
    }

    fn create_spending_txes(
        &self,
        rpc: &Client,
        coinswap_amount: u64,
        destinations: &[Address],
    ) -> Result<(Vec<Transaction>, Vec<u32>, Vec<u64>), Error> {
        //return funding_txes, position_of_output, output_value

        //TODO needs perhaps better way to create multiple txes for
        //multi-tx-coinswap could try multiple ways, and in combination
        //* use walletcreatefundedpsbt for the total amount, and if
        //  the number if inputs UTXOs is >number_of_txes then you're done
        //* come up with your own algorithm that sums up UTXOs
        //  would lose bitcoin core's cool utxo choosing algorithm though
        //  until their total value is >desired_amount
        //* use listunspent with minimumSumAmount
        //* pick individual utxos for no-change txes, and for the last one
        //  use walletcreatefundedpsbt which will create change

        //* randomly generate some satoshi amounts and send them into
        //  walletcreatefundedpsbt to create funding txes that create change
        //this is the solution used right now

        let next_change_addr_index = self.find_hd_next_index(rpc, 1)?;
        let change_branch_descriptor = &self.get_hd_wallet_descriptors(rpc)?[1];
        let change_addresses = rpc
            .derive_addresses(
                change_branch_descriptor,
                Some([
                    next_change_addr_index,
                    next_change_addr_index + destinations.len() as u32,
                ]),
            )
            .unwrap();

        self.lock_all_nonwallet_unspents(rpc)?;
        let mut output_values = Wallet::generate_amount_fractions(
            destinations.len(),
            coinswap_amount,
            5000, //use 5000 satoshi as the lower limit for now
        )
        .iter()
        .map(|f| (*f * coinswap_amount as f32) as u64)
        .collect::<Vec<u64>>();

        //rounding errors mean usually 1 or 2 satoshis are lost, add them back

        //this calculation works like this:
        //o = [a, b, c, ...]             | list of output values
        //t = coinswap amount            | total desired value
        //a <-- a + (t - (a+b+c+...))    | assign new first output value
        //a <-- a + (t -a-b-c-...)       | rearrange
        //a <-- t - b - c -...           |
        *output_values.first_mut().unwrap() =
            coinswap_amount - output_values.iter().skip(1).sum::<u64>();
        assert_eq!(output_values.iter().sum::<u64>(), coinswap_amount);

        let mut spending_txes = Vec::<Transaction>::new();
        let mut payment_output_positions = Vec::<u32>::new();
        for (address, &output_value, change_address) in izip!(
            destinations.iter(),
            output_values.iter(),
            change_addresses.iter()
        ) {
            log::trace!(target: "wallet", "output_value = {} to addr={}", output_value, address);

            let mut outputs = HashMap::<String, Amount>::new();
            outputs.insert(address.to_string(), Amount::from_sat(output_value));

            let psbt_result = rpc.wallet_create_funded_psbt(
                &[],
                &outputs,
                None,
                Some(WalletCreateFundedPsbtOptions {
                    include_watching: Some(true),
                    change_address: Some(change_address.clone()),
                    fee_rate: Some(Amount::from_btc(0.0001).unwrap()),
                    ..Default::default()
                }),
                None,
            )?;
            let decoded_psbt =
                rpc.call::<Value>("decodepsbt", &[Value::String(psbt_result.psbt)])?;

            //TODO proper error handling, theres many unwrap()s here
            //make this function return Result<>
            let inputs = decoded_psbt["tx"]["vin"]
                .as_array()
                .unwrap()
                .iter()
                .map(|vin| TxIn {
                    previous_output: OutPoint {
                        txid: Txid::from_hex(vin["txid"].as_str().unwrap()).unwrap(),
                        vout: vin["vout"].as_u64().unwrap() as u32,
                    },
                    sequence: 0,
                    witness: Vec::new(),
                    script_sig: Script::new(),
                })
                .collect::<Vec<TxIn>>();
            rpc.lock_unspent(
                &inputs
                    .iter()
                    .map(|vin| vin.previous_output)
                    .collect::<Vec<OutPoint>>(),
            )?;
            let outputs = decoded_psbt["tx"]["vout"]
                .as_array()
                .unwrap()
                .iter()
                .map(|vout| TxOut {
                    script_pubkey: Builder::from(
                        Vec::from_hex(vout["scriptPubKey"]["hex"].as_str().unwrap()).unwrap(),
                    )
                    .into_script(),
                    value: convert_json_rpc_bitcoin_to_satoshis(&vout["value"]),
                })
                .collect::<Vec<TxOut>>();

            let mut spending_tx = Transaction {
                input: inputs,
                output: outputs,
                lock_time: 0,
                version: 2,
            };
            self.sign_transaction(&mut spending_tx, &decoded_psbt);

            log::trace!(target: "wallet",
                "txhex = {}",
                bitcoin::consensus::encode::serialize_hex(&spending_tx)
            );

            let payment_pos = if psbt_result.change_position == 0 {
                1
            } else {
                0
            };

            spending_txes.push(spending_tx);
            payment_output_positions.push(payment_pos);
        }

        Ok((spending_txes, payment_output_positions, output_values))
    }

    fn create_and_import_coinswap_address(
        &mut self,
        rpc: &Client,
        other_pubkey: &PublicKey,
    ) -> (Address, SecretKey) {
        let (my_pubkey, my_privkey) = generate_keypair();

        let descriptor = rpc
            .get_descriptor_info(&format!(
                "wsh(sortedmulti(2,{},{}))",
                my_pubkey, other_pubkey
            ))
            .unwrap()
            .descriptor;

        let address_label = self.get_core_wallet_label();
        let result = rpc
            .import_multi(
                &[ImportMultiRequest {
                    timestamp: ImportMultiRescanSince::Now,
                    descriptor: Some(&descriptor),
                    watchonly: Some(true),
                    label: Some(&address_label),
                    ..Default::default()
                }],
                Some(&ImportMultiOptions {
                    rescan: Some(false),
                }),
            )
            .unwrap();
        for r in result {
            if !r.success {
                //TODO proper error handling
                panic!("failed import");
            }
        }
        //redeemscript and descriptor show up in `getaddressinfo` only after
        // the address gets outputs on it
        (
            //TODO should completely avoid derive_addresses
            //because its slower and provides no benefit over using rust-bitcoin
            rpc.derive_addresses(&descriptor[..], None).unwrap()[0].clone(),
            my_privkey,
        )
    }

    pub fn import_redeemscript(
        &self,
        rpc: &Client,
        redeemscript: &Script,
        address_label_type: CoreAddressLabelType,
    ) -> Result<(), Error> {
        let address_label = match address_label_type {
            CoreAddressLabelType::Wallet => self.get_core_wallet_label(),
            CoreAddressLabelType::WatchOnlySwapCoin => WATCH_ONLY_SWAPCOIN_LABEL.to_string(),
        };
        let spk = Address::p2wsh(&redeemscript, NETWORK).script_pubkey();
        let result = rpc.import_multi(
            &[ImportMultiRequest {
                timestamp: ImportMultiRescanSince::Now,
                script_pubkey: Some(ImportMultiRequestScriptPubkey::Script(&spk)),
                redeem_script: Some(redeemscript),
                watchonly: Some(true),
                label: Some(&address_label),
                ..Default::default()
            }],
            Some(&ImportMultiOptions {
                rescan: Some(false),
            }),
        )?;
        for r in result {
            if !r.success {
                return Err(Error::Rpc(bitcoincore_rpc::Error::UnexpectedStructure));
            }
        }
        Ok(())
    }

    pub fn import_tx_with_merkleproof(
        &self,
        rpc: &Client,
        tx: &Transaction,
        merkleproof: String,
    ) -> Result<(), Error> {
        let rawtx_hex = bitcoin::consensus::encode::serialize(tx).to_hex();

        rpc.call(
            "importprunedfunds",
            &[Value::String(rawtx_hex), Value::String(merkleproof)],
        )?;
        Ok(())
    }

    pub fn initalize_coinswap(
        &mut self,
        rpc: &Client,
        total_coinswap_amount: u64,
        other_multisig_pubkeys: &[PublicKey],
        hashlock_pubkeys: &[PublicKey],
        hashvalue: [u8; 20],
        locktime: u16, //returns: funding_txes, swapcoins, timelock_pubkeys
    ) -> Result<(Vec<Transaction>, Vec<WalletSwapCoin>, Vec<PublicKey>), Error> {
        let (coinswap_addresses, my_multisig_privkeys): (Vec<_>, Vec<_>) = other_multisig_pubkeys
            .iter()
            .map(|other_key| self.create_and_import_coinswap_address(rpc, other_key))
            .unzip();
        log::trace!(target: "wallet", "coinswap_addresses = {:#?}", coinswap_addresses);

        let (my_funding_txes, utxo_indexes, funding_amounts) =
            self.create_spending_txes(rpc, total_coinswap_amount, &coinswap_addresses)?;
        //for sweeping there would be another function, probably
        //probably have an enum called something like SendAmount which can be
        // an integer but also can be Sweep

        let mut timelock_pubkeys = Vec::<PublicKey>::new();
        let mut outgoing_swapcoins = Vec::<WalletSwapCoin>::new();

        for (
            my_funding_tx,
            utxo_index,
            &my_multisig_privkey,
            &other_multisig_pubkey,
            hashlock_pubkey,
            &funding_amount,
        ) in izip!(
            my_funding_txes.iter(),
            utxo_indexes.iter(),
            my_multisig_privkeys.iter(),
            other_multisig_pubkeys.iter(),
            hashlock_pubkeys.iter(),
            funding_amounts.iter()
        ) {
            let (timelock_pubkey, timelock_privkey) = generate_keypair();
            let contract_redeemscript = contracts::create_contract_redeemscript(
                hashlock_pubkey,
                &timelock_pubkey,
                hashvalue,
                locktime,
            );
            let my_senders_contract_tx = contracts::create_senders_contract_tx(
                OutPoint {
                    txid: my_funding_tx.txid(),
                    vout: *utxo_index,
                },
                funding_amount,
                &contract_redeemscript,
            );

            timelock_pubkeys.push(timelock_pubkey);
            outgoing_swapcoins.push(WalletSwapCoin::new(
                my_multisig_privkey,
                other_multisig_pubkey,
                my_senders_contract_tx,
                contract_redeemscript,
                timelock_privkey,
                funding_amount,
            ));
        }

        Ok((my_funding_txes, outgoing_swapcoins, timelock_pubkeys))
    }
}

pub fn generate_keypair() -> (PublicKey, SecretKey) {
    let mut privkey = [0u8; 32];
    OsRng.fill_bytes(&mut privkey);
    let secp = Secp256k1::new();
    let privkey = SecretKey::from_slice(&privkey).unwrap();
    let pubkey = PublicKey {
        compressed: true,
        key: secp256k1::PublicKey::from_secret_key(&secp, &privkey),
    };
    (pubkey, privkey)
}

pub fn create_multisig_redeemscript(key1: &PublicKey, key2: &PublicKey) -> Script {
    let builder = Builder::new().push_opcode(all::OP_PUSHNUM_2);
    if key1.serialize()[..] < key2.serialize()[..] {
        builder.push_key(key1).push_key(key2)
    } else {
        builder.push_key(key2).push_key(key1)
    }
    .push_opcode(all::OP_PUSHNUM_2)
    .push_opcode(all::OP_CHECKMULTISIG)
    .into_script()
}

fn convert_json_rpc_bitcoin_to_satoshis(amount: &Value) -> u64 {
    //to avoid floating point arithmetic, convert the bitcoin amount to
    //string with 8 decimal places, then remove the decimal point to
    //obtain the value in satoshi
    //this is necessary because the json rpc represents bitcoin values
    //as floats :(
    format!("{:.8}", amount.as_f64().unwrap())
        .replace(".", "")
        .parse::<u64>()
        .unwrap()
}
