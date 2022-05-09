// this file contains code handling the wallet and sync'ing the wallet
// for now the wallet is only sync'd via bitcoin core's RPC
// makers will only ever sync this way, but one day takers may sync in other
// ways too such as a lightweight wallet method

use std::fs::{File, OpenOptions};
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
    hashes::{
        hash160::Hash as Hash160,
        hex::{FromHex, ToHex},
    },
    secp256k1,
    secp256k1::{Secp256k1, SecretKey, Signature},
    util::{
        bip143::SigHashCache,
        bip32::{ChildNumber, DerivationPath, ExtendedPrivKey, ExtendedPubKey},
        ecdsa::PublicKey,
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
use crate::contracts::SwapCoin;
use crate::error::Error;
use crate::fidelity_bonds;
use crate::messages::Preimage;

//these subroutines are coded so that as much as possible they keep all their
//data in the bitcoin core wallet
//for example which privkey corresponds to a scriptpubkey is stored in hd paths

const DERIVATION_PATH: &str = "m/84'/1'/0'";
const WALLET_FILE_VERSION: u32 = 0;

//TODO the wallet file format is probably best handled with sqlite

#[derive(serde::Serialize, serde::Deserialize)]
struct WalletFileData {
    version: u32,
    seedphrase: String,
    extension: String,
    external_index: u32,
    incoming_swapcoins: Vec<IncomingSwapCoin>,
    outgoing_swapcoins: Vec<OutgoingSwapCoin>,
    prevout_to_contract_map: HashMap<OutPoint, Script>,
}

pub struct Wallet {
    pub network: Network,
    pub master_key: ExtendedPrivKey,
    wallet_file_name: String,
    external_index: u32,
    initial_address_import_count: usize,
    incoming_swapcoins: HashMap<Script, IncomingSwapCoin>,
    outgoing_swapcoins: HashMap<Script, OutgoingSwapCoin>,
    offer_maxsize_cache: u64,
    timelocked_script_index_map: HashMap<Script, u32>,
}

pub enum WalletSyncAddressAmount {
    Normal,
    Testing,
}

const WATCH_ONLY_SWAPCOIN_LABEL: &str = "watchonly_swapcoin_label";

//data needed to find information  in addition to ListUnspentResultEntry
//about a UTXO required to spend it
#[derive(Debug, Clone)]
pub enum UTXOSpendInfo {
    SeedCoin {
        path: String,
        input_value: u64,
    },
    SwapCoin {
        multisig_redeemscript: Script,
    },
    TimelockContract {
        swapcoin_multisig_redeemscript: Script,
        input_value: u64,
    },
    HashlockContract {
        swapcoin_multisig_redeemscript: Script,
        input_value: u64,
    },
    FidelityBondCoin {
        index: u32,
        input_value: u64,
    },
}

//swapcoins are UTXOs + metadata which are not from the deterministic wallet
//they are made in the process of a coinswap
#[derive(serde::Serialize, serde::Deserialize, Debug, Clone)]
pub struct IncomingSwapCoin {
    pub my_privkey: SecretKey,
    pub other_pubkey: PublicKey,
    pub other_privkey: Option<SecretKey>,
    pub contract_tx: Transaction,
    pub contract_redeemscript: Script,
    pub hashlock_privkey: SecretKey,
    pub funding_amount: u64,
    pub others_contract_sig: Option<Signature>,
    pub hash_preimage: Option<Preimage>,
}

//swapcoins are UTXOs + metadata which are not from the deterministic wallet
//they are made in the process of a coinswap
#[derive(serde::Serialize, serde::Deserialize, Debug, Clone)]
pub struct OutgoingSwapCoin {
    pub my_privkey: SecretKey,
    pub other_pubkey: PublicKey,
    pub contract_tx: Transaction,
    pub contract_redeemscript: Script,
    pub timelock_privkey: SecretKey,
    pub funding_amount: u64,
    pub others_contract_sig: Option<Signature>,
    pub hash_preimage: Option<Preimage>,
}

impl IncomingSwapCoin {
    pub fn new(
        my_privkey: SecretKey,
        other_pubkey: PublicKey,
        contract_tx: Transaction,
        contract_redeemscript: Script,
        hashlock_privkey: SecretKey,
        funding_amount: u64,
    ) -> Self {
        let secp = Secp256k1::new();
        let hashlock_pubkey = PublicKey {
            compressed: true,
            key: secp256k1::PublicKey::from_secret_key(&secp, &hashlock_privkey),
        };
        assert!(
            hashlock_pubkey
                == contracts::read_hashlock_pubkey_from_contract(&contract_redeemscript).unwrap()
        );
        Self {
            my_privkey,
            other_pubkey,
            other_privkey: None,
            contract_tx,
            contract_redeemscript,
            hashlock_privkey,
            funding_amount,
            others_contract_sig: None,
            hash_preimage: None,
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

        apply_two_signatures_to_2of2_multisig_spend(
            &my_pubkey,
            &self.other_pubkey,
            &sig_mine,
            &sig_other,
            input,
            redeemscript,
        );
        Ok(())
    }

    fn sign_hashlocked_transaction_input_given_preimage(
        &self,
        index: usize,
        tx: &Transaction,
        input: &mut TxIn,
        input_value: u64,
        hash_preimage: &[u8],
    ) {
        let secp = Secp256k1::new();
        let sighash = secp256k1::Message::from_slice(
            &SigHashCache::new(tx).signature_hash(
                index,
                &self.contract_redeemscript,
                input_value,
                SigHashType::All,
            )[..],
        )
        .unwrap();

        let sig_hashlock = secp.sign(&sighash, &self.hashlock_privkey);
        input.witness.push(sig_hashlock.serialize_der().to_vec());
        input.witness[0].push(SigHashType::All as u8);
        input.witness.push(hash_preimage.to_vec());
        input.witness.push(self.contract_redeemscript.to_bytes());
    }

    fn sign_hashlocked_transaction_input(
        &self,
        index: usize,
        tx: &Transaction,
        input: &mut TxIn,
        input_value: u64,
    ) {
        if self.hash_preimage.is_none() {
            panic!("invalid state, unable to sign: preimage unknown");
        }
        self.sign_hashlocked_transaction_input_given_preimage(
            index,
            tx,
            input,
            input_value,
            &self.hash_preimage.unwrap(),
        )
    }

    pub fn create_hashlock_spend_without_preimage(
        &self,
        destination_address: &Address,
    ) -> Transaction {
        let miner_fee = 136 * 10; //126 vbytes x 10 sat/vb, size calculated using testmempoolaccept
        let mut tx = Transaction {
            input: vec![TxIn {
                previous_output: OutPoint {
                    txid: self.contract_tx.txid(),
                    vout: 0, //contract_tx is one-input-one-output
                },
                sequence: 1, //hashlock spends must have 1 because of the `OP_CSV 1`
                witness: Vec::new(),
                script_sig: Script::new(),
            }],
            output: vec![TxOut {
                script_pubkey: destination_address.script_pubkey(),
                value: self.contract_tx.output[0].value - miner_fee,
            }],
            lock_time: 0,
            version: 2,
        };
        let index = 0;
        let preimage = Vec::new();
        self.sign_hashlocked_transaction_input_given_preimage(
            index,
            &tx.clone(),
            &mut tx.input[0],
            self.contract_tx.output[0].value,
            &preimage,
        );
        tx
    }
}

impl OutgoingSwapCoin {
    pub fn new(
        my_privkey: SecretKey,
        other_pubkey: PublicKey,
        contract_tx: Transaction,
        contract_redeemscript: Script,
        timelock_privkey: SecretKey,
        funding_amount: u64,
    ) -> Self {
        let secp = Secp256k1::new();
        let timelock_pubkey = PublicKey {
            compressed: true,
            key: secp256k1::PublicKey::from_secret_key(&secp, &timelock_privkey),
        };
        assert!(
            timelock_pubkey
                == contracts::read_timelock_pubkey_from_contract(&contract_redeemscript).unwrap()
        );
        Self {
            my_privkey,
            other_pubkey,
            contract_tx,
            contract_redeemscript,
            timelock_privkey,
            funding_amount,
            others_contract_sig: None,
            hash_preimage: None,
        }
    }

    fn sign_timelocked_transaction_input(
        &self,
        index: usize,
        tx: &Transaction,
        input: &mut TxIn,
        input_value: u64,
    ) {
        let secp = Secp256k1::new();
        let sighash = secp256k1::Message::from_slice(
            &SigHashCache::new(tx).signature_hash(
                index,
                &self.contract_redeemscript,
                input_value,
                SigHashType::All,
            )[..],
        )
        .unwrap();

        let sig_timelock = secp.sign(&sighash, &self.timelock_privkey);
        input.witness.push(sig_timelock.serialize_der().to_vec());
        input.witness[0].push(SigHashType::All as u8);
        input.witness.push(Vec::new());
        input.witness.push(self.contract_redeemscript.to_bytes());
    }

    pub fn create_timelock_spend(&self, destination_address: &Address) -> Transaction {
        let miner_fee = 128 * 1; //128 vbytes x 1 sat/vb, size calculated using testmempoolaccept
        let mut tx = Transaction {
            input: vec![TxIn {
                previous_output: OutPoint {
                    txid: self.contract_tx.txid(),
                    vout: 0, //contract_tx is one-input-one-output
                },
                sequence: self.get_timelock() as u32,
                witness: Vec::new(),
                script_sig: Script::new(),
            }],
            output: vec![TxOut {
                script_pubkey: destination_address.script_pubkey(),
                value: self.contract_tx.output[0].value - miner_fee,
            }],
            lock_time: 0,
            version: 2,
        };
        let index = 0;
        self.sign_timelocked_transaction_input(
            index,
            &tx.clone(),
            &mut tx.input[0],
            self.contract_tx.output[0].value,
        );
        tx
    }
}

pub trait WalletSwapCoin: SwapCoin {
    fn get_my_pubkey(&self) -> PublicKey;
    fn get_other_pubkey(&self) -> &PublicKey;
    fn get_fully_signed_contract_tx(&self) -> Transaction;
}

macro_rules! add_walletswapcoin_functions {
    () => {
        fn get_my_pubkey(&self) -> PublicKey {
            let secp = Secp256k1::new();
            PublicKey {
                compressed: true,
                key: secp256k1::PublicKey::from_secret_key(&secp, &self.my_privkey),
            }
        }

        fn get_other_pubkey(&self) -> &PublicKey {
            &self.other_pubkey
        }

        fn get_fully_signed_contract_tx(&self) -> Transaction {
            if self.others_contract_sig.is_none() {
                panic!("invalid state: others_contract_sig not known");
            }
            let my_pubkey = self.get_my_pubkey();
            let multisig_redeemscript =
                create_multisig_redeemscript(&my_pubkey, &self.other_pubkey);
            let index = 0;
            let secp = Secp256k1::new();
            let sighash = secp256k1::Message::from_slice(
                &SigHashCache::new(&self.contract_tx).signature_hash(
                    index,
                    &multisig_redeemscript,
                    self.funding_amount,
                    SigHashType::All,
                )[..],
            )
            .unwrap();
            let sig_mine = secp.sign(&sighash, &self.my_privkey);

            let mut signed_contract_tx = self.contract_tx.clone();
            apply_two_signatures_to_2of2_multisig_spend(
                &my_pubkey,
                &self.other_pubkey,
                &sig_mine,
                &self.others_contract_sig.unwrap(),
                &mut signed_contract_tx.input[index],
                &multisig_redeemscript,
            );
            signed_contract_tx
        }
    };
}

impl WalletSwapCoin for IncomingSwapCoin {
    add_walletswapcoin_functions!();
}

impl WalletSwapCoin for OutgoingSwapCoin {
    add_walletswapcoin_functions!();
}

impl Wallet {
    pub fn print_wallet_key_data(&self) {
        println!(
            "master key = {}, external_index = {}",
            self.master_key, self.external_index
        );

        for (multisig_redeemscript, swapcoin) in &self.incoming_swapcoins {
            Self::print_script_and_coin(multisig_redeemscript, swapcoin, self.network);
        }
        for (multisig_redeemscript, swapcoin) in &self.outgoing_swapcoins {
            Self::print_script_and_coin(multisig_redeemscript, swapcoin, self.network);
        }
        println!(
            "swapcoin count = {}",
            self.incoming_swapcoins.len() + self.outgoing_swapcoins.len()
        );
    }

    fn print_script_and_coin(script: &Script, coin: &dyn SwapCoin, network: Network) {
        let contract_tx = coin.get_contract_tx();
        println!(
            "{} {}:{} {}",
            Address::p2wsh(script, network),
            contract_tx.input[0].previous_output.txid,
            contract_tx.input[0].previous_output.vout,
            if coin.is_hash_preimage_known() {
                "  known"
            } else {
                "unknown"
            }
        )
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
            incoming_swapcoins: Vec::new(),
            outgoing_swapcoins: Vec::new(),
            prevout_to_contract_map: HashMap::<OutPoint, Script>::new(),
        };
        let wallet_file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(wallet_file_name)?;
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

    pub fn load_wallet_from_file<P: AsRef<Path>>(
        wallet_file_name: P,
        network: Network,
        sync_amount: WalletSyncAddressAmount,
    ) -> Result<Wallet, Error> {
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
        let xprv = ExtendedPrivKey::new_master(network, &seed.0).unwrap();

        log::debug!(target: "wallet",
            "loaded wallet file, external_index={} incoming_swapcoins={} outgoing_swapcoins={}",
            wallet_file_data.external_index,
            wallet_file_data.incoming_swapcoins.len(), wallet_file_data.outgoing_swapcoins.len());

        let wallet = Wallet {
            network,
            master_key: xprv,
            wallet_file_name,
            external_index: wallet_file_data.external_index,
            initial_address_import_count: match sync_amount {
                WalletSyncAddressAmount::Normal => 5000,
                WalletSyncAddressAmount::Testing => 6,
            },
            incoming_swapcoins: wallet_file_data
                .incoming_swapcoins
                .iter()
                .map(|sc| (sc.get_multisig_redeemscript(), sc.clone()))
                .collect::<HashMap<Script, IncomingSwapCoin>>(),
            outgoing_swapcoins: wallet_file_data
                .outgoing_swapcoins
                .iter()
                .map(|sc| (sc.get_multisig_redeemscript(), sc.clone()))
                .collect::<HashMap<Script, OutgoingSwapCoin>>(),
            offer_maxsize_cache: 0,
            timelocked_script_index_map: fidelity_bonds::generate_all_timelocked_addresses(&xprv),
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

    pub fn get_external_index(&self) -> u32 {
        self.external_index
    }

    pub fn update_swapcoins_list(&self) -> Result<(), Error> {
        let mut wallet_file_data = Wallet::load_wallet_file_data(&self.wallet_file_name)?;
        wallet_file_data.incoming_swapcoins = self
            .incoming_swapcoins
            .values()
            .cloned()
            .collect::<Vec<IncomingSwapCoin>>();
        wallet_file_data.outgoing_swapcoins = self
            .outgoing_swapcoins
            .values()
            .cloned()
            .collect::<Vec<OutgoingSwapCoin>>();
        let wallet_file = File::create(&self.wallet_file_name[..])?;
        serde_json::to_writer(wallet_file, &wallet_file_data).map_err(|e| io::Error::from(e))?;
        Ok(())
    }

    pub fn find_incoming_swapcoin(
        &self,
        multisig_redeemscript: &Script,
    ) -> Option<&IncomingSwapCoin> {
        self.incoming_swapcoins.get(multisig_redeemscript)
    }

    pub fn find_outgoing_swapcoin(
        &self,
        multisig_redeemscript: &Script,
    ) -> Option<&OutgoingSwapCoin> {
        self.outgoing_swapcoins.get(multisig_redeemscript)
    }

    pub fn find_incoming_swapcoin_mut(
        &mut self,
        multisig_redeemscript: &Script,
    ) -> Option<&mut IncomingSwapCoin> {
        self.incoming_swapcoins.get_mut(multisig_redeemscript)
    }

    pub fn add_incoming_swapcoin(&mut self, coin: IncomingSwapCoin) {
        self.incoming_swapcoins
            .insert(coin.get_multisig_redeemscript(), coin);
    }

    pub fn add_outgoing_swapcoin(&mut self, coin: OutgoingSwapCoin) {
        self.outgoing_swapcoins
            .insert(coin.get_multisig_redeemscript(), coin);
    }

    pub fn get_swapcoins_count(&self) -> usize {
        self.incoming_swapcoins.len() + self.outgoing_swapcoins.len()
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
        let last_index = (self.initial_address_import_count - 1) as u32;
        let last_addr =
            rpc.derive_addresses(&descriptor, Some([last_index, last_index]))?[0].clone();

        let first_addr_imported = rpc
            .get_address_info(&first_addr)?
            .is_watchonly
            .unwrap_or(false);
        let last_addr_imported = rpc
            .get_address_info(&last_addr)?
            .is_watchonly
            .unwrap_or(false);

        Ok(first_addr_imported && last_addr_imported)
    }

    fn is_swapcoin_descriptor_imported(&self, rpc: &Client, descriptor: &str) -> bool {
        let addr = rpc.derive_addresses(&descriptor, None).unwrap()[0].clone();
        rpc.get_address_info(&addr)
            .unwrap()
            .is_watchonly
            .unwrap_or(false)
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

    pub fn get_core_wallet_label(&self) -> String {
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
        log::debug!(target: "wallet",
            "import_initial_addresses with initial_address_import_count = {}",
            self.initial_address_import_count);
        let address_label = self.get_core_wallet_label();

        let import_requests = hd_descriptors_to_import
            .iter()
            .map(|desc| ImportMultiRequest {
                timestamp: ImportMultiRescanSince::Now,
                descriptor: Some(desc),
                range: Some((0, self.initial_address_import_count - 1)),
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
            .chain(
                self.timelocked_script_index_map
                    .keys()
                    .map(|spk| ImportMultiRequest {
                        timestamp: ImportMultiRescanSince::Now,
                        script_pubkey: Some(ImportMultiRequestScriptPubkey::Script(&spk)),
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

        let mut swapcoin_descriptors_to_import = self
            .incoming_swapcoins
            .values()
            .map(|sc| {
                format!(
                    "wsh(sortedmulti(2,{},{}))",
                    sc.get_other_pubkey(),
                    sc.get_my_pubkey()
                )
            })
            .map(|d| rpc.get_descriptor_info(&d).unwrap().descriptor)
            .filter(|d| !self.is_swapcoin_descriptor_imported(rpc, &d))
            .collect::<Vec<String>>();

        swapcoin_descriptors_to_import.extend(
            self.outgoing_swapcoins
                .values()
                .map(|sc| {
                    format!(
                        "wsh(sortedmulti(2,{},{}))",
                        sc.get_other_pubkey(),
                        sc.get_my_pubkey()
                    )
                })
                .map(|d| rpc.get_descriptor_info(&d).unwrap().descriptor)
                .filter(|d| !self.is_swapcoin_descriptor_imported(rpc, &d)),
        );

        //get first and last timelocked script, check if both are imported
        let first_timelocked_addr = Address::p2wsh(
            &self.get_timelocked_redeemscript_from_index(0),
            self.network,
        );
        let last_timelocked_addr = Address::p2wsh(
            &self.get_timelocked_redeemscript_from_index(
                fidelity_bonds::TIMELOCKED_ADDRESS_COUNT - 1,
            ),
            self.network,
        );
        log::debug!(target: "wallet", "first_timelocked_addr={} last_timelocked_addr={}",
            first_timelocked_addr, last_timelocked_addr);
        let is_timelock_branch_imported = rpc
            .get_address_info(&first_timelocked_addr)?
            .is_watchonly
            .unwrap_or(false)
            && rpc
                .get_address_info(&last_timelocked_addr)?
                .is_watchonly
                .unwrap_or(false);

        log::debug!(target: "wallet",
            concat!("hd_descriptors_to_import.len = {} swapcoin_descriptors_to_import.len = {}",
                " is_timelock_branch_imported = {}"),
            hd_descriptors_to_import.len(), swapcoin_descriptors_to_import.len(),
            is_timelock_branch_imported);
        if hd_descriptors_to_import.is_empty()
            && swapcoin_descriptors_to_import.is_empty()
            && is_timelock_branch_imported
        {
            return Ok(());
        }

        log::info!(target: "wallet", "New wallet detected, synchronizing balance...");
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
                "range": self.initial_address_import_count-1})
            })
            .chain(swapcoin_descriptors_to_import.iter().map(|d| json!(d)))
            .chain(
                self.timelocked_script_index_map
                    .keys()
                    .map(|spk| json!({ "desc": format!("raw({:x})", spk) })),
            )
            .collect::<Vec<Value>>();

        let scantxoutset_result: Value =
            rpc.call("scantxoutset", &[json!("start"), json!(desc_list)])?;
        if !scantxoutset_result["success"].as_bool().unwrap() {
            return Err(Error::Rpc(bitcoincore_rpc::Error::UnexpectedStructure));
        }
        log::info!(target: "wallet", "TxOut set scan complete, found {} btc",
            Amount::from_sat(convert_json_rpc_bitcoin_to_satoshis(&scantxoutset_result["total_amount"])),
        );
        let unspent_list = scantxoutset_result["unspents"].as_array().unwrap();
        log::debug!(target: "wallet", "scantxoutset found_coins={} txouts={} height={} bestblock={}",
            unspent_list.len(),
            scantxoutset_result["txouts"].as_u64().unwrap(),
            scantxoutset_result["height"].as_u64().unwrap(),
            scantxoutset_result["bestblock"].as_str().unwrap(),
        );
        for unspent in unspent_list {
            let blockhash = rpc.get_block_hash(unspent["height"].as_u64().unwrap())?;
            let txid = Txid::from_hex(unspent["txid"].as_str().unwrap()).unwrap();
            let rawtx = rpc.get_raw_transaction_hex(&txid, Some(&blockhash));
            if let Ok(rawtx_hex) = rawtx {
                log::debug!(target: "wallet", "found coin {}:{} {} height={} {}",
                    txid,
                    unspent["vout"].as_u64().unwrap(),
                    Amount::from_sat(convert_json_rpc_bitcoin_to_satoshis(&unspent["amount"])),
                    unspent["height"].as_u64().unwrap(),
                    unspent["desc"].as_str().unwrap(),
                );
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

    fn create_contract_scriptpubkey_outgoing_swapcoin_hashmap(
        &self,
    ) -> HashMap<Script, &OutgoingSwapCoin> {
        self.outgoing_swapcoins
            .values()
            .map(|osc| {
                (
                    contracts::redeemscript_to_scriptpubkey(&osc.contract_redeemscript),
                    osc,
                )
            })
            .collect::<HashMap<Script, &OutgoingSwapCoin>>()
    }

    fn create_contract_scriptpubkey_incoming_swapcoin_hashmap(
        &self,
    ) -> HashMap<Script, &IncomingSwapCoin> {
        self.incoming_swapcoins
            .values()
            .map(|isc| {
                (
                    contracts::redeemscript_to_scriptpubkey(&isc.contract_redeemscript),
                    isc,
                )
            })
            .collect::<HashMap<Script, &IncomingSwapCoin>>()
    }

    fn is_utxo_ours_and_spendable_get_pointer(
        &self,
        u: &ListUnspentResultEntry,
        contract_scriptpubkeys_outgoing_swapcoins: &HashMap<Script, &OutgoingSwapCoin>,
        option_contract_scriptpubkeys_incoming_swapcoins: Option<
            &HashMap<Script, &IncomingSwapCoin>,
        >,
        include_all_fidelity_bonds: bool,
    ) -> Option<UTXOSpendInfo> {
        if include_all_fidelity_bonds {
            if let Some(index) = self.timelocked_script_index_map.get(&u.script_pub_key) {
                return Some(UTXOSpendInfo::FidelityBondCoin {
                    index: *index,
                    input_value: u.amount.as_sat(),
                });
            }
        }

        if u.descriptor.is_none() {
            if let Some(swapcoin) = contract_scriptpubkeys_outgoing_swapcoins.get(&u.script_pub_key)
            {
                let timelock = swapcoin.get_timelock();
                if u.confirmations >= timelock.into() {
                    return Some(UTXOSpendInfo::TimelockContract {
                        swapcoin_multisig_redeemscript: swapcoin.get_multisig_redeemscript(),
                        input_value: u.amount.as_sat(),
                    });
                }
            }
            if option_contract_scriptpubkeys_incoming_swapcoins.is_some() {
                if let Some(swapcoin) = option_contract_scriptpubkeys_incoming_swapcoins
                    .unwrap()
                    .get(&u.script_pub_key)
                {
                    if swapcoin.is_hash_preimage_known() && u.confirmations >= 1 {
                        return Some(UTXOSpendInfo::HashlockContract {
                            swapcoin_multisig_redeemscript: swapcoin.get_multisig_redeemscript(),
                            input_value: u.amount.as_sat(),
                        });
                    }
                }
            }
            return None;
        }
        let descriptor = u.descriptor.as_ref().unwrap();
        if let Some(ret) = get_hd_path_from_descriptor(&descriptor) {
            //utxo is in a hd wallet
            let (fingerprint, addr_type, index) = ret;

            let secp = Secp256k1::new();
            let master_private_key = self
                .master_key
                .derive_priv(&secp, &DerivationPath::from_str(DERIVATION_PATH).unwrap())
                .unwrap();
            if fingerprint == master_private_key.fingerprint(&secp).to_string() {
                Some(UTXOSpendInfo::SeedCoin {
                    path: format!("m/{}/{}", addr_type, index),
                    input_value: u.amount.as_sat(),
                })
            } else {
                None
            }
        } else {
            //utxo might be one of our swapcoins
            let found = self
                .find_incoming_swapcoin(
                    u.witness_script
                        .as_ref()
                        .unwrap_or(&Script::from(Vec::from_hex("").unwrap())),
                )
                .map_or(false, |sc| sc.other_privkey.is_some())
                || self
                    .find_outgoing_swapcoin(
                        u.witness_script
                            .as_ref()
                            .unwrap_or(&Script::from(Vec::from_hex("").unwrap())),
                    )
                    .map_or(false, |sc| sc.hash_preimage.is_some());
            if found {
                Some(UTXOSpendInfo::SwapCoin {
                    multisig_redeemscript: u.witness_script.as_ref().unwrap().clone(),
                })
            } else {
                None
            }
        }
    }

    pub fn lock_all_nonwallet_unspents(&self, rpc: &Client) -> Result<(), Error> {
        //rpc.unlock_unspent(&[])?;
        //https://github.com/rust-bitcoin/rust-bitcoincore-rpc/issues/148
        rpc.call::<Value>("lockunspent", &[Value::Bool(true)])?;

        let contract_scriptpubkeys_outgoing_swapcoins =
            self.create_contract_scriptpubkey_outgoing_swapcoin_hashmap();
        let all_unspents = rpc.list_unspent(Some(0), Some(9999999), None, None, None)?;
        let utxos_to_lock = &all_unspents
            .into_iter()
            .filter(|u| {
                self.is_utxo_ours_and_spendable_get_pointer(
                    u,
                    &contract_scriptpubkeys_outgoing_swapcoins,
                    None,
                    false,
                )
                .is_none()
            })
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
        include_hashlocked: bool,
        include_fidelity_bonds: bool,
    ) -> Result<Vec<(ListUnspentResultEntry, UTXOSpendInfo)>, Error> {
        let contract_scriptpubkeys_outgoing_swapcoins =
            self.create_contract_scriptpubkey_outgoing_swapcoin_hashmap();
        let contract_scriptpubkeys_incoming_swapcoins =
            self.create_contract_scriptpubkey_incoming_swapcoin_hashmap();
        rpc.call::<Value>("lockunspent", &[Value::Bool(true)])
            .map_err(|e| Error::Rpc(e))?;
        Ok(rpc
            .list_unspent(Some(0), Some(9999999), None, None, None)?
            .iter()
            .map(|u| {
                (
                    u,
                    self.is_utxo_ours_and_spendable_get_pointer(
                        u,
                        &contract_scriptpubkeys_outgoing_swapcoins,
                        if include_hashlocked {
                            Some(&contract_scriptpubkeys_incoming_swapcoins)
                        } else {
                            None
                        },
                        include_fidelity_bonds,
                    ),
                )
            })
            .filter(|(_u, o_info)| o_info.is_some())
            .map(|(u, o_info)| (u.clone(), o_info.unwrap()))
            .collect::<Vec<(ListUnspentResultEntry, UTXOSpendInfo)>>())
    }

    pub fn find_incomplete_coinswaps(
        &self,
        rpc: &Client,
    ) -> Result<
        HashMap<
            Hash160,
            (
                Vec<(ListUnspentResultEntry, &IncomingSwapCoin)>,
                Vec<(ListUnspentResultEntry, &OutgoingSwapCoin)>,
            ),
        >,
        Error,
    > {
        rpc.call::<Value>("lockunspent", &[Value::Bool(true)])
            .map_err(|e| Error::Rpc(e))?;

        let completed_coinswap_hashvalues = self
            .incoming_swapcoins
            .values()
            .filter(|sc| sc.other_privkey.is_some())
            .map(|sc| sc.get_hashvalue())
            .collect::<HashSet<Hash160>>();

        let mut incomplete_swapcoin_groups = HashMap::<
            Hash160,
            (
                Vec<(ListUnspentResultEntry, &IncomingSwapCoin)>,
                Vec<(ListUnspentResultEntry, &OutgoingSwapCoin)>,
            ),
        >::new();
        let get_hashvalue = |s: &dyn SwapCoin| {
            let swapcoin_hashvalue = s.get_hashvalue();
            if completed_coinswap_hashvalues.contains(&swapcoin_hashvalue) {
                return None;
            }
            Some(swapcoin_hashvalue)
        };
        for utxo in rpc.list_unspent(Some(0), Some(9999999), None, None, None)? {
            if utxo.descriptor.is_none() {
                continue;
            }
            let multisig_redeemscript = if let Some(rs) = utxo.witness_script.as_ref() {
                rs
            } else {
                continue;
            };
            if let Some(s) = self.find_incoming_swapcoin(multisig_redeemscript) {
                if let Some(swapcoin_hashvalue) = get_hashvalue(s) {
                    incomplete_swapcoin_groups
                        .entry(swapcoin_hashvalue)
                        .or_insert((
                            Vec::<(ListUnspentResultEntry, &IncomingSwapCoin)>::new(),
                            Vec::<(ListUnspentResultEntry, &OutgoingSwapCoin)>::new(),
                        ))
                        .0
                        .push((utxo, s));
                }
            } else if let Some(s) = self.find_outgoing_swapcoin(multisig_redeemscript) {
                if let Some(swapcoin_hashvalue) = get_hashvalue(s) {
                    incomplete_swapcoin_groups
                        .entry(swapcoin_hashvalue)
                        .or_insert((
                            Vec::<(ListUnspentResultEntry, &IncomingSwapCoin)>::new(),
                            Vec::<(ListUnspentResultEntry, &OutgoingSwapCoin)>::new(),
                        ))
                        .1
                        .push((utxo, s));
                }
            } else {
                continue;
            };
        }
        Ok(incomplete_swapcoin_groups)
    }

    // live contract refers to a contract tx which has been broadcast
    // i.e. where there are UTXOs protected by contract_redeemscript's that we know about
    pub fn find_live_contract_unspents(
        &self,
        rpc: &Client,
    ) -> Result<
        (
            Vec<(&IncomingSwapCoin, ListUnspentResultEntry)>,
            Vec<(&OutgoingSwapCoin, ListUnspentResultEntry)>,
        ),
        Error,
    > {
        // populate hashmaps where key is contract scriptpubkey and value is the swapcoin
        let contract_scriptpubkeys_incoming_swapcoins =
            self.create_contract_scriptpubkey_incoming_swapcoin_hashmap();
        let contract_scriptpubkeys_outgoing_swapcoins =
            self.create_contract_scriptpubkey_outgoing_swapcoin_hashmap();

        rpc.call::<Value>("lockunspent", &[Value::Bool(true)])
            .map_err(|e| Error::Rpc(e))?;
        let listunspent = rpc.list_unspent(Some(0), Some(9999999), None, None, None)?;

        let (incoming_swapcoins_utxos, outgoing_swapcoins_utxos): (Vec<_>, Vec<_>) = listunspent
            .iter()
            .map(|u| {
                (
                    contract_scriptpubkeys_incoming_swapcoins.get(&u.script_pub_key),
                    contract_scriptpubkeys_outgoing_swapcoins.get(&u.script_pub_key),
                    u,
                )
            })
            .filter(|isc_osc_u| isc_osc_u.0.is_some() || isc_osc_u.1.is_some())
            .partition(|isc_osc_u| isc_osc_u.0.is_some());

        Ok((
            incoming_swapcoins_utxos
                .iter()
                .map(|isc_osc_u| (*isc_osc_u.0.unwrap(), isc_osc_u.2.clone()))
                .collect::<Vec<(&IncomingSwapCoin, ListUnspentResultEntry)>>(),
            outgoing_swapcoins_utxos
                .iter()
                .map(|isc_osc_u| (*isc_osc_u.1.unwrap(), isc_osc_u.2.clone()))
                .collect::<Vec<(&OutgoingSwapCoin, ListUnspentResultEntry)>>(),
        ))
    }

    fn find_hd_next_index(&self, rpc: &Client, address_type: u32) -> Result<u32, Error> {
        let mut max_index: i32 = -1;
        //TODO error handling
        let utxos = self.list_unspent_from_wallet(rpc, false, false)?;
        for (utxo, _) in utxos {
            if utxo.descriptor.is_none() {
                continue;
            }
            let descriptor = utxo.descriptor.unwrap();
            let ret = get_hd_path_from_descriptor(&descriptor);
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

    pub fn get_next_internal_addresses(
        &self,
        rpc: &Client,
        count: u32,
    ) -> Result<Vec<Address>, Error> {
        let next_change_addr_index = self.find_hd_next_index(rpc, 1)?;
        let change_branch_descriptor = &self.get_hd_wallet_descriptors(rpc)?[1];
        Ok(rpc.derive_addresses(
            change_branch_descriptor,
            Some([next_change_addr_index, next_change_addr_index + count]),
        )?)
    }

    pub fn refresh_offer_maxsize_cache(&mut self, rpc: Arc<Client>) -> Result<(), Error> {
        let utxos = self.list_unspent_from_wallet(&rpc, false, false)?;
        let balance: Amount = utxos.iter().fold(Amount::ZERO, |acc, u| acc + u.0.amount);
        self.offer_maxsize_cache = balance.as_sat();
        Ok(())
    }

    pub fn get_offer_maxsize_cache(&self) -> u64 {
        self.offer_maxsize_cache
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

    pub fn sign_transaction(
        &self,
        spending_tx: &mut Transaction,
        inputs_info: &mut dyn Iterator<Item = UTXOSpendInfo>,
    ) {
        log::debug!(target: "wallet", "unsigned spending tx = {:#?}", spending_tx);

        let secp = Secp256k1::new();
        let master_private_key = self
            .master_key
            .derive_priv(&secp, &DerivationPath::from_str(DERIVATION_PATH).unwrap())
            .unwrap();
        let tx_clone = spending_tx.clone();

        for (ix, (mut input, input_info)) in
            spending_tx.input.iter_mut().zip(inputs_info).enumerate()
        {
            log::debug!(target: "wallet", "signing with input_info = {:#?}", input_info);
            match input_info {
                UTXOSpendInfo::SwapCoin {
                    multisig_redeemscript,
                } => {
                    self.find_incoming_swapcoin(&multisig_redeemscript)
                        .unwrap()
                        .sign_transaction_input(ix, &tx_clone, &mut input, &multisig_redeemscript)
                        .unwrap();
                }
                UTXOSpendInfo::SeedCoin { path, input_value } => {
                    let privkey = master_private_key
                        .derive_priv(&secp, &DerivationPath::from_str(&path).unwrap())
                        .unwrap()
                        .private_key;
                    let pubkey = privkey.public_key(&secp);
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
                UTXOSpendInfo::TimelockContract {
                    swapcoin_multisig_redeemscript,
                    input_value,
                } => self
                    .find_outgoing_swapcoin(&swapcoin_multisig_redeemscript)
                    .unwrap()
                    .sign_timelocked_transaction_input(ix, &tx_clone, &mut input, input_value),
                UTXOSpendInfo::HashlockContract {
                    swapcoin_multisig_redeemscript,
                    input_value,
                } => self
                    .find_incoming_swapcoin(&swapcoin_multisig_redeemscript)
                    .unwrap()
                    .sign_hashlocked_transaction_input(ix, &tx_clone, &mut input, input_value),
                UTXOSpendInfo::FidelityBondCoin { index, input_value } => {
                    let privkey = self.get_timelocked_privkey_from_index(index);
                    let redeemscript = self.get_timelocked_redeemscript_from_index(index);
                    let sighash = SigHashCache::new(&tx_clone).signature_hash(
                        ix,
                        &redeemscript,
                        input_value,
                        SigHashType::All,
                    );
                    let sig = secp.sign(
                        &secp256k1::Message::from_slice(&sighash[..]).unwrap(),
                        &privkey.key,
                    );
                    input.witness.push(sig.serialize_der().to_vec());
                    input.witness[0].push(SigHashType::All as u8);
                    input.witness.push(redeemscript.as_bytes().to_vec());
                }
            }
        }
    }

    fn generate_amount_fractions(
        count: usize,
        total_amount: u64,
        lower_limit: u64,
    ) -> Result<Vec<f32>, Error> {
        for _ in 0..100000 {
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
                return Ok(fractions);
            }
        }
        Err(Error::Protocol(
            "unable to generate amount fractions, probably amount too small",
        ))
    }

    fn create_spending_txes(
        &self,
        rpc: &Client,
        coinswap_amount: u64,
        destinations: &[Address],
        fee_rate: u64,
    ) -> Result<(Vec<Transaction>, Vec<u32>, Vec<u64>, u64), Error> {
        //return funding_txes, position_of_output, output_value, total_miner_fee

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

        let change_addresses = self.get_next_internal_addresses(rpc, destinations.len() as u32)?;
        log::debug!(target: "wallet", "change addrs = {:?}", change_addresses);

        self.lock_all_nonwallet_unspents(rpc)?;
        let mut output_values = Wallet::generate_amount_fractions(
            destinations.len(),
            coinswap_amount,
            5000, //use 5000 satoshi as the lower limit for now
        )?
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
        log::debug!(target: "wallet", "output values = {:?}", output_values);

        let mut spending_txes = Vec::<Transaction>::new();
        let mut payment_output_positions = Vec::<u32>::new();
        let mut total_miner_fee = 0;
        for (address, &output_value, change_address) in izip!(
            destinations.iter(),
            output_values.iter(),
            change_addresses.iter()
        ) {
            log::debug!(target: "wallet", "output_value = {} to addr={}", output_value, address);

            let mut outputs = HashMap::<String, Amount>::new();
            outputs.insert(address.to_string(), Amount::from_sat(output_value));

            let psbt_result = rpc.wallet_create_funded_psbt(
                &[],
                &outputs,
                None,
                Some(WalletCreateFundedPsbtOptions {
                    include_watching: Some(true),
                    change_address: Some(change_address.clone()),
                    fee_rate: Some(Amount::from_sat(fee_rate)),
                    ..Default::default()
                }),
                None,
            )?;
            let decoded_psbt =
                rpc.call::<Value>("decodepsbt", &[Value::String(psbt_result.psbt)])?;
            total_miner_fee += psbt_result.fee.as_sat();
            log::debug!(target: "wallet", "created spending tx, miner fee={}", psbt_result.fee);

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

            let mut inputs_info = decoded_psbt["inputs"]
                .as_array()
                .unwrap()
                .iter()
                .map(|input_info| (input_info, input_info["bip32_derivs"].as_array().unwrap()))
                .map(|(input_info, bip32_info)| {
                    if bip32_info.len() == 2 {
                        UTXOSpendInfo::SwapCoin {
                            multisig_redeemscript: Builder::from(
                                Vec::from_hex(
                                    &input_info["witness_script"]["hex"].as_str().unwrap(),
                                )
                                .unwrap(),
                            )
                            .into_script(),
                        }
                    } else {
                        UTXOSpendInfo::SeedCoin {
                            path: bip32_info[0]["path"].as_str().unwrap().to_string(),
                            input_value: convert_json_rpc_bitcoin_to_satoshis(
                                &input_info["witness_utxo"]["amount"],
                            ),
                        }
                    }
                });
            self.sign_transaction(&mut spending_tx, &mut inputs_info);

            log::debug!(target: "wallet",
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

        Ok((
            spending_txes,
            payment_output_positions,
            output_values,
            total_miner_fee,
        ))
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

    pub fn import_wallet_redeemscript(
        &self,
        rpc: &Client,
        redeemscript: &Script,
    ) -> Result<(), bitcoincore_rpc::Error> {
        import_redeemscript(rpc, redeemscript, &self.get_core_wallet_label())
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
        hashvalue: Hash160,
        locktime: u16, //returns: funding_txes, swapcoins, total_miner_fee
        fee_rate: u64,
    ) -> Result<(Vec<Transaction>, Vec<OutgoingSwapCoin>, u64), Error> {
        let (coinswap_addresses, my_multisig_privkeys): (Vec<_>, Vec<_>) = other_multisig_pubkeys
            .iter()
            .map(|other_key| self.create_and_import_coinswap_address(rpc, other_key))
            .unzip();
        log::debug!(target: "wallet", "coinswap_addresses = {:#?}", coinswap_addresses);

        let (my_funding_txes, utxo_indexes, funding_amounts, total_miner_fee) =
            self.create_spending_txes(rpc, total_coinswap_amount, &coinswap_addresses, fee_rate)?;
        //for sweeping there would be another function, probably
        //probably have an enum called something like SendAmount which can be
        // an integer but also can be Sweep

        let mut outgoing_swapcoins = Vec::<OutgoingSwapCoin>::new();

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

            outgoing_swapcoins.push(OutgoingSwapCoin::new(
                my_multisig_privkey,
                other_multisig_pubkey,
                my_senders_contract_tx,
                contract_redeemscript,
                timelock_privkey,
                funding_amount,
            ));
        }

        Ok((my_funding_txes, outgoing_swapcoins, total_miner_fee))
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

pub fn import_watchonly_redeemscript(
    rpc: &Client,
    redeemscript: &Script,
) -> Result<(), bitcoincore_rpc::Error> {
    import_redeemscript(rpc, redeemscript, &WATCH_ONLY_SWAPCOIN_LABEL.to_string())
}

pub fn import_redeemscript(
    rpc: &Client,
    redeemscript: &Script,
    address_label: &String,
) -> Result<(), bitcoincore_rpc::Error> {
    let spk = contracts::redeemscript_to_scriptpubkey(&redeemscript);
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
            return Err(bitcoincore_rpc::Error::UnexpectedStructure);
        }
    }
    Ok(())
}

fn apply_two_signatures_to_2of2_multisig_spend(
    key1: &PublicKey,
    key2: &PublicKey,
    sig1: &Signature,
    sig2: &Signature,
    input: &mut TxIn,
    redeemscript: &Script,
) {
    let (sig_first, sig_second) = if key1.serialize()[..] < key2.serialize()[..] {
        (sig1, sig2)
    } else {
        (sig2, sig1)
    };

    input.witness.push(Vec::new()); //first is multisig dummy
    input.witness.push(sig_first.serialize_der().to_vec());
    input.witness.push(sig_second.serialize_der().to_vec());
    input.witness[1].push(SigHashType::All as u8);
    input.witness[2].push(SigHashType::All as u8);
    input.witness.push(redeemscript.to_bytes());
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

// returns None if not a hd descriptor (but possibly a swapcoin (multisig) descriptor instead)
fn get_hd_path_from_descriptor<'a>(descriptor: &'a str) -> Option<(&'a str, u32, i32)> {
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
        log::debug!(target: "wallet", "unexpected address_type = {}", path);
        return None;
    }
    let index = path_chunks[2].parse::<i32>();
    if index.is_err() {
        return None;
    }
    Some((path_chunks[0], addr_type.unwrap(), index.unwrap()))
}
