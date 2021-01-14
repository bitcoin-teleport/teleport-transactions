// this file contains code handling the wallet and sync'ing the wallet
// for now the wallet is only sync'd via bitcoin core's RPC
// makers will only ever sync this way, but one day takers may sync in other
// ways too such as a lightweight wallet method

use std::fs::File;
use std::io;
use std::io::Read;
use std::str::FromStr;
use std::sync::Arc;

use std::collections::HashMap;

use itertools::izip;

extern crate bitcoin_wallet;
use bitcoin_wallet::mnemonic;

extern crate bitcoin;
use bitcoin::{
    blockdata::{
        opcodes::all,
        script::{Builder, Script},
    },
    hashes::{
        hex::{FromHex, ToHex},
    },
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

extern crate bitcoincore_rpc;
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
use crate::contracts::read_pubkeys_from_multisig_redeemscript;
use std::path::Path;

//these subroutines are coded so that as much as possible they keep all their
//data in the bitcoin core wallet
//for example which privkey corresponds to a scriptpubkey is stored in hd paths

//TODO this goes in the config file
pub const NETWORK: Network = Network::Regtest; //not configurable for now
const INITIAL_ADDRESS_IMPORT_COUNT: usize = 500;
const DERIVATION_PATH: &str = "m/84'/1'/0'";
const WALLET_FILE_VERSION: u32 = 0;

//TODO the wallet file format is probably best handled with sqlite

#[derive(serde::Serialize, serde::Deserialize)]
struct WalletFileData {
    version: u32,
    seedphrase: String,
    extension: String,
    external_index: u32,
    swap_coins: Vec<SwapCoin>,
    prevout_to_contract_map: HashMap<OutPoint, Script>,
}

//TODO swap_coins should probably be a HashMap<Script, SwapCoin>
//where Script is the multisig redeemscript
pub struct Wallet {
    master_key: ExtendedPrivKey,
    wallet_file_name: String,
    external_index: u32,
    swap_coins: HashMap<Script, SwapCoin>,
}

//swapcoins are UTXOs + metadata which are not from the deterministic wallet
//they are made in the process of a coinswap
#[derive(serde::Serialize, serde::Deserialize, Debug, Clone)]
pub struct SwapCoin {
    pub my_privkey: SecretKey,
    pub other_pubkey: PublicKey,
    pub other_privkey: Option<SecretKey>,
    pub contract_tx: Transaction,
    pub contract_redeemscript: Script,
    pub funding_amount: u64,
    pub others_contract_sig: Option<Signature>,
    pub hash_preimage: Option<[u8; 32]>,
}

impl SwapCoin {
    pub fn new(
        my_privkey: SecretKey,
        other_pubkey: PublicKey,
        contract_tx: Transaction,
        contract_redeemscript: Script,
        funding_amount: u64,
    ) -> SwapCoin {
        SwapCoin {
            my_privkey,
            other_pubkey,
            other_privkey: None,
            contract_tx,
            contract_redeemscript,
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
        let my_pubkey = PublicKey {
            compressed: true,
            key: secp256k1::PublicKey::from_secret_key(&secp, &self.my_privkey),
        };

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
    pub fn save_new_wallet_file<P: AsRef<Path>>(
        wallet_file_name: P,
        seedphrase: String,
        extension: String,
    ) -> std::io::Result<()> {
        let wallet_file_data = WalletFileData {
            version: WALLET_FILE_VERSION,
            seedphrase,
            extension,
            external_index: 0,
            swap_coins: Vec::new(),
            prevout_to_contract_map: HashMap::<OutPoint, Script>::new(),
        };
        let wallet_file = File::create(wallet_file_name)?;
        serde_json::to_writer(wallet_file, &wallet_file_data)?;
        Ok(())
    }

    fn load_wallet_file_data<P: AsRef<Path>>(
        wallet_file_name: P,
    ) -> std::io::Result<WalletFileData> {
        let mut wallet_file = File::open(wallet_file_name)?;
        let mut wallet_file_str = String::new();
        wallet_file.read_to_string(&mut wallet_file_str)?;
        Ok(serde_json::from_str::<WalletFileData>(&wallet_file_str)?)
    }

    pub fn load_wallet_from_file<P: AsRef<Path>>(wallet_file_name: P) -> std::io::Result<Wallet> {
        let wallet_file_name = wallet_file_name
            .as_ref()
            .as_os_str()
            .to_string_lossy()
            .to_string();
        let wallet_file_data = Wallet::load_wallet_file_data(&wallet_file_name)?;
        let mnemonic_ret = mnemonic::Mnemonic::from_str(&wallet_file_data.seedphrase);
        if mnemonic_ret.is_err() {
            return Err(io::Error::new(io::ErrorKind::Other, "invalid seed phrase"));
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
                .collect::<HashMap<Script, SwapCoin>>(),
        };
        Ok(wallet)
    }

    pub fn update_external_index(&mut self, new_external_index: u32) -> io::Result<()> {
        self.external_index = new_external_index;
        let mut wallet_file_data = Wallet::load_wallet_file_data(&self.wallet_file_name)?;
        wallet_file_data.external_index = new_external_index;
        let wallet_file = File::create(&self.wallet_file_name[..])?;
        serde_json::to_writer(wallet_file, &wallet_file_data)?;
        Ok(())
    }

    pub fn update_swap_coins_list(&self) -> io::Result<()> {
        let mut wallet_file_data = Wallet::load_wallet_file_data(&self.wallet_file_name)?;
        wallet_file_data.swap_coins = self.swap_coins.values().cloned().collect::<Vec<SwapCoin>>();
        let wallet_file = File::create(&self.wallet_file_name[..])?;
        serde_json::to_writer(wallet_file, &wallet_file_data)?;
        Ok(())
    }

    pub fn find_swapcoin(&self, multisig_redeemscript: &Script) -> Option<&SwapCoin> {
        self.swap_coins.get(multisig_redeemscript)
    }

    pub fn find_swapcoin_mut(&mut self, multisig_redeemscript: &Script) -> Option<&mut SwapCoin> {
        self.swap_coins.get_mut(multisig_redeemscript)
    }

    pub fn add_swapcoin(&mut self, coin: SwapCoin) -> Result<(), &'static str> {
        self.swap_coins
            .insert(coin.get_multisig_redeemscript(), coin);
        match self.update_swap_coins_list() {
            Ok(_a) => Ok(()),
            Err(e) => {
                println!("err = {:?}", e);
                Err("error writing to disk")
            }
        }
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
    ) -> io::Result<bool> {
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
    ) -> io::Result<()> {
        let mut wallet_file_data = Wallet::load_wallet_file_data(&self.wallet_file_name[..])?;
        wallet_file_data
            .prevout_to_contract_map
            .insert(prevout, contract);
        let wallet_file = File::create(&self.wallet_file_name[..])?;
        serde_json::to_writer(wallet_file, &wallet_file_data)?;
        Ok(())
    }

    //pub fn get_recovery_phrase_from_file()

    fn is_xpub_descriptor_imported(&self, rpc: &Client, descriptor: &str) -> bool {
        let first_addr = rpc.derive_addresses(&descriptor, Some([0, 0])).unwrap()[0].clone();
        let last_index = (INITIAL_ADDRESS_IMPORT_COUNT - 1) as u32;
        let last_addr = rpc
            .derive_addresses(&descriptor, Some([last_index, last_index]))
            .unwrap()[0]
            .clone();

        //this issue
        // https://github.com/rust-bitcoin/rust-bitcoincore-rpc/issues/123
        //means that we cant use get_address_info() instead we have to
        // parse the json ourselves
        let first_addr_imported = rpc
            .call::<serde_json::Value>("getaddressinfo", &[Value::String(first_addr.to_string())])
            .unwrap()["iswatchonly"]
            .as_bool()
            .unwrap();
        let last_addr_imported = rpc
            .call::<serde_json::Value>("getaddressinfo", &[Value::String(last_addr.to_string())])
            .unwrap()["iswatchonly"]
            .as_bool()
            .unwrap();

        first_addr_imported && last_addr_imported
    }

    fn is_swapcoin_redeemscript_imported(
        &self,
        rpc: &Client,
        multisig_redeemscript: &Script,
    ) -> bool {
        let addr = Address::p2wsh(&multisig_redeemscript, NETWORK).to_string();
        rpc.call::<serde_json::Value>("getaddressinfo", &[Value::String(addr)])
            .unwrap()["iswatchonly"]
            .as_bool()
            .unwrap()
    }

    pub fn get_hd_wallet_descriptors(&self, rpc: &Client) -> Vec<String> {
        let secp = Secp256k1::new();
        let wallet_xpub = ExtendedPubKey::from_private(
            &secp,
            &self
                .master_key
                .derive_priv(&secp, &DerivationPath::from_str(DERIVATION_PATH).unwrap())
                .unwrap(),
        );
        let address_type = [0, 1];
        let descriptors: Vec<String> = address_type
            .iter()
            .map(|at| {
                rpc.get_descriptor_info(&format!("wpkh({}/{}/*)", wallet_xpub, at))
                    .unwrap()
                    .descriptor
            })
            .collect();
        descriptors
    }

    fn get_core_wallet_label(&self) -> String {
        let secp = Secp256k1::new();
        let m_xpub = ExtendedPubKey::from_private(&secp, &self.master_key);
        m_xpub.fingerprint().to_string()
    }

    pub fn import_initial_addresses(
        &self,
        rpc: &Client,
        descriptors_to_import: &[&String],
        swapcoins_to_import: &[&(Script, Script)],
    ) {
        let core_wallet_label = self.get_core_wallet_label();

        let import_requests = descriptors_to_import
            .iter()
            .map(|desc| ImportMultiRequest {
                timestamp: ImportMultiRescanSince::Now,
                descriptor: Some(desc),
                range: Some((0, INITIAL_ADDRESS_IMPORT_COUNT - 1)),
                watchonly: Some(true),
                label: Some(&core_wallet_label),
                ..Default::default()
            })
            .chain(
                swapcoins_to_import
                    .iter()
                    .map(|(redeemscript, scriptpubkey)| ImportMultiRequest {
                        timestamp: ImportMultiRescanSince::Now,
                        script_pubkey: Some(ImportMultiRequestScriptPubkey::Script(scriptpubkey)),
                        redeem_script: Some(redeemscript),
                        watchonly: Some(true),
                        label: Some(&core_wallet_label),
                        ..Default::default()
                    }),
            )
            .collect::<Vec<ImportMultiRequest>>();

        let result = rpc
            .import_multi(
                &import_requests,
                Some(&ImportMultiOptions {
                    rescan: Some(false),
                }),
            )
            .unwrap();
        for r in result {
            if r.success {
                continue;
            }
            panic!("import failed: {:?}", r.error);
        }
    }

    pub fn startup_sync(&mut self, rpc: &Client) {
        //TODO many of these unwraps to be replaced with proper error handling

        let descriptors = self.get_hd_wallet_descriptors(rpc);
        let descriptors_to_import: Vec<&String> = descriptors
            .iter()
            .filter(|d| !self.is_xpub_descriptor_imported(rpc, &d))
            .collect();

        //self.swap_coins used to be a Vec<SwapCoin> rather than HashMap
        //which is why this below set of iterator functions might look weird
        let swapcoin_redeemscripts_scriptpubkeys = self
            .swap_coins
            .values()
            .map(|s| s.get_multisig_redeemscript())
            .map(|rs| (rs.clone(), Address::p2wsh(&rs, NETWORK).script_pubkey()))
            .collect::<Vec<(Script, Script)>>();
        let swapcoins_to_import = swapcoin_redeemscripts_scriptpubkeys
            .iter()
            .filter(|(rs, _spk)| !self.is_swapcoin_redeemscript_imported(rpc, &rs))
            .collect::<Vec<&(Script, Script)>>();

        if descriptors_to_import.is_empty() && swapcoins_to_import.is_empty() {
            return;
        }

        println!("new wallet detected, synchronizing balance...");
        self.import_initial_addresses(rpc, &descriptors_to_import, &swapcoins_to_import);

        rpc.call::<Value>("scantxoutset", &[json!("abort")])
            .unwrap();
        let desc_list = descriptors_to_import
            .iter()
            .map(|d| {
                json!(
                {"desc": d,
                "range": INITIAL_ADDRESS_IMPORT_COUNT-1})
            })
            .chain(
                swapcoins_to_import
                    .iter()
                    .map(|(rs, _spk)| read_pubkeys_from_multisig_redeemscript(rs).unwrap())
                    .map(|(pub1, pub2)| json!(format!("wsh(multi(2,{},{}))", pub1, pub2))),
            )
            .collect::<Vec<Value>>();

        let scantxoutset_result: Result<Value, bitcoincore_rpc::Error> =
            rpc.call("scantxoutset", &[json!("start"), json!(desc_list)]);
        let result = scantxoutset_result.unwrap();
        if !result["success"].as_bool().unwrap() {
            panic!("failed to scan");
        }
        for unspent in result["unspents"].as_array().unwrap() {
            let blockhash = rpc
                .get_block_hash(unspent["height"].as_u64().unwrap())
                .unwrap();
            let txid = Txid::from_hex(unspent["txid"].as_str().unwrap()).unwrap();
            let rawtx = rpc.get_raw_transaction_hex(&txid, Some(&blockhash));
            if let Ok(rawtx_hex) = rawtx {
                let merkleproof = rpc
                    .get_tx_out_proof(&[txid], Some(&blockhash))
                    .unwrap()
                    .to_hex();
                let importprunedfunds_ret: Result<Value, bitcoincore_rpc::Error> = rpc.call(
                    "importprunedfunds",
                    &[Value::String(rawtx_hex), Value::String(merkleproof)],
                );
                if importprunedfunds_ret.is_err() {
                    panic!("failed to import funds");
                }
            } else {
                println!("block pruned, TODO add UTXO to wallet file");
                panic!("teleport doesnt work with pruning yet, try rescanning");
            }
        }

        let max_external_index = self.find_hd_next_index(rpc, 0);
        self.update_external_index(max_external_index).unwrap();
    }

    pub fn lock_all_nonwallet_unspents(&self, rpc: &Client) -> bitcoincore_rpc::Result<()> {
        //rpc.unlock_unspent(&[])?;
        //https://github.com/rust-bitcoin/rust-bitcoincore-rpc/issues/148
        rpc.call::<Value>("lockunspent", &[Value::Bool(true)])?;

        let core_wallet_label = self.get_core_wallet_label();
        let all_unspents = rpc.list_unspent(None, None, None, None, None)?;
        let utxos_to_lock = &all_unspents
            .into_iter()
            .filter(|u| {
                u.label.as_ref().unwrap_or(&String::new()) != &core_wallet_label
                    || u.witness_script.is_some()
                        && self
                            .find_swapcoin(
                                u.witness_script
                                    .as_ref()
                                    .unwrap_or(&Script::from(Vec::from_hex("").unwrap())),
                            )
                            .map_or(true, |sc| sc.other_privkey.is_none())
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
    ) -> bitcoincore_rpc::Result<Vec<ListUnspentResultEntry>> {
        self.lock_all_nonwallet_unspents(rpc)?;
        Ok(rpc.list_unspent(None, None, None, None, None)?)
    }

    fn find_hd_next_index(&self, rpc: &Client, address_type: u32) -> u32 {
        let mut max_index: i32 = -1;
        //TODO error handling
        let utxos = self.list_unspent_from_wallet(rpc).unwrap();
        for utxo in utxos {
            if utxo.descriptor.is_none() {
                continue;
            }
            //e.g
            //"desc": "wpkh([a945b5ca/1/1]029b77637989868dcd502dbc07d6304dc2150301693ae84a60b379c3b696b289ad)#aq759em9",
            let desc = utxo.descriptor.unwrap();
            let open = desc.find('[');
            let close = desc.find(']');
            if open.is_none() || close.is_none() {
                println!("unknown descriptor = {}", desc);
                continue;
            }
            let path = &desc[open.unwrap() + 1..close.unwrap()];
            let path_chunks: Vec<&str> = path.split('/').collect();
            if path_chunks.len() != 3 {
                println!("unexpected descriptor = {}", desc);
                continue;
                //unexpected descriptor = wsh(multi(2,[f67b69a3]0245ddf535f08a04fd86d794b76f8e3949f27f7ae039b641bf277c6a4552b4c387,[dbcd3c6e]030f781e9d2a6d3a823cee56be2d062ed4269f5a6294b20cb8817eb540c641d9a2))#8f70vn2q
            }
            let addr_type = path_chunks[1].parse::<u32>();
            if addr_type.is_err() {
                println!("unexpected address_type = {}", path);
                continue;
            }
            if addr_type.unwrap() != address_type {
                continue;
            }
            let index = path_chunks[2].parse::<i32>();
            if index.is_err() {
                continue;
            }
            max_index = std::cmp::max(max_index, index.unwrap());
        }
        (max_index + 1) as u32
    }

    pub fn get_next_external_address(&mut self, rpc: &Client) -> Address {
        let receive_branch_descriptor = &self.get_hd_wallet_descriptors(rpc)[0];
        let receive_address = rpc
            .derive_addresses(
                receive_branch_descriptor,
                Some([self.external_index, self.external_index]),
            )
            .unwrap()[0]
            .clone();
        self.update_external_index(self.external_index + 1).unwrap();
        receive_address
    }

    pub fn get_offer_maxsize(&self, rpc: Arc<Client>) -> bitcoincore_rpc::Result<u64> {
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
    ) -> (Vec<Transaction>, Vec<u32>, Vec<u64>) {
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

        let next_change_addr_index = self.find_hd_next_index(rpc, 1);
        let change_branch_descriptor = &self.get_hd_wallet_descriptors(rpc)[1];
        let change_addresses = rpc
            .derive_addresses(
                change_branch_descriptor,
                Some([
                    next_change_addr_index,
                    next_change_addr_index + destinations.len() as u32,
                ]),
            )
            .unwrap();

        self.lock_all_nonwallet_unspents(rpc).unwrap();
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
        *output_values.first_mut().unwrap() = coinswap_amount
            - output_values.iter().skip(1).sum::<u64>();
        assert_eq!(output_values.iter().sum::<u64>(), coinswap_amount);

        let mut spending_txes = Vec::<Transaction>::new();
        let mut payment_output_positions = Vec::<u32>::new();
        for (address, &output_value, change_address) in izip!(
            destinations.iter(),
            output_values.iter(),
            change_addresses.iter()
        ) {
            println!("output_value = {} to addr={}", output_value, address);

            let mut outputs = HashMap::<String, Amount>::new();
            outputs.insert(address.to_string(), Amount::from_sat(output_value));

            let psbt_result = rpc
                .wallet_create_funded_psbt(
                    &[],
                    &outputs,
                    None,
                    Some(WalletCreateFundedPsbtOptions {
                        include_watching: Some(true),
                        change_address: Some(change_address.clone()),
                        ..Default::default()
                    }),
                    None,
                )
                .unwrap();
            let decoded_psbt = rpc
                .call::<Value>("decodepsbt", &[Value::String(psbt_result.psbt)])
                .unwrap();

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
            )
            .unwrap();
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

            println!(
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

        (spending_txes, payment_output_positions, output_values)
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

        let core_wallet_label = self.get_core_wallet_label();
        let result = rpc
            .import_multi(
                &[ImportMultiRequest {
                    timestamp: ImportMultiRescanSince::Now,
                    descriptor: Some(&descriptor),
                    watchonly: Some(true),
                    label: Some(&core_wallet_label),
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

    pub fn import_redeemscript(&self, rpc: &Client, redeemscript: &Script) {
        let core_wallet_label = self.get_core_wallet_label();
        let spk = Address::p2wsh(&redeemscript, NETWORK).script_pubkey();
        let result = rpc
            .import_multi(
                &[ImportMultiRequest {
                    timestamp: ImportMultiRescanSince::Now,
                    script_pubkey: Some(ImportMultiRequestScriptPubkey::Script(&spk)),
                    redeem_script: Some(redeemscript),
                    watchonly: Some(true),
                    label: Some(&core_wallet_label),
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
    }

    pub fn import_tx_with_merkleproof(&self, rpc: &Client, tx: &Transaction, merkleproof: String) {
        let rawtx_hex = bitcoin::consensus::encode::serialize(tx).to_hex();

        let importprunedfunds_ret: Result<Value, bitcoincore_rpc::Error> = rpc.call(
            "importprunedfunds",
            &[Value::String(rawtx_hex), Value::String(merkleproof)],
        );
        if importprunedfunds_ret.is_err() {
            panic!("failed to import funds");
        }
    }

    pub fn initalize_coinswap(
        &mut self,
        rpc: &Client,
        total_coinswap_amount: u64,
        other_multisig_pubkeys: &[PublicKey],
        hashlock_pubkeys: &[PublicKey],
        hashvalue: [u8; 20],
        locktime: i64, //returns: funding_tx, swapcoin, timelock_pubkey, timelock_privkey
    ) -> (
        Vec<Transaction>,
        Vec<SwapCoin>,
        Vec<PublicKey>,
        Vec<SecretKey>,
    ) {
        let (coinswap_addresses, my_multisig_privkeys): (Vec<_>, Vec<_>) = other_multisig_pubkeys
            .iter()
            .map(|other_key| self.create_and_import_coinswap_address(rpc, other_key))
            .unzip();
        println!("coinswap_addresses = {:#?}", coinswap_addresses);

        let (my_funding_txes, utxo_indexes, funding_amounts) =
            self.create_spending_txes(rpc, total_coinswap_amount, &coinswap_addresses);
        //for sweeping there would be another function, probably
        //probably have an enum called something like SendAmount which can be
        // an integer but also can be Sweep

        let mut timelock_pubkeys = Vec::<PublicKey>::new();
        let mut timelock_privkeys = Vec::<SecretKey>::new();
        let mut contract_redeemscripts = Vec::<Script>::new();
        let mut outgoing_swapcoins = Vec::<SwapCoin>::new();

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
            contract_redeemscripts.push(contracts::create_contract_redeemscript(
                hashlock_pubkey,
                &timelock_pubkey,
                hashvalue,
                locktime,
            ));
            let my_senders_contract_tx = contracts::create_senders_contract_tx(
                OutPoint {
                    txid: my_funding_tx.txid(),
                    vout: *utxo_index,
                },
                funding_amount,
                &contract_redeemscripts.last().unwrap(),
            );

            timelock_pubkeys.push(timelock_pubkey);
            timelock_privkeys.push(timelock_privkey);
            outgoing_swapcoins.push(SwapCoin::new(
                my_multisig_privkey,
                other_multisig_pubkey,
                my_senders_contract_tx,
                contract_redeemscripts.last().unwrap().clone(),
                funding_amount,
            ));
        }

        (
            my_funding_txes,
            outgoing_swapcoins,
            timelock_pubkeys,
            timelock_privkeys,
        )
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
