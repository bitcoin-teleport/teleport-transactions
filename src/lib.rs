const RPC_CREDENTIALS: Option<(&str, &str)> = Some(("polaruser", "polarpass"));
//None; // use Bitcoin Core cookie-based authentication

const RPC_WALLET: &str = "teleport";
const RPC_HOSTPORT: &str = "localhost:18443";
//default ports: mainnet=8332, testnet=18332, regtest=18443, signet=38332

extern crate bitcoin;
extern crate bitcoin_wallet;
extern crate bitcoincore_rpc;

use dirs::home_dir;
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, Once, RwLock};

use bitcoin::hashes::hash160::Hash as Hash160;
use bitcoin::{Amount, Network};
use bitcoin_wallet::mnemonic::Mnemonic;
use bitcoincore_rpc::json::ListUnspentResultEntry;
use bitcoincore_rpc::{Auth, Client, Error, RpcApi};

pub mod wallet_sync;
use wallet_sync::{
    DisplayAddressType, IncomingSwapCoin, OutgoingSwapCoin, UTXOSpendInfo, Wallet, WalletSwapCoin,
    WalletSyncAddressAmount,
};

pub mod direct_send;
use direct_send::{CoinToSpend, Destination, SendAmount};

pub mod contracts;

pub mod maker_protocol;
use maker_protocol::MakerBehavior;

pub mod taker_protocol;
use taker_protocol::TakerConfig;

pub mod offerbook_sync;
use offerbook_sync::{get_advertised_maker_addresses, sync_offerbook_with_addresses, MakerAddress};

pub mod fidelity_bonds;
use fidelity_bonds::YearAndMonth;

pub mod cli;
pub mod directory_servers;
pub mod error;
pub mod funding_tx;
pub mod json;
pub mod messages;
pub mod watchtower_client;
pub mod watchtower_protocol;

static INIT: Once = Once::new();

fn str_to_bitcoin_network(net_str: &str) -> Network {
    match net_str {
        "main" => Network::Bitcoin,
        "test" => Network::Testnet,
        "signet" => Network::Signet,
        "regtest" => Network::Regtest,
        _ => panic!("unknown network: {}", net_str),
    }
}

pub fn get_bitcoin_rpc() -> Result<(Client, Network), Error> {
    let auth = match RPC_CREDENTIALS {
        Some((user, pass)) => Auth::UserPass(user.to_string(), pass.to_string()),
        None => {
            //TODO this currently only works for Linux and regtest,
            //     also support other OSes (Windows, MacOS...) and networks
            let data_dir = home_dir().unwrap().join(".bitcoin");
            Auth::CookieFile(data_dir.join("regtest").join(".cookie"))
        }
    };
    let rpc = Client::new(
        format!("http://{}/wallet/{}", RPC_HOSTPORT, RPC_WALLET),
        auth,
    )?;
    let network = str_to_bitcoin_network(rpc.get_blockchain_info()?.chain.as_str());
    Ok((rpc, network))
}

/// Setup function that will only run once, even if called multiple times.
pub fn setup_logger() {
    INIT.call_once(|| {
        env_logger::Builder::from_env(
            env_logger::Env::default()
                .default_filter_or("teleport=info,main=info,wallet=info")
                .default_write_style_or("always"),
        )
        .init();
    });
}

pub fn generate_wallet(
    wallet_file_name: &PathBuf,
    extension: Option<String>,
) -> Result<json::GenerateWalletResult, String> {
    let (rpc, network) = match get_bitcoin_rpc() {
        Ok(rpc) => rpc,
        Err(error) => {
            log::error!(target: "main", "error connecting to bitcoin node: {}", error);
            return Err(format!("Error connecting to bitcoin node: {}", error));
        }
    };

    let mnemonic = match Mnemonic::new_random(bitcoin_wallet::account::MasterKeyEntropy::Sufficient)
    {
        Ok(mnemonic) => mnemonic,
        Err(error) => return Err(format!("Error creating mnemonic: {}", error)),
    };

    if let Err(error) = Wallet::save_new_wallet_file(
        &wallet_file_name,
        mnemonic.to_string(),
        extension.as_deref().unwrap_or("").to_string(),
    ) {
        return Err(format!(
            "Error saving wallet file `{}`: {}",
            wallet_file_name.display(),
            error
        ));
    }

    let w = match Wallet::load_wallet_from_file(
        &wallet_file_name,
        network,
        WalletSyncAddressAmount::Normal,
    ) {
        Ok(w) => w,
        Err(error) => {
            return Err(format!("Error loading wallet file: {}", error));
        }
    };

    println!("Importing addresses into Core...");
    if let Err(error) = w.import_initial_addresses(
        &rpc,
        &w.get_hd_wallet_descriptors(&rpc)
            .unwrap()
            .iter()
            .collect::<Vec<&String>>(),
        &Vec::<_>::new(),
        &Vec::<_>::new(),
    ) {
        w.delete_wallet_file().unwrap();
        return Err(format!("Error importing addresses: {}", error));
    }

    let result = json::GenerateWalletResult {
        wallet_name: String::from(wallet_file_name.to_string_lossy()),
        seed_phrase: mnemonic.to_string(),
        extension,
    };

    return Ok(result);
}

pub fn recover_wallet(
    wallet_file_name: &PathBuf,
    seed_phrase: &str,
    extension: Option<String>,
) -> Result<json::RecoverWalletResult, String> {
    let seed_phrase = seed_phrase.trim().to_string();

    if let Err(error) = Mnemonic::from_str(&seed_phrase) {
        return Err(format!("Error creating mnemonic: {}", error));
    }

    if let Err(error) = Wallet::save_new_wallet_file(
        &wallet_file_name,
        seed_phrase,
        extension.as_deref().unwrap_or("").to_string(),
    ) {
        return Err(format!("Error saving wallet file: {}", error));
    }

    let result = json::RecoverWalletResult {
        wallet_name: String::from(wallet_file_name.to_string_lossy()),
        extension,
    };

    return Ok(result);
}

pub fn get_wallet_balance(
    wallet_file_name: &PathBuf,
) -> Result<json::GetWalletBalanceResult, String> {
    let (rpc, network) = match get_bitcoin_rpc() {
        Ok(rpc) => rpc,
        Err(error) => {
            log::error!(target: "main", "error connecting to bitcoin node: {:?}", error);
            return Err(format!("Error connecting to bitcoin node: {}", error));
        }
    };

    let mut wallet = match Wallet::load_wallet_from_file(
        wallet_file_name,
        network,
        WalletSyncAddressAmount::Normal,
    ) {
        Ok(w) => w,
        Err(error) => {
            log::error!(target: "main", "error loading wallet file `{}`: {}", wallet_file_name.display(), error);
            return Err(format!(
                "Error loading wallet file `{}`: {}",
                wallet_file_name.display(),
                error
            ));
        }
    };
    wallet.startup_sync(&rpc).unwrap();

    let mediantime = rpc.get_blockchain_info().unwrap().median_time;

    let utxos_incl_fbonds = wallet.list_unspent_from_wallet(&rpc, false, true).unwrap();
    let (mut utxos, fidelity_bond_utxos): (
        Vec<(ListUnspentResultEntry, UTXOSpendInfo)>,
        Vec<(ListUnspentResultEntry, UTXOSpendInfo)>,
    ) = utxos_incl_fbonds.into_iter().partition(|(_, usi)| {
        if let UTXOSpendInfo::FidelityBondCoin {
            index: _,
            input_value: _,
        } = usi
        {
            false
        } else {
            true
        }
    });

    utxos.sort_by(|(a, _), (b, _)| b.confirmations.cmp(&a.confirmations));
    let utxo_count = utxos.len();
    let balance: Amount = utxos
        .iter()
        .fold(Amount::ZERO, |acc, (u, _)| acc + u.amount);

    let incomplete_coinswaps = wallet.find_incomplete_coinswaps(&rpc).unwrap();

    let (incoming_contract_utxos, outgoing_contract_utxos) =
        wallet.find_live_contract_unspents(&rpc).unwrap();

    let incoming_contract_utxos = incoming_contract_utxos
        .into_iter()
        .map(|x| (x.0.to_owned(), x.1))
        .collect::<Vec<(IncomingSwapCoin, ListUnspentResultEntry)>>();

    let mut outgoing_contract_utxos = outgoing_contract_utxos
        .into_iter()
        .map(|x| (x.0.to_owned(), x.1))
        .collect::<Vec<(OutgoingSwapCoin, ListUnspentResultEntry)>>();
    outgoing_contract_utxos.sort_by(|a, b| b.1.confirmations.cmp(&a.1.confirmations));

    let result = json::GetWalletBalanceResult {
        mediantime,
        spendable_balance: json::SpendableBalance {
            balance,
            utxo_count,
            utxos,
            fidelity_bond_utxos,
        },
        incomplete_coinswaps,
        live_timelocked_contracts: json::LiveTimelockedContracts {
            incoming_contract_utxos,
            outgoing_contract_utxos,
        },
    };

    return Ok(result);
}

// TODO: return JSON serializable
pub fn get_wallet_addresses(
    wallet_file_name: &PathBuf,
    types: DisplayAddressType,
    network: Option<String>,
) -> Result<(), String> {
    let network = match get_bitcoin_rpc() {
        Ok((_rpc, network)) => network,
        Err(error) => {
            if let Some(net_str) = network {
                str_to_bitcoin_network(net_str.as_str())
            } else {
                return Err(format!(
                    "Network string not provided, and error connecting to bitcoin node: {}",
                    error
                ));
            }
        }
    };

    let wallet = match Wallet::load_wallet_from_file(
        wallet_file_name,
        network,
        WalletSyncAddressAmount::Normal,
    ) {
        Ok(w) => w,
        Err(error) => {
            log::error!(target: "main", "error loading wallet file: {:?}", error);
            return Err(format!("Error loading wallet file: {}", error));
        }
    };

    wallet.display_addresses(types);

    let result = ();

    return Ok(result);
}

pub fn get_receive_invoice(
    wallet_file_name: &PathBuf,
) -> Result<json::GetReceiveInvoiceResult, String> {
    let (rpc, network) = match get_bitcoin_rpc() {
        Ok(rpc) => rpc,
        Err(error) => {
            log::error!(target: "main", "error connecting to bitcoin node: {:?}", error);
            return Err(format!("Error connecting to bitcoin node: {}", error));
        }
    };

    let mut wallet = match Wallet::load_wallet_from_file(
        wallet_file_name,
        network,
        WalletSyncAddressAmount::Normal,
    ) {
        Ok(w) => w,
        Err(error) => {
            log::error!(target: "main", "error loading wallet file `{}`: {}", wallet_file_name.display(), error);
            return Err(format!(
                "Error loading wallet file `{}`: {}",
                wallet_file_name.display(),
                error
            ));
        }
    };
    wallet.startup_sync(&rpc).unwrap();

    let address = match wallet.get_next_external_address(&rpc) {
        Ok(a) => a,
        Err(error) => {
            log::error!(target: "main", "error getting address: {:?}", error);
            return Err(format!("Error getting address: {}", error));
        }
    };

    let result = json::GetReceiveInvoiceResult { address };

    return Ok(result);
}

pub fn get_fidelity_bond_address(
    wallet_file_name: &PathBuf,
    locktime: &YearAndMonth,
) -> Result<json::GetFidelityBondAddressResult, String> {
    let (rpc, network) = match get_bitcoin_rpc() {
        Ok(rpc) => rpc,
        Err(error) => {
            log::error!(target: "main", "error connecting to bitcoin node: {:?}", error);
            return Err(format!("Error connecting to bitcoin node: {}", error));
        }
    };

    let mut wallet = match Wallet::load_wallet_from_file(
        wallet_file_name,
        network,
        WalletSyncAddressAmount::Normal,
    ) {
        Ok(w) => w,
        Err(error) => {
            log::error!(target: "main", "error loading wallet file `{}`: {}", wallet_file_name.display(), error);
            return Err(format!(
                "Error loading wallet file `{}`: {}",
                wallet_file_name.display(),
                error
            ));
        }
    };
    wallet.startup_sync(&rpc).unwrap();

    let (address, unix_locktime) = wallet.get_timelocked_address(locktime);
    let result = json::GetFidelityBondAddressResult {
        address,
        unix_locktime,
    };

    return Ok(result);
}

pub fn run_maker(
    wallet_file_name: &PathBuf,
    sync_amount: WalletSyncAddressAmount,
    port: u16,
    maker_behavior: MakerBehavior,
    kill_flag: Option<Arc<RwLock<bool>>>,
) -> Result<(), String> {
    let (rpc, network) = match get_bitcoin_rpc() {
        Ok(rpc) => rpc,
        Err(error) => {
            log::error!(target: "main", "error connecting to bitcoin node: {:?}", error);
            return Err(format!("Error connecting to bitcoin node: {}", error));
        }
    };
    let mut wallet = match Wallet::load_wallet_from_file(wallet_file_name, network, sync_amount) {
        Ok(w) => w,
        Err(error) => {
            log::error!(target: "main", "error loading wallet file `{}`: {}", wallet_file_name.display(), error);
            return Err(format!(
                "Error loading wallet file `{}`: {}",
                wallet_file_name.display(),
                error
            ));
        }
    };
    wallet.startup_sync(&rpc).unwrap();

    let rpc_ptr = Arc::new(rpc);
    let wallet_ptr = Arc::new(RwLock::new(wallet));
    let config = maker_protocol::MakerConfig {
        port,
        rpc_ping_interval_secs: 60,
        watchtower_ping_interval_secs: 300,
        directory_servers_refresh_interval_secs: 60 * 60 * 12, //12 hours
        maker_behavior,
        kill_flag: if kill_flag.is_none() {
            Arc::new(RwLock::new(false))
        } else {
            kill_flag.unwrap().clone()
        },
        idle_connection_timeout: 300,
    };
    maker_protocol::start_maker(rpc_ptr, wallet_ptr, config);

    return Ok(());
}

pub fn run_taker(
    wallet_file_name: &PathBuf,
    sync_amount: WalletSyncAddressAmount,
    fee_rate: u64,
    send_amount: u64,
    maker_count: u16,
    tx_count: u32,
) -> Result<(), String> {
    let (rpc, network) = match get_bitcoin_rpc() {
        Ok(rpc) => rpc,
        Err(error) => {
            log::error!(target: "main", "error connecting to bitcoin node: {:?}", error);
            return Err(format!("Error connecting to bitcoin node: {}", error));
        }
    };

    let mut wallet = match Wallet::load_wallet_from_file(wallet_file_name, network, sync_amount) {
        Ok(w) => w,
        Err(error) => {
            log::error!(target: "main", "error loading wallet file `{}`: {}", wallet_file_name.display(), error);
            return Err(format!(
                "Error loading wallet file `{}`: {}",
                wallet_file_name.display(),
                error
            ));
        }
    };
    wallet.startup_sync(&rpc).unwrap();

    match taker_protocol::start_taker(
        &rpc,
        &mut wallet,
        TakerConfig {
            send_amount,
            maker_count,
            tx_count,
            required_confirms: 1,
            fee_rate,
        },
    ) {
        Ok(()) => Ok(()),
        Err(error) => {
            return Err(format!("Error running coinswap: {}", error));
        }
    }
}

// TODO: return JSON serializable
pub fn recover_from_incomplete_coinswap(
    wallet_file_name: &PathBuf,
    hashvalue: Hash160,
    dont_broadcast: bool,
) -> Result<(), String> {
    let (rpc, network) = match get_bitcoin_rpc() {
        Ok(rpc) => rpc,
        Err(error) => {
            log::error!(target: "main", "error connecting to bitcoin node: {:?}", error);
            return Err(format!("Error connecting to bitcoin node: {}", error));
        }
    };

    let mut wallet = match Wallet::load_wallet_from_file(
        wallet_file_name,
        network,
        WalletSyncAddressAmount::Normal,
    ) {
        Ok(w) => w,
        Err(error) => {
            log::error!(target: "main", "error loading wallet file `{}`: {}", wallet_file_name.display(), error);
            return Err(format!(
                "Error loading wallet file `{}`: {}",
                wallet_file_name.display(),
                error
            ));
        }
    };
    wallet.startup_sync(&rpc).unwrap();

    let incomplete_coinswaps = wallet.find_incomplete_coinswaps(&rpc).unwrap();
    let incomplete_coinswap = incomplete_coinswaps.get(&hashvalue);
    if incomplete_coinswap.is_none() {
        log::error!(target: "main", "hashvalue not refering to incomplete coinswap, run \
                `wallet-balance` to see list of incomplete coinswaps");
        return Err(format!("hashvalue not refering to incomplete coinswap"));
    }
    let incomplete_coinswap = incomplete_coinswap.unwrap();
    for (ii, swapcoin) in incomplete_coinswap
        .0
        .iter()
        .map(|(l, i)| (l, (i as &dyn WalletSwapCoin)))
        .chain(
            incomplete_coinswap
                .1
                .iter()
                .map(|(l, o)| (l, (o as &dyn WalletSwapCoin))),
        )
        .enumerate()
    {
        wallet
            .import_wallet_contract_redeemscript(&rpc, &swapcoin.1.get_contract_redeemscript())
            .unwrap();

        let signed_contract_tx = swapcoin.1.get_fully_signed_contract_tx();
        if dont_broadcast {
            let txhex = bitcoin::consensus::encode::serialize_hex(&signed_contract_tx);
            println!(
                "contract_tx_{} (txid = {}) = \n{}",
                ii,
                signed_contract_tx.txid(),
                txhex
            );
            let accepted = rpc
                .test_mempool_accept(&[txhex.clone()])
                .unwrap()
                .iter()
                .any(|tma| tma.allowed);
            assert!(accepted);
        } else {
            let txid = rpc.send_raw_transaction(&signed_contract_tx).unwrap();
            println!("broadcasted {}", txid);
        }
    }

    return Ok(());
}

// TODO: return JSON serializable
#[tokio::main]
pub async fn download_offers(
    network_str: Option<String>,
    maker_address: Option<String>,
) -> Result<(), String> {
    let maker_addresses = if let Some(maker_addr) = maker_address {
        vec![MakerAddress::Tor {
            address: maker_addr,
        }]
    } else {
        let network = match get_bitcoin_rpc() {
            Ok((_rpc, network)) => network,
            Err(error) => {
                if let Some(net_str) = network_str {
                    str_to_bitcoin_network(net_str.as_str())
                } else {
                    panic!(
                        "network string not provided, and error connecting to bitcoin node: {:?}",
                        error
                    );
                }
            }
        };
        get_advertised_maker_addresses(network)
            .await
            .expect("unable to sync maker addresses from directory servers")
    };
    let offers_addresses = sync_offerbook_with_addresses(maker_addresses.clone()).await;
    let mut addresses_offers_map = HashMap::new();
    for offer_address in offers_addresses.iter() {
        let address_str = match &offer_address.address {
            MakerAddress::Clearnet { address } => address,
            MakerAddress::Tor { address } => address,
        };
        addresses_offers_map.insert(address_str, offer_address);
    }

    println!(
        "{:<3} {:<70} {:<12} {:<12} {:<12} {:<12} {:<12} {:<12} {:<19}",
        "n",
        "maker address",
        "max size",
        "min size",
        "abs fee",
        "amt rel fee",
        "time rel fee",
        "minlocktime",
        "fidelity bond value",
    );

    for (ii, address) in maker_addresses.iter().enumerate() {
        let address_str = match &address {
            MakerAddress::Clearnet { address } => address,
            MakerAddress::Tor { address } => address,
        };
        if let Some(offer_address) = addresses_offers_map.get(&address_str) {
            let o = &offer_address.offer;

            println!(
                "{:<3} {:<70} {:<12} {:<12} {:<12} {:<12} {:<12} {:<12}",
                ii,
                address_str,
                o.max_size,
                o.min_size,
                o.absolute_fee_sat,
                o.amount_relative_fee_ppb,
                o.time_relative_fee_ppb,
                o.minimum_locktime,
            );
        } else {
            println!("{:<3} {:<70} UNREACHABLE", ii, address_str);
        }
    }

    Ok(())
}

pub fn direct_send(
    wallet_file_name: &PathBuf,
    fee_rate: u64,
    send_amount: SendAmount,
    destination: Destination,
    coins_to_spend: &[CoinToSpend],
    dont_broadcast: bool,
) -> Result<json::DirectSendResult, String> {
    let (rpc, network) = match get_bitcoin_rpc() {
        Ok(rpc) => rpc,
        Err(error) => {
            log::error!(target: "main", "error connecting to bitcoin node: {:?}", error);
            return Err(format!("Error connecting to bitcoin node: {}", error));
        }
    };

    let mut wallet = match Wallet::load_wallet_from_file(
        wallet_file_name,
        network,
        WalletSyncAddressAmount::Normal,
    ) {
        Ok(w) => w,
        Err(error) => {
            log::error!(target: "main", "error loading wallet file `{}`: {}", wallet_file_name.display(), error);
            return Err(format!(
                "Error loading wallet file `{}`: {}",
                wallet_file_name.display(),
                error
            ));
        }
    };
    wallet.startup_sync(&rpc).unwrap();

    let tx = wallet
        .create_direct_send(&rpc, fee_rate, send_amount, destination, coins_to_spend)
        .unwrap();
    let txhex = bitcoin::consensus::encode::serialize_hex(&tx);
    log::debug!("fully signed tx hex = {}", txhex);
    let test_mempool_accept_result = &rpc.test_mempool_accept(&[txhex.clone()]).unwrap()[0];
    if !test_mempool_accept_result.allowed {
        panic!(
            "created invalid transaction, reason = {:#?}",
            test_mempool_accept_result
        );
    }

    let mut txid = None;

    if !dont_broadcast {
        txid = Some(rpc.send_raw_transaction(&tx).unwrap());
    }

    let result = json::DirectSendResult {
        test_mempool_accept_result: test_mempool_accept_result.clone(),
        txhex,
        txid,
    };

    return Ok(result);
}

pub fn run_watchtower(
    data_file_path: &PathBuf,
    kill_flag: Option<Arc<RwLock<bool>>>,
) -> Result<(), String> {
    let (rpc, network) = match get_bitcoin_rpc() {
        Ok(rpc) => rpc,
        Err(error) => {
            log::error!(target: "main", "error connecting to bitcoin node: {:?}", error);
            return Err(format!("Error connecting to bitcoin node: {}", error));
        }
    };

    watchtower_protocol::start_watchtower(
        &rpc,
        data_file_path,
        network,
        if kill_flag.is_none() {
            Arc::new(RwLock::new(false))
        } else {
            kill_flag.unwrap().clone()
        },
    );

    return Ok(());
}
