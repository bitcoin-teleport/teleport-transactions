const RPC_CREDENTIALS: Option<(&str, &str)> = Some(("regtestrpcuser", "regtestrpcpass"));
//None; // use Bitcoin Core cookie-based authentication

const RPC_WALLET: &str = "teleport";
const RPC_HOSTPORT: &str = "localhost:18443";
//default ports: mainnet=8332, testnet=18332, regtest=18443, signet=38332

extern crate bitcoin;
extern crate bitcoin_wallet;
extern crate bitcoincore_rpc;

use dirs::home_dir;
use std::collections::HashMap;
use std::convert::TryInto;
use std::io;
use std::iter::repeat;
use std::path::PathBuf;
use std::sync::{Arc, Once, RwLock};

use bitcoin::hashes::{hash160::Hash as Hash160, hex::ToHex};
use bitcoin::{Amount, Network};
use bitcoin_wallet::mnemonic;
use bitcoincore_rpc::{Auth, Client, Error, RpcApi};

use chrono::NaiveDateTime;

pub mod wallet_sync;
use wallet_sync::{
    DisplayAddressType, UTXOSpendInfo, Wallet, WalletSwapCoin, WalletSyncAddressAmount,
};

pub mod direct_send;
use direct_send::{CoinToSpend, Destination, SendAmount};

pub mod contracts;
use contracts::{read_locktime_from_contract, SwapCoin};

pub mod maker_protocol;
use maker_protocol::MakerBehavior;

pub mod taker_protocol;
use taker_protocol::TakerConfig;

pub mod offerbook_sync;
use offerbook_sync::{get_advertised_maker_addresses, sync_offerbook_with_addresses, MakerAddress};

pub mod fidelity_bonds;
use fidelity_bonds::{get_locktime_from_index, YearAndMonth};

pub mod directory_servers;
pub mod error;
pub mod funding_tx;
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

pub fn generate_wallet(wallet_file_name: &PathBuf) -> std::io::Result<()> {
    let (rpc, network) = match get_bitcoin_rpc() {
        Ok(rpc) => rpc,
        Err(error) => {
            log::error!(target: "main", "error connecting to bitcoin node: {:?}", error);
            return Ok(());
        }
    };
    println!("input seed phrase extension (or leave blank for none): ");
    let mut extension = String::new();
    io::stdin().read_line(&mut extension)?;
    extension = extension.trim().to_string();
    let mnemonic =
        mnemonic::Mnemonic::new_random(bitcoin_wallet::account::MasterKeyEntropy::Sufficient)
            .unwrap();
    Wallet::save_new_wallet_file(&wallet_file_name, mnemonic.to_string(), extension.clone())
        .unwrap();

    let w = match Wallet::load_wallet_from_file(
        &wallet_file_name,
        network,
        WalletSyncAddressAmount::Normal,
    ) {
        Ok(w) => w,
        Err(error) => panic!("error loading wallet file: {:?}", error),
    };
    println!("Importing addresses into Core. . .");
    w.import_initial_addresses(
        &rpc,
        &w.get_hd_wallet_descriptors(&rpc)
            .unwrap()
            .iter()
            .collect::<Vec<&String>>(),
        &Vec::<_>::new(),
        &Vec::<_>::new(),
    )
    .unwrap();
    println!("Write down this seed phrase =\n{}", mnemonic.to_string());
    if !extension.trim().is_empty() {
        println!("And this extension =\n\"{}\"", extension);
    }
    println!(
        "\nThis seed phrase is NOT enough to backup all coins in your wallet\n\
        The teleport wallet file is needed to backup swapcoins"
    );
    println!("\nSaved to file `{}`", wallet_file_name.to_string_lossy());

    Ok(())
}

pub fn recover_wallet(wallet_file_name: &PathBuf) -> std::io::Result<()> {
    println!("input seed phrase: ");
    let mut seed_phrase = String::new();
    io::stdin().read_line(&mut seed_phrase)?;
    seed_phrase = seed_phrase.trim().to_string();

    if let Err(e) = mnemonic::Mnemonic::from_str(&seed_phrase) {
        println!("invalid seed phrase: {:?}", e);
        return Ok(());
    }

    println!("input seed phrase extension (or leave blank for none): ");
    let mut extension = String::new();
    io::stdin().read_line(&mut extension)?;
    extension = extension.trim().to_string();

    Wallet::save_new_wallet_file(&wallet_file_name, seed_phrase, extension).unwrap();
    println!("\nSaved to file `{}`", wallet_file_name.to_string_lossy());
    Ok(())
}

pub fn display_wallet_balance(wallet_file_name: &PathBuf, long_form: Option<bool>) {
    let (rpc, network) = match get_bitcoin_rpc() {
        Ok(rpc) => rpc,
        Err(error) => {
            log::error!(target: "main", "error connecting to bitcoin node: {:?}", error);
            return;
        }
    };
    let mut wallet = match Wallet::load_wallet_from_file(
        wallet_file_name,
        network,
        WalletSyncAddressAmount::Normal,
    ) {
        Ok(w) => w,
        Err(error) => {
            log::error!(target: "main", "error loading wallet file: {:?}", error);
            return;
        }
    };
    wallet.startup_sync(&rpc).unwrap();

    let long_form = long_form.unwrap_or(false);

    let utxos_incl_fbonds = wallet.list_unspent_from_wallet(&rpc, false, true).unwrap();
    let (mut utxos, mut fidelity_bond_utxos): (Vec<_>, Vec<_>) =
        utxos_incl_fbonds.iter().partition(|(_, usi)| {
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
    println!("= spendable wallet balance =");
    println!(
        "{:16} {:24} {:^8} {:<7} value",
        "coin", "address", "type", "conf",
    );
    for (utxo, _) in utxos {
        let txid = utxo.txid.to_hex();
        let addr = utxo.address.as_ref().unwrap().to_string();
        #[rustfmt::skip]
        println!(
            "{}{}{}:{} {}{}{} {:^8} {:<7} {}",
            if long_form { &txid } else {&txid[0..6] },
            if long_form { "" } else { ".." },
            if long_form { &"" } else { &txid[58..64] },
            utxo.vout,
            if long_form { &addr } else { &addr[0..10] },
            if long_form { "" } else { "...." },
            if long_form { &"" } else { &addr[addr.len() - 10..addr.len()] },
            if utxo.witness_script.is_some() {
                "swapcoin"
            } else {
                if utxo.descriptor.is_some() { "seed" } else { "timelock" }
            },
            utxo.confirmations,
            utxo.amount
        );
    }
    println!("coin count = {}", utxo_count);
    println!("total balance = {}", balance);

    let incomplete_coinswaps = wallet.find_incomplete_coinswaps(&rpc).unwrap();
    if !incomplete_coinswaps.is_empty() {
        println!("= incomplete coinswaps =");
        for (hashvalue, (utxo_incoming_swapcoins, utxo_outgoing_swapcoins)) in incomplete_coinswaps
        {
            let incoming_swapcoins_balance: Amount = utxo_incoming_swapcoins
                .iter()
                .fold(Amount::ZERO, |acc, us| acc + us.0.amount);
            let outgoing_swapcoins_balance: Amount = utxo_outgoing_swapcoins
                .iter()
                .fold(Amount::ZERO, |acc, us| acc + us.0.amount);

            println!(
                "{:16} {:8} {:8} {:<15} {:<7} value",
                "coin", "type", "preimage", "locktime/blocks", "conf",
            );
            for ((utxo, swapcoin), contract_type) in utxo_incoming_swapcoins
                .iter()
                .map(|(l, i)| (l, (*i as &dyn SwapCoin)))
                .zip(repeat("hashlock"))
                .chain(
                    utxo_outgoing_swapcoins
                        .iter()
                        .map(|(l, o)| (l, (*o as &dyn SwapCoin)))
                        .zip(repeat("timelock")),
                )
            {
                let txid = utxo.txid.to_hex();

                #[rustfmt::skip]
                println!("{}{}{}:{} {:8} {:8} {:^15} {:<7} {}",
                    if long_form { &txid } else {&txid[0..6] },
                    if long_form { "" } else { ".." },
                    if long_form { &"" } else { &txid[58..64] },
                    utxo.vout,
                    contract_type,
                    if swapcoin.is_hash_preimage_known() { "known" } else { "unknown" },
                    read_locktime_from_contract(&swapcoin.get_contract_redeemscript())
                        .expect("unable to read locktime from contract"),
                    utxo.confirmations,
                    utxo.amount
                );
            }
            if incoming_swapcoins_balance != Amount::ZERO {
                println!(
                    "amount earned if coinswap successful = {}",
                    (incoming_swapcoins_balance.to_signed().unwrap()
                        - outgoing_swapcoins_balance.to_signed().unwrap()),
                );
            }
            println!(
                "outgoing balance = {}\nhashvalue = {}",
                outgoing_swapcoins_balance,
                &hashvalue.to_hex()[..]
            );
        }
    }

    let (mut incoming_contract_utxos, mut outgoing_contract_utxos) =
        wallet.find_live_contract_unspents(&rpc).unwrap();
    if !outgoing_contract_utxos.is_empty() {
        outgoing_contract_utxos.sort_by(|a, b| b.1.confirmations.cmp(&a.1.confirmations));
        println!("= live timelocked contracts =");
        println!(
            "{:16} {:10} {:8} {:<7} {:<8} {:6}",
            "coin", "hashvalue", "timelock", "conf", "locked?", "value"
        );
        for (outgoing_swapcoin, utxo) in outgoing_contract_utxos {
            let txid = utxo.txid.to_hex();
            let timelock =
                read_locktime_from_contract(&outgoing_swapcoin.contract_redeemscript).unwrap();
            let hashvalue = outgoing_swapcoin.get_hashvalue().to_hex();
            #[rustfmt::skip]
            println!("{}{}{}:{} {}{} {:<8} {:<7} {:<8} {}",
                if long_form { &txid } else {&txid[0..6] },
                if long_form { "" } else { ".." },
                if long_form { &"" } else { &txid[58..64] },
                utxo.vout,
                if long_form { &hashvalue } else { &hashvalue[..8] },
                if long_form { "" } else { ".." },
                timelock,
                utxo.confirmations,
                if utxo.confirmations >= timelock.into() { "unlocked" } else { "locked" },
                utxo.amount
            );
        }
    }

    //ordinary users shouldnt be spending via the hashlock branch
    //maybe makers since they're a bit more expertly, and they dont start with the hash preimage
    //but takers should basically never use the hash preimage
    let expert_mode = true;
    if expert_mode && !incoming_contract_utxos.is_empty() {
        incoming_contract_utxos.sort_by(|a, b| b.1.confirmations.cmp(&a.1.confirmations));
        println!("= live hashlocked contracts =");
        println!(
            "{:16} {:10} {:8} {:<7} {:8} {:6}",
            "coin", "hashvalue", "timelock", "conf", "preimage", "value"
        );
        for (incoming_swapcoin, utxo) in incoming_contract_utxos {
            let txid = utxo.txid.to_hex();
            let timelock =
                read_locktime_from_contract(&incoming_swapcoin.contract_redeemscript).unwrap();
            let hashvalue = incoming_swapcoin.get_hashvalue().to_hex();
            #[rustfmt::skip]
            println!("{}{}{}:{} {}{} {:<8} {:<7} {:8} {}",
                if long_form { &txid } else {&txid[0..6] },
                if long_form { "" } else { ".." },
                if long_form { &"" } else { &txid[58..64] },
                utxo.vout,
                if long_form { &hashvalue } else { &hashvalue[..8] },
                if long_form { "" } else { ".." },
                timelock,
                utxo.confirmations,
                if incoming_swapcoin.is_hash_preimage_known() { "known" } else { "unknown" },
                utxo.amount
            );
        }
    }

    if fidelity_bond_utxos.len() > 0 {
        println!("= fidelity bond coins =");
        println!(
            "{:16} {:24} {:<7} {:<11} {:<8} {:6}",
            "coin", "address", "conf", "locktime", "locked?", "value"
        );

        let mediantime = rpc.get_blockchain_info().unwrap().median_time;
        fidelity_bond_utxos.sort_by(|(a, _), (b, _)| b.confirmations.cmp(&a.confirmations));
        for (utxo, utxo_spend_info) in fidelity_bond_utxos {
            let index = if let UTXOSpendInfo::FidelityBondCoin {
                index,
                input_value: _,
            } = utxo_spend_info
            {
                index
            } else {
                panic!("logic error, all these utxos should be fidelity bonds");
            };
            let unix_locktime = get_locktime_from_index(*index);
            let txid = utxo.txid.to_hex();
            let addr = utxo.address.as_ref().unwrap().to_string();
            #[rustfmt::skip]
            println!(
                "{}{}{}:{} {}{}{} {:<7} {:<11} {:<8} {:6}",
                if long_form { &txid } else {&txid[0..6] },
                if long_form { "" } else { ".." },
                if long_form { &"" } else { &txid[58..64] },
                utxo.vout,
                if long_form { &addr } else { &addr[0..10] },
                if long_form { "" } else { "...." },
                if long_form { &"" } else { &addr[addr.len() - 10..addr.len()] },
                utxo.confirmations,
                NaiveDateTime::from_timestamp(unix_locktime, 0)
                    .format("%Y-%m-%d")
                    .to_string(),
                if mediantime >= unix_locktime.try_into().unwrap() { "unlocked" } else { "locked" },
                utxo.amount
            );
        }
    }
}

pub fn display_wallet_addresses(
    wallet_file_name: &PathBuf,
    types: DisplayAddressType,
    network: Option<String>,
) {
    let network = match get_bitcoin_rpc() {
        Ok((_rpc, network)) => network,
        Err(error) => {
            if let Some(net_str) = network {
                str_to_bitcoin_network(net_str.as_str())
            } else {
                panic!(
                    "network string not provided, and error connecting to bitcoin node: {:?}",
                    error
                );
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
            return;
        }
    };
    wallet.display_addresses(types);
}

pub fn print_receive_invoice(wallet_file_name: &PathBuf) {
    let (rpc, network) = match get_bitcoin_rpc() {
        Ok(rpc) => rpc,
        Err(error) => {
            log::error!(target: "main", "error connecting to bitcoin node: {:?}", error);
            return;
        }
    };
    let mut wallet = match Wallet::load_wallet_from_file(
        wallet_file_name,
        network,
        WalletSyncAddressAmount::Normal,
    ) {
        Ok(w) => w,
        Err(error) => {
            log::error!(target: "main", "error loading wallet file: {:?}", error);
            return;
        }
    };
    wallet.startup_sync(&rpc).unwrap();

    let addr = match wallet.get_next_external_address(&rpc) {
        Ok(a) => a,
        Err(error) => {
            println!("error: {:?}", error);
            return;
        }
    };
    println!("{}", addr);
}

pub fn print_fidelity_bond_address(wallet_file_name: &PathBuf, locktime: &YearAndMonth) {
    let (rpc, network) = match get_bitcoin_rpc() {
        Ok(rpc) => rpc,
        Err(error) => {
            log::error!(target: "main", "error connecting to bitcoin node: {:?}", error);
            return;
        }
    };
    let mut wallet = match Wallet::load_wallet_from_file(
        wallet_file_name,
        network,
        WalletSyncAddressAmount::Normal,
    ) {
        Ok(w) => w,
        Err(error) => {
            log::error!(target: "main", "error loading wallet file: {:?}", error);
            return;
        }
    };
    wallet.startup_sync(&rpc).unwrap();

    let (addr, unix_locktime) = wallet.get_timelocked_address(locktime);
    println!(concat!(
        "WARNING: You should send coins to this address only once.",
        " Only single biggest value UTXO will be announced as a fidelity bond.",
        " Sending coins to this address multiple times will not increase",
        " fidelity bond value."
    ));
    println!(concat!(
        "WARNING: Only send coins here which are from coinjoins, coinswaps or",
        " otherwise not linked to your identity. Also, use a sweep transaction when funding the",
        " timelocked address, i.e. Don't create a change address."
    ));
    println!(
        "Coins sent to this address will not be spendable until {}",
        NaiveDateTime::from_timestamp(unix_locktime, 0)
            .format("%Y-%m-%d")
            .to_string()
    );
    println!("{}", addr);
}

pub fn run_maker(
    wallet_file_name: &PathBuf,
    sync_amount: WalletSyncAddressAmount,
    port: u16,
    maker_behavior: MakerBehavior,
    kill_flag: Option<Arc<RwLock<bool>>>,
) {
    let (rpc, network) = match get_bitcoin_rpc() {
        Ok(rpc) => rpc,
        Err(error) => {
            log::error!(target: "main", "error connecting to bitcoin node: {:?}", error);
            return;
        }
    };
    let mut wallet = match Wallet::load_wallet_from_file(wallet_file_name, network, sync_amount) {
        Ok(w) => w,
        Err(error) => {
            log::error!(target: "main", "error loading wallet file: {:?}", error);
            return;
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
}

pub fn run_taker(
    wallet_file_name: &PathBuf,
    sync_amount: WalletSyncAddressAmount,
    fee_rate: u64,
    send_amount: u64,
    maker_count: u16,
    tx_count: u32,
) {
    let (rpc, network) = match get_bitcoin_rpc() {
        Ok(rpc) => rpc,
        Err(error) => {
            log::error!(target: "main", "error connecting to bitcoin node: {:?}", error);
            return;
        }
    };
    let mut wallet = match Wallet::load_wallet_from_file(wallet_file_name, network, sync_amount) {
        Ok(w) => w,
        Err(error) => {
            log::error!(target: "main", "error loading wallet file: {:?}", error);
            return;
        }
    };
    wallet.startup_sync(&rpc).unwrap();
    taker_protocol::start_taker(
        &rpc,
        &mut wallet,
        TakerConfig {
            send_amount,
            maker_count,
            tx_count,
            required_confirms: 1,
            fee_rate,
        },
    );
}

pub fn recover_from_incomplete_coinswap(
    wallet_file_name: &PathBuf,
    hashvalue: Hash160,
    dont_broadcast: bool,
) {
    let (rpc, network) = match get_bitcoin_rpc() {
        Ok(rpc) => rpc,
        Err(error) => {
            log::error!(target: "main", "error connecting to bitcoin node: {:?}", error);
            return;
        }
    };
    let mut wallet = match Wallet::load_wallet_from_file(
        wallet_file_name,
        network,
        WalletSyncAddressAmount::Normal,
    ) {
        Ok(w) => w,
        Err(error) => {
            log::error!(target: "main", "error loading wallet file: {:?}", error);
            return;
        }
    };
    wallet.startup_sync(&rpc).unwrap();

    let incomplete_coinswaps = wallet.find_incomplete_coinswaps(&rpc).unwrap();
    let incomplete_coinswap = incomplete_coinswaps.get(&hashvalue);
    if incomplete_coinswap.is_none() {
        log::error!(target: "main", "hashvalue not refering to incomplete coinswap, run \
                `wallet-balance` to see list of incomplete coinswaps");
        return;
    }
    let incomplete_coinswap = incomplete_coinswap.unwrap();
    for (ii, swapcoin) in incomplete_coinswap
        .0
        .iter()
        .map(|(l, i)| (l, (*i as &dyn WalletSwapCoin)))
        .chain(
            incomplete_coinswap
                .1
                .iter()
                .map(|(l, o)| (l, (*o as &dyn WalletSwapCoin))),
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
}

#[tokio::main]
pub async fn download_and_display_offers(
    network_str: Option<String>,
    maker_address: Option<String>,
) {
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
}

pub fn direct_send(
    wallet_file_name: &PathBuf,
    fee_rate: u64,
    send_amount: SendAmount,
    destination: Destination,
    coins_to_spend: &[CoinToSpend],
    dont_broadcast: bool,
) {
    let (rpc, network) = match get_bitcoin_rpc() {
        Ok(rpc) => rpc,
        Err(error) => {
            log::error!(target: "main", "error connecting to bitcoin node: {:?}", error);
            return;
        }
    };
    let mut wallet = match Wallet::load_wallet_from_file(
        wallet_file_name,
        network,
        WalletSyncAddressAmount::Normal,
    ) {
        Ok(w) => w,
        Err(error) => {
            log::error!(target: "main", "error loading wallet file: {:?}", error);
            return;
        }
    };
    wallet.startup_sync(&rpc).unwrap();
    let tx = wallet
        .create_direct_send(&rpc, fee_rate, send_amount, destination, coins_to_spend)
        .unwrap();
    let txhex = bitcoin::consensus::encode::serialize_hex(&tx);
    let test_mempool_accept_result = &rpc.test_mempool_accept(&[txhex.clone()]).unwrap()[0];
    if !test_mempool_accept_result.allowed {
        panic!(
            "created invalid transaction, reason = {:#?}",
            test_mempool_accept_result
        );
    }
    println!(
        "actual fee rate = {:.3} sat/vb",
        test_mempool_accept_result
            .fees
            .as_ref()
            .unwrap()
            .base
            .as_sat() as f64
            / test_mempool_accept_result.vsize.unwrap() as f64
    );
    if dont_broadcast {
        println!("tx = \n{}", txhex);
    } else {
        let txid = rpc.send_raw_transaction(&tx).unwrap();
        println!("broadcasted {}", txid);
    }
}

pub fn run_watchtower(kill_flag: Option<Arc<RwLock<bool>>>) {
    let (rpc, network) = match get_bitcoin_rpc() {
        Ok(rpc) => rpc,
        Err(error) => {
            log::error!(target: "main", "error connecting to bitcoin node: {:?}", error);
            return;
        }
    };

    watchtower_protocol::start_watchtower(
        &rpc,
        network,
        if kill_flag.is_none() {
            Arc::new(RwLock::new(false))
        } else {
            kill_flag.unwrap().clone()
        },
    );
}
