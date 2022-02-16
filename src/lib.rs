extern crate bitcoin;
extern crate bitcoin_wallet;
extern crate bitcoincore_rpc;

use dirs::home_dir;
use std::collections::HashMap;
use std::io;
use std::iter::repeat;
use std::path::PathBuf;
use std::sync::{Arc, Once, RwLock};

use bitcoin::hashes::{hash160::Hash as Hash160, hex::ToHex};
use bitcoin::Amount;
use bitcoin_wallet::mnemonic;
use bitcoincore_rpc::{Auth, Client, Error, RpcApi};

pub mod wallet_sync;
use wallet_sync::{Wallet, WalletSwapCoin, WalletSyncAddressAmount};

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

pub mod directory_servers;
pub mod error;
pub mod messages;
pub mod watchtower_client;
pub mod watchtower_protocol;

static INIT: Once = Once::new();

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

pub fn get_bitcoin_rpc() -> Result<Client, Error> {
    //TODO put all this in a config file
    const RPC_CREDENTIALS: Option<(&str, &str)> = Some(("regtestrpcuser", "regtestrpcpass"));
    //Some(("btcrpcuser", "btcrpcpass"));
    //None; // use Bitcoin Core cookie-based authentication

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
        "http://localhost:18443/wallet/teleport",
        //"http://localhost:18332/wallet/teleport",
        auth,
    )?;
    rpc.get_blockchain_info()?;
    Ok(rpc)
}

pub fn generate_wallet(wallet_file_name: &PathBuf) -> std::io::Result<()> {
    let rpc = match get_bitcoin_rpc() {
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

    let w = match Wallet::load_wallet_from_file(&wallet_file_name, WalletSyncAddressAmount::Normal)
    {
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
    Ok(())
}

pub fn display_wallet_balance(wallet_file_name: &PathBuf, long_form: Option<bool>) {
    let mut wallet =
        match Wallet::load_wallet_from_file(wallet_file_name, WalletSyncAddressAmount::Normal) {
            Ok(w) => w,
            Err(error) => {
                log::error!(target: "main", "error loading wallet file: {:?}", error);
                return;
            }
        };
    let rpc = match get_bitcoin_rpc() {
        Ok(rpc) => rpc,
        Err(error) => {
            log::error!(target: "main", "error connecting to bitcoin node: {:?}", error);
            return;
        }
    };
    wallet.startup_sync(&rpc).unwrap();

    let long_form = long_form.unwrap_or(false);

    let mut utxos = wallet.list_unspent_from_wallet(&rpc, false).unwrap();
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
        let addr = utxo.address.unwrap().to_string();
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
}

pub fn display_wallet_keys(wallet_file_name: &PathBuf) {
    let wallet =
        match Wallet::load_wallet_from_file(wallet_file_name, WalletSyncAddressAmount::Normal) {
            Ok(w) => w,
            Err(error) => {
                log::error!(target: "main", "error loading wallet file: {:?}", error);
                return;
            }
        };
    wallet.print_wallet_key_data();
}

pub fn print_receive_invoice(wallet_file_name: &PathBuf) {
    let mut wallet =
        match Wallet::load_wallet_from_file(wallet_file_name, WalletSyncAddressAmount::Normal) {
            Ok(w) => w,
            Err(error) => {
                log::error!(target: "main", "error loading wallet file: {:?}", error);
                return;
            }
        };
    let rpc = match get_bitcoin_rpc() {
        Ok(rpc) => rpc,
        Err(error) => {
            log::error!(target: "main", "error connecting to bitcoin node: {:?}", error);
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

pub fn run_maker(
    wallet_file_name: &PathBuf,
    sync_amount: WalletSyncAddressAmount,
    port: u16,
    maker_behavior: MakerBehavior,
    kill_flag: Option<Arc<RwLock<bool>>>,
) {
    let rpc = match get_bitcoin_rpc() {
        Ok(rpc) => rpc,
        Err(error) => {
            log::error!(target: "main", "error connecting to bitcoin node: {:?}", error);
            return;
        }
    };
    let mut wallet = match Wallet::load_wallet_from_file(wallet_file_name, sync_amount) {
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
    send_amount: u64,
    maker_count: u16,
    tx_count: u32,
) {
    let rpc = match get_bitcoin_rpc() {
        Ok(rpc) => rpc,
        Err(error) => {
            log::error!(target: "main", "error connecting to bitcoin node: {:?}", error);
            return;
        }
    };
    let mut wallet = match Wallet::load_wallet_from_file(wallet_file_name, sync_amount) {
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
            fee_rate: 1000, //satoshis per thousand vbytes, i.e. 1000 = 1 sat/vb
        },
    );
}

pub fn recover_from_incomplete_coinswap(
    wallet_file_name: &PathBuf,
    hashvalue: Hash160,
    dont_broadcast: bool,
) {
    let mut wallet =
        match Wallet::load_wallet_from_file(wallet_file_name, WalletSyncAddressAmount::Normal) {
            Ok(w) => w,
            Err(error) => {
                log::error!(target: "main", "error loading wallet file: {:?}", error);
                return;
            }
        };
    let rpc = match get_bitcoin_rpc() {
        Ok(rpc) => rpc,
        Err(error) => {
            log::error!(target: "main", "error connecting to bitcoin node: {:?}", error);
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
            .import_wallet_redeemscript(&rpc, &swapcoin.1.get_contract_redeemscript())
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
pub async fn download_and_display_offers(maker_address: Option<String>) {
    let maker_addresses = if let Some(maker_addr) = maker_address {
        vec![MakerAddress::Tor {
            address: maker_addr,
        }]
    } else {
        get_advertised_maker_addresses()
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
        "{:3} {:70} {:12} {:12} {:12} {:12} {:12} {:12}",
        "n",
        "maker address",
        "max size",
        "min size",
        "abs fee",
        "amt rel fee",
        "time rel fee",
        "minlocktime"
    );
    for (ii, address) in maker_addresses.iter().enumerate() {
        let address_str = match &address {
            MakerAddress::Clearnet { address } => address,
            MakerAddress::Tor { address } => address,
        };
        if let Some(offer_address) = addresses_offers_map.get(&address_str) {
            let o = &offer_address.offer;
            println!(
                "{:3} {:70} {:12} {:12} {:12} {:12} {:12} {:12}",
                ii,
                address,
                o.max_size,
                o.min_size,
                o.absolute_fee_sat,
                o.amount_relative_fee_ppb,
                o.time_relative_fee_ppb,
                o.minimum_locktime
            );
        } else {
            println!("{:3} {:70} UNREACHABLE", ii, address);
        }
    }
}

pub fn direct_send(
    wallet_file_name: &PathBuf,
    send_amount: SendAmount,
    destination: Destination,
    coins_to_spend: &[CoinToSpend],
    dont_broadcast: bool,
) {
    let rpc = match get_bitcoin_rpc() {
        Ok(rpc) => rpc,
        Err(error) => {
            log::error!(target: "main", "error connecting to bitcoin node: {:?}", error);
            return;
        }
    };
    let mut wallet =
        match Wallet::load_wallet_from_file(wallet_file_name, WalletSyncAddressAmount::Normal) {
            Ok(w) => w,
            Err(error) => {
                log::error!(target: "main", "error loading wallet file: {:?}", error);
                return;
            }
        };
    wallet.startup_sync(&rpc).unwrap();
    let tx = wallet
        .create_direct_send(&rpc, send_amount, destination, coins_to_spend)
        .unwrap();
    if dont_broadcast {
        let txhex = bitcoin::consensus::encode::serialize_hex(&tx);
        let accepted = rpc
            .test_mempool_accept(&[txhex.clone()])
            .unwrap()
            .iter()
            .any(|tma| tma.allowed);
        assert!(accepted);
        println!("tx = \n{}", txhex);
    } else {
        let txid = rpc.send_raw_transaction(&tx).unwrap();
        println!("broadcasted {}", txid);
    }
}

pub fn run_watchtower(kill_flag: Option<Arc<RwLock<bool>>>) {
    let rpc = match get_bitcoin_rpc() {
        Ok(rpc) => rpc,
        Err(error) => {
            log::error!(target: "main", "error connecting to bitcoin node: {:?}", error);
            return;
        }
    };

    watchtower_protocol::start_watchtower(
        &rpc,
        if kill_flag.is_none() {
            Arc::new(RwLock::new(false))
        } else {
            kill_flag.unwrap().clone()
        },
    );
}
