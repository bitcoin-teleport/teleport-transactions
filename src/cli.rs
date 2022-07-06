extern crate bitcoin;
extern crate bitcoin_wallet;
extern crate bitcoincore_rpc;

use std::convert::TryInto;
use std::io;
use std::io::Result;
use std::iter::repeat;
use std::path::PathBuf;
use std::sync::{Arc, RwLock};

use bitcoin::hashes::{hash160::Hash as Hash160, hex::ToHex};
use bitcoin::Amount;

use chrono::NaiveDateTime;

use crate as teleport;
use crate::contracts::{read_locktime_from_contract, SwapCoin};
use crate::direct_send::{CoinToSpend, Destination, SendAmount};
use crate::fidelity_bonds::{get_locktime_from_index, YearAndMonth};
use crate::json;
use crate::maker_protocol::MakerBehavior;
use crate::wallet_sync::{DisplayAddressType, UTXOSpendInfo, WalletSyncAddressAmount};

pub fn generate_wallet(wallet_file_name: &PathBuf) -> Result<()> {
    println!("input seed phrase extension (or leave blank for none): ");
    let mut extension = String::new();
    io::stdin().read_line(&mut extension)?;
    let extension = match !extension.trim().is_empty() {
        true => Some(extension.trim().to_string()),
        false => None,
    };

    let json::GenerateWalletResult {
        wallet_name,
        seed_phrase,
        extension,
    } = teleport::generate_wallet(&wallet_file_name, extension).unwrap();

    println!("\nWrite down this seed phrase =\n\"{}\"", seed_phrase);

    if let Some(extension) = extension {
        println!("\nAnd this extension =\n\"{}\"", extension);
    }

    println!(
        "\nThis seed phrase is NOT enough to backup all coins in your wallet\n\
        The teleport wallet file is needed to backup swapcoins"
    );
    println!("\nSaved to file `{}`", wallet_name);

    Ok(())
}

pub fn recover_wallet(wallet_file_name: &PathBuf) -> Result<()> {
    println!("input seed phrase: ");
    let mut seed_phrase = String::new();
    io::stdin().read_line(&mut seed_phrase)?;
    seed_phrase = seed_phrase.trim().to_string();

    println!("input seed phrase extension (or leave blank for none): ");
    let mut extension = String::new();
    io::stdin().read_line(&mut extension)?;
    extension = extension.trim().to_string();

    teleport::recover_wallet(&wallet_file_name, &seed_phrase, Some(extension)).unwrap();
    println!("\nSaved to file `{}`", wallet_file_name.to_string_lossy());
    Ok(())
}

pub fn display_wallet_balance(wallet_file_name: &PathBuf, long_form: Option<bool>) {
    let long_form = long_form.unwrap_or(false);

    let json::GetWalletBalanceResult {
        mediantime,
        spendable_balance,
        incomplete_coinswaps,
        live_timelocked_contracts,
    } = teleport::get_wallet_balance(&wallet_file_name).unwrap();

    let json::SpendableBalance {
        balance,
        utxo_count,
        utxos,
        mut fidelity_bond_utxos,
    } = spendable_balance;

    let json::LiveTimelockedContracts {
        mut incoming_contract_utxos,
        mut outgoing_contract_utxos,
    } = live_timelocked_contracts;

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
                .map(|(l, i)| (l, (i as &dyn SwapCoin)))
                .zip(repeat("hashlock"))
                .chain(
                    utxo_outgoing_swapcoins
                        .iter()
                        .map(|(l, o)| (l, (o as &dyn SwapCoin)))
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
            let unix_locktime = get_locktime_from_index(index);
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

// TODO: move render code here from lib.rs
pub fn display_wallet_addresses(
    wallet_file_name: &PathBuf,
    types: DisplayAddressType,
    network: Option<String>,
) {
    teleport::get_wallet_addresses(&wallet_file_name, types, network).unwrap();
}

pub fn print_receive_invoice(wallet_file_name: &PathBuf) {
    let json::GetReceiveInvoiceResult { address } =
        teleport::get_receive_invoice(&wallet_file_name).unwrap();

    println!("{}", address);
}

pub fn print_fidelity_bond_address(wallet_file_name: &PathBuf, locktime: &YearAndMonth) {
    let json::GetFidelityBondAddressResult {
        address,
        unix_locktime,
    } = teleport::get_fidelity_bond_address(&wallet_file_name, locktime).unwrap();

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
    println!("{}", address);
}

pub fn run_maker(
    wallet_file_name: &PathBuf,
    sync_amount: WalletSyncAddressAmount,
    port: u16,
    maker_behavior: MakerBehavior,
    kill_flag: Option<Arc<RwLock<bool>>>,
) {
    teleport::run_maker(
        wallet_file_name,
        sync_amount,
        port,
        maker_behavior,
        kill_flag,
    )
    .unwrap();
}

pub fn run_taker(
    wallet_file_name: &PathBuf,
    sync_amount: WalletSyncAddressAmount,
    fee_rate: u64,
    send_amount: u64,
    maker_count: u16,
    tx_count: u32,
) {
    teleport::run_taker(
        wallet_file_name,
        sync_amount,
        fee_rate,
        send_amount,
        maker_count,
        tx_count,
    )
    .unwrap();
}

// TODO: move render code here from lib.rs
pub fn recover_from_incomplete_coinswap(
    wallet_file_name: &PathBuf,
    hashvalue: Hash160,
    dont_broadcast: bool,
) {
    teleport::recover_from_incomplete_coinswap(wallet_file_name, hashvalue, dont_broadcast)
        .unwrap();
}

// TODO: move render code here from lib.rs
pub fn download_and_display_offers(network_str: Option<String>, maker_address: Option<String>) {
    teleport::download_offers(network_str, maker_address).unwrap();
}

pub fn direct_send(
    wallet_file_name: &PathBuf,
    fee_rate: u64,
    send_amount: SendAmount,
    destination: Destination,
    coins_to_spend: &[CoinToSpend],
    dont_broadcast: bool,
) {
    let json::DirectSendResult {
        test_mempool_accept_result,
        txhex,
        txid,
    } = teleport::direct_send(
        wallet_file_name,
        fee_rate,
        send_amount,
        destination,
        coins_to_spend,
        dont_broadcast,
    )
    .unwrap();

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

    if let Some(txid) = txid {
        println!("broadcasted {}", txid);
    } else {
        println!("tx = \n{}", txhex);
    }
}

pub fn run_watchtower(data_file_path: &PathBuf, kill_flag: Option<Arc<RwLock<bool>>>) {
    teleport::run_watchtower(data_file_path, kill_flag).unwrap();
}
