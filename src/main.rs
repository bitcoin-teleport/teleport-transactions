use std::io;

use std::sync::{Arc, RwLock};

extern crate bitcoin_wallet;
use bitcoin_wallet::mnemonic;

extern crate bitcoin;
use bitcoin::hashes::hex::ToHex;
use bitcoin::Amount;

extern crate bitcoincore_rpc;
use bitcoincore_rpc::{Auth, Client, Error, RpcApi};

use structopt::StructOpt;

extern crate rand;

mod wallet_sync;
use std::path::PathBuf;
use wallet_sync::Wallet;

mod contracts;
mod maker_protocol;
mod messages;
mod offerbook_sync;
mod taker_protocol;

fn generate_wallet(wallet_file_name: &PathBuf) -> std::io::Result<()> {
    let rpc = match get_bitcoin_rpc() {
        Ok(rpc) => rpc,
        Err(error) => {
            println!("error connecting to bitcoin node: {:?}", error);
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

    println!("Write down this seed phrase =\n{}", mnemonic.to_string());

    if !extension.trim().is_empty() {
        println!("And this extension =\n\"{}\"", extension);
    }

    println!("\nThis seed phrase is NOT enough to backup all coins in your wallet");

    Wallet::save_new_wallet_file(&wallet_file_name, mnemonic.to_string(), extension)?;

    let w = match Wallet::load_wallet_from_file(&wallet_file_name) {
        Ok(w) => w,
        Err(error) => panic!("error loading wallet file: {:?}", error),
    };
    println!("Importing addresses into Core. . .");
    w.import_initial_addresses(
        &rpc,
        &w.get_hd_wallet_descriptors(&rpc)
            .iter()
            .collect::<Vec<&String>>(),
        &Vec::<_>::new(),
    );
    Ok(())
}

fn recover_wallet(wallet_file_name: &PathBuf) -> std::io::Result<()> {
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

    Wallet::save_new_wallet_file(&wallet_file_name, seed_phrase, extension)?;
    Ok(())
}

fn get_bitcoin_rpc() -> Result<Client, Error> {
    //TODO put all this in a config file
    let auth = Auth::UserPass(
        "regtestrpcuser".to_string(),
        "regtestrpcpass".to_string(),
        //"btcrpcuser".to_string(),
        //"btcrpcpass".to_string()
    );
    let rpc = Client::new(
        "http://localhost:18443/wallet/teleport"
            //"http://localhost:18332/wallet/teleport"
            .to_string(),
        auth,
    )?;
    rpc.get_blockchain_info()?;
    Ok(rpc)
}

fn display_wallet_balance(wallet_file_name: &PathBuf) {
    let mut wallet = match Wallet::load_wallet_from_file(wallet_file_name) {
        Ok(w) => w,
        Err(error) => {
            println!("error loading wallet file: {:?}", error);
            return;
        }
    };
    let rpc = match get_bitcoin_rpc() {
        Ok(rpc) => rpc,
        Err(error) => {
            println!("error connecting to bitcoin node: {:?}", error);
            return;
        }
    };
    wallet.startup_sync(&rpc);

    let utxos = wallet.list_unspent_from_wallet(&rpc).unwrap();
    let utxo_count = utxos.len();
    let balance: Amount = utxos.iter().fold(Amount::ZERO, |acc, u| acc + u.amount);
    println!(
        "{:16} {:24} {:8} {:<7} value",
        "outpoint", "address", "swapcoin", "conf",
    );
    for utxo in utxos {
        let txid = utxo.txid.to_hex();
        let addr = utxo.address.unwrap().to_string();
        #[rustfmt::skip]
        println!(
            "{}..{}:{} {}....{} {:^8} {:<7} {}",
            &txid[0..6],
            &txid[58..64],
            utxo.vout,
            &addr[0..10],
            &addr[addr.len() - 10..addr.len()],
            if utxo.witness_script.is_some() { "yes" } else { "no" },
            utxo.confirmations,
            utxo.amount
        );
    }
    println!("coin count = {}", utxo_count);
    println!("total balance = {}", balance);
}

fn print_receive_invoice(wallet_file_name: &PathBuf) {
    let mut wallet = match Wallet::load_wallet_from_file(wallet_file_name) {
        Ok(w) => w,
        Err(error) => {
            println!("error loading wallet file: {:?}", error);
            return;
        }
    };
    let rpc = match get_bitcoin_rpc() {
        Ok(rpc) => rpc,
        Err(error) => {
            println!("error connecting to bitcoin node: {:?}", error);
            return;
        }
    };
    wallet.startup_sync(&rpc);

    let addr = wallet.get_next_external_address(&rpc);
    println!("receive invoice:\n\nbitcoin:{}\n", addr);
}

fn run_maker(wallet_file_name: &PathBuf, port: u16) {
    let rpc = match get_bitcoin_rpc() {
        Ok(rpc) => rpc,
        Err(error) => {
            println!("error connecting to bitcoin node: {:?}", error);
            return;
        }
    };
    let mut wallet = match Wallet::load_wallet_from_file(wallet_file_name) {
        Ok(w) => w,
        Err(error) => {
            println!("error loading wallet file: {:?}", error);
            return;
        }
    };
    wallet.startup_sync(&rpc);

    let rpc_ptr = Arc::new(rpc);
    let wallet_ptr = Arc::new(RwLock::new(wallet));
    maker_protocol::start_maker(rpc_ptr, wallet_ptr, port);
}

fn run_taker(wallet_file_name: &PathBuf) {
    let rpc = match get_bitcoin_rpc() {
        Ok(rpc) => rpc,
        Err(error) => {
            println!("error connecting to bitcoin node: {:?}", error);
            return;
        }
    };
    let mut wallet = match Wallet::load_wallet_from_file(wallet_file_name) {
        Ok(w) => w,
        Err(error) => {
            println!("error loading wallet file: {:?}", error);
            return;
        }
    };
    wallet.startup_sync(&rpc);
    taker_protocol::start_taker(&rpc, &mut wallet);
}

#[derive(Debug, StructOpt)]
#[structopt(name = "teleport", about = "A tool for CoinSwap")]
struct ArgsWithWalletFile {
    /// Wallet file
    #[structopt(default_value = "wallet.teleport", parse(from_os_str), long)]
    wallet_file_name: PathBuf,

    /// Subcommand
    #[structopt(flatten)]
    subcommand: Subcommand,
}

#[derive(Debug, StructOpt)]
#[structopt(name = "teleport", about = "A tool for CoinSwap")]
enum Subcommand {
    /// Generates a new wallet file from a given seed phrase.
    GenerateWallet,

    /// Recovers a wallet file from a given seed phrase.
    RecoverWallet,

    /// Prints current wallet balance.
    WalletBalance,

    /// Prints receive invoice.
    GetReceiveInvoice,

    /// Runs Maker server on provided port.
    RunMaker { port: u16 },

    /// Runs Taker.
    CoinswapSend,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = ArgsWithWalletFile::from_args();

    match args.subcommand {
        Subcommand::GenerateWallet => {
            generate_wallet(&args.wallet_file_name)?;
        }

        Subcommand::RecoverWallet => {
            recover_wallet(&args.wallet_file_name)?;
        }

        Subcommand::WalletBalance => {
            display_wallet_balance(&args.wallet_file_name);
        }

        Subcommand::GetReceiveInvoice => {
            print_receive_invoice(&args.wallet_file_name);
        }

        Subcommand::RunMaker { port } => {
            run_maker(&args.wallet_file_name, port);
        }

        Subcommand::CoinswapSend => {
            run_taker(&args.wallet_file_name);
        }
    }

    Ok(())
}
