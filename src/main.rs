extern crate bitcoin;
extern crate bitcoin_wallet;
extern crate bitcoincore_rpc;

use dirs::home_dir;
use std::io;
use std::path::PathBuf;
use std::sync::{Arc, RwLock};

use bitcoin::hashes::hex::ToHex;
use bitcoin::Amount;
use bitcoin_wallet::mnemonic;
use bitcoincore_rpc::{Auth, Client, Error, RpcApi};

use structopt::StructOpt;

mod wallet_sync;
use wallet_sync::Wallet;

mod contracts;
mod error;
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

    println!(
        "\nThis seed phrase is NOT enough to backup all coins in your wallet\n\
        The teleport wallet file is needed to backup swapcoins"
    );

    Wallet::save_new_wallet_file(&wallet_file_name, mnemonic.to_string(), extension).unwrap();

    let w = match Wallet::load_wallet_from_file(&wallet_file_name) {
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

    Wallet::save_new_wallet_file(&wallet_file_name, seed_phrase, extension).unwrap();
    Ok(())
}

fn get_bitcoin_rpc() -> Result<Client, Error> {
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
        "http://localhost:18443/wallet/teleport"
            //"http://localhost:18332/wallet/teleport"
            .to_string(),
        auth,
    )?;
    rpc.get_blockchain_info()?;
    Ok(rpc)
}

fn display_wallet_balance(wallet_file_name: &PathBuf, long_form: Option<bool>) {
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
    wallet.startup_sync(&rpc).unwrap();

    let long_form = long_form.unwrap_or(false);

    let mut utxos = wallet.list_unspent_from_wallet(&rpc).unwrap();
    utxos.sort_by(|a, b| b.confirmations.cmp(&a.confirmations));
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
            "{}{}{}:{} {}{}{} {:^8} {:<7} {}",
            if long_form { &txid } else {&txid[0..6] },
            if long_form { "" } else { ".." },
            if long_form { &"" } else { &txid[58..64] },
            utxo.vout,
            if long_form { &addr } else { &addr[0..10] },
            if long_form { "" } else { "...." },
            if long_form { &"" } else { &addr[addr.len() - 10..addr.len()] },
            if utxo.witness_script.is_some() { "yes" } else { "no" },
            utxo.confirmations,
            utxo.amount
        );
    }
    println!("coin count = {}", utxo_count);
    println!("total balance = {}", balance);
}

fn display_wallet_keys(wallet_file_name: &PathBuf) {
    let wallet = match Wallet::load_wallet_from_file(wallet_file_name) {
        Ok(w) => w,
        Err(error) => {
            println!("error loading wallet file: {:?}", error);
            return;
        }
    };
    wallet.print_wallet_key_data();
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
    wallet.startup_sync(&rpc).unwrap();

    let addr = match wallet.get_next_external_address(&rpc) {
        Ok(a) => a,
        Err(error) => {
            println!("error: {:?}", error);
            return;
        }
    };
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
    wallet.startup_sync(&rpc).unwrap();

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
    wallet.startup_sync(&rpc).unwrap();
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
    WalletBalance { long_form: Option<bool> },

    /// Dumps all information in wallet file for debugging
    DisplayWalletKeys,

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
        Subcommand::WalletBalance { long_form } => {
            display_wallet_balance(&args.wallet_file_name, long_form);
        }
        Subcommand::DisplayWalletKeys => {
            display_wallet_keys(&args.wallet_file_name);
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

#[cfg(test)]
mod test {
    use bitcoin::util::amount::Amount;
    use serde_json::Value;
    use std::{thread, time};
    use tokio::io::AsyncWriteExt;

    use std::str::FromStr;

    use super::*;

    static TAKER: &str = "tests/taker-wallet";
    static MAKER1: &str = "tests/maker-wallet-1";
    static MAKER2: &str = "tests/maker-wallet-2";

    // Helper function to create new wallet
    fn create_wallet_and_import(rpc: &Client, filename: PathBuf) -> Wallet {
        let mnemonic =
            mnemonic::Mnemonic::new_random(bitcoin_wallet::account::MasterKeyEntropy::Sufficient)
                .unwrap();

        Wallet::save_new_wallet_file(&filename, mnemonic.to_string(), "".to_string()).unwrap();

        let wallet = Wallet::load_wallet_from_file(filename).unwrap();
        // import intital addresses to core
        wallet
            .import_initial_addresses(
                &rpc,
                &wallet
                    .get_hd_wallet_descriptors(&rpc)
                    .unwrap()
                    .iter()
                    .collect::<Vec<&String>>(),
                &Vec::<_>::new(),
            )
            .unwrap();

        wallet
    }

    pub fn generate_1_block(rpc: &Client) {
        rpc.generate_to_address(1, &rpc.get_new_address(None, None).unwrap())
            .unwrap();
    }

    async fn kill_maker(addr: &str) {
        // Need to connect twice by a delay to stop maker
        // The outer loop in [maker_protocol::run()] iterates
        // immediately upon connecting a client,
        // The first iteration doesn't register kill signal
        // Signal registers in the 2nd iteration when a new client connects
        {
            let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();
            let (_, mut writer) = stream.split();

            writer.write_all(b"kill").await.unwrap();
        }
        thread::sleep(time::Duration::from_secs(5));
        {
            tokio::net::TcpStream::connect(addr).await.unwrap();
        }
    }

    // This test requires a bitcoin regtest node running in local machine with a
    // wallet name `teleport` loaded and have enough balance to execute transactions.
    #[tokio::test]
    async fn test_standard_coin_swap() {
        let rpc = get_bitcoin_rpc().unwrap();

        // unlock all utxos to avoid "insufficient fund" error
        rpc.call::<Value>("lockunspent", &[Value::Bool(true)])
            .unwrap();

        // create taker wallet
        let mut taker = create_wallet_and_import(&rpc, TAKER.into());

        // create maker1 wallet
        let mut maker1 = create_wallet_and_import(&rpc, MAKER1.into());

        // create maker2 wallet
        let mut maker2 = create_wallet_and_import(&rpc, MAKER2.into());

        // Check files are created
        assert!(std::path::Path::new(TAKER).exists());
        assert!(std::path::Path::new(MAKER1).exists());
        assert!(std::path::Path::new(MAKER2).exists());

        // Create 3 taker and maker address and send 0.05 btc to each
        for _ in 0..3 {
            let taker_address = taker.get_next_external_address(&rpc).unwrap();
            let maker1_address = maker1.get_next_external_address(&rpc).unwrap();
            let maker2_address = maker2.get_next_external_address(&rpc).unwrap();

            rpc.send_to_address(
                &taker_address,
                Amount::from_btc(0.05).unwrap(),
                None,
                None,
                None,
                None,
                None,
                None,
            )
            .unwrap();
            rpc.send_to_address(
                &maker1_address,
                Amount::from_btc(0.05).unwrap(),
                None,
                None,
                None,
                None,
                None,
                None,
            )
            .unwrap();
            rpc.send_to_address(
                &maker2_address,
                Amount::from_btc(0.05).unwrap(),
                None,
                None,
                None,
                None,
                None,
                None,
            )
            .unwrap();
        }

        generate_1_block(&rpc);

        // Check inital wallet assertions
        assert_eq!(taker.get_external_index(), 3);
        assert_eq!(maker1.get_external_index(), 3);
        assert_eq!(maker2.get_external_index(), 3);

        assert_eq!(taker.list_unspent_from_wallet(&rpc).unwrap().len(), 3);
        assert_eq!(maker1.list_unspent_from_wallet(&rpc).unwrap().len(), 3);
        assert_eq!(maker2.list_unspent_from_wallet(&rpc).unwrap().len(), 3);

        assert_eq!(taker.lock_all_nonwallet_unspents(&rpc).unwrap(), ());
        assert_eq!(maker1.lock_all_nonwallet_unspents(&rpc).unwrap(), ());
        assert_eq!(maker2.lock_all_nonwallet_unspents(&rpc).unwrap(), ());

        // Start threads and execute swaps
        let maker1_thread = thread::spawn(|| {
            run_maker(&PathBuf::from_str(MAKER1).unwrap(), 6102);
        });

        let maker2_thread = thread::spawn(|| {
            run_maker(&PathBuf::from_str(MAKER2).unwrap(), 16102);
        });

        let taker_thread = thread::spawn(|| {
            // Wait and then start the taker
            thread::sleep(time::Duration::from_secs(5));
            run_taker(&PathBuf::from_str(TAKER).unwrap());
        });

        taker_thread.join().unwrap();

        kill_maker("127.0.0.1:6102").await;

        kill_maker("127.0.0.1:16102").await;

        maker1_thread.join().unwrap();

        maker2_thread.join().unwrap();

        // Recreate the wallet
        let taker = Wallet::load_wallet_from_file(&TAKER).unwrap();
        let maker1 = Wallet::load_wallet_from_file(&MAKER1).unwrap();
        let maker2 = Wallet::load_wallet_from_file(&MAKER2).unwrap();

        // Check assertions
        assert_eq!(taker.get_swap_coins_count(), 3);
        assert_eq!(maker1.get_swap_coins_count(), 6);
        assert_eq!(maker2.get_swap_coins_count(), 6);

        let rpc = get_bitcoin_rpc().unwrap();

        let utxos = taker.list_unspent_from_wallet(&rpc).unwrap();
        let balance: Amount = utxos.iter().fold(Amount::ZERO, |acc, u| acc + u.amount);
        assert_eq!(utxos.len(), 6);
        assert!(balance < Amount::from_btc(0.15).unwrap());

        let utxos = maker1.list_unspent_from_wallet(&rpc).unwrap();
        let balance: Amount = utxos.iter().fold(Amount::ZERO, |acc, u| acc + u.amount);
        assert_eq!(utxos.len(), 6);
        assert!(balance > Amount::from_btc(0.15).unwrap());

        let utxos = maker2.list_unspent_from_wallet(&rpc).unwrap();
        let balance: Amount = utxos.iter().fold(Amount::ZERO, |acc, u| acc + u.amount);
        assert_eq!(utxos.len(), 6);
        assert!(balance > Amount::from_btc(0.15).unwrap());
    }
}
