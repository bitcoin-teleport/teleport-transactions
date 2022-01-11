use bitcoin::consensus::encode::deserialize;
use bitcoin::hashes::{hash160::Hash as Hash160, hex::FromHex};
use bitcoin::Transaction;

use std::path::PathBuf;
use structopt::StructOpt;

use teleport;
use teleport::maker_protocol::MakerBehavior;
use teleport::wallet_sync::WalletSyncAddressAmount;
use teleport::watchtower_client::ContractInfo;

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
    /// Generates a new seed phrase and wallet file
    GenerateWallet,

    /// Recovers a wallet file from an existing seed phrase
    RecoverWallet,

    /// Prints current wallet balance.
    WalletBalance {
        /// Whether to print entire TXIDs and addresses
        long_form: Option<bool>,
    },

    /// Dumps all information in wallet file for debugging
    DisplayWalletKeys,

    /// Prints receive invoice.
    GetReceiveInvoice,

    /// Runs Maker server
    RunMaker {
        /// Port to listen on, default is 6102
        port: Option<u16>,
        /// Special behavior used for testing e.g. "closeonsignsenderscontracttx"
        special_behavior: Option<String>,
    },

    /// Runs Taker.
    CoinswapSend,

    /// Broadcast contract transactions for incomplete coinswap. Locked up bitcoins are
    /// returned to your wallet after the timeout
    RecoverFromIncompleteCoinswap {
        /// Hashvalue as hex string which uniquely identifies the coinswap
        hashvalue: Hash160,
        /// Dont broadcast transactions, only output their transaction hex string
        dont_broadcast: Option<bool>,
    },

    /// Run watchtower
    RunWatchtower,

    /// Test watchtower client
    TestWatchtowerClient {
        contract_transactions_hex: Vec<String>,
    },
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    teleport::setup_logger();
    let args = ArgsWithWalletFile::from_args();

    match args.subcommand {
        Subcommand::GenerateWallet => {
            teleport::generate_wallet(&args.wallet_file_name)?;
        }
        Subcommand::RecoverWallet => {
            teleport::recover_wallet(&args.wallet_file_name)?;
        }
        Subcommand::WalletBalance { long_form } => {
            teleport::display_wallet_balance(&args.wallet_file_name, long_form);
        }
        Subcommand::DisplayWalletKeys => {
            teleport::display_wallet_keys(&args.wallet_file_name);
        }
        Subcommand::GetReceiveInvoice => {
            teleport::print_receive_invoice(&args.wallet_file_name);
        }
        Subcommand::RunMaker {
            port,
            special_behavior,
        } => {
            let maker_special_behavior = match special_behavior.unwrap_or(String::new()).as_str() {
                "closeonsignsenderscontracttx" => MakerBehavior::CloseOnSignSendersContractTx,
                _ => MakerBehavior::Normal,
            };
            teleport::run_maker(
                &args.wallet_file_name,
                WalletSyncAddressAmount::Normal,
                port.unwrap_or(6102),
                maker_special_behavior,
                None,
            );
        }
        Subcommand::CoinswapSend => {
            teleport::run_taker(&args.wallet_file_name, WalletSyncAddressAmount::Normal);
        }
        Subcommand::RecoverFromIncompleteCoinswap {
            hashvalue,
            dont_broadcast,
        } => {
            teleport::recover_from_incomplete_coinswap(
                &args.wallet_file_name,
                hashvalue,
                dont_broadcast.unwrap_or(false),
            );
        }
        Subcommand::RunWatchtower => {
            teleport::run_watchtower(None);
        }
        Subcommand::TestWatchtowerClient {
            mut contract_transactions_hex,
        } => {
            if contract_transactions_hex.is_empty() {
                // https://bitcoin.stackexchange.com/questions/68811/what-is-the-absolute-smallest-size-of-the-data-bytes-that-a-blockchain-transac
                contract_transactions_hex =
                    vec![String::from(concat!("020000000001010000000000000",
                "0000000000000000000000000000000000000000000000000000000000000fdffffff010100000000",
                "000000160014ffffffffffffffffffffffffffffffffffffffff02210200000000000000000000000",
                "000000000000000000000000000000000000000014730440220777777777777777777777777777777",
                "777777777777777777777777777777777702205555555555555555555555555555555555555555555",
                "5555555555555555555550100000000"))];
            }
            let contract_txes = contract_transactions_hex
                .iter()
                .map(|cth| {
                    deserialize::<Transaction>(
                        &Vec::from_hex(&cth).expect("Invalid transaction hex string"),
                    )
                    .expect("Unable to deserialize transaction hex")
                })
                .collect::<Vec<Transaction>>();
            let contracts_to_watch = contract_txes
                .iter()
                .map(|contract_tx| ContractInfo {
                    contract_tx: contract_tx.clone(),
                })
                .collect::<Vec<ContractInfo>>();
            teleport::watchtower_client::test_watchtower_client(contracts_to_watch);
        }
    }

    Ok(())
}
