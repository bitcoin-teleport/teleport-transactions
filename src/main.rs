use bitcoin::consensus::encode::deserialize;
use bitcoin::hashes::{hash160::Hash as Hash160, hex::FromHex};
use bitcoin::{Script, Transaction};

use std::path::PathBuf;
use structopt::StructOpt;

use teleport;
use teleport::direct_send::{CoinToSpend, Destination, SendAmount};
use teleport::fidelity_bonds::YearAndMonth;
use teleport::maker_protocol::MakerBehavior;
use teleport::wallet_sync::WalletSyncAddressAmount;
use teleport::watchtower_protocol::{ContractTransaction, ContractsInfo};

#[derive(Debug, StructOpt)]
#[structopt(name = "teleport", about = "A tool for CoinSwap")]
struct ArgsWithWalletFile {
    /// Wallet file
    #[structopt(default_value = "wallet.teleport", parse(from_os_str), long)]
    wallet_file_name: PathBuf,

    /// Dont broadcast transactions, only output their transaction hex string
    /// Only for commands which involve sending transactions e.g. recover-from-incomplete-coinswap
    #[structopt(short, long)]
    dont_broadcast: bool,

    /// Miner fee rate, in satoshis per thousand vbytes, i.e. 1000 = 1 sat/vb
    #[structopt(default_value = "1000", short = "f", long)]
    fee_rate: u64,

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

    /// Runs yield generator aiming to produce an income
    RunYieldGenerator {
        /// Port to listen on, default is 6102
        port: Option<u16>,
        /// Special behavior used for testing e.g. "closeonsignsenderscontracttx"
        special_behavior: Option<String>,
    },

    /// Prints a fidelity bond timelocked address
    GetFidelityBondAddress {
        /// Locktime value of timelocked address as yyyy-mm year and month, for example "2025-03"
        year_and_month: YearAndMonth,
    },

    /// Runs Taker.
    DoCoinswap {
        /// Amount to send (in sats)
        send_amount: u64, //TODO convert this to SendAmount
        /// How many makers to route through, default 2
        maker_count: Option<u16>,
        /// How many transactions per hop, default 3
        tx_count: Option<u32>,
    },

    /// Broadcast contract transactions for incomplete coinswap. Locked up bitcoins are
    /// returned to your wallet after the timeout
    RecoverFromIncompleteCoinswap {
        /// Hashvalue as hex string which uniquely identifies the coinswap
        hashvalue: Hash160,
    },

    /// Download all offers from all makers out there. If bitcoin node not configured then
    /// provide the network as an argument, can also optionally download from one given maker
    DownloadOffers {
        /// Network in question, options are "main", "test", "signet". Only used if configured
        /// bitcoin node RPC is unreachable
        network: Option<String>,
        /// Optional single maker address to only download from. Useful if testing if your own
        /// maker is reachable
        maker_address: Option<String>,
    },

    /// Send a transaction from the wallet
    DirectSend {
        /// Amount to send (in sats), or "sweep" for sweep
        send_amount: SendAmount,
        /// Address to send coins to, or "wallet" to send back to own wallet
        destination: Destination,
        /// Coins to spend as inputs, either in long form "<txid>:vout" or short
        /// form "txid-prefix..txid-suffix:vout"
        coins_to_spend: Vec<CoinToSpend>,
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
        Subcommand::RunYieldGenerator {
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
        Subcommand::GetFidelityBondAddress { year_and_month } => {
            teleport::print_fidelity_bond_address(&args.wallet_file_name, &year_and_month);
        }
        Subcommand::DoCoinswap {
            send_amount,
            maker_count,
            tx_count,
        } => {
            teleport::run_taker(
                &args.wallet_file_name,
                WalletSyncAddressAmount::Normal,
                args.fee_rate,
                send_amount,
                maker_count.unwrap_or(2),
                tx_count.unwrap_or(3),
            );
        }
        Subcommand::RecoverFromIncompleteCoinswap { hashvalue } => {
            teleport::recover_from_incomplete_coinswap(
                &args.wallet_file_name,
                hashvalue,
                args.dont_broadcast,
            );
        }
        Subcommand::DownloadOffers {
            network,
            maker_address,
        } => {
            teleport::download_and_display_offers(network, maker_address);
        }
        Subcommand::DirectSend {
            send_amount,
            destination,
            coins_to_spend,
        } => {
            teleport::direct_send(
                &args.wallet_file_name,
                args.fee_rate,
                send_amount,
                destination,
                &coins_to_spend,
                args.dont_broadcast,
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
                .map(|cth| ContractTransaction {
                    tx: deserialize::<Transaction>(
                        &Vec::from_hex(&cth).expect("Invalid transaction hex string"),
                    )
                    .expect("Unable to deserialize transaction hex"),
                    redeemscript: Script::new(),
                    hashlock_spend_without_preimage: None,
                    timelock_spend: None,
                    timelock_spend_broadcasted: false,
                })
                .collect::<Vec<ContractTransaction>>();
            teleport::watchtower_client::test_watchtower_client(ContractsInfo {
                contract_txes,
                wallet_label: String::new(),
            });
        }
    }

    Ok(())
}
