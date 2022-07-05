use crate::wallet_sync::{IncomingSwapCoin, OutgoingSwapCoin, UTXOSpendInfo};
use bitcoin::hashes::hash160::Hash as Hash160;
use bitcoin::{Address, Amount, Txid};
use bitcoincore_rpc::json::{ListUnspentResultEntry, TestMempoolAcceptResult};
use serde::Serialize;
use std::collections::HashMap;

#[derive(Serialize, Debug)]
pub struct GenerateWalletResult {
    pub wallet_name: String,
    pub seed_phrase: String,
    pub extension: Option<String>,
}

#[derive(Serialize, Debug)]
pub struct RecoverWalletResult {
    pub wallet_name: String,
    pub extension: Option<String>,
}

#[derive(Serialize, Debug)]
pub struct GetWalletBalanceResult {
    pub mediantime: u64,
    pub spendable_balance: SpendableBalance,
    pub incomplete_coinswaps: HashMap<
        Hash160,
        (
            Vec<(ListUnspentResultEntry, IncomingSwapCoin)>,
            Vec<(ListUnspentResultEntry, OutgoingSwapCoin)>,
        ),
    >,
    pub live_timelocked_contracts: LiveTimelockedContracts,
}

#[derive(Serialize, Debug)]
pub struct SpendableBalance {
    #[serde(with = "bitcoin::util::amount::serde::as_btc")]
    pub balance: Amount,
    pub utxo_count: usize,
    pub utxos: Vec<(ListUnspentResultEntry, UTXOSpendInfo)>,
    pub fidelity_bond_utxos: Vec<(ListUnspentResultEntry, UTXOSpendInfo)>,
}

#[derive(Serialize, Debug)]
pub struct LiveTimelockedContracts {
    pub incoming_contract_utxos: Vec<(IncomingSwapCoin, ListUnspentResultEntry)>,
    pub outgoing_contract_utxos: Vec<(OutgoingSwapCoin, ListUnspentResultEntry)>,
}

#[derive(Serialize, Debug)]
pub struct GetWalletAdressesResult {
    // TODO:
}

#[derive(Serialize, Debug)]
pub struct GetReceiveInvoiceResult {
    pub address: Address,
}

#[derive(Serialize, Debug)]
pub struct GetFidelityBondAddressResult {
    pub address: Address,
    pub unix_locktime: i64,
}

#[derive(Serialize, Debug)]
pub struct RecoverFromIncompleteCoinswapResult {
    // TODO:
}

#[derive(Serialize, Debug)]
pub struct DownloadOffersResult {
    // TODO:
}

pub struct DirectSendResult {
    pub test_mempool_accept_result: TestMempoolAcceptResult,
    pub txhex: String,
    pub txid: Option<Txid>,
}
