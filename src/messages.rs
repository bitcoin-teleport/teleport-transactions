//we make heavy use of serde_json's de/serialization for the benefits of
//having the compiler check for us, extra type checking and readability

//this works because of enum representations in serde
//see https://serde.rs/enum-representations.html

use serde::{Deserialize, Serialize};

use bitcoin::secp256k1::{SecretKey, Signature};
use bitcoin::util::key::PublicKey;
use bitcoin::{Script, Transaction};

use crate::error::Error;

//TODO the structs here which are actual messages should have the word Message
//added to their name e.g. SignSendersContractTx
//to distinguish them from structs which just collect together
//data e.g. SenderContractTxInfo

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct TakerHello {
    pub protocol_version_min: u32,
    pub protocol_version_max: u32,
}

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct GiveOffer;

#[derive(Debug, Serialize, Deserialize)]
pub struct SenderContractTxNoncesInfo {
    pub multisig_key_nonce: SecretKey,
    pub hashlock_key_nonce: SecretKey,
    pub timelock_pubkey: PublicKey,
    pub senders_contract_tx: Transaction,
    pub multisig_redeemscript: Script,
    pub funding_input_value: u64,
}

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct SignSendersContractTx {
    pub txes_info: Vec<SenderContractTxNoncesInfo>,
    pub hashvalue: [u8; 20],
    pub locktime: u16,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ConfirmedCoinSwapTxInfo {
    pub funding_tx: Transaction,
    pub funding_tx_merkleproof: String,
    pub multisig_redeemscript: Script,
    pub multisig_key_nonce: SecretKey,
    pub contract_redeemscript: Script,
    pub hashlock_key_nonce: SecretKey,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct NextCoinSwapTxInfo {
    pub next_coinswap_multisig_pubkey: PublicKey,
    pub next_hashlock_pubkey: PublicKey,
}

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct ProofOfFunding {
    pub confirmed_funding_txes: Vec<ConfirmedCoinSwapTxInfo>,
    pub next_coinswap_info: Vec<NextCoinSwapTxInfo>,
    pub next_locktime: u16,
}

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct SendersAndReceiversContractSigs {
    pub receivers_sigs: Vec<Signature>,
    pub senders_sigs: Vec<Signature>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ReceiversContractTxInfo {
    pub multisig_redeemscript: Script,
    pub contract_tx: Transaction,
}

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct SignReceiversContractTx {
    pub txes: Vec<ReceiversContractTxInfo>,
}

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct HashPreimage {
    pub senders_multisig_redeemscripts: Vec<Script>,
    pub receivers_multisig_redeemscripts: Vec<Script>,
    pub preimage: [u8; 32],
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SwapCoinPrivateKey {
    pub multisig_redeemscript: Script,
    pub key: SecretKey,
}

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct PrivateKeyHandover {
    pub swapcoin_private_keys: Vec<SwapCoinPrivateKey>, //could easily be called private_keys not swapcoin_private_keys
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "method", rename_all = "lowercase")]
pub enum TakerToMakerMessage {
    TakerHello(TakerHello),
    GiveOffer(GiveOffer),
    SignSendersContractTx(SignSendersContractTx),
    ProofOfFunding(ProofOfFunding),
    SendersAndReceiversContractSigs(SendersAndReceiversContractSigs),
    SignReceiversContractTx(SignReceiversContractTx),
    HashPreimage(HashPreimage),
    PrivateKeyHandover(PrivateKeyHandover),
}

impl std::convert::TryFrom<&str> for TakerToMakerMessage {
    type Error = Error;

    fn try_from(m: &str) -> Result<Self, Self::Error> {
        match m {
            _ if m == "takerhello" => Ok(Self::TakerHello(Default::default())),
            _ if m == "giveoffer" => Ok(Self::GiveOffer(Default::default())),
            _ if m == "signsenderscontracttx" => {
                Ok(Self::SignSendersContractTx(Default::default()))
            }
            _ if m == "proofoffunding" => Ok(Self::ProofOfFunding(Default::default())),
            _ if m == "sendersandreceiverscontractsigs" => {
                Ok(Self::SendersAndReceiversContractSigs(Default::default()))
            }
            _ if m == "signreceiverscontracttx" => {
                Ok(Self::SignReceiversContractTx(Default::default()))
            }
            _ if m == "hashpreimage" => Ok(Self::HashPreimage(Default::default())),
            _ if m == "privatekeyhandover" => Ok(Self::PrivateKeyHandover(Default::default())),
            _ => Err(Error::Protocol("unsupported TakerToMakerMessage")),
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct MakerHello {
    pub protocol_version_min: u32,
    pub protocol_version_max: u32,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Offer {
    pub absolute_fee: u32,
    pub amount_relative_fee: f32,
    pub max_size: u64,
    pub min_size: u64,
    pub tweakable_point: PublicKey,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SendersContractSig {
    pub sigs: Vec<Signature>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SenderContractTxInfo {
    pub contract_tx: Transaction,
    pub timelock_pubkey: PublicKey,
    pub multisig_redeemscript: Script,
    pub funding_amount: u64,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SignSendersAndReceiversContractTxes {
    pub receivers_contract_txes: Vec<Transaction>,
    pub senders_contract_txes_info: Vec<SenderContractTxInfo>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ReceiversContractSig {
    pub sigs: Vec<Signature>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "method", rename_all = "lowercase")]
pub enum MakerToTakerMessage {
    MakerHello(MakerHello),
    Offer(Offer),
    SendersContractSig(SendersContractSig),
    SignSendersAndReceiversContractTxes(SignSendersAndReceiversContractTxes),
    ReceiversContractSig(ReceiversContractSig),
    PrivateKeyHandover(PrivateKeyHandover),
}
