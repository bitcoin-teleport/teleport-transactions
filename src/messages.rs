//we make heavy use of serde_json's de/serialization for the benefits of
//having the compiler check for us, extra type checking and readability

//this works because of enum representations in serde
//see https://serde.rs/enum-representations.html

use serde::{Deserialize, Serialize};

use bitcoin::consensus::{Decodable, Encodable};
use bitcoin::hashes::hash160::Hash as Hash160;
use bitcoin::hashes::Hash;
use bitcoin::secp256k1::{SecretKey, Signature};
use bitcoin::util::key::PublicKey;
use bitcoin::{Script, Transaction};

use crate::serialization::{NetDeserilize, NetSerializationError, NetSerialize};

pub const PREIMAGE_LEN: usize = 32;
pub type Preimage = [u8; PREIMAGE_LEN];

//TODO the structs here which are actual messages should have the word Message
//added to their name e.g. SignSendersContractTx
//to distinguish them from structs which just collect together
//data e.g. SenderContractTxInfo

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct TakerHello {
    pub protocol_version_min: u32,
    pub protocol_version_max: u32,
}

impl NetSerialize for TakerHello {
    fn net_serialize<W: std::io::Write>(&self, mut w: W) -> Result<usize, NetSerializationError> {
        let mut len = self.protocol_version_min.consensus_encode(&mut w)?;
        len += self.protocol_version_max.consensus_encode(&mut w)?;
        Ok(len)
    }
}

impl NetDeserilize for TakerHello {
    fn net_deserialize<R: std::io::Read>(mut r: R) -> Result<Self, NetSerializationError> {
        Ok(Self {
            protocol_version_min: u32::consensus_decode(&mut r)?,
            protocol_version_max: u32::consensus_decode(&mut r)?,
        })
    }
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct GiveOffer;

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq, Clone)]
pub struct SenderContractTxNoncesInfo {
    pub multisig_key_nonce: SecretKey,
    pub hashlock_key_nonce: SecretKey,
    pub timelock_pubkey: PublicKey,
    pub senders_contract_tx: Transaction,
    pub multisig_redeemscript: Script,
    pub funding_input_value: u64,
}

impl NetSerialize for SenderContractTxNoncesInfo {
    fn net_serialize<W: std::io::Write>(&self, mut w: W) -> Result<usize, NetSerializationError> {
        let mut len = self.multisig_key_nonce.net_serialize(&mut w)?;
        len += self.hashlock_key_nonce.net_serialize(&mut w)?;
        len += self.timelock_pubkey.net_serialize(&mut w)?;
        len += self.senders_contract_tx.consensus_encode(&mut w)?;
        len += self.multisig_redeemscript.consensus_encode(&mut w)?;
        len += self.funding_input_value.consensus_encode(&mut w)?;

        Ok(len)
    }
}

impl NetDeserilize for SenderContractTxNoncesInfo {
    fn net_deserialize<R: std::io::Read>(mut r: R) -> Result<Self, NetSerializationError> {
        Ok(Self {
            multisig_key_nonce: SecretKey::net_deserialize(&mut r)?,
            hashlock_key_nonce: SecretKey::net_deserialize(&mut r)?,
            timelock_pubkey: PublicKey::net_deserialize(&mut r)?,
            senders_contract_tx: Transaction::consensus_decode(&mut r)?,
            multisig_redeemscript: Script::net_deserialize(&mut r)?,
            funding_input_value: u64::consensus_decode(&mut r)?,
        })
    }
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct SignSendersContractTx {
    pub txes_info: Vec<SenderContractTxNoncesInfo>,
    pub hashvalue: Hash160,
    pub locktime: u16,
}

impl NetSerialize for SignSendersContractTx {
    fn net_serialize<W: std::io::Write>(&self, mut w: W) -> Result<usize, NetSerializationError> {
        let mut len = self.txes_info.net_serialize(&mut w)?;
        len += self.hashvalue.as_inner().net_serialize(&mut w)?;
        len += self.locktime.consensus_encode(&mut w)?;

        Ok(len)
    }
}

impl NetDeserilize for SignSendersContractTx {
    fn net_deserialize<R: std::io::Read>(mut r: R) -> Result<Self, NetSerializationError> {
        Ok(Self {
            txes_info: Vec::<SenderContractTxNoncesInfo>::net_deserialize(&mut r)?,
            hashvalue: Hash160::from_slice(&<[u8; 20]>::net_deserialize(&mut r)?)?,
            locktime: u16::consensus_decode(&mut r)?,
        })
    }
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq, Clone)]
pub struct ConfirmedCoinSwapTxInfo {
    pub funding_tx: Transaction,
    pub funding_tx_merkleproof: String,
    pub multisig_redeemscript: Script,
    pub multisig_key_nonce: SecretKey,
    pub contract_redeemscript: Script,
    pub hashlock_key_nonce: SecretKey,
}

impl NetSerialize for ConfirmedCoinSwapTxInfo {
    fn net_serialize<W: std::io::Write>(&self, mut w: W) -> Result<usize, NetSerializationError> {
        let mut len = self.funding_tx.consensus_encode(&mut w)?;
        len += self.funding_tx_merkleproof.consensus_encode(&mut w)?;
        len += self.multisig_redeemscript.consensus_encode(&mut w)?;
        len += self.multisig_key_nonce.net_serialize(&mut w)?;
        len += self.contract_redeemscript.consensus_encode(&mut w)?;
        len += self.hashlock_key_nonce.net_serialize(&mut w)?;

        Ok(len)
    }
}

impl NetDeserilize for ConfirmedCoinSwapTxInfo {
    fn net_deserialize<R: std::io::Read>(mut r: R) -> Result<Self, NetSerializationError> {
        Ok(Self {
            funding_tx: Transaction::consensus_decode(&mut r)?,
            funding_tx_merkleproof: String::consensus_decode(&mut r)?,
            multisig_redeemscript: Script::net_deserialize(&mut r)?,
            multisig_key_nonce: SecretKey::net_deserialize(&mut r)?,
            contract_redeemscript: Script::net_deserialize(&mut r)?,
            hashlock_key_nonce: SecretKey::net_deserialize(&mut r)?,
        })
    }
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq, Clone)]
pub struct NextCoinSwapTxInfo {
    pub next_coinswap_multisig_pubkey: PublicKey,
    pub next_hashlock_pubkey: PublicKey,
}

impl NetSerialize for NextCoinSwapTxInfo {
    fn net_serialize<W: std::io::Write>(&self, mut w: W) -> Result<usize, NetSerializationError> {
        let mut len = self.next_coinswap_multisig_pubkey.net_serialize(&mut w)?;
        len += self.next_hashlock_pubkey.net_serialize(&mut w)?;
        Ok(len)
    }
}

impl NetDeserilize for NextCoinSwapTxInfo {
    fn net_deserialize<R: std::io::Read>(mut r: R) -> Result<Self, NetSerializationError> {
        Ok(Self {
            next_coinswap_multisig_pubkey: PublicKey::net_deserialize(&mut r)?,
            next_hashlock_pubkey: PublicKey::net_deserialize(&mut r)?,
        })
    }
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProofOfFunding {
    pub confirmed_funding_txes: Vec<ConfirmedCoinSwapTxInfo>,
    pub next_coinswap_info: Vec<NextCoinSwapTxInfo>,
    pub next_locktime: u16,
}

impl NetSerialize for ProofOfFunding {
    fn net_serialize<W: std::io::Write>(&self, mut w: W) -> Result<usize, NetSerializationError> {
        let mut len = self.confirmed_funding_txes.net_serialize(&mut w)?;
        len += self.next_coinswap_info.net_serialize(&mut w)?;
        len += self.next_locktime.consensus_encode(&mut w)?;

        Ok(len)
    }
}

impl NetDeserilize for ProofOfFunding {
    fn net_deserialize<R: std::io::Read>(mut r: R) -> Result<Self, NetSerializationError> {
        Ok(Self {
            confirmed_funding_txes: Vec::<ConfirmedCoinSwapTxInfo>::net_deserialize(&mut r)?,
            next_coinswap_info: Vec::<NextCoinSwapTxInfo>::net_deserialize(&mut r)?,
            next_locktime: u16::consensus_decode(&mut r)?,
        })
    }
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct SendersAndReceiversContractSigs {
    pub receivers_sigs: Vec<Signature>,
    pub senders_sigs: Vec<Signature>,
}

impl NetSerialize for SendersAndReceiversContractSigs {
    fn net_serialize<W: std::io::Write>(&self, mut w: W) -> Result<usize, NetSerializationError> {
        let mut len = self.receivers_sigs.net_serialize(&mut w)?;
        len += self.senders_sigs.net_serialize(&mut w)?;

        Ok(len)
    }
}

impl NetDeserilize for SendersAndReceiversContractSigs {
    fn net_deserialize<R: std::io::Read>(mut r: R) -> Result<Self, NetSerializationError> {
        Ok(Self {
            receivers_sigs: Vec::<Signature>::net_deserialize(&mut r)?,
            senders_sigs: Vec::<Signature>::net_deserialize(&mut r)?,
        })
    }
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq, Clone)]
pub struct ReceiversContractTxInfo {
    pub multisig_redeemscript: Script,
    pub contract_tx: Transaction,
}

impl NetSerialize for ReceiversContractTxInfo {
    fn net_serialize<W: std::io::Write>(&self, mut w: W) -> Result<usize, NetSerializationError> {
        let mut len = self.multisig_redeemscript.consensus_encode(&mut w)?;
        len += self.contract_tx.consensus_encode(&mut w)?;

        Ok(len)
    }
}

impl NetDeserilize for ReceiversContractTxInfo {
    fn net_deserialize<R: std::io::Read>(mut r: R) -> Result<Self, NetSerializationError> {
        Ok(Self {
            multisig_redeemscript: Script::consensus_decode(&mut r)?,
            contract_tx: Transaction::consensus_decode(&mut r)?,
        })
    }
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct SignReceiversContractTx {
    pub txes: Vec<ReceiversContractTxInfo>,
}

impl NetSerialize for SignReceiversContractTx {
    fn net_serialize<W: std::io::Write>(&self, mut w: W) -> Result<usize, NetSerializationError> {
        self.txes.net_serialize(&mut w)
    }
}

impl NetDeserilize for SignReceiversContractTx {
    fn net_deserialize<R: std::io::Read>(mut r: R) -> Result<Self, NetSerializationError> {
        Ok(Self {
            txes: Vec::<ReceiversContractTxInfo>::net_deserialize(&mut r)?,
        })
    }
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct HashPreimage {
    pub senders_multisig_redeemscripts: Vec<Script>,
    pub receivers_multisig_redeemscripts: Vec<Script>,
    pub preimage: Preimage,
}

impl NetSerialize for HashPreimage {
    fn net_serialize<W: std::io::Write>(&self, mut w: W) -> Result<usize, NetSerializationError> {
        let mut len = self.senders_multisig_redeemscripts.net_serialize(&mut w)?;
        len += self
            .receivers_multisig_redeemscripts
            .net_serialize(&mut w)?;
        len += self.preimage.consensus_encode(&mut w)?;

        Ok(len)
    }
}

impl NetDeserilize for HashPreimage {
    fn net_deserialize<R: std::io::Read>(mut r: R) -> Result<Self, NetSerializationError> {
        Ok(Self {
            senders_multisig_redeemscripts: Vec::<Script>::net_deserialize(&mut r)?,
            receivers_multisig_redeemscripts: Vec::<Script>::net_deserialize(&mut r)?,
            preimage: <[u8; 32]>::consensus_decode(&mut r)?,
        })
    }
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq, Clone)]
pub struct SwapCoinPrivateKey {
    pub multisig_redeemscript: Script,
    pub key: SecretKey,
}

impl NetSerialize for SwapCoinPrivateKey {
    fn net_serialize<W: std::io::Write>(&self, mut w: W) -> Result<usize, NetSerializationError> {
        let mut len = self.multisig_redeemscript.net_serialize(&mut w)?;
        len += self.key.net_serialize(&mut w)?;

        Ok(len)
    }
}

impl NetDeserilize for SwapCoinPrivateKey {
    fn net_deserialize<R: std::io::Read>(mut r: R) -> Result<Self, NetSerializationError> {
        Ok(Self {
            multisig_redeemscript: Script::net_deserialize(&mut r)?,
            key: SecretKey::net_deserialize(&mut r)?,
        })
    }
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct PrivateKeyHandover {
    pub swapcoin_private_keys: Vec<SwapCoinPrivateKey>, //could easily be called private_keys not swapcoin_private_keys
}

impl NetSerialize for PrivateKeyHandover {
    fn net_serialize<W: std::io::Write>(&self, mut w: W) -> Result<usize, NetSerializationError> {
        self.swapcoin_private_keys.net_serialize(&mut w)
    }
}

impl NetDeserilize for PrivateKeyHandover {
    fn net_deserialize<R: std::io::Read>(mut r: R) -> Result<Self, NetSerializationError> {
        Ok(Self {
            swapcoin_private_keys: Vec::<SwapCoinPrivateKey>::net_deserialize(&mut r)?,
        })
    }
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct TestMessage;

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
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
    TestMessage(TestMessage),
}

impl TakerToMakerMessage {
    fn to_flag(&self) -> u8 {
        match self {
            TakerToMakerMessage::TakerHello(_) => 1,
            TakerToMakerMessage::GiveOffer(_) => 2,
            TakerToMakerMessage::SignSendersContractTx(_) => 3,
            TakerToMakerMessage::ProofOfFunding(_) => 4,
            TakerToMakerMessage::SendersAndReceiversContractSigs(_) => 5,
            TakerToMakerMessage::SignReceiversContractTx(_) => 6,
            TakerToMakerMessage::HashPreimage(_) => 7,
            TakerToMakerMessage::PrivateKeyHandover(_) => 8,
            TakerToMakerMessage::TestMessage(_) => 9,
        }
    }
}

impl NetSerialize for TakerToMakerMessage {
    fn net_serialize<W: std::io::Write>(&self, mut w: W) -> Result<usize, NetSerializationError> {
        let mut len = self.to_flag().consensus_encode(&mut w)?;

        match self {
            TakerToMakerMessage::TakerHello(msg) => {
                len += msg.net_serialize(&mut w)?;
                Ok(len)
            }
            TakerToMakerMessage::GiveOffer(_) => Ok(len),
            TakerToMakerMessage::SignSendersContractTx(msg) => {
                len += msg.net_serialize(&mut w)?;
                Ok(len)
            }
            TakerToMakerMessage::ProofOfFunding(msg) => {
                len += msg.net_serialize(&mut w)?;
                Ok(len)
            }
            TakerToMakerMessage::SendersAndReceiversContractSigs(msg) => {
                len += msg.net_serialize(&mut w)?;
                Ok(len)
            }
            TakerToMakerMessage::SignReceiversContractTx(msg) => {
                len += msg.net_serialize(&mut w)?;
                Ok(len)
            }
            TakerToMakerMessage::HashPreimage(msg) => {
                len += msg.net_serialize(&mut w)?;
                Ok(len)
            }
            TakerToMakerMessage::PrivateKeyHandover(msg) => {
                len += msg.net_serialize(&mut w)?;
                Ok(len)
            }
            TakerToMakerMessage::TestMessage(_) => Ok(len),
        }
    }
}

impl NetDeserilize for TakerToMakerMessage {
    fn net_deserialize<R: std::io::Read>(mut r: R) -> Result<Self, NetSerializationError> {
        let flag_byte = u8::consensus_decode(&mut r)?;

        match flag_byte {
            1 => Ok(Self::TakerHello(TakerHello::net_deserialize(&mut r)?)),
            2 => Ok(Self::GiveOffer(GiveOffer)),
            3 => Ok(Self::SignSendersContractTx(
                SignSendersContractTx::net_deserialize(&mut r)?,
            )),
            4 => Ok(Self::ProofOfFunding(ProofOfFunding::net_deserialize(
                &mut r,
            )?)),
            5 => Ok(Self::SendersAndReceiversContractSigs(
                SendersAndReceiversContractSigs::net_deserialize(&mut r)?,
            )),
            6 => Ok(Self::SignReceiversContractTx(
                SignReceiversContractTx::net_deserialize(&mut r)?,
            )),
            7 => Ok(Self::HashPreimage(HashPreimage::net_deserialize(&mut r)?)),
            8 => Ok(Self::PrivateKeyHandover(
                PrivateKeyHandover::net_deserialize(&mut r)?,
            )),
            9 => Ok(Self::TestMessage(TestMessage)),
            _ => Err(NetSerializationError::General(
                "unknown byte flag in message",
            )),
        }
    }
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct MakerHello {
    pub protocol_version_min: u32,
    pub protocol_version_max: u32,
}

impl NetSerialize for MakerHello {
    fn net_serialize<W: std::io::Write>(&self, mut w: W) -> Result<usize, NetSerializationError> {
        let mut len = self.protocol_version_min.consensus_encode(&mut w)?;
        len += self.protocol_version_max.consensus_encode(&mut w)?;

        Ok(len)
    }
}

impl NetDeserilize for MakerHello {
    fn net_deserialize<R: std::io::Read>(mut r: R) -> Result<Self, NetSerializationError> {
        Ok(Self {
            protocol_version_min: u32::consensus_decode(&mut r)?,
            protocol_version_max: u32::consensus_decode(&mut r)?,
        })
    }
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
pub struct Offer {
    pub absolute_fee: u32,
    pub amount_relative_fee: f32,
    pub max_size: u64,
    pub min_size: u64,
    pub tweakable_point: PublicKey,
}

impl NetSerialize for f32 {
    fn net_serialize<W: std::io::Write>(&self, mut w: W) -> Result<usize, NetSerializationError> {
        Ok(self.to_be_bytes().consensus_encode(&mut w)?)
    }
}

impl NetDeserilize for f32 {
    fn net_deserialize<R: std::io::Read>(mut r: R) -> Result<Self, NetSerializationError> {
        Ok(Self::from_be_bytes(<[u8; 4]>::consensus_decode(&mut r)?))
    }
}

impl NetSerialize for Offer {
    fn net_serialize<W: std::io::Write>(&self, mut w: W) -> Result<usize, NetSerializationError> {
        let mut len = self.absolute_fee.consensus_encode(&mut w)?;
        len += self.amount_relative_fee.net_serialize(&mut w)?;
        len += self.max_size.consensus_encode(&mut w)?;
        len += self.min_size.consensus_encode(&mut w)?;
        len += self.tweakable_point.net_serialize(&mut w)?;

        Ok(len)
    }
}

impl NetDeserilize for Offer {
    fn net_deserialize<R: std::io::Read>(mut r: R) -> Result<Self, NetSerializationError> {
        Ok(Self {
            absolute_fee: u32::consensus_decode(&mut r)?,
            amount_relative_fee: f32::net_deserialize(&mut r)?,
            max_size: u64::consensus_decode(&mut r)?,
            min_size: u64::consensus_decode(&mut r)?,
            tweakable_point: PublicKey::net_deserialize(&mut r)?,
        })
    }
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct SendersContractSig {
    pub sigs: Vec<Signature>,
}

impl NetSerialize for SendersContractSig {
    fn net_serialize<W: std::io::Write>(&self, mut w: W) -> Result<usize, NetSerializationError> {
        self.sigs.net_serialize(&mut w)
    }
}

impl NetDeserilize for SendersContractSig {
    fn net_deserialize<R: std::io::Read>(mut r: R) -> Result<Self, NetSerializationError> {
        Ok(Self {
            sigs: Vec::<Signature>::net_deserialize(&mut r)?,
        })
    }
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
pub struct SenderContractTxInfo {
    pub contract_tx: Transaction,
    pub timelock_pubkey: PublicKey,
    pub multisig_redeemscript: Script,
    pub funding_amount: u64,
}

impl NetSerialize for SenderContractTxInfo {
    fn net_serialize<W: std::io::Write>(&self, mut w: W) -> Result<usize, NetSerializationError> {
        let mut len = self.contract_tx.consensus_encode(&mut w)?;
        len += self.timelock_pubkey.net_serialize(&mut w)?;
        len += self.multisig_redeemscript.net_serialize(&mut w)?;
        len += self.funding_amount.consensus_encode(&mut w)?;

        Ok(len)
    }
}

impl NetDeserilize for SenderContractTxInfo {
    fn net_deserialize<R: std::io::Read>(mut r: R) -> Result<Self, NetSerializationError> {
        Ok(Self {
            contract_tx: Transaction::consensus_decode(&mut r)?,
            timelock_pubkey: PublicKey::net_deserialize(&mut r)?,
            multisig_redeemscript: Script::net_deserialize(&mut r)?,
            funding_amount: u64::consensus_decode(&mut r)?,
        })
    }
}

#[derive(Debug, Serialize, Deserialize, PartialEq)]
pub struct SignSendersAndReceiversContractTxes {
    pub receivers_contract_txes: Vec<Transaction>,
    pub senders_contract_txes_info: Vec<SenderContractTxInfo>,
}

impl NetSerialize for SignSendersAndReceiversContractTxes {
    fn net_serialize<W: std::io::Write>(&self, mut w: W) -> Result<usize, NetSerializationError> {
        let mut len = self.receivers_contract_txes.consensus_encode(&mut w)?;
        len += self.senders_contract_txes_info.net_serialize(&mut w)?;

        Ok(len)
    }
}

impl NetDeserilize for SignSendersAndReceiversContractTxes {
    fn net_deserialize<R: std::io::Read>(mut r: R) -> Result<Self, NetSerializationError> {
        Ok(Self {
            receivers_contract_txes: Vec::<Transaction>::consensus_decode(&mut r)?,
            senders_contract_txes_info: Vec::<SenderContractTxInfo>::net_deserialize(&mut r)?,
        })
    }
}

#[derive(Debug, Serialize, Deserialize, PartialEq)]
pub struct ReceiversContractSig {
    pub sigs: Vec<Signature>,
}

impl NetSerialize for ReceiversContractSig {
    fn net_serialize<W: std::io::Write>(&self, mut w: W) -> Result<usize, NetSerializationError> {
        self.sigs.net_serialize(&mut w)
    }
}

impl NetDeserilize for ReceiversContractSig {
    fn net_deserialize<R: std::io::Read>(mut r: R) -> Result<Self, NetSerializationError> {
        Ok(Self {
            sigs: Vec::<Signature>::net_deserialize(&mut r)?,
        })
    }
}

#[derive(Debug, Serialize, Deserialize, PartialEq)]
#[serde(tag = "method", rename_all = "lowercase")]
pub enum MakerToTakerMessage {
    MakerHello(MakerHello),
    Offer(Offer),
    SendersContractSig(SendersContractSig),
    SignSendersAndReceiversContractTxes(SignSendersAndReceiversContractTxes),
    ReceiversContractSig(ReceiversContractSig),
    PrivateKeyHandover(PrivateKeyHandover),
}

impl MakerToTakerMessage {
    fn to_flag(&self) -> u8 {
        match self {
            MakerToTakerMessage::MakerHello(_) => 1,
            MakerToTakerMessage::Offer(_) => 2,
            MakerToTakerMessage::SendersContractSig(_) => 3,
            MakerToTakerMessage::SignSendersAndReceiversContractTxes(_) => 4,
            MakerToTakerMessage::ReceiversContractSig(_) => 5,
            MakerToTakerMessage::PrivateKeyHandover(_) => 6,
        }
    }
}

impl NetSerialize for MakerToTakerMessage {
    fn net_serialize<W: std::io::Write>(&self, mut w: W) -> Result<usize, NetSerializationError> {
        let mut len = self.to_flag().consensus_encode(&mut w)?;

        match self {
            MakerToTakerMessage::MakerHello(msg) => {
                len += msg.net_serialize(&mut w)?;
                Ok(len)
            }
            MakerToTakerMessage::Offer(msg) => {
                len += msg.net_serialize(&mut w)?;
                Ok(len)
            }
            MakerToTakerMessage::SendersContractSig(msg) => {
                len += msg.net_serialize(&mut w)?;
                Ok(len)
            }
            MakerToTakerMessage::SignSendersAndReceiversContractTxes(msg) => {
                len += msg.net_serialize(&mut w)?;
                Ok(len)
            }
            MakerToTakerMessage::ReceiversContractSig(msg) => {
                len += msg.net_serialize(&mut w)?;
                Ok(len)
            }
            MakerToTakerMessage::PrivateKeyHandover(msg) => {
                len += msg.net_serialize(&mut w)?;
                Ok(len)
            }
        }
    }
}

impl NetDeserilize for MakerToTakerMessage {
    fn net_deserialize<R: std::io::Read>(mut r: R) -> Result<Self, NetSerializationError> {
        let flag = u8::consensus_decode(&mut r)?;

        match flag {
            1 => Ok(Self::MakerHello(MakerHello::net_deserialize(&mut r)?)),
            2 => Ok(Self::Offer(Offer::net_deserialize(&mut r)?)),
            3 => Ok(Self::SendersContractSig(
                SendersContractSig::net_deserialize(&mut r)?,
            )),
            4 => Ok(Self::SignSendersAndReceiversContractTxes(
                SignSendersAndReceiversContractTxes::net_deserialize(&mut r)?,
            )),
            5 => Ok(Self::ReceiversContractSig(
                ReceiversContractSig::net_deserialize(&mut r)?,
            )),
            6 => Ok(Self::PrivateKeyHandover(
                PrivateKeyHandover::net_deserialize(&mut r)?,
            )),
            _ => Err(NetSerializationError::General("unknown byte flag")),
        }
    }
}

#[cfg(test)]
mod test {
    use bitcoin::secp256k1::Secp256k1;
    use bitcoin::secp256k1::{Message, SecretKey};

    use bitcoin::secp256k1::rand::thread_rng;
    use bitcoin::secp256k1::rand::RngCore;

    use bitcoin::hashes::hex::FromHex;

    use bitcoin::PrivateKey;

    use crate::serialization::serialize;

    use super::*;

    fn test_tx() -> Transaction {
        let tx_bytes = Vec::from_hex("0100000001a15d57094aa7a21a28cb20b59aab8fc7d1149a3bdbcddba9c622e4f5f6a99ece010000006c493046022100f93bb0e7d8db7bd46e40132d1f8242026e045f03a0efe71bbb8e3f475e970d790221009337cd7f1f929f00cc6ff01f03729b069a7c21b59b1736ddfee5db5946c5da8c0121033b9b137ee87d5a812d6f506efdd37f0affa7ffc310711c06c7f3e097c9447c52ffffffff0100e1f505000000001976a9140389035a9225b3839e2bbf32d826a1e222031fd888ac00000000").unwrap();
        Transaction::consensus_decode(&tx_bytes[..]).unwrap()
    }

    fn test_script() -> Script {
        let script_bytes = Vec::from_hex("6c493046022100f93bb0e7d8db7bd46e40132d1f8242026e045f03a0efe71bbb8e3f475e970d790221009337cd7f1f929f00cc6ff01f03729b069a7c21b59b1736ddfee5db5946c5da8c0121033b9b137ee87d5a812d6f506efdd37f0affa7ffc310711c06c7f3e097c9447c52").unwrap();
        Script::net_deserialize(&script_bytes[..]).unwrap()
    }

    fn test_secret() -> SecretKey {
        let mut bytes = [0u8; 32];
        thread_rng().fill_bytes(&mut bytes);
        SecretKey::from_slice(&bytes).unwrap()
    }

    fn test_pubkey() -> PublicKey {
        let secret = test_secret();

        PublicKey::from_private_key(
            &Secp256k1::new(),
            &PrivateKey {
                compressed: true,
                network: bitcoin::Network::Regtest,
                key: secret,
            },
        )
    }

    fn test_sig() -> Signature {
        let full = Secp256k1::new();
        let (sk, _) = full.generate_keypair(&mut thread_rng());
        let msg = Message::from_slice(&[2u8; 32]).unwrap();
        full.sign(&msg, &sk)
    }

    fn test_proof_of_funding() -> ProofOfFunding {
        let tx_info_msg = ConfirmedCoinSwapTxInfo {
            funding_tx: test_tx(),
            funding_tx_merkleproof: "Random String".to_string(),
            multisig_redeemscript: test_script(),
            multisig_key_nonce: test_secret(),
            contract_redeemscript: test_script(),
            hashlock_key_nonce: test_secret(),
        };

        let next_tx_info_msg = NextCoinSwapTxInfo {
            next_coinswap_multisig_pubkey: test_pubkey(),
            next_hashlock_pubkey: test_pubkey(),
        };

        ProofOfFunding {
            confirmed_funding_txes: vec![tx_info_msg; 5],
            next_coinswap_info: vec![next_tx_info_msg; 5],
            next_locktime: 2784u16,
        }
    }

    #[test]
    fn test_taker_to_maker() {
        let msg1 = TakerToMakerMessage::TakerHello(TakerHello {
            protocol_version_min: 30,
            protocol_version_max: 50,
        });

        let msg2 = TakerToMakerMessage::GiveOffer(GiveOffer);

        let tx_nonce_info = SenderContractTxNoncesInfo {
            multisig_key_nonce: test_secret(),
            hashlock_key_nonce: test_secret(),
            timelock_pubkey: test_pubkey(),
            senders_contract_tx: test_tx(),
            multisig_redeemscript: test_script(),
            funding_input_value: 12345,
        };

        let mut hashvalue = [0u8; 20];
        thread_rng().fill_bytes(&mut hashvalue);

        let msg3 = TakerToMakerMessage::SignSendersContractTx(SignSendersContractTx {
            txes_info: vec![tx_nonce_info; 5],
            hashvalue: Hash160::from_slice(&hashvalue).unwrap(),
            locktime: 3450,
        });

        let msg4 = TakerToMakerMessage::ProofOfFunding(test_proof_of_funding());

        let sigs = SendersAndReceiversContractSigs {
            receivers_sigs: vec![test_sig(); 10],
            senders_sigs: vec![test_sig(); 10],
        };

        let msg5 = TakerToMakerMessage::SendersAndReceiversContractSigs(sigs);

        let reciever_contract_tx_info = ReceiversContractTxInfo {
            multisig_redeemscript: test_script().clone(),
            contract_tx: test_tx().clone(),
        };

        let msg6 = TakerToMakerMessage::SignReceiversContractTx(SignReceiversContractTx {
            txes: vec![reciever_contract_tx_info; 5],
        });

        let mut preimage = [0u8; 32];
        thread_rng().fill_bytes(&mut preimage);

        let msg7 = TakerToMakerMessage::HashPreimage(HashPreimage {
            senders_multisig_redeemscripts: vec![test_script().clone(); 5],
            receivers_multisig_redeemscripts: vec![test_script().clone(); 5],
            preimage,
        });

        let swap_coin_privkey = SwapCoinPrivateKey {
            multisig_redeemscript: test_script(),
            key: test_secret(),
        };

        let msg8 = TakerToMakerMessage::PrivateKeyHandover(PrivateKeyHandover {
            swapcoin_private_keys: vec![swap_coin_privkey.clone(); 5],
        });

        let msgs = vec![msg1, msg2, msg3, msg4, msg5, msg6, msg7, msg8];

        let encoded = serialize(&msgs).unwrap();

        let decoded = Vec::<TakerToMakerMessage>::net_deserialize(&encoded[..]).unwrap();

        assert_eq!(decoded, msgs);
    }

    #[test]
    fn test_maker_to_maker() {
        let msg1 = MakerToTakerMessage::MakerHello(MakerHello {
            protocol_version_min: 30,
            protocol_version_max: 50,
        });

        let msg2 = MakerToTakerMessage::Offer(Offer {
            absolute_fee: 1000,
            amount_relative_fee: 54.678,
            max_size: 567,
            min_size: 123,
            tweakable_point: test_pubkey(),
        });

        let msg3 = MakerToTakerMessage::SendersContractSig(SendersContractSig {
            sigs: vec![test_sig(); 5],
        });

        let txinfo = SenderContractTxInfo {
            contract_tx: test_tx(),
            timelock_pubkey: test_pubkey(),
            multisig_redeemscript: test_script(),
            funding_amount: 100,
        };

        let msg4 = MakerToTakerMessage::SignSendersAndReceiversContractTxes(
            SignSendersAndReceiversContractTxes {
                receivers_contract_txes: vec![test_tx(); 5],
                senders_contract_txes_info: vec![txinfo; 6],
            },
        );

        let msg5 = MakerToTakerMessage::ReceiversContractSig(ReceiversContractSig {
            sigs: vec![test_sig(); 10],
        });

        let swapcoin_privkeys = SwapCoinPrivateKey {
            multisig_redeemscript: test_script(),
            key: test_secret(),
        };

        let msg6 = MakerToTakerMessage::PrivateKeyHandover(PrivateKeyHandover {
            swapcoin_private_keys: vec![swapcoin_privkeys; 5],
        });

        let messages = vec![msg1, msg2, msg3, msg4, msg5, msg6];

        let encoded = serialize(&messages).unwrap();

        let decoded = Vec::<MakerToTakerMessage>::net_deserialize(&encoded[..]).unwrap();

        assert_eq!(decoded, messages);
    }
}
