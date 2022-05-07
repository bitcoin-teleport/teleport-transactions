use std::collections::HashMap;
use std::fmt::Display;
use std::num::ParseIntError;
use std::str::FromStr;

use chrono::NaiveDate;

use bitcoin::blockdata::opcodes;
use bitcoin::blockdata::script::{Builder, Instruction, Script};
use bitcoin::secp256k1::{Context, Secp256k1, Signing};
use bitcoin::util::bip32::{ChildNumber, DerivationPath, ExtendedPrivKey};
use bitcoin::util::key::{PrivateKey, PublicKey};

use crate::contracts::redeemscript_to_scriptpubkey;
use crate::wallet_sync::Wallet;

const TIMELOCKED_MPK_PATH: &str = "m/84'/0'/0'/2";
pub const TIMELOCKED_ADDRESS_COUNT: u32 = 960;

#[derive(Debug)]
pub struct YearAndMonth {
    year: u32,
    month: u32,
}

impl YearAndMonth {
    pub fn to_index(&self) -> u32 {
        (self.year - 2020) * 12 + (self.month - 1)
    }
}

impl FromStr for YearAndMonth {
    type Err = YearAndMonthError;

    // yyyy-mm
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.len() != 7 {
            return Err(YearAndMonthError::WrongLength);
        }
        let year = String::from(&s[..4]).parse::<u32>()?;
        let month = String::from(&s[5..]).parse::<u32>()?;
        if 2020 <= year && year <= 2079 && 1 <= month && month <= 12 {
            Ok(YearAndMonth { year, month })
        } else {
            Err(YearAndMonthError::OutOfRange)
        }
    }
}

#[derive(Debug)]
pub enum YearAndMonthError {
    WrongLength,
    ParseIntError(ParseIntError),
    OutOfRange,
}

impl From<ParseIntError> for YearAndMonthError {
    fn from(p: ParseIntError) -> YearAndMonthError {
        YearAndMonthError::ParseIntError(p)
    }
}

impl Display for YearAndMonthError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            YearAndMonthError::WrongLength => write!(f, "WrongLength, should be yyyy-mm"),
            YearAndMonthError::ParseIntError(p) => p.fmt(f),
            YearAndMonthError::OutOfRange => {
                write!(f, "Out of range, must be between 2020-01 and 2079-12")
            }
        }
    }
}

fn create_timelocked_redeemscript(locktime: i64, pubkey: &PublicKey) -> Script {
    Builder::new()
        .push_int(locktime)
        .push_opcode(opcodes::all::OP_CLTV)
        .push_opcode(opcodes::all::OP_DROP)
        .push_key(&pubkey)
        .push_opcode(opcodes::all::OP_CHECKSIG)
        .into_script()
}

pub fn read_locktime_from_timelocked_redeemscript(redeemscript: &Script) -> Option<i64> {
    if let Instruction::PushBytes(locktime_bytes) = redeemscript.instructions().nth(0)?.ok()? {
        let mut u8slice: [u8; 8] = [0; 8];
        u8slice[..locktime_bytes.len()].copy_from_slice(&locktime_bytes);
        Some(i64::from_le_bytes(u8slice))
    } else {
        None
    }
}

fn get_timelocked_master_key_from_root_master_key(master_key: &ExtendedPrivKey) -> ExtendedPrivKey {
    let secp = Secp256k1::new();

    master_key
        .derive_priv(
            &secp,
            &DerivationPath::from_str(TIMELOCKED_MPK_PATH).unwrap(),
        )
        .unwrap()
}

pub fn get_locktime_from_index(index: u32) -> i64 {
    let year_off = index as i32 / 12;
    let month = index % 12;
    NaiveDate::from_ymd(2020 + year_off, 1 + month, 1)
        .and_hms(0, 0, 0)
        .timestamp()
}

fn get_timelocked_redeemscript_from_index<C: Context + Signing>(
    secp: &Secp256k1<C>,
    timelocked_master_private_key: &ExtendedPrivKey,
    index: u32,
) -> Script {
    let privkey = timelocked_master_private_key
        .ckd_priv(secp, ChildNumber::Normal { index })
        .unwrap()
        .private_key;
    let pubkey = privkey.public_key(&secp);
    let locktime = get_locktime_from_index(index);
    create_timelocked_redeemscript(locktime, &pubkey)
}

pub fn generate_all_timelocked_addresses(master_key: &ExtendedPrivKey) -> HashMap<Script, u32> {
    let timelocked_master_private_key = get_timelocked_master_key_from_root_master_key(master_key);
    let mut timelocked_script_index_map = HashMap::<Script, u32>::new();

    let secp = Secp256k1::new();
    //all these magic numbers and constants are explained in the fidelity bonds bip
    // https://gist.github.com/chris-belcher/7257763cedcc014de2cd4239857cd36e
    for index in 0..TIMELOCKED_ADDRESS_COUNT {
        let redeemscript =
            get_timelocked_redeemscript_from_index(&secp, &timelocked_master_private_key, index);
        let spk = redeemscript_to_scriptpubkey(&redeemscript);
        timelocked_script_index_map.insert(spk, index);
    }
    timelocked_script_index_map
}

impl Wallet {
    pub fn get_timelocked_redeemscript_from_index(&self, index: u32) -> Script {
        get_timelocked_redeemscript_from_index(
            &Secp256k1::new(),
            &get_timelocked_master_key_from_root_master_key(&self.master_key),
            index,
        )
    }

    pub fn get_timelocked_privkey_from_index(&self, index: u32) -> PrivateKey {
        get_timelocked_master_key_from_root_master_key(&self.master_key)
            .ckd_priv(&Secp256k1::new(), ChildNumber::Normal { index })
            .unwrap()
            .private_key
    }
}
