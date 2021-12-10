use bitcoin::consensus::encode::{Decodable, Encodable, ReadExt, WriteExt};
use bitcoin::secp256k1::{SecretKey, Signature};
use bitcoin::{PublicKey, Script, VarInt};

// Maximum size, in bytes, of a vector we are allowed to decode
// TODO: Decide whether its useful
pub const MAX_VEC_SIZE: usize = 4_000_000;

#[derive(Debug)]
pub enum NetSerializationError {
    IO(std::io::Error),

    ConsensusEcode(bitcoin::consensus::encode::Error),

    Secp256k1(bitcoin::secp256k1::Error),

    Hash(bitcoin::hashes::Error),

    Key(bitcoin::util::key::Error),

    OverSizedAllocation { requested: usize, max: usize },

    General(&'static str),
}

impl From<bitcoin::secp256k1::Error> for NetSerializationError {
    fn from(e: bitcoin::secp256k1::Error) -> Self {
        NetSerializationError::Secp256k1(e)
    }
}

impl From<bitcoin::consensus::encode::Error> for NetSerializationError {
    fn from(e: bitcoin::consensus::encode::Error) -> Self {
        NetSerializationError::ConsensusEcode(e)
    }
}

impl From<bitcoin::hashes::Error> for NetSerializationError {
    fn from(e: bitcoin::hashes::Error) -> Self {
        NetSerializationError::Hash(e)
    }
}

impl From<std::io::Error> for NetSerializationError {
    fn from(e: std::io::Error) -> Self {
        NetSerializationError::IO(e)
    }
}

impl From<bitcoin::util::key::Error> for NetSerializationError {
    fn from(e: bitcoin::util::key::Error) -> Self {
        NetSerializationError::Key(e)
    }
}

// A Serializable Trait that defines byte encoding of structures
// Anywhere we need byte encoded data (Network, Database) we can use this.
// The underlying encoding of primitve datatyes and structures are done
// via bitcoin::consensus::encode::Encodale trait.
pub trait NetSerialize {
    fn net_serialize<W: std::io::Write>(&self, w: W) -> Result<usize, NetSerializationError>;
}

pub trait NetDeserilize: Sized {
    fn net_deserialize<R: std::io::Read>(r: R) -> Result<Self, NetSerializationError>;
}

// Implementation of Ser/Deserializable for some primitives not covered
// by bitcoin::consensus::encode::Encodable
impl NetSerialize for [u8; 20] {
    fn net_serialize<W: std::io::Write>(&self, mut w: W) -> Result<usize, NetSerializationError> {
        w.emit_slice(&self[..])?;
        Ok(20)
    }
}

impl NetDeserilize for [u8; 20] {
    fn net_deserialize<R: std::io::Read>(mut r: R) -> Result<Self, NetSerializationError> {
        let mut bytes = [0u8; 20];
        r.read_slice(&mut bytes)?;

        Ok(bytes)
    }
}

impl NetSerialize for Signature {
    fn net_serialize<W: std::io::Write>(&self, mut w: W) -> Result<usize, NetSerializationError> {
        Ok(w.write(&self.serialize_compact()[..])?)
    }
}

impl NetDeserilize for Signature {
    fn net_deserialize<R: std::io::Read>(mut r: R) -> Result<Self, NetSerializationError> {
        let mut sig_buff = [0u8; 64];
        r.read_exact(&mut sig_buff)?;
        Ok(Signature::from_compact(&sig_buff[..])?)
    }
}

impl NetSerialize for SecretKey {
    fn net_serialize<W: std::io::Write>(&self, mut w: W) -> Result<usize, NetSerializationError> {
        Ok(w.write(&self[..])?)
    }
}

impl NetDeserilize for SecretKey {
    fn net_deserialize<R: std::io::Read>(mut r: R) -> Result<Self, NetSerializationError> {
        let mut secret_key_bytes = [0u8; 32];
        r.read_slice(&mut secret_key_bytes)?;
        Ok(SecretKey::from_slice(&secret_key_bytes)?)
    }
}

impl NetSerialize for PublicKey {
    fn net_serialize<W: std::io::Write>(&self, mut w: W) -> Result<usize, NetSerializationError> {
        Ok(w.write(&self.to_bytes()[..])?)
    }
}

impl NetDeserilize for PublicKey {
    fn net_deserialize<R: std::io::Read>(mut r: R) -> Result<Self, NetSerializationError> {
        let mut bytes = [0u8; 33];
        r.read_slice(&mut bytes)?;
        Ok(PublicKey::from_slice(&bytes)?)
    }
}

impl NetSerialize for Script {
    fn net_serialize<W: std::io::Write>(&self, mut w: W) -> Result<usize, NetSerializationError> {
        Ok(self.consensus_encode(&mut w)?)
    }
}

impl NetDeserilize for Script {
    fn net_deserialize<R: std::io::Read>(mut r: R) -> Result<Self, NetSerializationError> {
        Ok(Self::consensus_decode(&mut r)?)
    }
}

impl<T: NetSerialize> NetSerialize for Vec<T> {
    fn net_serialize<W: std::io::Write>(&self, mut w: W) -> Result<usize, NetSerializationError> {
        let mut len = 0;
        len += VarInt(self.len() as u64).consensus_encode(&mut w)?;
        for c in self.iter() {
            len += c.net_serialize(&mut w)?;
        }
        Ok(len)
    }
}

impl<T: NetDeserilize> NetDeserilize for Vec<T> {
    fn net_deserialize<R: std::io::Read>(mut r: R) -> Result<Self, NetSerializationError> {
        let len = VarInt::consensus_decode(&mut r)?.0;
        let byte_size = (len as usize)
            .checked_mul(std::mem::size_of::<T>())
            .ok_or(NetSerializationError::General("Invalid length of vector"))?;
        if byte_size > MAX_VEC_SIZE {
            return Err(NetSerializationError::OverSizedAllocation {
                requested: byte_size,
                max: MAX_VEC_SIZE,
            }
            .into());
        }
        let mut ret = Vec::with_capacity(len as usize);
        for _ in 0..len {
            ret.push(NetDeserilize::net_deserialize(&mut r)?);
        }
        Ok(ret)
    }
}

#[allow(dead_code)]
// Helper function to quickly generate serialized data
pub fn serialize<T: NetSerialize>(thing: &T) -> Result<Vec<u8>, NetSerializationError> {
    let mut bytes = Vec::new();

    thing.net_serialize(&mut bytes)?;

    Ok(bytes)
}
