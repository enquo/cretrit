//! Serde support for `CipherText`.

use serde::{de, ser::Error};
use serde::{
    Deserialize as SerdeDeserialize, Deserializer as SerdeDeserializer,
    Serialize as SerdeSerialize, Serializer as SerdeSerializer,
};

use crate::ciphertext::{CipherText, Serializable};
use crate::{ciphersuite::CipherSuite, cmp::Comparator};

impl<S: CipherSuite<W, M>, CMP: Comparator<M>, const N: usize, const W: u16, const M: u8>
    SerdeSerialize for CipherText<S, CMP, N, W, M>
where
    CipherText<S, CMP, N, W, M>: Serializable<N, W, M>,
{
    fn serialize<SS>(&self, serializer: SS) -> Result<SS::Ok, SS::Error>
    where
        SS: SerdeSerializer,
    {
        serializer.serialize_bytes(
            &self
                .to_vec()
                .map_err(|e| SS::Error::custom(e.to_string()))?,
        )
    }
}

impl<'de, S: CipherSuite<W, M>, CMP: Comparator<M>, const N: usize, const W: u16, const M: u8>
    SerdeDeserialize<'de> for CipherText<S, CMP, N, W, M>
where
    CipherText<S, CMP, N, W, M>: Serializable<N, W, M>,
{
    fn deserialize<SD>(deserializer: SD) -> Result<CipherText<S, CMP, N, W, M>, SD::Error>
    where
        SD: SerdeDeserializer<'de>,
    {
        // serde_bytes handles the insane variety of formats that various serialization formats
        // present as what they think of as "bytes", like JSON's love of "a sequence of numbers".
        let v: Vec<u8> = serde_bytes::deserialize(deserializer)?;
        CipherText::<S, CMP, N, W, M>::from_slice(&v).map_err(|e| de::Error::custom(e.to_string()))
    }
}
