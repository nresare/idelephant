// copied from surrealdb while we are waiting for a solution to
// https://github.com/surrealdb/surrealdb/issues/5730

use base64::{engine::general_purpose::STANDARD_NO_PAD, Engine};
use serde::{
    de::{self, SeqAccess, Visitor},
    Deserialize, Serialize,
};
use std::fmt::{self, Display, Formatter};
use std::ops::Deref;

#[derive(Clone, Debug, Default, Eq, PartialEq, PartialOrd, Hash)]
pub struct Bytes(pub(crate) Vec<u8>);

impl Bytes {
    pub fn into_inner(self) -> Vec<u8> {
        self.0
    }
}

impl From<Vec<u8>> for Bytes {
    fn from(v: Vec<u8>) -> Self {
        Self(v)
    }
}

impl From<Bytes> for Vec<u8> {
    fn from(val: Bytes) -> Self {
        val.0
    }
}

impl Deref for Bytes {
    type Target = Vec<u8>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl Display for Bytes {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "encoding::base64::decode(\"{}\")",
            STANDARD_NO_PAD.encode(&self.0)
        )
    }
}

impl Serialize for Bytes {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_bytes(&self.0)
    }
}

impl<'de> Deserialize<'de> for Bytes {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct RawBytesVisitor;

        impl<'de> Visitor<'de> for RawBytesVisitor {
            type Value = Bytes;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("bytes or sequence of bytes")
            }

            fn visit_byte_buf<E>(self, v: Vec<u8>) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                Ok(Bytes(v))
            }

            fn visit_bytes<E>(self, v: &[u8]) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                Ok(Bytes(v.to_owned()))
            }

            fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
            where
                A: SeqAccess<'de>,
            {
                let capacity = seq.size_hint().unwrap_or_default();
                let mut vec = Vec::with_capacity(capacity);
                while let Some(byte) = seq.next_element()? {
                    vec.push(byte);
                }
                Ok(Bytes(vec))
            }
        }

        deserializer.deserialize_byte_buf(RawBytesVisitor)
    }
}

#[cfg(test)]
mod tests {
    use super::Bytes;

    #[test]
    fn json_roundtrip() {
        let val = Bytes::from(vec![1, 2, 3, 5]);
        let json = serde_json::to_string(&val).unwrap();
        let deserialized = serde_json::from_str(&json).unwrap();
        assert_eq!(val, deserialized);
    }
}
