use std::hash::Hash;

use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use indexmap::IndexMap;
use serde::{Deserialize, Deserializer, Serialize, Serializer, ser::SerializeStruct};
use serde_bytes::ByteBuf;

#[derive(Debug, Clone)]
pub struct BoundedMap<K, V> {
    map: IndexMap<K, V>,
    capacity: usize,
}

impl<K: Eq + Hash, V: CanonicalSerialize + CanonicalDeserialize> BoundedMap<K, V> {
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            map: IndexMap::with_capacity(capacity),
            capacity,
        }
    }

    pub fn insert(&mut self, key: K, value: V) {
        if self.map.len() >= self.capacity {
            self.map.shift_remove_index(0);
        }
        self.map.insert(key, value);
    }

    pub fn get(&self, key: &K) -> Option<&V> {
        self.map.get(key)
    }

    pub fn contains_key(&self, key: &K) -> bool {
        self.map.contains_key(key)
    }

    pub fn len(&self) -> usize {
        self.map.len()
    }

    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }

    pub fn capacity(&self) -> usize {
        self.capacity
    }
}

impl<K, V> Serialize for BoundedMap<K, V>
where
    K: Serialize + Eq + Hash,
    V: CanonicalSerialize,
{
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        use serde::ser::Error;

        let mut s = serializer.serialize_struct("BoundedMap", 2)?;
        s.serialize_field("capacity", &self.capacity)?;

        let entries: Result<Vec<_>, _> = self
            .map
            .iter()
            .map(|(k, v)| {
                let v = crate::utils::serialize(v)
                    .map_err(|e| S::Error::custom(format!("Failed to serialize value: {}", e)))?;
                Ok((k, v))
            })
            .collect();

        s.serialize_field("entries", &entries?)?;
        s.end()
    }
}

impl<'de, K, V> Deserialize<'de> for BoundedMap<K, V>
where
    K: Deserialize<'de> + Eq + Hash,
    V: CanonicalDeserialize,
{
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        use serde::de::Error;

        #[derive(Deserialize)]
        struct BoundedMapHelper<K> {
            capacity: usize,
            entries: Vec<(K, Vec<u8>)>,
        }

        let helper = BoundedMapHelper::deserialize(deserializer)?;
        let mut map = IndexMap::with_capacity(helper.capacity);

        for (k, v) in helper.entries {
            let v = crate::utils::deserialize(&v)
                .map_err(|e| D::Error::custom(format!("Failed to deserialize value: {}", e)))?;
            map.insert(k, v);
        }

        Ok(BoundedMap {
            map,
            capacity: helper.capacity,
        })
    }
}

/// Adapter for serialization of arkworks-compatible types using CanonicalSerialize
pub fn ark_se<S, A: CanonicalSerialize>(a: &A, s: S) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    let mut bytes = vec![];
    a.serialize_with_mode(&mut bytes, ark_serialize::Compress::Yes)
        .map_err(serde::ser::Error::custom)?;
    s.serialize_bytes(&bytes)
}
/// Adapter for deserialization of arkworks-compatible types using CanonicalDeserialize
pub fn ark_de<'de, D, A: CanonicalDeserialize>(data: D) -> Result<A, D::Error>
where
    D: serde::de::Deserializer<'de>,
{
    let s: ByteBuf = serde::de::Deserialize::deserialize(data)?;
    let a = A::deserialize_with_mode(
        s.as_slice(),
        ark_serialize::Compress::Yes,
        ark_serialize::Validate::Yes,
    );
    a.map_err(serde::de::Error::custom)
}
