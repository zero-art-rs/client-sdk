use std::hash::Hash;

use indexmap::IndexMap;

#[derive(Debug)]
pub struct BoundedMap<K, V> {
    map: IndexMap<K, V>,
    capacity: usize,
}

impl<K: Eq + Hash, V> BoundedMap<K, V> {
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

    pub fn len(&self) -> usize {
        self.map.len()
    }

    pub fn capacity(&self) -> usize {
        self.capacity
    }
}
