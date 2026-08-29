use std::{
    collections::{HashMap, VecDeque},
    hash::Hash,
};

#[derive(Debug, Clone)]
struct Entry<V> {
    value: V,
    generation: u64,
}

#[derive(Debug, Clone)]
pub struct BoundedMap<K, V> {
    max_entries: usize,
    next_generation: u64,
    order: VecDeque<(K, u64)>,
    map: HashMap<K, Entry<V>>,
}

impl<K, V> BoundedMap<K, V>
where
    K: Eq + Hash + Clone,
{
    pub fn new(max_entries: usize) -> Self {
        Self {
            max_entries: max_entries.max(1),
            next_generation: 1,
            order: VecDeque::new(),
            map: HashMap::new(),
        }
    }

    pub fn get(&self, key: &K) -> Option<&V> {
        self.map.get(key).map(|entry| &entry.value)
    }

    pub fn get_cloned_refresh(&mut self, key: &K) -> Option<V>
    where
        V: Clone,
    {
        let value = self.map.get(key)?.value.clone();
        self.touch(key);
        Some(value)
    }

    pub fn contains_key(&self, key: &K) -> bool {
        self.map.contains_key(key)
    }

    pub fn get_mut(&mut self, key: &K) -> Option<&mut V> {
        if !self.map.contains_key(key) {
            return None;
        }
        let generation = self.allocate_generation();
        self.order.push_back((key.clone(), generation));
        self.compact_order_if_needed();
        let entry = self.map.get_mut(key).expect("entry presence checked above");
        entry.generation = generation;
        Some(&mut entry.value)
    }

    pub fn insert(&mut self, key: K, value: V) -> Option<V> {
        let generation = self.allocate_generation();
        if self.map.contains_key(&key) {
            let entry_key = key.clone();
            self.order.push_back((key, generation));
            self.compact_order_if_needed();
            let entry = self
                .map
                .get_mut(&entry_key)
                .expect("entry presence checked above");
            entry.generation = generation;
            return Some(std::mem::replace(&mut entry.value, value));
        }

        if self.map.len() >= self.max_entries {
            self.evict_oldest();
        }

        self.order.push_back((key.clone(), generation));
        self.compact_order_if_needed();
        self.map.insert(key, Entry { value, generation });
        None
    }

    pub fn remove(&mut self, key: &K) -> Option<V> {
        let entry = self.map.remove(key)?;
        self.compact_order_if_needed();
        Some(entry.value)
    }

    pub fn len(&self) -> usize {
        self.map.len()
    }

    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }

    fn evict_oldest(&mut self) {
        while let Some((oldest, generation)) = self.order.pop_front() {
            let should_remove = self
                .map
                .get(&oldest)
                .map(|entry| entry.generation == generation)
                .unwrap_or(false);
            if should_remove {
                self.map.remove(&oldest);
                break;
            }
        }
    }

    fn touch(&mut self, key: &K) {
        if !self.map.contains_key(key) {
            return;
        }
        let generation = self.allocate_generation();
        self.order.push_back((key.clone(), generation));
        self.compact_order_if_needed();
        if let Some(entry) = self.map.get_mut(key) {
            entry.generation = generation;
        }
    }

    fn allocate_generation(&mut self) -> u64 {
        let generation = self.next_generation;
        self.next_generation = self.next_generation.saturating_add(1);
        generation
    }

    fn compact_order_if_needed(&mut self) {
        let max_order_len = self.max_entries.saturating_mul(4).saturating_add(16);
        if self.order.len() <= max_order_len {
            return;
        }

        let mut active = self
            .map
            .iter()
            .map(|(key, entry)| (key.clone(), entry.generation))
            .collect::<Vec<_>>();
        active.sort_by_key(|(_, generation)| *generation);
        self.order = active.into_iter().collect();
    }
}

#[cfg(test)]
mod tests {
    use super::BoundedMap;

    #[test]
    fn evicts_oldest_entry_when_capacity_is_reached() {
        let mut map = BoundedMap::new(2);
        map.insert("one".to_string(), 1usize);
        map.insert("two".to_string(), 2usize);
        map.insert("three".to_string(), 3usize);

        assert_eq!(map.len(), 2);
        assert!(map.get(&"one".to_string()).is_none());
        assert_eq!(map.get(&"two".to_string()), Some(&2));
        assert_eq!(map.get(&"three".to_string()), Some(&3));
    }

    #[test]
    fn get_mut_refreshes_entry_order() {
        let mut map = BoundedMap::new(2);
        map.insert("one".to_string(), 1usize);
        map.insert("two".to_string(), 2usize);
        *map.get_mut(&"one".to_string()).unwrap() = 10;
        map.insert("three".to_string(), 3usize);

        assert_eq!(map.get(&"one".to_string()), Some(&10));
        assert!(map.get(&"two".to_string()).is_none());
    }

    #[test]
    fn cloned_get_refreshes_entry_order() {
        let mut map = BoundedMap::new(2);
        map.insert("one".to_string(), 1usize);
        map.insert("two".to_string(), 2usize);
        assert_eq!(map.get_cloned_refresh(&"one".to_string()), Some(1));
        map.insert("three".to_string(), 3usize);

        assert_eq!(map.get(&"one".to_string()), Some(&1));
        assert!(map.get(&"two".to_string()).is_none());
    }

    #[test]
    fn stale_order_entries_do_not_evict_recent_value() {
        let mut map = BoundedMap::new(2);
        map.insert("one".to_string(), 1usize);
        map.insert("two".to_string(), 2usize);
        assert_eq!(map.get_cloned_refresh(&"one".to_string()), Some(1));
        assert_eq!(map.get_cloned_refresh(&"one".to_string()), Some(1));
        map.insert("three".to_string(), 3usize);

        assert_eq!(map.get(&"one".to_string()), Some(&1));
        assert!(map.get(&"two".to_string()).is_none());
        assert_eq!(map.get(&"three".to_string()), Some(&3));
    }
}
