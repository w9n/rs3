use std::collections::HashMap;
use std::hash::Hash;

#[derive(Debug)]
pub(crate) struct LruCache<K, V> {
    entries: HashMap<K, LruEntry<K, V>>,
    head: Option<K>,
    tail: Option<K>,
}

#[derive(Debug)]
struct LruEntry<K, V> {
    value: V,
    previous: Option<K>,
    next: Option<K>,
}

impl<K, V> Default for LruCache<K, V> {
    fn default() -> Self {
        Self {
            entries: HashMap::new(),
            head: None,
            tail: None,
        }
    }
}

impl<K, V> LruCache<K, V>
where
    K: Clone + Eq + Hash,
{
    pub(crate) fn new() -> Self {
        Self::default()
    }

    pub(crate) fn len(&self) -> usize {
        self.entries.len()
    }

    pub(crate) fn peek_cloned(&self, key: &K) -> Option<V>
    where
        V: Clone,
    {
        self.entries.get(key).map(|entry| entry.value.clone())
    }

    pub(crate) fn insert(&mut self, key: K, value: V) -> Option<V> {
        if let Some(entry) = self.entries.get_mut(&key) {
            let previous = std::mem::replace(&mut entry.value, value);
            self.touch(&key);
            return Some(previous);
        }

        let previous = self.tail.clone();
        let entry = LruEntry {
            value,
            previous: previous.clone(),
            next: None,
        };
        if let Some(previous) = previous {
            if let Some(previous_entry) = self.entries.get_mut(&previous) {
                previous_entry.next = Some(key.clone());
            }
        } else {
            self.head = Some(key.clone());
        }
        self.tail = Some(key.clone());
        self.entries.insert(key, entry);
        None
    }

    pub(crate) fn pop_lru(&mut self) -> Option<(K, V)> {
        let key = self.head.clone()?;
        self.detach(&key);
        self.entries.remove(&key).map(|entry| (key, entry.value))
    }

    pub(crate) fn touch(&mut self, key: &K) {
        if !self.entries.contains_key(key) {
            return;
        }
        if self.tail.as_ref() == Some(key) {
            return;
        }
        self.detach(key);
        self.push_back_existing(key);
    }

    fn detach(&mut self, key: &K) {
        let Some(entry) = self.entries.get(key) else {
            return;
        };
        let previous = entry.previous.clone();
        let next = entry.next.clone();

        match previous.as_ref() {
            Some(previous) => {
                if let Some(previous_entry) = self.entries.get_mut(previous) {
                    previous_entry.next = next.clone();
                }
            }
            None => {
                self.head = next.clone();
            }
        }

        match next.as_ref() {
            Some(next) => {
                if let Some(next_entry) = self.entries.get_mut(next) {
                    next_entry.previous = previous.clone();
                }
            }
            None => {
                self.tail = previous.clone();
            }
        }

        if let Some(entry) = self.entries.get_mut(key) {
            entry.previous = None;
            entry.next = None;
        }
    }

    fn push_back_existing(&mut self, key: &K) {
        let previous = self.tail.clone();
        if let Some(previous) = previous.as_ref() {
            if let Some(previous_entry) = self.entries.get_mut(previous) {
                previous_entry.next = Some(key.clone());
            }
        } else {
            self.head = Some(key.clone());
        }

        if let Some(entry) = self.entries.get_mut(key) {
            entry.previous = previous;
            entry.next = None;
        }
        self.tail = Some(key.clone());
    }
}

#[cfg(test)]
mod tests {
    use super::LruCache;

    #[test]
    fn touch_moves_entry_to_back_and_pop_removes_lru() {
        let mut cache = LruCache::new();
        cache.insert("a", 1);
        cache.insert("b", 2);
        cache.insert("c", 3);

        assert_eq!(cache.peek_cloned(&"a"), Some(1));
        cache.touch(&"a");
        assert_eq!(cache.pop_lru(), Some(("b", 2)));
        assert_eq!(cache.pop_lru(), Some(("c", 3)));
        assert_eq!(cache.pop_lru(), Some(("a", 1)));
        assert_eq!(cache.pop_lru(), None);
    }

    #[test]
    fn replacing_entry_preserves_single_node() {
        let mut cache = LruCache::new();
        assert_eq!(cache.insert("a", 1), None);
        assert_eq!(cache.insert("b", 2), None);
        assert_eq!(cache.insert("a", 3), Some(1));

        assert_eq!(cache.len(), 2);
        assert_eq!(cache.pop_lru(), Some(("b", 2)));
        assert_eq!(cache.pop_lru(), Some(("a", 3)));
        assert_eq!(cache.pop_lru(), None);
    }

    #[test]
    fn touching_missing_entry_does_not_change_order() {
        let mut cache = LruCache::new();
        cache.insert("a", 1);
        cache.insert("b", 2);

        cache.touch(&"missing");

        assert_eq!(cache.pop_lru(), Some(("a", 1)));
        assert_eq!(cache.pop_lru(), Some(("b", 2)));
        assert_eq!(cache.pop_lru(), None);
    }
}
