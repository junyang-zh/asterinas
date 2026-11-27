// SPDX-License-Identifier: MPL-2.0

//! Intervals and interval sets used in VMARs.

use alloc::vec::Vec;
use alloc::collections::btree_map::{BTreeMap, Cursor, CursorMut};
use core::ops::Range;

#[cfg(feature = "memory_accounting")]
use ostd::mm::heap::accounting::AccountingAllocator as IntervalAllocator;
#[cfg(not(feature = "memory_accounting"))]
type IntervalMap<K, V> = BTreeMap<K, V>;
#[cfg(feature = "memory_accounting")]
type IntervalMap<K, V> = BTreeMap<K, V, IntervalAllocator>;
#[cfg(not(feature = "memory_accounting"))]
type IntervalCursor<'a, K, V> = Cursor<'a, K, V>;
#[cfg(feature = "memory_accounting")]
type IntervalCursor<'a, K, V> = Cursor<'a, K, V>;
#[cfg(not(feature = "memory_accounting"))]
type IntervalCursorMut<'a, K, V> = CursorMut<'a, K, V>;
#[cfg(feature = "memory_accounting")]
type IntervalCursorMut<'a, K, V> = CursorMut<'a, K, V, IntervalAllocator>;

#[cfg(not(feature = "memory_accounting"))]
type IntervalArray<V> = Vec<V>;
#[cfg(feature = "memory_accounting")]
type IntervalArray<V> = Vec<V, IntervalAllocator>;

/// The interval of an item in an interval set.
///
/// All items in the interval set must have a range.
pub(crate) trait Interval<K: Clone> {
    /// Returns the range of the interval.
    fn range(&self) -> Range<K>;
}

/// A collection that contains non-overlapping intervals as items.
///
/// In particular, the collection allows one to retrieve interval items that
/// intersect with a point of value or range of values.
#[derive(Debug)]
pub(crate) struct IntervalSet<K, V>
where
    K: Clone + Ord,
    V: Interval<K>,
{
    storage: Storage<K, V>,
    #[cfg(feature = "memory_accounting")]
    accounting: IntervalAllocator,
}

/// Most leaf tables contain either zero intervals or one mapping. Keep
/// that interval in the page-table metadata until a second key is needed.
#[derive(Debug)]
enum Storage<K, V> {
    Inline(Option<V>),
    Array(IntervalArray<V>),
    Tree(IntervalMap<K, V>),
}

impl<K, V> Default for IntervalSet<K, V>
where
    K: Clone + Ord,
    V: Interval<K>,
{
    fn default() -> Self {
        Self::new()
    }
}

impl<K, V> IntervalSet<K, V>
where
    K: Clone + Ord,
    V: Interval<K>,
{
    // Keep moderately populated page tables in one allocation. Bound the
    // bytes shifted on insertion and switch dense or highly fragmented
    // tables to the B-tree.
    fn array_limit() -> usize {
        (4 * ostd::mm::PAGE_SIZE / size_of::<V>().max(1)).clamp(2, 512)
    }

    /// Creates a new interval set.
    #[cfg(not(feature = "memory_accounting"))]
    pub(crate) const fn new() -> Self {
        Self {
            storage: Storage::Inline(None),
        }
    }

    #[cfg(feature = "memory_accounting")]
    pub(crate) fn new() -> Self {
        let accounting = IntervalAllocator::new();
        Self { storage: Storage::Inline(None), accounting }
    }

    #[cfg(feature = "memory_accounting")]
    pub(crate) fn allocation_snapshot(&self) -> ostd::mm::heap::accounting::AllocationSnapshot {
        self.accounting.snapshot()
    }

    #[cfg(ktest)]
    pub(super) fn inline_mut(&mut self) -> Option<&mut Option<V>> {
        match &mut self.storage {
            Storage::Inline(slot) => Some(slot),
            Storage::Array(_) | Storage::Tree(_) => None,
        }
    }

    /// Small sets retain their sorted values directly without a separate key.
    pub(super) fn small_mut(&mut self) -> Option<&mut [V]> {
        match &mut self.storage {
            Storage::Inline(slot) => Some(slot.as_mut_slice()),
            Storage::Array(pair) => Some(pair.as_mut_slice()),
            Storage::Tree(_) => None,
        }
    }

    fn ensure_tree(&mut self) -> &mut IntervalMap<K, V> {
        if !matches!(self.storage, Storage::Tree(_)) {
            #[cfg(feature = "memory_accounting")]
            let mut tree = BTreeMap::new_in(self.accounting.clone());
            #[cfg(not(feature = "memory_accounting"))]
            let mut tree = BTreeMap::new();
            match core::mem::replace(&mut self.storage, Storage::Inline(None)) {
                Storage::Inline(Some(old)) => { tree.insert(old.range().start, old); }
                Storage::Array(pair) => {
                    for old in pair { tree.insert(old.range().start, old); }
                }
                Storage::Inline(None) => {}
                Storage::Tree(_) => unreachable!(),
            }
            self.storage = Storage::Tree(tree);
        }
        let Storage::Tree(tree) = &mut self.storage else { unreachable!() };
        tree
    }

    /// Inserts or replaces the interval keyed by its lower endpoint.
    pub(crate) fn insert(&mut self, item: V) {
        let start = item.range().start;
        match &mut self.storage {
            Storage::Inline(slot) => {
                if slot.as_ref().is_none_or(|old| old.range().start == start) {
                    *slot = Some(item);
                } else {
                    let old = slot.take().unwrap();
                    let items = if old.range().start < start { [old, item] } else { [item, old] };
                    #[cfg(not(feature = "memory_accounting"))]
                    let mut array = Vec::with_capacity(2);
                    #[cfg(feature = "memory_accounting")]
                    let mut array = Vec::with_capacity_in(2, self.accounting.clone());
                    array.extend(items);
                    self.storage = Storage::Array(array);
                }
                return;
            }
            Storage::Array(array) => {
                let index = array.partition_point(|v| v.range().start < start);
                if let Some(old) = array.get_mut(index)
                    && old.range().start == start
                {
                    *old = item;
                    return;
                }
                if array.len() < Self::array_limit() {
                    if array.len() == array.capacity() {
                        let next = (array.len() + (array.len() / 2).max(1)).min(Self::array_limit());
                        array.reserve_exact(next - array.len());
                    }
                    array.insert(index, item);
                    return;
                }
            }
            Storage::Tree(_) => {}
        }
        self.ensure_tree().insert(start, item);
    }

    fn take_from_array(&mut self, index: usize) -> V {
        let Storage::Array(array) = &mut self.storage else { unreachable!() };
        let taken = array.remove(index);
        if array.len() == 1 {
            let last = array.pop();
            self.storage = Storage::Inline(last);
        } else if array.len() <= array.capacity() / 4 {
            array.shrink_to(2 * array.len());
        }
        taken
    }

    pub(crate) fn remove(&mut self, key: &K) -> Option<V> {
        match &mut self.storage {
            Storage::Inline(slot) => slot.take_if(|v| v.range().start == *key),
            Storage::Array(pair) => {
                let index = pair.binary_search_by(|v| v.range().start.cmp(key)).ok()?;
                Some(self.take_from_array(index))
            }
            Storage::Tree(tree) => tree.remove(key),
        }
    }

    #[cfg(any(ktest, feature = "memory_accounting"))]
    pub(crate) fn iter(&self) -> impl DoubleEndedIterator<Item = &V> {
        let (single, tree) = match &self.storage {
            Storage::Inline(slot) => (slot.as_slice(), None),
            Storage::Array(pair) => (pair.as_slice(), None),
            Storage::Tree(tree) => (&[][..], Some(tree.values())),
        };
        single.into_iter().chain(tree.into_iter().flatten())
    }

    pub(crate) fn find_one(&self, point: &K) -> Option<&V> {
        match &self.storage {
            Storage::Inline(slot) => slot.as_ref().filter(|v| v.range().contains(point)),
            Storage::Array(array) => array.get(array.partition_point(|v| v.range().end <= *point))
                .filter(|v| v.range().start <= *point),
            Storage::Tree(tree) => tree.lower_bound(core::ops::Bound::Excluded(point))
                .peek_prev().and_then(|(_, v)| (v.range().end > *point).then_some(v)),
        }
    }

    pub(super) fn find_one_mut(&mut self, point: &K) -> Option<&mut V> {
        match &mut self.storage {
            Storage::Inline(slot) => slot.as_mut().filter(|v| v.range().contains(point)),
            Storage::Array(array) => {
                let index = array.partition_point(|v| v.range().end <= *point);
                array.get_mut(index).filter(|v| v.range().start <= *point)
            }
            Storage::Tree(tree) => tree.range_mut((core::ops::Bound::Unbounded, core::ops::Bound::Included(point)))
                .next_back().and_then(|(_, v)| (v.range().end > *point).then_some(v)),
        }
    }

    /// Finds all interval items that intersect with the given range.
    pub(crate) fn find<'a>(&'a self, range: &Range<K>) -> impl Iterator<Item = &'a V> {
        let (small, tree) = match &self.storage {
            Storage::Inline(slot) => (slot.as_slice(), None),
            Storage::Array(pair) => (pair.as_slice(), None),
            Storage::Tree(tree) => (&[][..], Some(IntervalIter {
                cursor: tree.lower_bound(core::ops::Bound::Excluded(&range.start)),
                range: range.clone(),
                peeked_prev: false,
            })),
        };
        let range = range.clone();
        let first = small.partition_point(|v| v.range().end <= range.start);
        small[first..].iter().take_while(move |v| {
            let start = v.range().start;
            start <= range.start || start < range.end
        }).chain(tree.into_iter().flatten())
    }

    pub(super) fn first_intersection(&self, range: &Range<K>) -> Option<&V> {
        self.find(range).next()
    }

    pub(super) fn gap_before(&mut self, point: &K) -> IntervalCursorMut<'_, K, V> {
        self.ensure_tree().lower_bound_mut(core::ops::Bound::Included(point))
    }

    pub(crate) fn find_prev(&self, point: &K) -> Option<&V> {
        match &self.storage {
            Storage::Inline(slot) => slot.as_ref().filter(|v| v.range().start < *point),
            Storage::Array(array) => array[..array.partition_point(|v| v.range().start < *point)].last(),
            Storage::Tree(tree) => tree.upper_bound(core::ops::Bound::Excluded(point))
                .peek_prev().map(|(_, v)| v),
        }
    }

    pub(crate) fn find_next(&self, point: &K) -> Option<&V> {
        let tree = match &self.storage {
            Storage::Inline(slot) => return slot.as_ref().filter(|v| v.range().end > *point),
            Storage::Array(array) => return array.get(array.partition_point(|v| v.range().end <= *point)),
            Storage::Tree(tree) => tree,
        };
        let cursor = tree.lower_bound(core::ops::Bound::Excluded(point));
        if let Some((_, v)) = cursor.peek_prev() && v.range().end > *point {
            Some(v)
        } else {
            cursor.peek_next().map(|(_, v)| v)
        }
    }

    pub(crate) fn take_one(&mut self, point: &K) -> Option<V> {
        let tree = match &mut self.storage {
            Storage::Inline(slot) => return slot.take_if(|v| v.range().contains(point)),
            Storage::Array(pair) => {
                let index = pair.partition_point(|v| v.range().end <= *point);
                if pair.get(index)?.range().start > *point {
                    return None;
                }
                return Some(self.take_from_array(index));
            }
            Storage::Tree(tree) => tree,
        };
        let mut cursor = tree.lower_bound_mut(core::ops::Bound::Excluded(point));
        if let Some((_, v)) = cursor.peek_prev() && v.range().end > *point {
            return Some(cursor.remove_prev().unwrap().1);
        }
        None
    }

    /// Takes all interval items that intersect with the given range.
    ///
    /// This method returns a draining iterator that removes the items from the
    /// interval set.
    #[cfg(ktest)]
    pub(crate) fn take<'a>(&'a mut self, range: &Range<K>) -> IntervalDrain<'a, K, V> {
        let cursor = self
            .ensure_tree()
            .lower_bound_mut(core::ops::Bound::Excluded(&range.start));
        IntervalDrain {
            cursor,
            range: range.clone(),
            drained_prev: false,
        }
    }

    /// Clears the interval set, removing all intervals.
    pub(crate) fn clear(&mut self) {
        self.storage = Storage::Inline(None);
    }
}

/// An iterator that iterates over intervals in an interval set.
#[derive(Debug)]
pub(crate) struct IntervalIter<'a, K, V>
where
    K: Clone + Ord,
    V: Interval<K>,
{
    cursor: IntervalCursor<'a, K, V>,
    range: Range<K>,
    peeked_prev: bool,
}

impl<'a, K, V> Iterator for IntervalIter<'a, K, V>
where
    K: Clone + Ord,
    V: Interval<K>,
{
    type Item = &'a V;

    fn next(&mut self) -> Option<Self::Item> {
        // There's one previous element that may intersect with the range.
        if !self.peeked_prev {
            self.peeked_prev = true;
            if let Some((_, v)) = self.cursor.peek_prev()
                && v.range().end > self.range.start
            {
                return Some(v);
            }
        }

        // Find all intersected elements following it.
        if let Some((_, v)) = self.cursor.next() {
            if v.range().start >= self.range.end {
                return None;
            }
            return Some(v);
        }

        None
    }
}

/// A draining iterator that iterates over intervals in an interval set.
#[cfg_attr(not(ktest), expect(dead_code))]
#[derive(Debug)]
pub(crate) struct IntervalDrain<'a, K, V>
where
    K: Clone + Ord,
    V: Interval<K>,
{
    cursor: IntervalCursorMut<'a, K, V>,
    range: Range<K>,
    drained_prev: bool,
}

impl<K, V> Iterator for IntervalDrain<'_, K, V>
where
    K: Clone + Ord,
    V: Interval<K>,
{
    type Item = V;

    fn next(&mut self) -> Option<Self::Item> {
        // There's one previous element that may intersect with the range.
        if !self.drained_prev {
            self.drained_prev = true;
            if let Some((_, v)) = self.cursor.peek_prev()
                && v.range().end > self.range.start
            {
                return Some(self.cursor.remove_prev().unwrap().1);
            }
        }

        // Find all intersected elements following it.
        if let Some((_, v)) = self.cursor.peek_next() {
            if v.range().start >= self.range.end {
                return None;
            }
            return Some(self.cursor.remove_next().unwrap().1);
        }

        None
    }
}

#[cfg(ktest)]
mod tests {
    use alloc::{vec, vec::Vec};

    use ostd::prelude::ktest;

    use super::*;

    #[derive(Clone, Debug, PartialEq)]
    struct TestInterval {
        range: Range<i32>,
    }

    impl Interval<i32> for TestInterval {
        fn range(&self) -> Range<i32> {
            self.range.clone()
        }
    }

    #[ktest]
    fn small_array_grows_replaces_and_preserves_order() {
        let item = |start| TestInterval { range: start..start + 3 };
        let mut set = IntervalSet::new();
        set.insert(item(8));
        set.insert(item(2));
        assert!(matches!(&set.storage, Storage::Array(a) if a.len() == 2 && a.capacity() == 2));
        assert_eq!(set.find(&(4..9)).count(), 2);
        assert_eq!(set.find_next(&5).unwrap().range(), 8..11);
        assert_eq!(set.find_prev(&8).unwrap().range(), 2..5);
        set.insert(TestInterval {range: 2..6});
        assert_eq!(set.take_one(&5).unwrap().range(), 2..6);
        assert!(matches!(set.storage, Storage::Inline(Some(_))));
        set.insert(item(20));
        assert_eq!(set.remove(&8).unwrap().range(), 8..11);
        set.insert(item(8)); set.insert(item(2));
        assert!(matches!(set.storage, Storage::Array(_)));
        assert_eq!(set.iter().map(|v| v.range().start).collect::<Vec<_>>(), vec![2,8,20]);
        set.insert(item(30));
        assert!(matches!(set.storage, Storage::Array(_)));
        set.insert(item(25));
        assert!(matches!(set.storage, Storage::Array(_)));
        assert_eq!(set.iter().map(|v| v.range().start).collect::<Vec<_>>(), vec![2,8,20,25,30]);
    }

    #[ktest]
    fn packed_intervals_spill_without_losing_covered_pages_or_gaps() {
        let mut set = IntervalSet::new();
        let limit = IntervalSet::<i32, TestInterval>::array_limit() as i32;
        for i in (0..limit).rev() {
            set.insert(TestInterval { range: 4*i..4*i+2 });
        }
        assert!(matches!(&set.storage, Storage::Array(a) if a.len() == limit as usize));
        for i in 0..limit {
            assert_eq!(set.find_one(&(4*i+1)).unwrap().range(), 4*i..4*i+2);
            assert!(set.find_one(&(4*i+2)).is_none());
            assert!(set.take_one(&(4*i+3)).is_none());
        }
        assert_eq!(set.find(&(3..10)).count(), 2);
        set.find_one_mut(&5).unwrap().range.end = 7;
        assert_eq!(set.take_one(&6).unwrap().range(), 4..7);
        set.insert(TestInterval { range: 4..6 });
        set.insert(TestInterval { range: 4*limit..4*limit+2 });
        assert!(matches!(set.storage, Storage::Tree(_)));
        assert_eq!(set.iter().count(), limit as usize + 1);
        assert_eq!(set.find_prev(&(4*limit)).unwrap().range().start, 4*(limit-1));
        assert_eq!(set.find_next(&(4*limit-1)).unwrap().range().start, 4*limit);
    }

    #[cfg(feature = "memory_accounting")]
    #[ktest]
    fn btree_allocation_growth_and_clear() {
        let mut set = IntervalSet::new();
        assert_eq!(set.allocation_snapshot().allocations, 0);
        let limit = IntervalSet::<i32, TestInterval>::array_limit() as i32;
        for index in 0..limit {
            set.insert(TestInterval { range: index * 2..index * 2 + 1 });
        }
        let array = set.allocation_snapshot();
        assert_eq!(array.allocations, 1);
        assert!(array.requested_bytes >= limit as usize * size_of::<TestInterval>());
        set.insert(TestInterval { range: limit * 2..limit * 2 + 1 });
        let full = set.allocation_snapshot();
        assert!(full.allocations > 1);
        assert!(full.requested_bytes > 0);
        assert!(full.charged_bytes >= full.requested_bytes);
        for index in 0..256 { set.remove(&(index * 2)); }
        assert!(set.allocation_snapshot().requested_bytes < full.requested_bytes);
        set.clear();
        let empty = set.allocation_snapshot();
        assert_eq!(empty.allocations, 0);
        assert_eq!(empty.requested_bytes, 0);
        assert_eq!(empty.charged_bytes, 0);
    }

    #[ktest]
    fn insert_and_find_one() {
        let mut set = IntervalSet::new();
        let interval = TestInterval { range: 10..20 };
        set.insert(interval.clone());

        assert_eq!(set.find_one(&15), Some(&interval));
        assert_eq!(set.find_one(&25), None);
    }

    #[ktest]
    fn remove() {
        let mut set = IntervalSet::new();
        let interval = TestInterval { range: 10..20 };
        set.insert(interval.clone());

        assert_eq!(set.remove(&10), Some(interval));
        assert_eq!(set.remove(&10), None);
    }

    #[ktest]
    fn iter() {
        let mut set = IntervalSet::new();
        let interval1 = TestInterval { range: 10..20 };
        let interval2 = TestInterval { range: 30..40 };
        set.insert(interval1.clone());
        set.insert(interval2.clone());

        let intervals: Vec<&TestInterval> = set.iter().collect();
        assert_eq!(intervals, vec![&interval1, &interval2]);
    }

    #[ktest]
    fn find() {
        let mut set = IntervalSet::new();
        let interval1 = TestInterval { range: 10..20 };
        let interval2 = TestInterval { range: 30..40 };
        let interval3 = TestInterval { range: 40..50 };
        let interval4 = TestInterval { range: 80..90 };
        set.insert(interval1.clone());
        set.insert(interval2.clone());
        set.insert(interval3.clone());
        set.insert(interval4.clone());

        let found: Vec<&TestInterval> = set.find(&(35..50)).collect();
        assert_eq!(found, vec![&interval2, &interval3]);
    }

    #[ktest]
    fn take_one() {
        let mut set = IntervalSet::new();
        let interval1 = TestInterval { range: 10..20 };
        let interval2 = TestInterval { range: 20..30 };
        set.insert(interval1.clone());
        set.insert(interval2.clone());

        assert_eq!(set.take_one(&15), Some(interval1));
        assert_eq!(set.take_one(&15), None);
    }

    #[ktest]
    fn take() {
        let mut set = IntervalSet::new();
        let interval1 = TestInterval { range: 10..20 };
        let interval2 = TestInterval { range: 30..40 };
        let interval3 = TestInterval { range: 45..50 };
        let interval4 = TestInterval { range: 60..70 };
        set.insert(interval1.clone());
        set.insert(interval2.clone());
        set.insert(interval3.clone());
        set.insert(interval4.clone());

        let taken: Vec<TestInterval> = set.take(&(35..45)).collect();
        assert_eq!(taken, vec![interval2]);
    }

    #[ktest]
    fn singleton_lookup_replacement_and_promotion() {
        let mut set = IntervalSet::new();
        set.insert(TestInterval { range: 20..30 });
        assert!(set.inline_mut().is_some());
        assert!(set.find_one(&19).is_none());
        assert!(set.find_one(&20).is_some());
        assert!(set.find_one(&30).is_none());
        assert!(set.find_prev(&20).is_none());
        assert!(set.find_next(&20).is_some());
        assert_eq!(set.find(&(10..21)).count(), 1);
        assert_eq!(set.find(&(20..20)).count(), 1);
        assert_eq!(set.find(&(30..40)).count(), 0);
        set.insert(TestInterval { range: 20..32 });
        assert!(set.find_one(&31).is_some());
        set.insert(TestInterval { range: 40..45 });
        assert!(set.inline_mut().is_none());
        assert_eq!(set.find(&(29..41)).count(), 2);
        assert_eq!(set.take_one(&41).unwrap().range, 40..45);
        set.clear();
        assert!(set.inline_mut().is_some());
        assert!(set.find_next(&0).is_none());
    }

    #[ktest]
    fn clear() {
        let mut set = IntervalSet::new();
        let interval1 = TestInterval { range: 10..20 };
        let interval2 = TestInterval { range: 20..30 };
        set.insert(interval1);
        set.insert(interval2);

        set.clear();
        assert!(set.iter().next().is_none());
    }
}
