// SPDX-License-Identifier: MPL-2.0

//! Hierarchical rw protocol: shared ancestors, an exclusive covering node, and
//! implicitly exclusive descendants. Always acquire from root toward leaves;
//! release descendants, covering writer, then ancestors toward the root.

use core::{marker::PhantomData, ops::Range};

use align_ext::AlignExt;

use super::{Cursor, MAX_NR_LEVELS};
use crate::{
    mm::{
        Vaddr, nr_base_per_page, nr_subpage_per_huge,
        page_table::{
            PageTable, PageTableConfig, PageTableGuard, PagingLevel, PteStateRef, page_size,
            pte_index,
        },
    },
    task::atomic_mode::InAtomicMode,
};

pub(super) fn lock_range<'rcu, C: PageTableConfig>(
    pt: &'rcu PageTable<C>,
    guard: &'rcu dyn InAtomicMode,
    va: &Range<Vaddr>,
    min_level: PagingLevel,
) -> Cursor<'rcu, C> {
    traverse(pt, guard, va, min_level, false).unwrap()
}

pub(super) fn try_lock_range<'rcu, C: PageTableConfig>(
    pt: &'rcu PageTable<C>,
    guard: &'rcu dyn InAtomicMode,
    va: &Range<Vaddr>,
) -> Option<Cursor<'rcu, C>> {
    traverse(pt, guard, va, 1, true)
}

fn traverse<'rcu, C: PageTableConfig>(
    pt: &'rcu PageTable<C>,
    guard: &'rcu dyn InAtomicMode,
    va: &Range<Vaddr>,
    min_level: PagingLevel,
    nonblocking: bool,
) -> Option<Cursor<'rcu, C>> {
    // Array drops from low to high: any failure releases the acquired path in
    // reverse order. No guard is forgotten and no descendant lock is acquired.
    let mut path: [Option<PageTableGuard<'rcu, C>>; MAX_NR_LEVELS] = core::array::from_fn(|_| None);
    let mut current = pt.root.borrow();
    let guard_level;
    loop {
        let level = current.level();
        let idx = pte_index::<C>(va.start, level);
        let descend = level > min_level && idx == pte_index::<C>(va.end - 1, level);
        if descend {
            let read = if nonblocking {
                current.clone_ref().try_read(guard)?
            } else {
                current.clone_ref().lock_read(guard)
            };
            if let PteStateRef::PageTable(child) = read.entry_state(idx) {
                path[level as usize - 1] = Some(read);
                current = child;
                continue;
            }
            // Never upgrade while retaining our own reader ticket. Ancestor
            // locks keep current attached while the entry is revalidated below.
            drop(read);
        }
        let mut write = if nonblocking {
            current.try_lock(guard)?
        } else {
            current.lock(guard)
        };
        if descend {
            let mut entry = write.entry(va.start.align_down(page_size::<C>(level)));
            let child = match entry.to_ref() {
                PteStateRef::PageTable(child) => Some(child),
                PteStateRef::Absent => {
                    let new_child = entry.alloc_if_none(guard).unwrap();
                    let child = (*new_child).clone_ref();
                    drop(new_child); // Implicit: no physical child lock to release.
                    Some(child)
                }
                PteStateRef::Mapped(_) => None,
            };
            if let Some(child) = child {
                path[level as usize - 1] = Some(write.downgrade());
                current = child;
                continue;
            }
        }
        guard_level = level;
        path[level as usize - 1] = Some(write);
        break;
    }
    Some(Cursor {
        path,
        rcu_guard: guard,
        level: guard_level,
        guard_level,
        va: va.start,
        barrier_va: va.clone(),
        _phantom: PhantomData,
    })
}

pub(super) fn unlock_range<C: PageTableConfig>(cursor: &mut Cursor<'_, C>) {
    // Implicit guards drop without touching a physical lock. The covering
    // writer is released before any shared ancestor protecting its attachment.
    for slot in &mut cursor.path {
        drop(slot.take());
    }
}

/// Marks all the nodes in the sub-tree rooted at the node as stray, and
/// returns the num of pages mapped within the sub-tree.
///
/// It must be called upon the node after the node is removed from the parent
/// page table. It also unlocks the nodes in the sub-tree.
///
/// This function returns the number of physical frames mapped in the sub-tree.
///
/// # Safety
///
/// The caller must ensure that all the nodes in the sub-tree are locked
/// and all guards are forgotten.
///
/// This function must not be called upon a shared node, e.g., the second-
/// top level nodes that the kernel space and user space share.
pub(super) unsafe fn dfs_mark_stray_and_unlock<C: PageTableConfig>(
    rcu_guard: &dyn InAtomicMode,
    mut sub_tree: PageTableGuard<C>,
    subtree_va: Vaddr,
) -> usize {
    *sub_tree.stray_mut() = true;
    let level = sub_tree.level();

    if level == 1 {
        return sub_tree.nr_children() as usize;
    }

    let mut num_frames = 0;

    for i in (0..nr_subpage_per_huge::<C>()).rev() {
        let pte_va = subtree_va + i * page_size::<C>(level);
        let child = sub_tree.entry(pte_va);
        match child.to_ref() {
            PteStateRef::PageTable(pt) => {
                // SAFETY: The caller ensures that the node is locked and the new guard is unique.
                let locked_pt = unsafe { pt.make_guard_unchecked(rcu_guard) };
                // SAFETY: The caller ensures that all the nodes in the sub-tree are locked and all
                // guards are forgotten.
                num_frames += unsafe { dfs_mark_stray_and_unlock(rcu_guard, locked_pt, pte_va) };
            }
            PteStateRef::Absent => {}
            PteStateRef::Mapped(_) => {
                num_frames += nr_base_per_page::<C>(level);
            }
        }
    }

    num_frames
}
