// SPDX-License-Identifier: MPL-2.0

//! Implementation of the locking protocol.

use core::{marker::PhantomData, ops::Range};

use align_ext::AlignExt;

use super::{Cursor, GuardInPath, MAX_NR_LEVELS};
use crate::{
    mm::{
        nr_subpage_per_huge,
        page_table::{
            page_size, pte_index, zeroed_pt_pool, Child, MapTrackingStatus, PageTable,
            PageTableEntryTrait, PageTableMode, PageTableNode, PageTableWriteLock,
            PagingConstsTrait, PagingLevel,
        },
        Vaddr,
    },
    task::disable_preempt,
};

pub(super) fn lock_range<'a, M: PageTableMode, E: PageTableEntryTrait, C: PagingConstsTrait>(
    pt: &'a PageTable<M, E, C>,
    va: &Range<Vaddr>,
    new_pt_is_tracked: MapTrackingStatus,
) -> Cursor<'a, M, E, C> {
    let preempt_guard = disable_preempt();

    zeroed_pt_pool::prefill(&preempt_guard);

    let mut path: [GuardInPath<E, C>; MAX_NR_LEVELS] = core::array::from_fn(|_| GuardInPath::None);
    let mut level = C::NR_LEVELS;

    let mut cur_pt_paddr = pt.root.start_paddr();

    // Go down and get proper locks. The cursor should hold a write lock of a
    // page table node containing the virtual address range.
    //
    // While going down, we will hold read locks of previous path of too-high levels.
    let cur_wlock = loop {
        let start_idx = pte_index::<C>(va.start, level);
        let level_too_high = {
            let end_idx = pte_index::<C>(va.end - 1, level);
            level > 1 && start_idx == end_idx
        };
        if !level_too_high {
            break None;
        }

        // SAFETY: It's OK to get a reference to the page table node since
        // the PT is alive. We will forget the reference later.
        let cur_pt = unsafe { PageTableNode::<E, C>::from_raw(cur_pt_paddr) };
        let cur_pt_rlockguard = cur_pt.lock_read();

        let child = cur_pt_rlockguard.read_child_ref(start_idx);
        match child {
            Child::PageTable(_) => unreachable!(),
            Child::PageTableRef(pt) => {
                path[level as usize - 1] = GuardInPath::ReadLocked(cur_pt_rlockguard);
                cur_pt_paddr = pt;
                level -= 1;
                continue;
            }
            Child::None => {
                // Upgrade to write lock.
                let cur_pt = cur_pt_rlockguard.unlock();
                let mut cur_pt_wlockguard = cur_pt.lock_write();

                let entry = cur_pt_wlockguard.entry(start_idx);
                match entry.to_ref() {
                    Child::PageTable(_) => unreachable!(),
                    Child::PageTableRef(pt) => {
                        // Downgrade to read lock.
                        let cur_pt = cur_pt_wlockguard.unlock();
                        let cur_pt_rlockguard = cur_pt.lock_read();
                        path[level as usize - 1] = GuardInPath::ReadLocked(cur_pt_rlockguard);
                        cur_pt_paddr = pt;
                        level -= 1;
                        continue;
                    }
                    Child::None => {
                        // We need to allocate a new page table node.
                        let pt = zeroed_pt_pool::alloc::<E, C>(
                            &preempt_guard,
                            level - 1,
                            new_pt_is_tracked,
                        );
                        let pt = pt.unlock();
                        cur_pt_paddr = pt.start_paddr();
                        let _ = entry.replace(Child::PageTable(pt));
                        // Downgrade to read lock.
                        let cur_pt = cur_pt_wlockguard.unlock();
                        let cur_pt_rlockguard = cur_pt.lock_read();
                        path[level as usize - 1] = GuardInPath::ReadLocked(cur_pt_rlockguard);
                        level -= 1;
                        continue;
                    }
                    _ => {
                        break Some(cur_pt_wlockguard);
                    }
                }
            }
            _ => {
                let _ = cur_pt_rlockguard.unlock().into_raw();
                break None;
            }
        }
    };

    // Get write lock of the current page table node.
    let mut cur_pt_wlockguard = cur_wlock.unwrap_or_else(|| {
        // SAFETY: It's OK to get a reference to the page table node since
        // the PT is alive. We will forget the reference later.
        let cur_pt = unsafe { PageTableNode::<E, C>::from_raw(cur_pt_paddr) };
        cur_pt.lock_write()
    });

    // Once we have locked the sub-tree that is not astray, we won't read any
    // astray nodes in the following traversal since we must lock before reading.
    dfs_acquire_lock(
        &mut cur_pt_wlockguard,
        va.start.align_down(page_size::<C>(level + 1)),
        va.clone(),
    );

    path[level as usize - 1] = GuardInPath::WriteLocked(cur_pt_wlockguard);

    #[cfg(debug_assertions)]
    {
        for i in (C::NR_LEVELS..level).rev() {
            match &path[i as usize - 1] {
                GuardInPath::None => {
                    panic!("Expected read lock at level {}, found none", i);
                }
                GuardInPath::ReadLocked(_) => {}
                GuardInPath::WriteLocked(_) => {
                    panic!("Expected write lock at level {}, found write lock", i);
                }
            }
        }
    }

    Cursor::<'a, M, E, C> {
        path,
        level,
        guard_level: level,
        va: va.start,
        barrier_va: va.clone(),
        preempt_guard,
        _phantom: PhantomData,
    }
}

pub(super) fn unlock_range<M: PageTableMode, E: PageTableEntryTrait, C: PagingConstsTrait>(
    cursor: &mut Cursor<'_, M, E, C>,
) {
    for i in 1..cursor.guard_level {
        match cursor.path[i as usize - 1].take() {
            GuardInPath::None => {}
            GuardInPath::ReadLocked(_) => {
                panic!(
                    "Expected write lock or none at level {}, found write lock",
                    i
                );
            }
            GuardInPath::WriteLocked(wguard) => {
                let _ = wguard.unlock().into_raw();
            }
        }
    }

    let GuardInPath::WriteLocked(guard_node) = cursor.path[cursor.guard_level as usize - 1].take()
    else {
        panic!("Expected write lock");
    };
    let cur_node_va = cursor.barrier_va.start / page_size::<C>(cursor.guard_level + 1)
        * page_size::<C>(cursor.guard_level + 1);

    dfs_release_lock(guard_node, cur_node_va, cursor.barrier_va.clone());

    for i in (cursor.guard_level + 1)..=C::NR_LEVELS {
        match cursor.path[i as usize - 1].take() {
            GuardInPath::None => {
                panic!("Expected read lock at level {}, found none", i);
            }
            GuardInPath::ReadLocked(rguard) => {
                let _ = rguard.unlock().into_raw();
            }
            GuardInPath::WriteLocked(_) => {
                panic!("Expected read lock at level {}, found write lock", i);
            }
        }
    }
}

/// Acquires the locks for the given range in the sub-tree rooted at the node.
///
/// `cur_node_va` must be the virtual address of the `cur_node`. The `va_range`
/// must be within the range of the `cur_node`. The range must not be empty.
///
/// The function will forget all the [`PageTableWriteLock`] objects in the sub-tree
/// with [`PageTableWriteLock::into_raw_paddr`].
fn dfs_acquire_lock<E: PageTableEntryTrait, C: PagingConstsTrait>(
    cur_node: &mut PageTableWriteLock<E, C>,
    cur_node_va: Vaddr,
    va_range: Range<Vaddr>,
) {
    debug_assert!(!*cur_node.astray_mut());
    let cur_level = cur_node.level();

    if cur_level > 1 {
        let idx_range = dfs_get_idx_range::<C>(cur_level, cur_node_va, &va_range);
        for i in idx_range {
            let child = cur_node.entry(i);
            match child.to_ref() {
                Child::PageTableRef(pt) => {
                    // SAFETY: This must be alive since we have a reference
                    // to the parent node that is still alive.
                    let pt = unsafe { PageTableNode::<E, C>::from_raw(pt) };
                    let mut pt = pt.lock_write();
                    let child_node_va = cur_node_va + i * page_size::<C>(cur_level);
                    let child_node_va_end = child_node_va + page_size::<C>(cur_level);
                    let va_start = va_range.start.max(child_node_va);
                    let va_end = va_range.end.min(child_node_va_end);
                    dfs_acquire_lock(&mut pt, child_node_va, va_start..va_end);
                    let _ = pt.into_raw_paddr();
                }
                Child::None
                | Child::Frame(_, _)
                | Child::Untracked(_, _, _)
                | Child::PageTable(_)
                | Child::Token(_) => {}
            }
        }
    }
}

/// Releases the locks for the given range in the sub-tree rooted at the node.
pub(super) fn dfs_release_lock<E: PageTableEntryTrait, C: PagingConstsTrait>(
    mut cur_node: PageTableWriteLock<E, C>,
    cur_node_va: Vaddr,
    va_range: Range<Vaddr>,
) {
    let cur_level = cur_node.level();

    if cur_level > 1 {
        let idx_range = dfs_get_idx_range::<C>(cur_level, cur_node_va, &va_range);
        for i in idx_range.rev() {
            let child = cur_node.entry(i);
            match child.to_ref() {
                Child::PageTableRef(pt) => {
                    // SAFETY: The node was locked before and we have a
                    // reference to the parent node that is still alive.
                    let child_node = unsafe { PageTableWriteLock::<E, C>::from_raw_paddr(pt) };
                    let child_node_va = cur_node_va + i * page_size::<C>(cur_level);
                    let child_node_va_end = child_node_va + page_size::<C>(cur_level);
                    let va_start = va_range.start.max(child_node_va);
                    let va_end = va_range.end.min(child_node_va_end);
                    dfs_release_lock(child_node, child_node_va, va_start..va_end);
                }
                Child::None
                | Child::Frame(_, _)
                | Child::Untracked(_, _, _)
                | Child::PageTable(_)
                | Child::Token(_) => {}
            }
        }
    }

    let _ = cur_node.unlock().into_raw();
}

fn dfs_get_idx_range<C: PagingConstsTrait>(
    cur_node_level: PagingLevel,
    cur_node_va: Vaddr,
    va_range: &Range<Vaddr>,
) -> Range<usize> {
    debug_assert!(va_range.start >= cur_node_va);
    debug_assert!(va_range.end <= cur_node_va + page_size::<C>(cur_node_level + 1));

    let start_idx = (va_range.start - cur_node_va) / page_size::<C>(cur_node_level);
    let end_idx = (va_range.end - cur_node_va).div_ceil(page_size::<C>(cur_node_level));

    debug_assert!(start_idx < end_idx);
    debug_assert!(end_idx <= nr_subpage_per_huge::<C>());

    start_idx..end_idx
}
