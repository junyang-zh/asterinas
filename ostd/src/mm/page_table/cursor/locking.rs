// SPDX-License-Identifier: MPL-2.0

//! Implementation of the locking protocol.

use core::{marker::PhantomData, ops::Range};

use super::{Cursor, GuardInPath, MAX_NR_LEVELS};
use crate::{
    mm::{
        page_table::{
            pte_index, zeroed_pt_pool, Child, MapTrackingStatus, PageTable, PageTableEntryTrait,
            PageTableMode, PageTableNode, PagingConstsTrait,
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
    let cur_pt_wlockguard = cur_wlock.unwrap_or_else(|| {
        // SAFETY: It's OK to get a reference to the page table node since
        // the PT is alive. We will forget the reference later.
        let cur_pt = unsafe { PageTableNode::<E, C>::from_raw(cur_pt_paddr) };
        cur_pt.lock_write()
    });

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
                    panic!("Expected read lock at level {}, found write lock", i);
                }
                GuardInPath::ImplicitlyLocked(_) => {
                    panic!("Expected read lock at level {}, found implicitly locked", i);
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
    #[cfg(debug_assertions)]
    {
        for i in 1..cursor.level {
            debug_assert!(matches!(
                cursor.path[i as usize - 1].take(),
                GuardInPath::None
            ))
        }
        for i in cursor.level..cursor.guard_level {
            debug_assert!(matches!(
                cursor.path[i as usize - 1].take(),
                GuardInPath::ImplicitlyLocked(_)
            ))
        }
    }

    let GuardInPath::WriteLocked(guard_node) = cursor.path[cursor.guard_level as usize - 1].take()
    else {
        panic!("Expected write lock");
    };

    guard_node.unlock().into_raw();

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
            GuardInPath::ImplicitlyLocked(_) => {
                panic!("Expected read lock at level {}, found implicitly locked", i);
            }
        }
    }
}
