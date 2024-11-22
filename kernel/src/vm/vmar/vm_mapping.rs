// SPDX-License-Identifier: MPL-2.0

use core::{num::NonZeroUsize, ops::Range};

use align_ext::AlignExt;
use ostd::mm::{
    tlb::TlbFlushOp,
    vm_space::{Cursor, CursorMut, Token, VmItem},
    CachePolicy, Frame, FrameAllocOptions, PageFlags, PageProperty, VmSpace,
};

use super::interval_set::Interval;
use crate::{
    prelude::*,
    thread::exception::PageFaultInfo,
    vm::{perms::VmPerms, util::duplicate_frame, vmo::Vmo},
};

/// Mapping a range of physical pages into a `Vmar`.
///
/// A `VmMapping` can bind with a `Vmo` which can provide physical pages for
/// mapping. Otherwise, it must be an anonymous mapping and will map any empty
/// physical page. A `VmMapping` binding with a `Vmo` is called VMO-backed
/// mapping. Generally, a VMO-backed mapping is a file-backed mapping. Yet
/// there are also some situations where specific pages that are not in a file
/// need to be mapped. e.g:
///  - Mappings to the VDSO data.
///  - Shared anonymous mappings. because the mapped pages need to be retained
///    and shared with other processes.
///
/// Such mappings will also be VMO-backed mappings.
///
/// This type controls the actual mapping in the [`VmSpace`]. It is a linear
/// type and cannot be [`Drop`]. To remove a mapping, use [`Self::unmap`].
#[derive(Debug)]
pub(super) struct VmMapping {
    /// The size of mapping, in bytes. The map size can even be larger than the
    /// size of VMO. Those pages outside VMO range cannot be read or write.
    ///
    /// Zero sized mapping is not allowed. So this field is always non-zero.
    map_size: NonZeroUsize,
    /// The base address relative to the root VMAR where the VMO is mapped.
    map_to_addr: Vaddr,
    /// Specific physical pages that need to be mapped. If this field is
    /// `None`, it means that the mapping is an independent anonymous mapping.
    ///
    /// The start of the virtual address maps to the start of the range
    /// specified in [`MappedVmo`].
    vmo: Option<MappedVmo>,
    /// Whether the mapping is shared.
    ///
    /// The updates to a shared mapping are visible among processes, or carried
    /// through to the underlying file for file-backed shared mappings.
    is_shared: bool,
    /// Whether the mapping needs to handle surrounding pages when handling
    /// page fault.
    handle_page_faults_around: bool,
    /// The permissions of pages in the mapping.
    ///
    /// All pages within the same `VmMapping` have the same permissions.
    perms: VmPerms,
}

/// A marker directly recorded in the PT rather than the tree.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct VmMarker {
    pub(super) perms: VmPerms,
    pub(super) is_shared: bool,
    pub(super) vmo_backed_id: Option<u32>,
}

/// A file-backed VMO mapping.
#[derive(Debug)]
pub(super) struct VmoBackedVMA {
    pub(super) id: u32,
    /// The size of mapping, in bytes. The map size can even be larger than the
    /// size of VMO. Those pages outside VMO range cannot be read or write.
    ///
    /// Zero sized mapping is not allowed. So this field is always non-zero.
    pub(super) map_size: NonZeroUsize,
    /// The base address relative to the root VMAR where the VMO is mapped.
    pub(super) map_to_addr: Vaddr,
    /// Specific physical pages that need to be mapped.
    ///
    /// The start of the virtual address maps to the start of the range
    /// specified in [`MappedVmo`].
    pub(super) vmo: MappedVmo,
    /// Whether the mapping needs to handle surrounding pages when handling
    /// page fault.
    pub(super) handle_page_faults_around: bool,
}

impl Clone for VmoBackedVMA {
    fn clone(&self) -> Self {
        Self {
            vmo: self.vmo.dup().unwrap(),
            ..*self
        }
    }
}

bitflags! {
    struct VmMarkerToken: usize {
        // Always set
        const MAPPED    = 1 << 0;
        const READ      = 1 << 1;
        const WRITE     = 1 << 2;
        const EXEC      = 1 << 3;
        const SHARED    = 1 << 4;
    }
}

impl VmMarker {
    pub(super) fn encode(self) -> Token {
        let mut token = VmMarkerToken::MAPPED;
        if self.perms.contains(VmPerms::READ) {
            token |= VmMarkerToken::READ;
        }
        if self.perms.contains(VmPerms::WRITE) {
            token |= VmMarkerToken::WRITE;
        }
        if self.perms.contains(VmPerms::EXEC) {
            token |= VmMarkerToken::EXEC;
        }
        if self.is_shared {
            token |= VmMarkerToken::SHARED;
        }
        let mut bits = token.bits();
        if let Some(vmo_backed_id) = self.vmo_backed_id {
            bits |= (vmo_backed_id as usize) << 5;
        }
        Token::try_from(bits).unwrap()
    }

    pub(super) fn decode(token: Token) -> Self {
        let vmo_backed_id = usize::from(token) >> 5;
        let vmo_backed_id = if vmo_backed_id == 0 {
            None
        } else {
            Some(vmo_backed_id as u32)
        };

        let token = VmMarkerToken::from_bits_truncate(token.into());

        debug_assert!(token.contains(VmMarkerToken::MAPPED));

        let mut perms = VmPerms::empty();

        if token.contains(VmMarkerToken::READ) {
            perms |= VmPerms::READ;
        }
        if token.contains(VmMarkerToken::WRITE) {
            perms |= VmPerms::WRITE;
        }
        if token.contains(VmMarkerToken::EXEC) {
            perms |= VmPerms::EXEC;
        }

        let is_shared = token.contains(VmMarkerToken::SHARED);

        Self {
            perms,
            is_shared,
            vmo_backed_id,
        }
    }
}

impl Interval<Vaddr> for VmMapping {
    fn range(&self) -> Range<Vaddr> {
        self.map_to_addr..self.map_to_addr + self.map_size.get()
    }
}

/***************************** Basic methods *********************************/

impl VmMapping {
    pub(super) fn new(
        map_size: NonZeroUsize,
        map_to_addr: Vaddr,
        vmo: Option<MappedVmo>,
        is_shared: bool,
        handle_page_faults_around: bool,
        perms: VmPerms,
    ) -> Self {
        Self {
            map_size,
            map_to_addr,
            vmo,
            is_shared,
            handle_page_faults_around,
            perms,
        }
    }

    pub(super) fn new_fork(&self) -> Result<VmMapping> {
        Ok(VmMapping {
            vmo: self.vmo.as_ref().map(|vmo| vmo.dup()).transpose()?,
            ..*self
        })
    }

    /// Returns the mapping's start address.
    pub fn map_to_addr(&self) -> Vaddr {
        self.map_to_addr
    }

    /// Returns the mapping's end address.
    pub fn map_end(&self) -> Vaddr {
        self.map_to_addr + self.map_size.get()
    }

    /// Returns the mapping's size.
    pub fn map_size(&self) -> usize {
        self.map_size.get()
    }

    // Returns the permissions of pages in the mapping.
    pub fn perms(&self) -> VmPerms {
        self.perms
    }
}

/**************************** Transformations ********************************/

impl VmMapping {
    /// Enlarges the mapping by `extra_size` bytes to the high end.
    pub fn enlarge(self, vm_space: &Arc<VmSpace>, extra_size: usize) -> Self {
        if self.vmo.is_none() {
            let end = self.map_end();
            let mut cursor = vm_space.cursor_mut(&(end..end + extra_size)).unwrap();
            cursor.mark(
                extra_size,
                VmMarker {
                    perms: self.perms,
                    is_shared: self.is_shared,
                    vmo_backed_id: None,
                }
                .encode(),
            );
        } else {
            todo!();
        }
        Self {
            map_size: NonZeroUsize::new(self.map_size.get() + extra_size).unwrap(),
            ..self
        }
    }

    /// Splits the mapping at the specified address.
    ///
    /// The address must be within the mapping and page-aligned. The address
    /// must not be either the start or the end of the mapping.
    fn split(self, at: Vaddr) -> Result<(Self, Self)> {
        debug_assert!(self.map_to_addr < at && at < self.map_end());
        debug_assert!(at % PAGE_SIZE == 0);

        let (mut l_vmo, mut r_vmo) = (None, None);

        if let Some(vmo) = self.vmo {
            let at_offset = vmo.range.start + at - self.map_to_addr;

            let l_range = vmo.range.start..at_offset;
            let r_range = at_offset..vmo.range.end;

            l_vmo = Some(MappedVmo::new(vmo.vmo.dup()?, l_range));
            r_vmo = Some(MappedVmo::new(vmo.vmo.dup()?, r_range));
        }

        let left_size = at - self.map_to_addr;
        let right_size = self.map_size.get() - left_size;
        let left = Self {
            map_to_addr: self.map_to_addr,
            map_size: NonZeroUsize::new(left_size).unwrap(),
            vmo: l_vmo,
            ..self
        };
        let right = Self {
            map_to_addr: at,
            map_size: NonZeroUsize::new(right_size).unwrap(),
            vmo: r_vmo,
            ..self
        };

        Ok((left, right))
    }

    /// Splits the mapping at the specified address.
    ///
    /// There are four conditions:
    /// 1. |-outside `range`-| + |------------within `range`------------|
    /// 2. |------------within `range`------------| + |-outside `range`-|
    /// 3. |-outside `range`-| + |-within `range`-| + |-outside `range`-|
    /// 4. |----------------------within `range` -----------------------|
    ///
    /// Returns (left outside, within, right outside) if successful.
    ///
    /// # Panics
    ///
    /// Panics if the mapping does not contain the range, or if the start or
    /// end of the range is not page-aligned.
    pub fn split_range(self, range: &Range<Vaddr>) -> Result<(Option<Self>, Self, Option<Self>)> {
        let mapping_range = self.range();
        if range.start <= mapping_range.start && mapping_range.end <= range.end {
            // Condition 4.
            return Ok((None, self, None));
        } else if mapping_range.start < range.start {
            let (left, within) = self.split(range.start).unwrap();
            if range.end < mapping_range.end {
                // Condition 3.
                let (within, right) = within.split(range.end).unwrap();
                return Ok((Some(left), within, Some(right)));
            } else {
                // Condition 1.
                return Ok((Some(left), within, None));
            }
        } else if mapping_range.contains(&range.end) {
            // Condition 2.
            let (within, right) = self.split(range.end).unwrap();
            return Ok((None, within, Some(right)));
        }
        panic!("The mapping does not contain the splitting range.");
    }
}

/************************** VM Space operations ******************************/

impl VmMapping {
    /// Unmaps the mapping from the VM space.
    pub(super) fn unmap(self, vm_space: &VmSpace) -> Result<()> {
        let range = self.range();
        let mut cursor = vm_space.cursor_mut(&range)?;
        cursor.unmap(range.len());

        Ok(())
    }

    /// Change the perms of the mapping.
    pub(super) fn protect(self, vm_space: &VmSpace, perms: VmPerms) -> Self {
        let range = self.range();

        let mut cursor = vm_space.cursor_mut(&range).unwrap();

        let mut prot_op = |p: &mut PageProperty| p.flags = perms.into();
        let mut token_op = |t: &mut Token| {
            let mut marker = VmMarker::decode(*t);
            marker.perms = perms;
            *t = marker.encode();
        };
        while cursor.virt_addr() < range.end {
            if let Some(va) =
                cursor.protect_next(range.end - cursor.virt_addr(), &mut prot_op, &mut token_op)
            {
                cursor.flusher().issue_tlb_flush(TlbFlushOp::Range(va));
            } else {
                break;
            }
        }
        cursor.flusher().dispatch_tlb_flush();

        Self { perms, ..self }
    }
}

/// A wrapper that represents a mapped [`Vmo`] and provide required functionalities
/// that need to be provided to mappings from the VMO.
#[derive(Debug)]
pub(super) struct MappedVmo {
    vmo: Vmo,
    /// Represents the accessible range in the VMO for mappings.
    range: Range<usize>,
}

impl MappedVmo {
    /// Creates a `MappedVmo` used for mapping.
    pub(super) fn new(vmo: Vmo, range: Range<usize>) -> Self {
        Self { vmo, range }
    }

    pub(super) fn size(&self) -> usize {
        self.range.len()
    }

    /// Gets the committed frame at the input offset in the mapped VMO.
    ///
    /// If the VMO has not committed a frame at this index, it will commit
    /// one first and return it.
    pub(super) fn get_committed_frame(&self, page_offset: usize) -> Result<Frame> {
        debug_assert!(page_offset < self.range.len());
        debug_assert!(page_offset % PAGE_SIZE == 0);
        self.vmo.commit_page(self.range.start + page_offset)
    }

    /// Traverses the indices within a specified range of a VMO sequentially.
    ///
    /// For each index position, you have the option to commit the page as well as
    /// perform other operations.
    pub(super) fn operate_on_range<F>(&self, range: &Range<usize>, operate: F) -> Result<()>
    where
        F: FnMut(&mut dyn FnMut() -> Result<Frame>) -> Result<()>,
    {
        debug_assert!(range.start < self.range.len());
        debug_assert!(range.end <= self.range.len());

        let range = self.range.start + range.start..self.range.start + range.end;

        self.vmo.operate_on_range(&range, operate)
    }

    /// Duplicates the capability.
    pub(super) fn dup(&self) -> Result<Self> {
        Ok(Self {
            vmo: self.vmo.dup()?,
            range: self.range.clone(),
        })
    }
}
