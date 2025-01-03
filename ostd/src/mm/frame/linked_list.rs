// SPDX-License-Identifier: MPL-2.0

//! Enabling linked lists of frames without heap allocation.
//!
//! This module leverages the customizability of the metadata system (see
//! [super::meta]) to allow any type of frame to be used in a linked list.

use core::{cell::SyncUnsafeCell, ops::Deref, ptr::NonNull};

use super::{
    meta::{AnyFrameMeta, FRAME_METADATA_MAX_ALIGN, FRAME_METADATA_MAX_SIZE},
    Frame, MetaSlot,
};

/// A linked list of frames.
///
/// # Example
///
/// To create metadata types that allows linked list links, wrap the metadata
/// type in [`Link`]:
///
/// ```rust
/// use ostd::{
///     mm::frame::{linked_list::{Link, LinkedList}, Frame},
///     impl_untyped_frame_meta_for,
/// };
///
/// struct MyMeta { mark: usize }
///
/// type MyFrame = Frame<Link<MyMeta>>;
///
/// impl_untyped_frame_meta_for!(MyMeta);
///
/// let frame1 = MyFrame::new(MyMeta { mark: 1 });
/// let frame2 = MyFrame::new(MyMeta { mark: 2 });
/// 
/// let mut list = LinkedList::new();
/// list.cursor_front_mut().insert_before(frame1);
/// list.cursor_front_mut().insert_before(frame2);
///
/// let mut cursor = list.cursor_front_mut();
/// assert_eq!(cursor.current().unwrap().mark, 2);
/// cursor.move_next();
/// assert_eq!(cursor.current().unwrap().mark, 1);
/// ```
pub struct LinkedList<M> {
    head: Option<NonNull<Link<M>>>,
    tail: Option<NonNull<Link<M>>>,
}

impl<M> LinkedList<M> {
    /// Creates a new linked list.
    pub const fn new() -> Self {
        Self {
            head: None,
            tail: None,
        }
    }

    /// Gets a cursor that can mutate the linked list links.
    pub fn cursor_front_mut(&mut self) -> CursorMut<'_, M> {
        CursorMut {
            list: self,
            current: self.head,
        }
    }
}

/// A cursor that can mutate the linked list links.
pub struct CursorMut<'a, M> {
    list: &'a mut LinkedList<M>,
    current: Option<NonNull<Link<M>>>,
}

/// Errors that can occur when inserting a frame into a linked list.
pub enum InsertionError<M> {
    /// The provided frame is already in a linked list.
    AlreadyLinked(Frame<Link<M>>),
}

impl<M> CursorMut<'_, M>
where Link<M>: AnyFrameMeta
{
    /// Moves the cursor to the next frame.
    /// 
    /// If the cursor is pointing to the "ghost" non-element then this will
    /// move it to the first element of the [`LinkedList`]. If it is pointing
    /// to the last element of the LinkedList then this will move it to the
    /// "ghost" non-element.
    pub fn move_next(&mut self) {
        self.current = self.current.and_then(|current| unsafe {
            let current = current.as_ref();
            *current.next.get()
        });
    }

    /// Inserts a frame before the current frame.
    /// 
    /// If the cursor is pointing at the "ghost" non-element then the new
    /// element is inserted at the end of the [`LinkedList`].
    pub fn insert_before(&mut self, mut frame: Frame<Link<M>>) -> core::result::Result<(), InsertionError<M>> {
        unsafe {
            if frame.meta().next().is_some() || frame.meta().next().is_some() {
                return Err(InsertionError::AlreadyLinked(frame));
            }
        }

        let item = frame.meta() as *const Link<M>;
        let item = NonNull::from(item.cast_mut());

        if let Some(current) = &mut self.current {
            unsafe {
                if let Some(prev) = current.as_mut().prev.get_mut() {
                    debug_assert_eq!(*prev.as_ref().next.get_mut(), Some(*current));
                    *prev.as_mut().next.get_mut() = Some(item);
                    frame.meta().prev.get_mut().set(Some(*prev));
                }
            }
        }
    }
}

/// The metadata of linked list frames.
///
/// To allow other metadata to be customized, this type is a wrapper around the
/// actual metadata type `M`.
/// 
/// Linked list frames can be contained in a [`LinkedList`].
pub struct Link<M> {
    next: SyncUnsafeCell<Option<NonNull<Link<M>>>>,
    prev: SyncUnsafeCell<Option<NonNull<Link<M>>>>,
    meta: M,
}

impl<M> Deref for Link<M> {
    type Target = M;

    fn deref(&self) -> &Self::Target {
        &self.meta
    }
}

impl<M> Link<M> {
    /// Creates a new linked list metadata.
    pub const fn new(meta: M) -> Self {
        Self {
            next: Cell::new(None),
            prev: Cell::new(None),
            meta,
        }
    }

    /// # Safety
    /// 
    /// No other mutable references to the link should exist.
    unsafe fn next(&self) -> Option<NonNull<Link<M>>> {
        *self.next.get()
    }

    /// # Safety
    /// 
    /// No other mutable references to the link should exist.
    unsafe fn prev(&self) -> Option<NonNull<Link<M>>> {
        *self.prev.get()
    }
}

/// Helper for const generics expressions that have a boolean value.
#[doc(hidden)]
pub enum Assert<const CHECK: bool> {}
/// Marker trait for const generics expressions that is true.
#[doc(hidden)]
pub trait IsTrue {}
impl IsTrue for Assert<true> {}

// SAFETY: The size and alignment of `Link<M>` must be within the limits.
// Also, if `M` is typed, `Link<M>` must not be untyped.
unsafe impl<M> AnyFrameMeta for Link<M>
where
    M: AnyFrameMeta,
    Assert<{ core::mem::size_of::<Link<M>>() < FRAME_METADATA_MAX_SIZE }>: IsTrue,
    Assert<{ core::mem::align_of::<Link<M>>() <= FRAME_METADATA_MAX_ALIGN }>: IsTrue,
{
    fn on_drop(&mut self, reader: &mut crate::mm::VmReader<crate::mm::Infallible>) {
        self.meta.on_drop(reader);
    }

    fn is_untyped(&self) -> bool {
        self.meta.is_untyped()
    }
}
