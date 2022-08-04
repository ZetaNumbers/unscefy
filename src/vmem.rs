use std::{num::NonZeroUsize, ops};

type NonZeroVAddr = std::num::NonZeroU32;
type VAddr = u32;
type VSize = u32;

pub const PAGE_SIZE: VSize = 0x1000;
pub const PAGE_ENTRY_COUNT: usize = 0x100000;

#[non_exhaustive]
#[derive(Clone, Copy, Debug)]
enum Error {
    OutOfMemory,
    PageOccupied(VAddr),
    PageUnoccupied(VAddr),
    IllegalRead,
    IllegalWrite,
}

/// Implements bump allocation strategy for fast page creation
pub struct VMem {
    page_cursor: usize,
    page_table: Box<[Option<PageEntry>; PAGE_ENTRY_COUNT]>,
}

impl VMem {
    pub fn new() -> Self {
        const EMPTY_PAGE: Option<PageEntry> = None;
        let mut page_table = Box::new([EMPTY_PAGE; PAGE_ENTRY_COUNT]);
        page_table[0] = Some(PageEntry::zeroed(Permissions::default()));
        *page_table.last_mut().unwrap() = Some(PageEntry::zeroed(Permissions::default()));
        VMem {
            page_cursor: 1,
            page_table,
        }
    }

    pub fn map_zeroed(
        &mut self,
        base: VAddr,
        size: VSize,
        perm: Permissions,
    ) -> Result<ops::Range<VAddr>, Error> {
        assert_eq!(base % PAGE_SIZE, 0, "start address must be page aligned");
        let base_page = base / PAGE_SIZE;
        let size_in_pages = size.div_ceil(PAGE_SIZE);
        let pages = &mut self.page_table[base_page as usize..][..size_in_pages as usize];
        for (i, page) in pages.iter().enumerate() {
            if page.is_some() {
                return Err(Error::PageOccupied(i as VAddr * PAGE_SIZE));
            }
        }
        pages.fill_with(|| Some(PageEntry::zeroed(perm)));
        if self.page_cursor == base_page {
            self.page_cursor = base_page + size_in_pages;
        }
        Ok(base..base + size_in_pages * PAGE_SIZE)
    }

    pub fn map_load(
        &mut self,
        base: VAddr,
        size: VSize,
        bytes: &[u8],
        perm: Permissions,
    ) -> Result<(), Error> {
        assert!(bytes.len() < size as usize);
        self.load(
            self.map_zeroed(base, size.len().try_into().unwrap(), perm)?,
            bytes,
        )
    }

    pub fn alloc_zeroed(
        &mut self,
        size: VSize,
        perm: Permissions,
    ) -> Result<ops::Range<VAddr>, Error> {
        assert_eq!(base % PAGE_SIZE, 0, "start address must be page aligned");
        let base_page = base / PAGE_SIZE;
        let size_in_pages = size.div_ceil(PAGE_SIZE);
        let pages = &mut self.page_table[base_page as usize..][..size_in_pages as usize];
        for (i, page) in pages.iter().enumerate() {
            if page.is_some() {
                return Err(Error::PageOccupied(i as VAddr * PAGE_SIZE));
            }
        }
        pages.fill_with(|| Some(PageEntry::zeroed(perm)));
        if self.page_cursor == base_page {
            self.page_cursor = base_page + size_in_pages;
        }
        Ok(base..base + size_in_pages * PAGE_SIZE)
    }

    pub fn alloc_load(
        &mut self,
        size: VSize,
        bytes: &[u8],
        perm: Permissions,
    ) -> Result<(), Error> {
        assert!(bytes.len() < size as usize);
        self.load(
            self.alloc_zeroed(size.len().try_into().unwrap(), perm)?,
            bytes,
        )
    }

    fn load(&mut self, mut dst: ops::Range<VAddr>, mut src: &[u8]) -> Result<(), Error> {
        assert!(src.len() < dst.len());
        while !src.is_empty() {
            let (page_dst, _) = self.page_from_mut(&mut dst.start)?;
            if page_dst.len() <= src.len() {
                let page_src;
                (page_src, src) = src.split_at(page_dst.len());
                page_dst.copy_from_slice(page_src);
            } else {
                page_dst[..src.len()].copy_from_slice(src);
                src = &[];
            }
        }
        Ok(())
    }

    fn page_from_mut(&mut self, base: &mut VAddr) -> Result<(&mut [u8], Permissions), Error> {
        let page = self.page_table[(*base / PAGE_SIZE) as usize]
            .as_mut()
            .ok_or_else(|| Error::PageUnoccupied(base & !(PAGE_SIZE - 1)))?;

        let bytes = &mut page.mem[(base % PAGE_SIZE) as usize..];
        *base += bytes.len() as VSize;
        Ok((bytes, page.perm))
    }

    pub fn _map_load(
        &mut self,
        base: NonZeroVAddr,
        bytes: &[u8],
        perm: Permissions,
    ) -> Result<(), Error> {
        if bytes.len() == 0 {
            return Ok(());
        }

        let size_aligned = bytes
            .len()
            .checked_next_multiple_of(PAGE_SIZE)
            .ok_or(Error::OutOfMemory)?;
        let size_in_pages = size_aligned / PAGE_SIZE;

        let base_page = match base {
            Some(base) => {
                let base = base.get() as usize;
                assert_eq!(
                    base % PAGE_SIZE,
                    0,
                    "load base address should be page aligned"
                );

                let base_page = base / PAGE_SIZE;
                if base_page == self.page_cursor {
                    return self.load(None, bytes, perm);
                }
                base_page
            }
            None => self.page_cursor,
        };

        if (base_page + 1..base_page + size_in_pages).contains(&self.page_cursor) {
            return Err(Error::PageOccupied(self.page_cursor as u32 - 1));
        }

        for (i, entry) in self.page_table[pages].iter().enumerate() {
            if let Some(_) = entry {
                return Err(Error::PageOccupied((i * PAGE_SIZE).try_into().unwrap()));
            }
        }
        todo!()
    }
}

pub struct PageEntry {
    mem: Box<[u8; PAGE_SIZE]>,
    perm: Permissions,
}

impl PageEntry {
    pub const fn zeroed(perm: Permissions) -> Self {
        PageEntry {
            mem: Box::new([0; PAGE_SIZE]),
            perm,
        }
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub struct Permissions {
    pub read: bool,
    pub write: bool,
    pub exec: bool,
}

// pub struct VMemMutSlice<'a> {
//     raw: VMemRawSlice,
//     vmem: &'a mut VMem,
// }

// struct VMemRawSlice {
//     base: VAddr,
//     size: VSize,
// }
