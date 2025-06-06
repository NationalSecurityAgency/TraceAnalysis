use std::collections::HashMap;

use dataflow::address::AddressRange;

use crate::ProgramState;

const HAS_VALUE: u64 = i64::MIN as u64;
const HAS_SOURCE: u64 = i64::MIN as u64 >> 1;
const SOURCE_MASK: u64 = (u64::MAX >> 2) ^ 0xff;

const PAGE_SIZE: usize = 4096;
const PAGE_MASK: u64 = u64::MAX ^ (PAGE_SIZE as u64 - 1);

#[derive(Debug, Clone, Default)]
pub struct HashMap4kPage(HashMap<u64, Box<[u64; PAGE_SIZE]>>, u64);

impl HashMap4kPage {
    pub fn snapshot(&self) -> Vec<(u16, u64, u8, u64)> {
        self.0
            .iter()
            .map(|(key, value)| {
                let space = *key as u16 & 0xfff;
                let base = PAGE_MASK as u64 & *key;
                value
                    .iter()
                    .copied()
                    .enumerate()
                    .filter_map(move |(offset, data)| {
                        if data & (HAS_VALUE | HAS_SOURCE) == 0 {
                            return None;
                        }
                        let address = offset as u64 + base;
                        let value = data as u8;
                        let source = (data & SOURCE_MASK) >> 8;
                        Some((space, address, value, source))
                    })
            })
            .flatten()
            .collect()
    }

    #[inline]
    fn inner(&self) -> &HashMap<u64, Box<[u64; PAGE_SIZE]>> {
        &self.0
    }

    #[inline]
    fn inner_mut(&mut self) -> &mut HashMap<u64, Box<[u64; PAGE_SIZE]>> {
        &mut self.0
    }

    // This is a hack to avoid hitting the recursion limit in the trait solver b/c Rust is unable
    // to determine that we can only recursively call ourself with a depth of one (if our address
    // range wraps), we split the range in two and call ourselves twice.
    #[inline]
    fn add_value_internal<V>(&mut self, address: &AddressRange, iter: &mut V)
    where
        V: Iterator<Item = Option<u8>>,
    {
        let Some(first) = address.first().map(|a| a.offset()) else {
            return;
        };

        let Some(last) = address.last().map(|a| a.offset()) else {
            return;
        };

        let index = (self.1 << 8) | HAS_SOURCE;
        self.1 += 1;

        let space = address.space();
        let space_id = space.id() as u64 & 0xfff;

        if last < first {
            // The previous call to add_value increments the index, but both parts of this range
            // should be associated with the same index so we revert that change
            self.1 -= 1;
            self.add_value_internal(&space.index(first..=space.mask()), iter);
            self.1 -= 1;
            self.add_value_internal(&space.index(0..=last), iter);
            return;
        }

        let inner = self.inner_mut();

        let first_page = first & PAGE_MASK;
        let last_page = last & PAGE_MASK;

        if first_page == last_page {
            let start = (first - first_page) as usize;
            let size = address.size() as usize;
            let page = inner
                .entry(first_page | space_id)
                .or_insert_with(|| Box::new([0u64; PAGE_SIZE]));
            let data = unsafe { page.get_unchecked_mut(start..start + size) };
            data.iter_mut().zip(iter).for_each(|(dst, src)| {
                *dst = match src {
                    Some(value) => HAS_VALUE | index | (value as u64),
                    None => index,
                };
            });
            return;
        }

        {
            let start = (first - first_page) as usize;
            let page = inner
                .entry(first_page | space_id)
                .or_insert_with(|| Box::new([0u64; PAGE_SIZE]));
            let data = unsafe { page.get_unchecked_mut(start..) };
            data.iter_mut().zip(&mut *iter).for_each(|(dst, src)| {
                *dst = match src {
                    Some(value) => HAS_VALUE | index | (value as u64),
                    None => index,
                };
            });
        }

        for base in (first_page + PAGE_SIZE as u64..last_page).step_by(PAGE_SIZE) {
            let page = inner
                .entry(base | space_id)
                .or_insert_with(|| Box::new([0u64; PAGE_SIZE]));
            page.iter_mut().zip(&mut *iter).for_each(|(dst, src)| {
                *dst = match src {
                    Some(value) => HAS_VALUE | index | (value as u64),
                    None => index,
                };
            });
        }

        {
            let end = (last - last_page) as usize;
            let page = inner
                .entry(last_page | space_id)
                .or_insert_with(|| Box::new([0u64; PAGE_SIZE]));
            let data = unsafe { page.get_unchecked_mut(..end) };
            data.iter_mut().zip(&mut *iter).for_each(|(dst, src)| {
                *dst = match src {
                    Some(value) => HAS_VALUE | index | (value as u64),
                    None => index,
                };
            });
        }
    }
}

impl ProgramState for HashMap4kPage {
    fn resolve<V>(&self, address: &AddressRange, value: &mut V)
    where
        V: Extend<(Option<u8>, Option<u64>)>,
    {
        let Some(first) = address.first().map(|a| a.offset()) else {
            return;
        };

        let Some(last) = address.last().map(|a| a.offset()) else {
            return;
        };

        let space = address.space();

        if last < first {
            self.resolve(&space.index(first..=space.mask()), value);
            self.resolve(&space.index(0..=last), value);
            return;
        }

        let space_id = space.id() as u64 & 0xfff;

        let inner = self.inner();

        let first_page = first & PAGE_MASK;
        let last_page = last & PAGE_MASK;

        // This is both an optimization of the most likely path (copies within a single page), and
        // an optimization for more complicated paths below (copies that span multiple pages). By
        // handling the single page case here, we can elide several bounds checks below that would
        // have to make sure that we don't duplicate copies.
        if first_page == last_page {
            let start = (first - first_page) as usize;
            let size = address.size() as usize;
            let Some(page) = inner.get(&(first_page | space_id)) else {
                value.extend(std::iter::repeat((None, None)).take(size));
                return;
            };
            // SAFETY: The bitmasks ensure that start is clamped between 0..=0xfff, and we know
            // that we do not cross a page boundary so the addition of size will not exceed 0xfff.
            let data = unsafe { page.get_unchecked(start..start + size) };
            value.extend(data.iter().copied().map(|entry| {
                let value = (entry & HAS_VALUE != 0).then_some(entry as u8);
                let source = (entry & HAS_SOURCE != 0).then_some((entry & SOURCE_MASK) >> 8);
                (value, source)
            }));
            return;
        }

        // Given the above check, we are guarenteed to cross a page boundary, so we handle the
        // first page uniquely since it has the potential to be a partial page
        {
            let start = (first - first_page) as usize;
            if let Some(page) = inner.get(&(first_page | space_id)) {
                // SAFETY: The bitmasking calculations clamp start to be in the range 0..=0xfff
                // which guarantees that start will be within the page
                let data = unsafe { page.get_unchecked(start..) };
                value.extend(data.iter().copied().map(|entry| {
                    let value = (entry & HAS_VALUE != 0).then_some(entry as u8);
                    let source = (entry & HAS_SOURCE != 0).then_some((entry & SOURCE_MASK) >> 8);
                    (value, source)
                }));
            } else {
                value.extend(std::iter::repeat((None, None)).take(PAGE_SIZE - start));
            }
        }

        // This loop almost certainly never runs b/c memory accesses rarely span three+ pages.
        // But in the case it does run, we all of the middle pages can handled without any bounds
        // checkeding.
        for base in (first_page + PAGE_SIZE as u64..last_page).step_by(PAGE_SIZE) {
            if let Some(page) = inner.get(&(base | space_id)) {
                value.extend(page.iter().copied().map(|entry| {
                    let value = (entry & HAS_VALUE != 0).then_some(entry as u8);
                    let source = (entry & HAS_SOURCE != 0).then_some((entry & SOURCE_MASK) >> 8);
                    (value, source)
                }));
            } else {
                value.extend(std::iter::repeat((None, None)).take(PAGE_SIZE));
            }
        }

        // Given that we were guaranteed to cross a page boundary at least once, we can safely copy
        // from the beginning of the page w/o accidently copying twice. So this last copy handles
        // the last, potentially partial page.
        {
            let end = (last - last_page) as usize;
            if let Some(page) = inner.get(&(last_page | space_id)) {
                // SAFETY: The bitmasking calculations clamp end to be in the range 0..=0xfff
                // which guarantees that end will be within the page
                let data = unsafe { page.get_unchecked(..=end) };
                value.extend(data.iter().copied().map(|entry| {
                    let value = (entry & HAS_VALUE != 0).then_some(entry as u8);
                    let source = (entry & HAS_SOURCE != 0).then_some((entry & SOURCE_MASK) >> 8);
                    (value, source)
                }));
            } else {
                value.extend(std::iter::repeat((None, None)).take(end));
            }
        }
    }

    fn add_value<V>(&mut self, address: &AddressRange, value: V)
    where
        V: IntoIterator<Item = Option<u8>>,
    {
        let mut iter = value.into_iter();
        self.add_value_internal(address, &mut iter);
    }
}
