// This module is HEAVILY inspired by the `string-interner` crate. I basically copied their generic
// interface and specialized it to a single backend, hasher, and symbol. Instead of making the
// storage "strategy" (backend) generic, I made the type being stored by the `StringBackend`
// generic to allow for slices of arbitrary types to be interned and used that backend for
// everything.
//
// TODO: Investigate `lasso` implementation for thread-safe interning if needed.
use hashbrown::hash_map::{DefaultHashBuilder, HashMap, RawEntryMut};
use std::hash::{BuildHasher, Hash, Hasher};
use std::marker::PhantomData;
use std::num::NonZeroUsize;

#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Index(NonZeroUsize);

impl Index {
    #[inline]
    pub fn try_from_usize(index: usize) -> Option<Self> {
        NonZeroUsize::new(index.wrapping_add(1)).map(Self)
    }

    #[inline]
    pub fn to_usize(self) -> usize {
        self.0.get() - 1
    }
}

pub struct SeqCache<T> {
    dedup: HashMap<Index, (), ()>,
    hasher: DefaultHashBuilder,
    ends: Vec<usize>,
    buffer: Vec<T>,
    marker: PhantomData<fn() -> Index>,
}

impl<T> SeqCache<T> {
    pub fn new() -> Self {
        Self {
            dedup: HashMap::default(),
            hasher: Default::default(),
            ends: Vec::new(),
            buffer: Vec::new(),
            marker: Default::default(),
        }
    }

    #[inline]
    #[allow(dead_code)]
    pub fn len(&self) -> usize {
        self.dedup.len()
    }

    #[inline]
    #[allow(dead_code)]
    pub fn size(&self) -> usize {
        self.buffer.len() * std::mem::size_of::<T>()
    }

    #[inline]
    #[allow(dead_code)]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn iter(&self) -> SeqCacheIter<T> {
        SeqCacheIter {
            cursor: 0,
            start: 0,
            cache: self,
        }
    }
}

pub struct SeqCacheIter<'cache, T> {
    cursor: usize,
    start: usize,
    cache: &'cache SeqCache<T>,
}

impl<'cache, T> Iterator for SeqCacheIter<'cache, T> {
    type Item = &'cache [T];

    fn next(&mut self) -> Option<Self::Item> {
        let end = *(self.cache.ends.get(self.cursor)?);
        self.cursor += 1;
        let seq = self.cache.buffer.get(self.start..end)?;
        self.start = end;
        Some(seq)
    }
}

impl<T> SeqCache<T>
where
    T: Clone + PartialEq + Eq + Hash,
{
    #[inline]
    pub fn get<S>(&self, seq: S) -> Option<Index>
    where
        S: AsRef<[T]>,
    {
        let seq = seq.as_ref();
        let Self {
            dedup,
            hasher,
            ends,
            buffer,
            marker: _,
        } = self;
        let hash = make_hash(hasher, seq);
        dedup
            .raw_entry()
            .from_hash(hash, |index| {
                // SAFETY: This is safe because we only operate on indices that
                //         we receive from our backend making them valid.
                let (from, to) = unsafe { index_to_span_unchecked(ends, index.to_usize()) };
                seq == &buffer[from..to]
            })
            .map(|(&index, &())| index)
    }

    #[inline]
    pub fn get_or_intern<S>(&mut self, seq: S) -> Index
    where
        S: AsRef<[T]>,
    {
        let seq = seq.as_ref();
        let Self {
            dedup,
            hasher,
            ends,
            buffer,
            marker: _,
        } = self;
        let hash = make_hash(hasher, seq);
        let entry = dedup.raw_entry_mut().from_hash(hash, |index| {
            // SAFETY: This is safe because we only operate on indices that
            //         we receive from our backend making them valid.
            let (from, to) = unsafe { index_to_span_unchecked(ends, index.to_usize()) };
            seq == &buffer[from..to]
        });

        let (&mut index, &mut ()) = match entry {
            RawEntryMut::Occupied(occupied) => occupied.into_key_value(),
            RawEntryMut::Vacant(vacant) => {
                buffer.extend_from_slice(seq);
                let to = buffer.len();
                let index = Index::try_from_usize(ends.len()).expect("out of indices");
                ends.push(to);

                vacant.insert_with_hasher(hash, index, (), |index| {
                    // SAFETY: This is safe because we only operate on indices that
                    //         we receive from our backend making them valid.
                    let (from, to) = unsafe { index_to_span_unchecked(ends, index.to_usize()) };
                    let seq = &buffer[from..to];
                    make_hash(hasher, seq)
                })
            }
        };

        index
    }

    #[inline]
    pub fn resolve(&self, index: Index) -> Option<&[T]> {
        let index = index.to_usize();
        let (from, to) = self.ends.get(index).copied().map(|to| {
            let from = self.ends.get(index.wrapping_sub(1)).copied().unwrap_or(0);
            (from, to)
        })?;
        Some(&self.buffer[from..to])
    }
}

#[inline]
// SAFETY: Caller must guarantee that index is within bounds of ends
unsafe fn index_to_span_unchecked(ends: &Vec<usize>, index: usize) -> (usize, usize) {
    let to = *ends.get_unchecked(index);
    let from = ends.get(index.wrapping_sub(1)).copied().unwrap_or(0);
    (from, to)
}

fn make_hash<T>(builder: &impl BuildHasher, value: &T) -> u64
where
    T: ?Sized + Hash,
{
    let state = &mut builder.build_hasher();
    value.hash(state);
    state.finish()
}
