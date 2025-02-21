
use std::collections::BTreeMap;
use std::rc::Rc;

pub struct SegmentTreeEntry<T> {
    pub sort_key: u64,
    pub data: Rc<T>,
}
impl<T> Clone for SegmentTreeEntry<T> {
    fn clone(&self) -> Self {
        SegmentTreeEntry {
            sort_key: self.sort_key,
            data: self.data.clone(),
        }
    }
}
impl<T> PartialEq for SegmentTreeEntry<T> {
    fn eq(&self, other: &Self) -> bool {
        return self.sort_key == other.sort_key;
    }
}
impl<T> Eq for SegmentTreeEntry<T> {}
impl<T> PartialOrd for SegmentTreeEntry<T> {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        self.sort_key.partial_cmp(&other.sort_key)
    }
}
impl<T> Ord for SegmentTreeEntry<T> {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.sort_key.cmp(&other.sort_key)
    }
}

pub struct WSegmentTree<T> {
    pub min: u64,
    pub max: u64,
    pub mid: u64,

    pub left: Option<Box<WSegmentTree<T>>>,
    pub right: Option<Box<WSegmentTree<T>>>,
    
    pub elements: Vec<SegmentTreeEntry<T>>,
}
pub struct RSegmentTree<T> {
    pub min: u64,
    pub max: u64,
    pub mid: u64,

    pub left: Option<Box<RSegmentTree<T>>>,
    pub right: Option<Box<RSegmentTree<T>>>,
    
    pub elements: Vec<SegmentTreeEntry<T>>,
}

impl<T> WSegmentTree<T> {
    pub fn new(min: u64, max: u64) -> Self {
        Self {
            min: min,
            max: max,
            mid: (min + max) / 2,
            left: None,
            right: None,
            elements: Vec::new(),
        }
    }
    pub fn add_location(&mut self, entry: SegmentTreeEntry<T>, start: u64, end: u64) {
        if start <= self.min && end >= self.max {
            self.elements.push(entry);
        } else {
            if start < self.mid {
                if let Some(child) = &mut self.left {
                    child.add_location(entry.clone(), start, end);
                } else {
                    let mut child = Self::new(self.min, self.mid);
                    child.add_location(entry.clone(), start, end);
                    self.left = Some(Box::new(child));
                }
            }

            if end > self.mid {
                if let Some(child) = &mut self.right {
                    child.add_location(entry, start, end);
                } else {
                    let mut child = Self::new(self.mid, self.max);
                    child.add_location(entry, start, end);
                    self.right = Some(Box::new(child));
                }
            }
        }
    }
    pub fn finalize(self) -> RSegmentTree<T> {
        RSegmentTree::new(self)
    }
}
impl<T> RSegmentTree<T> {
    pub fn new_empty() -> Self {
        Self {
            min: 0,
            max: 0,
            mid: 0,
            left: None,
            right: None,
            elements: Vec::new()
        }
    }
    pub fn new(mut branch: WSegmentTree<T>) -> Self {
        branch.elements.sort_unstable_by_key(|e| e.sort_key);

        Self {
            min: branch.min,
            max: branch.max,
            mid: branch.mid,
            left: branch.left.map_or(None, |l| Some(Box::new(l.finalize()))),
            right: branch.right.map_or(None, |r| Some(Box::new(r.finalize()))),
            elements: branch.elements,
        }
    }
    pub fn extend_from_self(&self, start: u64, end: u64, results: &mut Vec<Rc<T>>) {
        let start = self.elements.binary_search_by_key(&start, |elem| elem.sort_key);
        let end = self.elements.binary_search_by_key(&end, |elem| elem.sort_key);

        let start = match start { Ok(idx) | Err(idx) => idx };
        let end = match end { Ok(idx) | Err(idx) => idx };

        for i in &self.elements[start .. end] {
            results.push(i.data.clone())
        }
    }
    pub fn search(&self, time: u64, start: u64, end: u64, results: &mut Vec<Rc<T>>) {
        self.extend_from_self(start, end, results);

        if self.min + 1 != self.max {
            if time < self.mid {
                if let Some(left) = &self.left {
                    left.search(time, start, end, results);
                }
            }
            if time >= self.mid {
                if let Some(right) = &self.right {
                    right.search(time, start, end, results);
                }
            }
        }
    }
    pub fn retrieve_entries(&self, table: &mut BTreeMap<*const T, Rc<T>>) {
        for entry in &self.elements {
            let addr : *const T = entry.data.as_ref();
            if !table.contains_key(&addr) {
                table.insert(addr, entry.data.clone());
            }
        }
        if let Some(t) = self.left.as_ref() { t.retrieve_entries(table); }
        if let Some(t) = self.right.as_ref() { t.retrieve_entries(table); }
    }
}
