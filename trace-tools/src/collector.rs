use hashbrown::HashMap;
use trace::record::Record;

pub struct TraceCollector {
    pub reg_write_effects: HashMap<u32, Vec<u8>>,
    pub memory_write_effects: HashMap<u64, u8>,
    pub memory_read_effects: HashMap<u64, u8>,
}

impl TraceCollector {
    pub fn new() -> Self {
        Self {
            reg_write_effects: HashMap::new(),
            memory_write_effects: HashMap::new(),
            memory_read_effects: HashMap::new(),
        }
    }
    pub fn update(&mut self, record: Record) {
        if let Record::RegWrite(rec) = record {
            let key = rec.regnum();
            self.reg_write_effects
                .insert(key, Vec::from(rec.contents()));
        } else if let Record::MemWrite(rec) = record {
            let key = rec.address();
            let mut i: u64 = 0 as u64;
            for x in rec.contents() {
                self.memory_write_effects.insert(key + i, *x);
                i += 1;
            }
        } else if let Record::MemRead(rec) = record {
            let key = rec.address();
            let mut i: u64 = 0 as u64;
            for x in rec.contents() {
                if !self.memory_write_effects.contains_key(&(key + i)) {
                    // we only want to write this effect if we haven't already written to the address being read
                    self.memory_read_effects.insert(key + i, *x);
                }
                i += 1;
            }
        }
    }

    pub fn clear(&mut self) {
        self.reg_write_effects.clear();
        self.memory_write_effects.clear();
        self.memory_read_effects.clear();
    }
}
