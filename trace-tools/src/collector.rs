use hashbrown::HashMap;
use trace::record::Record;

pub struct TraceCollector {
    pub reg_write_effects: HashMap<u32, Vec<u8>>,
    pub memory_write_effects: HashMap<u64, u8>,
    pub memory_read_effects: HashMap<u64, u8>,
    pub metadata: Vec<u8>,
    pub arch: trace::record::Arch,
}

impl TraceCollector {
    pub fn new(arch: trace::record::Arch) -> Self {
        Self {
            reg_write_effects: HashMap::new(),
            memory_write_effects: HashMap::new(),
            memory_read_effects: HashMap::new(),
            metadata: Vec::new(),
            arch,
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
        } else if let Record::FileMeta(_) = record {
            let _ = self.arch.emit_record(record, &mut self.metadata);
        } else if let Record::Meta(_) = record {
            let _ = self.arch.emit_record(record, &mut self.metadata);
        }
    }

    pub fn clear(&mut self) {
        self.reg_write_effects.clear();
        self.memory_write_effects.clear();
        self.memory_read_effects.clear();
    }
}
