use dataflow::prelude::GhidraLifter;
use panda::prelude::*;
use panda::CPUArchPtr;

use std::cell::{OnceCell, RefCell};
use std::sync::{OnceLock, Mutex};
use std::collections::HashMap;

pub use trace::record::emit_le32 as varfmt;

pub static ARCH: trace::Arch = trace::Arch::X86;

pub fn get_instruction(cpu: &mut CPUState, pc: u64, insbytes: &mut Vec<u8>) {
    let mut buffer = [0u8; 15];
    if panda::mem::virtual_memory_read_into(cpu, pc as _, buffer.as_mut_slice()).is_err() {
        let next_page: u64 = (-4096i64 as u64) & pc + 0x1000;
        let count: usize = (next_page - pc) as usize;
        if panda::mem::virtual_memory_read_into(cpu, pc as _, &mut buffer[..count]).is_err() {
            eprintln!("[WARN] Failed to read instruction at {pc:#x?}");
            return;
        }
    }

    let length = DECODER.with(|decoder| {
        let decoder = decoder.get_or_init(|| {
            let lifter = match GhidraLifter::new(dataflow::prelude::X86) {
                Ok(l) => l,
                Err(e) => {
                    eprintln!("[ERROR] Could not create lifter for x86: {e:}");
                    std::process::exit(1)
                }
            };

            RefCell::new(Decoder {
                cache: HashMap::new(),
                lifter,
            })
        });


        decoder.borrow_mut().instruction_length(pc, buffer)
    });
    insbytes.extend_from_slice(&mut buffer[..length]);
}

pub fn current_tid(cpu: &mut CPUState) -> u32 {
    let gs = unsafe { (*panda::cpu_arch_state!(cpu)).segs[panda::sys::R_GS as usize].base };
    let fs = unsafe { (*panda::cpu_arch_state!(cpu)).segs[panda::sys::R_FS as usize].base };
    let Ok(mut threads) = THREADS.get_or_init(|| Mutex::new(vec![(gs, fs)])).lock() else {
        eprintln!("[ERROR] thread lock is poisoned");
        std::process::exit(1)
    };
    if let Some(tid) = threads.iter().position(|&entry| entry == (gs, fs)) {
        return tid as _;
    }
    let tid = threads.len();
    threads.push((gs, fs));
    tid as _
}

impl super::RegsExt for super::Regs {
    fn update(&mut self, cpu: &CPUState) {
        self.inner_mut().clear();
        self.inner_mut().extend(unsafe {
            (*panda::cpu_arch_state!(cpu)).regs
        }.into_iter().map(|r: u32| r.to_le_bytes()).flatten());
    }
    
    fn register_names() -> &'static [&'static str] {
        &[
            "EAX",
            "ECX",
            "EDX",
            "EBX",
            "ESP",
            "EBP",
            "ESI",
            "EDI", 
        ]
    }

    fn register_sizes() -> &'static [usize] {
        &[4usize; 8]
    }
}

struct Decoder {
    cache: HashMap<(u64, [u8; 15]), usize>,
    lifter: GhidraLifter,
}

impl Decoder {
    pub fn instruction_length(&mut self, pc: u64, insbytes: [u8; 15]) -> usize {
        *self.cache.entry((pc, insbytes)).or_insert_with(|| {
            let Ok(length) = self.lifter.instruction_length(pc, &insbytes[..]) else {
                eprintln!("[ERROR] Failed to lift instruction");
                std::process::exit(1)
            };
            if length == 0 {
                eprintln!("[WARN] Lifter reported zero-byte instruction: {pc:#x?} {insbytes:x?}");
            }
            length
        })
    }
}

static THREADS: OnceLock<Mutex<Vec<(u32, u32)>>> = OnceLock::new();

thread_local! {
    static DECODER: OnceCell<RefCell<Decoder>> = OnceCell::new(); 
}
