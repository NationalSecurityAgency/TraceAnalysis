use panda::prelude::*;
use panda::CPUArchPtr;

pub use trace::record::emit_le32 as varfmt;

pub static ARCH: trace::Arch = trace::Arch::Mipsel;

pub fn get_instruction(cpu: &mut CPUState, pc: u64, insbytes: &mut Vec<u8>) {
    let mut buffer = [0u8; 4];
    if panda::mem::virtual_memory_read_into(cpu, pc as _, buffer.as_mut_slice()).is_err() {
        eprintln!("[WARN] Failed to read memory at {pc:#x?}");
        return;
    }
    insbytes.extend_from_slice(buffer.as_slice());
}

pub fn current_tid(_cpu: &mut CPUState) -> u32 {
    0
}

impl super::RegsExt for super::Regs {
    fn update(&mut self, cpu: &CPUState) {
        self.inner_mut().clear();
        self.inner_mut().extend(unsafe {
            (*panda::cpu_arch_state!(cpu)).active_tc.gpr
        }.into_iter().skip(1).take(31).map(|r: u32| r.to_le_bytes()).flatten());
    }

    fn register_names() -> &'static [&'static str] {
        &[
            "AT",
            "V0",
            "V1",
            "A0",
            "A1",
            "A2",
            "A3",
            "T0",
            "T1",
            "T2",
            "T3",
            "T4",
            "T5",
            "T6",
            "T7",
            "S0",
            "S1",
            "S2",
            "S3",
            "S4",
            "S5",
            "S6",
            "S7",
            "T8",
            "T9",
            "K0",
            "K1",
            "GP",
            "SP",
            "FP",
            "RA",
        ]
    }

    fn register_sizes() -> &'static [usize] {
        &[4usize; 31]
    }
}
