use panda::prelude::*;
use panda::CPUArchPtr;

pub use trace::record::emit_be64 as varfmt;

pub static ARCH: trace::Arch = trace::Arch::Mips64;

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
        //self.inner_mut().clear();
        //self.inner_mut().extend(unsafe {
        //    (*panda::cpu_arch_state!(cpu)).active_tc.gpr
        //}.into_iter().skip(1).take(31).map(|r: u64| r.to_be_bytes()).flatten());
        
        // TODO: Bindings may be pulling in the wrong copy of CPUMIPSStats
        // Observation: the closure inside of the `map` function above does not type check b/c it
        // is expecting a u32 even though `target_ulong` on `mips64` should be `u64`.
        todo!()
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
        &[8usize; 31]
    }
}
