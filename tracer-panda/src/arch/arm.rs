use panda::prelude::*;
use panda::CPUArchPtr;

pub use trace::record::emit_le32 as varfmt;

pub static ARCH: trace::Arch = trace::Arch::Arm;

pub fn get_instruction(cpu: &mut CPUState, pc: u64, insbytes: &mut Vec<u8>) {
    let length: usize = if unsafe { (*panda::cpu_arch_state!(cpu)).thumb } != 0 {
        2
    } else {
        4
    };
    let mut buffer = [0u8; 4];
    let buffer = &mut buffer[..length];
    if panda::mem::virtual_memory_read_into(cpu, pc as _, buffer).is_err() {
        eprintln!("[WARN] Failed to read memory at {pc:#x?}");
        return;
    }
    insbytes.extend_from_slice(buffer);
}

pub fn current_tid(_cpu: &mut CPUState) -> u32 {
    0
}

impl super::RegsExt for super::Regs {
    fn update(&mut self, cpu: &CPUState) {
        self.inner_mut().clear();
        self.inner_mut().extend(
            unsafe { (*panda::cpu_arch_state!(cpu)).regs }
                .into_iter()
                .take(15)
                .map(|r: u32| r.to_le_bytes())
                .flatten(),
        );
    }

    fn register_names() -> &'static [&'static str] {
        &[
            "R0", "R1", "R2", "R3", "R4", "R5", "R6", "R7", "R8", "R9", "R10", "R11", "R12", "LR",
            "SP",
        ]
    }

    fn register_sizes() -> &'static [usize] {
        &[4usize; 15]
    }
}
