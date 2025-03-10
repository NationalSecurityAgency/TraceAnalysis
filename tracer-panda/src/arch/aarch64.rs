use panda::prelude::*;
use panda::CPUArchPtr;

pub use trace::record::emit_le64 as varfmt;

pub static ARCH: trace::Arch = trace::Arch::Arm64;

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
        self.inner_mut().extend(
            unsafe { (*panda::cpu_arch_state!(cpu)).xregs }
                .into_iter()
                .take(15)
                .map(|r: u64| r.to_le_bytes())
                .flatten(),
        );
    }

    fn register_names() -> &'static [&'static str] {
        &[
            "X0", "X1", "X2", "X3", "X4", "X5", "X6", "X7", "X8", "X9", "X10", "X11", "X12", "LR",
            "SP",
        ]
    }

    fn register_sizes() -> &'static [usize] {
        &[8usize; 15]
    }
}
