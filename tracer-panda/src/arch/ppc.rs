use panda::prelude::*;
use panda::CPUArchPtr;

pub use trace::record::emit_be32 as varfmt;

pub static ARCH: trace::Arch = trace::Arch::PowerPc;

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
            (*panda::cpu_arch_state!(cpu)).gpr
        }.into_iter().map(|r: u32| r.to_be_bytes()).flatten());
        let lr: u32 = unsafe { (*panda::cpu_arch_state!(cpu)).lr };
        self.inner_mut().extend(lr.to_be_bytes());
    }

    fn register_names() -> &'static [&'static str] {
        &[
            "R0",
            "R1",
            "R2",
            "R3",
            "R4",
            "R5",
            "R6",
            "R7",
            "R8",
            "R9",
            "R10",
            "R11",
            "R12",
            "R13",
            "R14",
            "R15",
            "R16",
            "R17",
            "R18",
            "R19",
            "R20",
            "R21",
            "R22",
            "R23",
            "R24",
            "R25",
            "R26",
            "R27",
            "R28",
            "R29",
            "R30",
            "R31",
            "LR",
        ]
    }

    fn register_sizes() -> &'static [usize] {
        &[4usize; 33]
    }
}
