use super::DynamicTarget;
use dataflow::{
    architecture::{Architecture, X86_64},
    lifter::GhidraLifter,
};
use gdbstub::arch::Arch;
use std::rc::Rc;
use trace::index::{spacetime_index::SpacetimeRTree, SpacetimeBlock};
use tracing::{debug, trace};

// TODO: This should probably get moved to the trace::index module
pub fn get_data_from_index_results(blocks: Vec<Rc<SpacetimeBlock>>) -> Option<Vec<u8>> {
    if blocks.is_empty() {
        None
    } else if blocks.len() == 1 {
        // TODO: Performance: Can we do better than just cloning the data vec
        // from behind the Rc<> ?
        Some(blocks[0].clone().data[..].to_vec())
    } else {
        //blocks.len() > 1

        // TODO: find a way to consolidate the blocks returned from the find() call
        // into a concrete value (u64).
        for block in blocks {
            trace!(
                "Block: {:?} {:?} - {:?}",
                block.address,
                block.len,
                block.data
            );
        }

        todo!()
    }
}

#[derive(Debug)]
pub struct TraceRegsX64 {
    /// RAX, RBX, RCX, RDX, RSI, RDI, RBP, RSP, R8-R15
    pub regs: [(u64, u64); 16],
    /// Status register
    pub eflags: (u64, u64),
    /// Instruction pointer
    pub rip: (u64, u64),
    /// Segment registers: CS, SS, DS, ES, FS, GS
    // pub segments: TODO,
    /// FPU registers: ST0 through ST7
    pub st: [(u64, u64); 8],
    /// FPU internal registers
    pub fpu: (),
    /// SIMD Registers: XMM0 through XMM15
    pub xmm: [(u64, u64); 16],
    /// SSE Status/Control Register
    pub mxcsr: (u64, u64),
}

impl DynamicTarget for TraceRegsX64 {
    type Arch = gdbstub_arch::x86::X86_64_SSE;

    fn new() -> Self {
        let ghidra_lifter = GhidraLifter::new(Architecture::X86_64(X86_64))
            .expect("Couldn't create ghidra lifter for x86_64 architecture!");
        let r = |regname| {
            let address_range = ghidra_lifter.register_by_name(regname).unwrap();
            (
                address_range.offset(),
                address_range.offset() + address_range.size(),
            )
        };

        #[rustfmt::skip]
        let obj = Self {
            regs: [
                r("RAX"), r("RBX"), r("RCX"), r("RDX"), r("RSI"), r("RDI"),
                r("RBP"), r("RSP"), r("R8"),  r("R9"),  r("R10"), r("R11"),
                r("R12"), r("R13"), r("R14"), r("R15"),
            ],
            eflags: r("eflags"),
            rip: r("RIP"),
            st: [r("ST0"), r("ST1"), r("ST2"), r("ST3"), r("ST4"), r("ST5"), r("ST6"), r("ST7")],
            fpu: (),
            xmm: [
                r("XMM0"),  r("XMM1"),  r("XMM2"),  r("XMM3"),  r("XMM4"),
                r("XMM5"),  r("XMM6"),  r("XMM7"),  r("XMM8"),  r("XMM9"),
                r("XMM10"), r("XMM11"), r("XMM12"), r("XMM13"), r("XMM14"),
                r("XMM15"),
            ],
            mxcsr: r("MXCSR"),
        };

        trace!("{obj:?}");
        obj
    }

    fn read_registers(
        &self,
        reg_space: &mut SpacetimeRTree,
        tick: u64,
        pc: u64,
        regs: &mut <Self::Arch as Arch>::Registers,
    ) {
        debug!("Reading registers at tick: {tick}");

        for (i, (start, end)) in self.regs.iter().enumerate() {
            let blocks = reg_space.find(tick, *start, *end);
            match get_data_from_index_results(blocks) {
                Some(data) => {
                    regs.regs[i] = u64::from_le_bytes(
                        data.try_into()
                            .expect("Reg {i}: Data slice from index had incorrect length!"),
                    )
                }
                None => regs.regs[i] = 0, // TODO: should this remain unchanged? or be all zeroes?
            };
        }

        regs.eflags =
            match get_data_from_index_results(reg_space.find(tick, self.eflags.0, self.eflags.1)) {
                Some(data) => u32::from_le_bytes(
                    data.try_into()
                        .expect("Reg eflags: Data slice from index had incorrect length!"),
                ),
                None => 0,
            };

        regs.rip = pc;

        // TODO: Support for segment register?
        // regs.segments.<cs,ss,ds,es,fs,gs>

        // TODO: We don't currently support tracing float registers
        // for (i, (start, end)) in self.st.iter().enumerate() {
        //     match get_data_from_index_results(reg_space.find(tick, start, end)) {
        //         Some(data) => regs[i] = data,
        //         None => regs[i].fill(0)
        //     }
        // }

        // TODO: Tracing support for more registers
        // regs.fpu = gdbstub_arch::x86::reg::X87FpuInternalRegs::default();
        // regs.xmm.iter_mut().for_each(|xmm_reg| *xmm_reg = 0);
        // regs.mxcsr = 0;
    }

    fn write_registers(
        &self,
        _reg_space: &mut SpacetimeRTree,
        _tick: u64,
        _regs: &<Self::Arch as Arch>::Registers,
    ) {
        // For now, I think this function will just do nothing because we're
        // working with a trace. This is just supposed to be a way to inspect
        // what happened through the familiar lens of 'gdb'. We do not provide
        // a way to say: "what happens if I change this register from X to Y?"
        // That would require some kind of emulation.
    }
}
