#![allow(unused_variables)]
use dataflow_core::address::{Address, AddressRange};
use dataflow_core::architecture::Architecture;
use dataflow_core::datastore::Datastore;
use dataflow_core::delta::Delta;
use dataflow_core::operation::OperationKind;
use dataflow_core::plugins::DataflowPlugin;
use dataflow_core::space::{Space, SpaceKind, SpaceManager};
use dataflow_core::{Index, Tick};

use hashbrown::HashMap;
use hashbrown::HashSet;

use std::sync::mpsc::{self, Sender};
use std::thread::{self, JoinHandle};

mod writers;

use writers::Message;

// To properly track functions and syscalls, one needs to specify
// calling convention, among other things. Concretely, we require the
// information:
// - Which register is the stack pointer
// - How much stack to pull off for the context
// - Which register contains the function return value
// - Which register contains the syscall return value
// - Which register contains the syscall number
// - The minimum contiguous write size to constitute a "buffer"

pub struct SyscallRun {
    tick: Tick,
    number: Option<usize>,
    ret_val: Option<usize>,
    context: Vec<ContextDep>,
    state: SyscallRunState,
    caller: Option<Index>,
}

impl SyscallRun {
    fn new(
        tick: Tick,
        number: Option<usize>,
        context: Vec<ContextDep>,
        caller: Option<Index>,
    ) -> Self {
        Self {
            tick,
            number,
            ret_val: None,
            context,
            state: SyscallRunState::Beginning,
            caller,
        }
    }
}

fn is_branch(arch: &FnTrackerArch, asm: &str) -> bool {
    match arch {
        FnTrackerArch::X86 => asm.starts_with("J"),
        FnTrackerArch::PPC => asm.starts_with("b"), // FIXME: Powerpc needs to be lowercase for some reason...
        FnTrackerArch::ARM64 => asm.starts_with("b"),
        FnTrackerArch::ARM32 => asm.starts_with("b"),
    }
}
fn is_nop(arch: &FnTrackerArch, asm: &str) -> bool {
    match arch {
        FnTrackerArch::X86 => asm.starts_with("ENDBR") || asm.starts_with("NOP"),
        FnTrackerArch::PPC => false,
        FnTrackerArch::ARM64 => false,
        FnTrackerArch::ARM32 => false,
    }
}
fn is_return(arch: &FnTrackerArch, asm: &str) -> bool {
    match arch {
        FnTrackerArch::X86 => asm.starts_with("RET"),
        FnTrackerArch::PPC => asm == "blr ",
        FnTrackerArch::ARM64 => asm == "ret ",
        FnTrackerArch::ARM32 => asm == "ret ",
    }
}
fn is_call(arch: &FnTrackerArch, asm: &str) -> bool {
    match arch {
        FnTrackerArch::X86 => asm.starts_with("CALL "),
        FnTrackerArch::PPC => asm.starts_with("bl ") || asm.starts_with("blrl "),
        FnTrackerArch::ARM64 => {
            asm.starts_with("bl ") || asm.starts_with("blx ") || asm.starts_with("blr")
        }
        FnTrackerArch::ARM32 => {
            asm.starts_with("bl ") || asm.starts_with("blx ") || asm.starts_with("blr")
        }
    }
}
fn is_syscall(arch: &FnTrackerArch, asm: &str) -> bool {
    match arch {
        FnTrackerArch::X86 => {
            asm.starts_with("INT ") || asm.starts_with("SYSENTER ") || asm.starts_with("SYSCALL ")
        }
        FnTrackerArch::PPC => asm.starts_with("sc "),
        FnTrackerArch::ARM64 => asm.starts_with("svc "),
        FnTrackerArch::ARM32 => asm.starts_with("swi "),
    }
}
fn is_sysret(arch: &FnTrackerArch, asm: &str) -> bool {
    match arch {
        FnTrackerArch::X86 => {
            asm.starts_with("IRET") || asm.starts_with("SYSEXIT") || asm.starts_with("SYSRET")
        }
        FnTrackerArch::PPC => asm.starts_with("bctr"), // TODO: Double check this instruction
        FnTrackerArch::ARM64 => asm.starts_with("bctr"),
        FnTrackerArch::ARM32 => asm.starts_with("bctr"),
    }
}
fn is_kernel(_arch: &FnTrackerArch, off: u64) -> bool {
    false // TODO get kernel offset from app and compare here
}

#[derive(Clone)]
pub struct ContextDep {
    index: Index,
    bank: SpaceKind,
    offset: u64,
}

pub struct FunctionRun {
    addr: Option<Address>,
    tick: Option<Tick>,
    context: Vec<ContextDep>,
    start: Option<Index>,
    end: Option<Index>,
    callsite: Option<Address>,
    ret: Option<Index>,
    ret_val: Option<usize>,
    stack_ptr: Option<Address>,
    first_pc: Option<Address>,
    depth: i64,
    reads: HashMap<Address, u8>,
    writes: HashMap<Address, u8>,
    read_buffers: HashMap<Address, Buffer>,
    write_buffers: HashMap<Address, Buffer>,
    calls: Vec<Index>,
    ticks: Vec<Tick>,
    state: FunctionRunState,
}

impl FunctionRun {
    pub fn new(
        callsite: Option<Address>,
        stack_ptr: Option<Address>,
        depth: i64,
        context: Vec<ContextDep>,
    ) -> Self {
        Self {
            addr: None,
            tick: None,
            context,
            start: None,
            end: None,
            callsite,
            ret: None,
            ret_val: None,
            stack_ptr,
            first_pc: None,
            depth,
            reads: HashMap::new(),
            writes: HashMap::new(),
            read_buffers: HashMap::new(),
            write_buffers: HashMap::new(),
            calls: Vec::new(),
            ticks: Vec::new(),
            state: FunctionRunState::Beginning,
        }
    }

    fn compute_buffers_helper(
        &self,
        mem: &HashMap<Address, u8>,
        min_size: u64,
    ) -> HashMap<Address, Buffer> {
        let mut completed_addrs = HashSet::new();
        let mut ans = HashMap::new();
        for (addr, _) in mem.iter() {
            if completed_addrs.contains(addr) {
                continue;
            }

            let mut start = *addr;
            let mut size = 1;

            completed_addrs.insert(start);

            //println!("Starting start={:?}", start);

            // Walk backwards from addr
            while start.offset() > 0 && mem.contains_key(&(start - 1u64)) {
                completed_addrs.insert(start - 1u64);
                start -= 1u64;
                size += 1;
            }
            //println!("Backwards start={:?}", start);

            // Walk forwards from addr
            while mem.contains_key(&(start + size)) {
                completed_addrs.insert(start + size);
                size += 1;
            }
            //println!("Forwards end={:?}", start+u64::from(size));

            if size < min_size {
                continue;
            }

            let mut data = vec![0u8; size as usize];

            for off in 0..size {
                if let Some(val) = mem.get(&(start + off)) {
                    data[off as usize] = *val;
                } else {
                    panic!(
                        "SHOULD NEVER HAPPEN: Cannot get buffer value at offset={:?} start={:?}",
                        off, start
                    );
                }
            }

            //println!("buf start={:?}", start);
            ans.insert(start, Buffer::new(start, data));
        }

        return ans;
    }

    fn compute_buffers(&mut self, min_size: u64) {
        self.read_buffers = self.compute_buffers_helper(&self.reads, min_size);
        self.write_buffers = self.compute_buffers_helper(&self.writes, min_size);
    }
}

pub struct Buffer {
    extent: AddressRange,
    data: Vec<u8>,
}

impl Buffer {
    fn new(start: Address, data: Vec<u8>) -> Self {
        Self {
            extent: AddressRange::new(start.space(), start.offset(), data.len() as _),
            data: data.to_vec(),
        }
    }
}

#[derive(PartialEq)]
enum FunctionRunState {
    Beginning,
    BeginningInMiddle,
    Running,
    Done,
}

#[derive(PartialEq)]
enum SyscallRunState {
    Beginning,
    Running,
    Done,
}

#[derive(Debug)]
pub enum FnTrackerArch {
    X86,
    PPC,
    ARM64,
    ARM32,
}

pub struct FnTracker {
    arch: FnTrackerArch,
    register_space: Space,
    memory_space: Space,
    threads: Vec<JoinHandle<()>>,
    //functiontick_writer: Sender<Message>,
    functionrun_writer: Sender<Message>,
    syscallrun_writer: Sender<Message>,
    buffer_writer: Sender<Message>,
    functionruns: HashMap<Index, FunctionRun>,
    syscallruns: HashMap<Index, SyscallRun>,
    callstack: Vec<Index>,
    callerfunctionrun: Option<Index>,
    currentfunctionrun: Option<Index>,
    currentsyscallrun: Option<Index>,
    currentdepth: i64,
    stack_reg: Address,       // Which register to get the stack location from
    reg_context_start: u64,   // Where in register space to start reading register context from
    reg_context_size: u64,    // How much of the register address space to read for the context
    stack_context_size: u64,  // How much stack to read for the context
    ret_reg: Address,         // Which register to read the return value from
    syscall_num_reg: Address, // Which register to read syscall number from
    min_buffer_size: u64,     // How many contiguous bytes constitute a buffer
}

impl FnTracker {
    pub fn new(
        arch: FnTrackerArch,
        register_space: Space,
        memory_space: Space,
        stack_reg: u64,
        ret_reg: u64,
        syscall_num_reg: u64,
        reg_context_start: u64,
        context_size: u64,
        buf_size: u64,
    ) -> Self {
        let mut threads = Vec::with_capacity(3);

        // let (functiontick_writer, chan) = mpsc::channel();
        // threads.push(thread::spawn(move || { writers::write_functionticks(chan, "out/"); }));

        let (functionrun_writer, chan) = mpsc::channel();
        threads.push(thread::spawn(move || {
            writers::write_functionruns(chan, "out/");
        }));

        let (syscallrun_writer, chan) = mpsc::channel();
        threads.push(thread::spawn(move || {
            writers::write_syscallruns(chan, "out/");
        }));

        let (buffer_writer, chan) = mpsc::channel();
        threads.push(thread::spawn(move || {
            writers::write_buffers(chan, "out/");
        }));

        Self {
            arch,
            register_space,
            memory_space,
            threads,
            //functiontick_writer,
            functionrun_writer,
            syscallrun_writer,
            buffer_writer,
            syscallruns: HashMap::new(),
            functionruns: HashMap::new(),
            callstack: Vec::new(),
            callerfunctionrun: None,
            currentfunctionrun: None,
            currentsyscallrun: None,
            currentdepth: 0 as i64,
            stack_reg: Address::new(register_space, stack_reg),
            reg_context_start: reg_context_start,
            reg_context_size: context_size,
            stack_context_size: context_size,
            ret_reg: Address::new(register_space, ret_reg),
            syscall_num_reg: Address::new(register_space, syscall_num_reg),
            min_buffer_size: buf_size,
        }
    }

    #[inline]
    fn address_size(&self) -> u64 {
        self.memory_space.addr_size() as u64
    }

    fn compute_context(
        &self,
        store: &Datastore,
        addr: Address,
        base: u64,
        size: u64,
    ) -> Vec<ContextDep> {
        let mut ans = Vec::<ContextDep>::new();
        for off in 0..size {
            let ctx_addr = addr + off;
            if let Some(idx) = store.last_modified(&ctx_addr) {
                ans.push(ContextDep {
                    index: *idx,
                    bank: addr.space().kind(),
                    offset: u64::from(base + off),
                });
            }
        }
        return ans;
    }

    pub fn write_syscallrun(&mut self) {
        if let Some(cur_sc) = self.currentsyscallrun {
            if let Some(scrun) = self.syscallruns.get(&cur_sc) {
                let tick = scrun.tick;
                let number = scrun.number;
                let retval = scrun.ret_val;
                let context = scrun.context.clone();
                let caller = scrun.caller;
                let _ = self
                    .syscallrun_writer
                    .send(Message::SyscallRun((tick, number, retval, context, caller)));
            }
        }
    }

    pub fn write_functionrun(&mut self) {
        if let Some(cur_func) = self.currentfunctionrun {
            if let Some(fnrun) = self.functionruns.get(&cur_func) {
                let idx = fnrun.start.unwrap();
                let addr = fnrun.addr;
                let tick = fnrun.tick.unwrap();
                let end = fnrun.end;
                let callsite = fnrun.callsite;
                let retval = fnrun.ret_val;
                let stackdepth = fnrun.depth;
                let stackptr = fnrun.stack_ptr;
                let first_pc = fnrun.first_pc.unwrap();
                let retdep = fnrun.ret;
                let context = fnrun.context.clone();
                let calls = fnrun.calls.clone();
                let ticks = fnrun.ticks.clone();
                let _ = self.functionrun_writer.send(Message::FunctionRun((
                    idx, addr, first_pc, tick, end, callsite, retval, stackdepth, stackptr, retdep,
                    context, calls, ticks,
                )));

                for (a, b) in fnrun.read_buffers.iter() {
                    let _ = self.buffer_writer.send(Message::Buffer((
                        idx,
                        *a,
                        b.extent.size(),
                        false,
                        b.data.clone(),
                    )));
                }

                for (a, b) in fnrun.write_buffers.iter() {
                    let _ = self.buffer_writer.send(Message::Buffer((
                        idx,
                        *a,
                        b.extent.size(),
                        true,
                        b.data.clone(),
                    )));
                }
            }
        }
    }
}

impl From<&'_ dataflow_core::analysis::Analysis> for FnTracker {
    fn from(analysis: &dataflow_core::analysis::Analysis) -> Self {
        let memory_space = analysis.default_data_space();
        let register_space = analysis.register_space();
        match analysis.arch() {
            Architecture::X86(_) => Self::new(
                FnTrackerArch::X86,
                register_space,
                memory_space,
                32,
                0,
                0,
                0,
                64,
                9,
            ),
            Architecture::X86_64(_) => Self::new(
                FnTrackerArch::X86,
                register_space,
                memory_space,
                32,
                0,
                0,
                0,
                64,
                9,
            ),
            Architecture::X86_64Compat32(_) => Self::new(
                FnTrackerArch::X86,
                register_space,
                memory_space,
                32,
                0,
                0,
                0,
                64,
                9,
            ),
            Architecture::PPCBE32(_) => Self::new(
                FnTrackerArch::PPC,
                register_space,
                memory_space,
                0x04,
                0x0c,
                0x00,
                0,
                64,
                9,
            ),
            Architecture::AARCH64(_) => Self::new(
                FnTrackerArch::ARM64,
                register_space,
                memory_space,
                0x8,    //stack -- sp
                0x4000, //ret -- x0
                0x4040, //syscallnum -- x8
                0x4000, // reg_context_start -- x0
                64,     // context_size (x0-x7 regs; 64-bytes stack)
                9,      // buffer size
            ),
            Architecture::ARM32(_) => Self::new(
                FnTrackerArch::ARM32,
                register_space,
                memory_space,
                0x54, //stack -- sp
                0x20, //ret -- r0
                0x3c, //syscallnum -- r7
                0x20, // reg_context_start -- r0
                0x34, // context_size (r0-r12 regs; 52-bytes stack)
                9,    // buffer size
            ),
            _ => unimplemented!(),
        }
    }
}

impl DataflowPlugin for FnTracker {
    fn on_instruction(
        &mut self,
        store: &Datastore,
        tick: Tick,
        pc: u64,
        insbytes: &[u8],
        assembly: &str,
    ) {
        let idx = store.instruction_index();
        if let Some(cur_func) = self.currentfunctionrun {
            if let Some(fnrun) = self.functionruns.get_mut(&cur_func) {
                fnrun.ticks.push(tick);
                if fnrun.state == FunctionRunState::Beginning {
                    // This is if we're on the instruction just after a function call

                    // HEURISTIC if this instruction is itself a branch, then we
                    // want to continue and wait for the branch target instruction
                    // (to handle things like the PLT)
                    //
                    // We want to wait for the first non-nop instruction to make this
                    // determination

                    if is_branch(&self.arch, assembly) || is_nop(&self.arch, assembly) {
                        log::debug!(" Branching!");
                        return;
                    }

                    let addr = Address::new(self.memory_space, pc);
                    fnrun.state = FunctionRunState::Running;
                    fnrun.tick = Some(tick);
                    fnrun.addr = Some(addr);
                    fnrun.first_pc = Some(addr);
                    fnrun.start = Some(idx);
                    // Populate the call edge on the caller

                    if let Some(caller_func) = self.callerfunctionrun {
                        if let Some(ref mut caller) = self.functionruns.get_mut(&caller_func) {
                            caller.calls.push(idx);
                        }
                    }
                } else if fnrun.state == FunctionRunState::BeginningInMiddle {
                    // This is if we're on the first encountered instruction
                    // of a function that we had started before the beginning of the trace

                    let addr = Address::new(self.memory_space, pc);
                    fnrun.state = FunctionRunState::Running;
                    fnrun.tick = Some(0);
                    fnrun.addr = None;
                    fnrun.first_pc = Some(addr);
                    fnrun.start = Some(0);
                    // Populate the call edge on the caller

                    if let Some(caller_func) = self.callerfunctionrun {
                        if let Some(ref mut caller) = self.functionruns.get_mut(&caller_func) {
                            caller.calls.push(idx);
                        }
                    }
                }
            }
        }
        if let Some(cur_scrun) = self.currentsyscallrun {
            if let Some(ref mut scrun) = self.syscallruns.get_mut(&cur_scrun) {
                if scrun.state == SyscallRunState::Beginning {
                    if is_kernel(&self.arch, pc) {
                        scrun.state = SyscallRunState::Running;
                    } else {
                        // ASSUMPTION: we skip over the kernelspace code involved with the syscall
                        scrun.ret_val = None;

                        for (_, _, d) in store.instruction_deltas() {
                            if d.space == self.ret_reg.space() && d.offset == self.ret_reg.offset()
                            {
                                scrun.ret_val = match d.as_complete() {
                                    Some(sized_val) => Some(sized_val.as_usize()),
                                    None => None,
                                };
                                break;
                            }
                        }

                        scrun.state = SyscallRunState::Done;
                        self.write_syscallrun();

                        self.currentsyscallrun = None;
                    }
                }
            }
        }

        // Now currentfunctionrun and currentsyscallrun should reflect
        // the syscall or function we are currently in (even if we are
        // about to call another function.
        //
        // Therefore this is the moment to collect all the reads and
        // writes and associate them with this function

        if let Some(cur_func) = self.currentfunctionrun {
            //let _ = self.functiontick_writer.send(Message::FunctionTick((tick, cur_func)));

            if let Some(ref mut fnrun) = self.functionruns.get_mut(&cur_func) {
                for (tick, opcode, delta) in store.instruction_deltas() {
                    if *opcode == OperationKind::Store {
                        for off in 0..delta.size {
                            if let Some(val) = delta.value.get(off as _) {
                                // Now populate the write into the
                                // function run information. When
                                // looking for "outputs" to the
                                // function, we want the last write
                                // and so we will happily overwrite
                                // any previously stored writes to
                                // this address.
                                fnrun.writes.insert(
                                    Address::new(self.memory_space, delta.offset + off),
                                    *val,
                                );
                            }
                        }
                    } else if *opcode == OperationKind::Load {
                        // Get the actual address that was read
                        if let Some(assoc_range) = Delta::associated_range(delta) {
                            for off in 0..delta.size {
                                if let Some(val) = delta.value.get(off as _) {
                                    let read_addr = assoc_range.first().unwrap() + off;
                                    // Since we are looking for "inputs"
                                    // to the function, we take the first
                                    // read (within the function) of an
                                    // address as the "input" value at
                                    // that address
                                    if !fnrun.reads.contains_key(&read_addr) {
                                        fnrun.reads.insert(read_addr, *val);
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        // Now we see if we are about to go somewhere else (another
        // syscall or function, so we look for
        // call/ret/syscall/sysret) and update accordingly:

        if is_call(&self.arch, assembly) {
            log::debug!(" Call instruction!");
            self.currentdepth += 1;
            // Get stack info from datastore
            let mut stack_base: Option<Address> = None;
            if let Some(stack_base_index) = store.last_modified(&self.stack_reg) {
                //println!("stack base index {:?}", stack_base_index);
                if let Some(&(_, _, stack_delta)) = store.delta(*stack_base_index) {
                    //println!("stack base delta {:?}", stack_delta);
                    if let Some(stack_base_offset_sized) =
                        stack_delta.value.as_sized(self.address_size() as _)
                    {
                        //println!("stack offset {:?}", stack_base_offset_sized);
                        let stack_base_offset = stack_base_offset_sized.as_usize() as u64;
                        stack_base = Some(Address::new(self.memory_space, stack_base_offset));
                    }
                }
            }

            // This is if the current instruction is a call (which may also be the first instruction of a function, notably)

            // Collect register context from datastore
            let mut context = self.compute_context(
                store,
                Address::new(self.register_space, self.reg_context_start),
                self.reg_context_start,
                self.reg_context_size,
            );

            // Collect stack context from datastore
            if let Some(stack_ptr) = stack_base {
                //println!("stack ptr {:?}", stack_ptr);
                context.append(&mut self.compute_context(
                    store,
                    stack_ptr,
                    0,
                    self.stack_context_size,
                ));
            }

            let fnrun = FunctionRun::new(
                Some(Address::new(self.memory_space, pc)),
                stack_base,
                self.currentdepth,
                context,
            );
            let caller_idx = self.currentfunctionrun;

            // Place this function run into our current "execution" context:
            self.functionruns.insert(idx, fnrun);
            self.callstack.push(idx);
            self.currentfunctionrun = Some(idx);
            self.callerfunctionrun = caller_idx;
        } else if is_return(&self.arch, assembly) {
            log::debug!(" Return instruction!");
            self.currentdepth -= 1;
            // Populate
            if let Some(cur_func) = self.currentfunctionrun {
                if let Some(ref mut fnrun) = self.functionruns.get_mut(&cur_func) {
                    fnrun.state = FunctionRunState::Done;
                    fnrun.end = Some(idx);
                    log::debug!("fntrack: ret_reg = {:?}", self.ret_reg);
                    if let Some(ret_idx) = store.last_modified(&self.ret_reg) {
                        fnrun.ret = Some(*ret_idx);
                        fnrun.ret_val = match store.delta(*ret_idx) {
                            Some(&(_, _, return_delta)) => match return_delta.as_complete() {
                                Some(sized_val) => Some(sized_val.as_usize()),
                                None => None,
                            },
                            None => None,
                        };
                    } else {
                        fnrun.ret = None;
                    }
                    fnrun.compute_buffers(self.min_buffer_size);
                    self.write_functionrun();
                    self.callstack.pop();
                    if self.callstack.len() > 0 {
                        self.currentfunctionrun = Some(self.callstack[self.callstack.len() - 1]);
                    } else {
                        self.currentfunctionrun = None;
                    }

                    if self.callstack.len() > 1 {
                        self.callerfunctionrun = Some(self.callstack[self.callstack.len() - 2]);
                    } else {
                        self.callerfunctionrun = None;
                    }
                }
            } else {
                self.currentfunctionrun = Some(0);

                // This is a functionrun object corresponding to a
                // function that had started before the beginning of our
                // trace. Thus its starttick and startindex are all 0
                // and its pc is None (i.e. "unknown")

                let mut fnrun = FunctionRun::new(
                    None, // pc
                    None, // stackptr
                    self.currentdepth,
                    Vec::<ContextDep>::new(),
                );
                fnrun.state = FunctionRunState::BeginningInMiddle;

                self.functionruns.insert(0, fnrun);
            }
        } else if is_syscall(&self.arch, assembly) {
            let context = self.compute_context(
                store,
                Address::new(self.register_space, self.reg_context_start),
                self.reg_context_start,
                self.reg_context_size,
            );
            let mut number: Option<usize> = None;
            if let Some(number_index) = store.last_modified(&self.syscall_num_reg) {
                //println!("num index {:?}", number_index);
                if let Some(&(_, _, d)) = store.delta(*number_index) {
                    //println!("num delta {:?}", d);
                    if let Some(sized_val) = d.as_complete() {
                        //println!("sized {:?}", sized_val);
                        number = Some(sized_val.as_usize());
                    }
                }
            }
            //println!("number {:?}", number);
            let scrun = SyscallRun::new(tick, number, context, self.currentfunctionrun);

            self.syscallruns.insert(idx, scrun);
            self.currentsyscallrun = Some(idx);
        } else if is_sysret(&self.arch, assembly) {
            if let Some(cur_scrun) = self.currentsyscallrun {
                if let Some(ref mut scrun) = self.syscallruns.get_mut(&cur_scrun) {
                    if scrun.state == SyscallRunState::Running {
                        scrun.ret_val = None;

                        for (_, _, d) in store.instruction_deltas() {
                            if d.space == self.ret_reg.space() && d.offset == self.ret_reg.offset()
                            {
                                scrun.ret_val = match d.as_complete() {
                                    Some(sized_val) => Some(sized_val.as_usize()),
                                    None => None,
                                };
                                break;
                            }
                        }

                        scrun.state = SyscallRunState::Done;
                        self.write_syscallrun();

                        self.currentsyscallrun = None;
                    }
                }
            }
        }
    }

    fn on_fini(&mut self) {
        //self.functiontick_writer.send(Message::Done).unwrap();
        // flush function
        loop {
            if let Some(cur_func) = self.currentfunctionrun {
                if let Some(ref mut fnrun) = self.functionruns.get_mut(&cur_func) {
                    fnrun.compute_buffers(self.min_buffer_size);
                    self.write_functionrun();
                    self.callstack.pop();
                    if self.callstack.len() > 0 {
                        self.currentfunctionrun = Some(self.callstack[self.callstack.len() - 1]);
                    } else {
                        self.currentfunctionrun = None;
                    }
                }
            } else {
                break;
            }
        }

        self.functionrun_writer.send(Message::Done).unwrap();
        self.syscallrun_writer.send(Message::Done).unwrap();
        self.buffer_writer.send(Message::Done).unwrap();
        for thread in self.threads.drain(..) {
            thread.join().unwrap();
        }
    }
}
