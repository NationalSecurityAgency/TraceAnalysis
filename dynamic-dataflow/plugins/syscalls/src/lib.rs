use dataflow_core::address::AddressRange;
use dataflow_core::analysis::EmulatorOutput;
use dataflow_core::datastore::Datastore;
use dataflow_core::delta::Delta;
use dataflow_core::operation::Operation;
use dataflow_core::oplog::OpLog;
use dataflow_core::plugins::DataflowPlugin;
use dataflow_core::slot::Slot;
use dataflow_core::space::{Space, SpaceManager};
use dataflow_core::value::PartialValue;

/// This plugin does basic modeling for `CallOther` operations that arise from syscalls.
///
/// This plugin is essential depending on which technique is used for gathering a trace. Tools like
/// Intel PIN and QEMU user mode are unable to detect writes to memory that occur during the
/// execution of a syscall. Therefore, dataflow analysis may be relying on stale data that is in
/// memory from before the execution of the syscall which results in incorrect analysis.
///
/// This plugin will mitigate these effects by understanding the syscall ABI for a specific
/// platform and forcing the analysis to "forget" what it knows about regions memory that could
/// have been written to during the execution of a syscall. For the syscalls that the plugin
/// understands, this is a strict overestimate of the side effects of the syscall. For example,
/// there is a call `read(42, 0xdeadbee0, 0x10)` then all of memory from `0xdeadbee0` to
/// `0xdeadbeef0` will be "forgotten" by this plugin even if only 4 bytes were actually read. There
/// are pros and cons to this approach, and in the future, this may be configurable.

/// Models for Linux syscalls on `x86_64` machines.
pub struct LinuxSyscallsx64 {
    constant: Space,
    register: Space,
    memory: Space,
}

impl LinuxSyscallsx64 {
    // Sizes of various structs used in syscalls, these are likely to be overestimates as I am
    // using their definitions in libc instead of the kernel ones.
    // sizeof(struct stat)
    const STAT_SIZE: u64 = 0x90;
    // sizeof(struct sigaction)
    const SIGACTION_SIZE: u64 = 0x98;
    // sizeof(struct sigset)
    const SIGSET_SIZE: u64 = 0x88;
    // sizeof(struct statfs)
    const STATFS_SIZE: u64 = 0x78;
    // sizeof(struct rlimit)
    const RLIMIT_SIZE: u64 = 0x10;

    pub fn new<T: SpaceManager>(manager: &T) -> Self {
        Self {
            constant: manager.constant_space(),
            register: manager.register_space(),
            memory: manager.default_data_space(),
        }
    }

    // This is modified from the implementation in analysis/other plugins to remove handling of
    // slots not backed by registers (e.g. constants/memory). The x86_64 linux syscall ABI strictly
    // uses registers for arguments.
    fn resolve_input(store: &Datastore, slot: &mut Slot) {
        slot.value = PartialValue::default();
        for (i, address) in slot.as_range().iter().enumerate() {
            if let Some(index) = store.last_modified(&address) {
                if let Some((_, _, delta)) = store.delta(*index) {
                    slot.value.set_or_unset(i, delta.value_at(address));
                }
            }
        }
    }

    pub fn is_syscall(&self, op: &Operation) -> bool {
        if let Operation::CallOther(op) = op {
            let &[iaddr0, _] = op.inputs();
            return iaddr0 == self.syscall_const();
        }
        false
    }

    fn memory(&self, offset: u64, size: u64) -> AddressRange {
        AddressRange::new(self.memory, offset, size)
    }

    fn syscall_const(&self) -> AddressRange {
        AddressRange::new(self.constant, 5, 4)
    }

    // EAX
    fn syscall_num(&self) -> AddressRange {
        AddressRange::new(self.register, 0x00, 4)
    }

    // RAX
    fn syscall_ret(&self) -> AddressRange {
        AddressRange::new(self.register, 0x00, 8)
    }

    // RDI
    #[allow(dead_code)]
    fn syscall_arg0(&self) -> AddressRange {
        AddressRange::new(self.register, 0x38, 8)
    }

    // RSI
    fn syscall_arg1(&self) -> AddressRange {
        AddressRange::new(self.register, 0x30, 8)
    }

    // RDX
    fn syscall_arg2(&self) -> AddressRange {
        AddressRange::new(self.register, 0x10, 8)
    }

    // R10
    fn syscall_arg3(&self) -> AddressRange {
        AddressRange::new(self.register, 0x90, 8)
    }

    // R8
    #[allow(dead_code)]
    fn syscall_arg4(&self) -> AddressRange {
        AddressRange::new(self.register, 0x80, 8)
    }

    // R9
    #[allow(dead_code)]
    fn syscall_arg5(&self) -> AddressRange {
        AddressRange::new(self.register, 0x88, 8)
    }
}

impl DataflowPlugin for LinuxSyscallsx64 {
    fn on_operation(
        &mut self,
        store: &Datastore,
        _oplog: &OpLog,
        op: Operation,
        output: &mut EmulatorOutput,
    ) {
        let _span =
            tracing::trace_span!("on_operation", index = store.instruction_index()).entered();
        if !self.is_syscall(&op) {
            return;
        }
        tracing::trace!("detected syscall");

        // No matter what syscall is performed, RAX will hold the return value
        output.delta = Some(Delta::Dataflow(Slot::from(self.syscall_ret()), None));

        let mut input0 = Slot::from(self.syscall_num());
        Self::resolve_input(store, &mut input0);
        let Some(sysno) = input0.value.as_u32() else {
            tracing::warn!("could not determine syscall number, skipping...");
            return;
        };
        match sysno {
            0 | 17 => {
                tracing::trace!(sysno = sysno, "SYS_(P)READ(64)");
                let mut base = Slot::from(self.syscall_arg1());
                let mut size = Slot::from(self.syscall_arg2());

                Self::resolve_input(store, &mut base);
                Self::resolve_input(store, &mut size);

                let Some(base) = base.value.as_u64() else {
                    tracing::warn!(sysno = sysno, "unable to resolve base address");
                    return;
                };

                let Some(size) = size.value.as_u64() else {
                    tracing::warn!(sysno = sysno, "unable to resolve size");
                    return;
                };

                let range = self.memory(base, size);
                tracing::trace! {
                    space = range.space().id(),
                    offset = %Hex(range.offset()),
                    size = range.size(),
                    "clearing dataflow"
                };
                output.clear_ranges.push(range);
            }

            4 | 5 | 6 => {
                tracing::trace!(sysno = sysno, "SYS_(F/L)STAT");
                let mut base = Slot::from(self.syscall_arg1());
                Self::resolve_input(store, &mut base);
                let Some(base) = base.value.as_u64() else {
                    tracing::warn!(sysno = sysno, "unable to resolve address of struct");
                    return;
                };

                let range = self.memory(base, Self::STAT_SIZE);
                tracing::trace! {
                    space = range.space().id(),
                    offset = %Hex(range.offset()),
                    size = range.size(),
                    "clearing dataflow"
                };
                output.clear_ranges.push(range);
            }

            13 => {
                tracing::trace!(sysno = sysno, "SYS_RT_SIGACTION");
                let mut base = Slot::from(self.syscall_arg2());
                Self::resolve_input(store, &mut base);
                let Some(base) = base.value.as_u64() else {
                    tracing::warn!(sysno = sysno, "unable to resolve address of struct");
                    return;
                };

                if base == 0 {
                    return;
                }

                let range = self.memory(base, Self::SIGACTION_SIZE);
                tracing::trace! {
                    space = range.space().id(),
                    offset = %Hex(range.offset()),
                    size = range.size(),
                    "clearing dataflow"
                };
                output.clear_ranges.push(range);
            }

            14 => {
                tracing::trace!(sysno = sysno, "SYS_RT_SIGPROCMASK");
                let mut base = Slot::from(self.syscall_arg2());
                Self::resolve_input(store, &mut base);
                let Some(base) = base.value.as_u64() else {
                    tracing::warn!(sysno = sysno, "unable to resolve address of struct");
                    return;
                };

                if base == 0 {
                    return;
                }

                let range = self.memory(base, Self::SIGSET_SIZE);
                tracing::trace! {
                    space = range.space().id(),
                    offset = %Hex(range.offset()),
                    size = range.size(),
                    "clearing dataflow"
                };
                output.clear_ranges.push(range);
            }

            137 => {
                tracing::trace!(sysno = sysno, "SYS_STATFS");
                let mut base = Slot::from(self.syscall_arg1());
                Self::resolve_input(store, &mut base);
                let Some(base) = base.value.as_u64() else {
                    tracing::warn!(sysno = sysno, "unable to resolve address of struct");
                    return;
                };

                let range = self.memory(base, Self::STATFS_SIZE);
                tracing::trace! {
                    space = range.space().id(),
                    offset = %Hex(range.offset()),
                    size = range.size(),
                    "clearing dataflow"
                };
                output.clear_ranges.push(range);
            }

            217 => {
                tracing::trace!(sysno = sysno, "SYS_GETDENTS64");
                let mut base = Slot::from(self.syscall_arg1());
                let mut size = Slot::from(self.syscall_arg2());

                Self::resolve_input(store, &mut base);
                Self::resolve_input(store, &mut size);

                let Some(base) = base.value.as_u64() else {
                    tracing::warn!(sysno = sysno, "unable to resolve base address");
                    return;
                };

                let Some(size) = size.value.as_u64() else {
                    tracing::warn!(sysno = sysno, "unable to resolve size");
                    return;
                };

                let range = self.memory(base, size);
                tracing::trace! {
                    space = range.space().id(),
                    offset = %Hex(range.offset()),
                    size = range.size(),
                    "clearing dataflow"
                };
                output.clear_ranges.push(range);
            }

            302 => {
                tracing::trace!(sysno = sysno, "SYS_PRLIMIT64");
                let mut base = Slot::from(self.syscall_arg3());
                Self::resolve_input(store, &mut base);
                let Some(base) = base.value.as_u64() else {
                    tracing::warn!(sysno = sysno, "unable to resolve address of struct");
                    return;
                };

                if base == 0 {
                    return;
                }

                let range = self.memory(base, Self::RLIMIT_SIZE);
                tracing::trace! {
                    space = range.space().id(),
                    offset = %Hex(range.offset()),
                    size = range.size(),
                    "clearing dataflow"
                };
                output.clear_ranges.push(range);
            }

            _ => {
                tracing::trace!(sysno = sysno, "unhandled syscall")
            }
        }
    }
}

struct Hex<T>(T);

impl std::fmt::Display for Hex<u64> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:#018x}", self.0)
    }
}
