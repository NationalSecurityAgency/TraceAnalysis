use std::cell::RefCell;

use trace::record::{Instruction, MemRead, MemWrite, Pc, Record, RegWriteNative, ThreadId};

use crate::{log, qemu, registers, tracefile, translation_block};

pub fn on_plugin_install(id: qemu::qemu_plugin_id_t, info: &qemu::qemu_info_t, args: Args) {
    let _span = tracing::trace_span!("on_plugin_install", id = id);

    let Some(arch) = info.target_name() else {
        tracing::error!("info is missing architecture information");
        panic!()
    };

    let arch = match arch {
        "x86_64" => trace::Arch::X86_64,
        "i386" => trace::Arch::X86,
        "ppc64" => trace::Arch::PowerPc64,
        "ppc" => trace::Arch::PowerPc,
        "aarch64" => trace::Arch::Arm64,
        "arm" => trace::Arch::Arm,
        "m68k" => trace::Arch::M68k,
        "mips" => trace::Arch::Mips,
        "mips64" => trace::Arch::Mips64,
        "mipsel" => trace::Arch::Mipsel,
        "mips64el" => trace::Arch::Mipsel64,
        "sparc32" => trace::Arch::Sparc,
        "sparc64" => trace::Arch::Sparc64,
        "riscv32" => trace::Arch::RiscV,
        "riscv64" => trace::Arch::RiscV64,
        name => {
            tracing::error!(arch = name, "unsupported architecture");
            panic!()
        }
    };

    let mut filename: Option<&str> = None;

    for arg in args {
        let Some((key, value)) = arg.split_once('=') else {
            tracing::warn!(arg = arg, "skipping argument with no value (missing '=')");
            continue;
        };

        match key {
            "output" => {
                filename = Some(value);
            }
            _ => {
                tracing::warn!(arg = key, "skipping unknown argument");
            }
        }
    }

    let filename = filename.unwrap_or("trace.out");

    let file = match std::fs::File::create(filename) {
        Ok(f) => f,
        Err(err) => {
            tracing::error!(filename = filename, error = %err, "failed to open trace file");
            panic!()
        }
    };

    tracefile::initialize(file, arch);

    register_vcpu_init::<Plugin>(id);
    register_on_tb_trans::<Plugin>(id);
    register_on_exit(Plugin, id);
}

pub struct Scope;

pub struct Args<'scope> {
    _scope: &'scope Scope,
    argc: usize,
    argv: *const *const i8,
    curr: usize,
}

impl<'scope> Args<'scope> {
    pub fn new(s: &'scope Scope, argc: i32, argv: *const *const i8) -> Self {
        if argc < 0 {
            tracing::error!(argc = argc, "unexpected value for argc");
            panic!()
        }

        if argc > 0 && argv.is_null() {
            tracing::error!(argv = ?argv, "unexpected value for argv");
            panic!()
        }

        Self {
            _scope: s,
            argc: argc as usize,
            argv,
            curr: 0,
        }
    }
}

impl<'scope> Iterator for Args<'scope> {
    type Item = &'scope str;

    fn next(&mut self) -> Option<Self::Item> {
        while self.curr < self.argc {
            let i = self.curr;
            self.curr += 1;

            let argv_n = unsafe { self.argv.add(i).read() };
            if argv_n.is_null() {
                tracing::warn!(n = i, "skipping null argument");
                continue;
            }

            let c_str = unsafe { std::ffi::CStr::from_ptr(argv_n) };

            let Ok(arg) = c_str.to_str() else {
                tracing::warn!(n = i, arg = ?c_str, "skipping argument with non-UTF-8 data");
                continue;
            };

            return Some(arg);
        }
        None
    }
}

pub struct Plugin;

pub trait OnVCpuInit {
    fn on_vcpu_init(id: qemu::qemu_plugin_id_t, vcpu_index: u32);
}

impl OnVCpuInit for Plugin {
    fn on_vcpu_init(id: qemu::qemu_plugin_id_t, vcpu_index: u32) {
        let _span = tracing::trace_span!("on_vcpu_init", id = id, vcpu = vcpu_index).entered();
        registers::initialize();
    }
}

pub trait OnExit {
    fn on_exit(&self, id: qemu::qemu_plugin_id_t);
}

impl OnExit for Plugin {
    fn on_exit(&self, id: qemu::qemu_plugin_id_t) {
        let _span = tracing::trace_span!("on_exit", id = id).entered();

        'write_mmap: {
            let Ok(mut writer) = std::fs::File::create("mmap.dat") else {
                tracing::warn!("unable to open mmap.dat for writing");
                break 'write_mmap;
            };

            let Ok(mut reader) = std::fs::File::open("/proc/self/maps") else {
                tracing::warn!("unable to open /proc/self/maps for reading");
                break 'write_mmap;
            };

            if let Err(err) = std::io::copy(&mut reader, &mut writer) {
                tracing::warn!(error = %err, "unable to copy /proc/self/maps to mmap.dat");
            }
        }
    }
}

pub trait OnTbTrans {
    fn on_tb_trans(id: qemu::qemu_plugin_id_t, tb: *mut qemu::qemu_plugin_tb);
}

impl OnTbTrans for Plugin {
    fn on_tb_trans(id: qemu::qemu_plugin_id_t, tb: *mut qemu::qemu_plugin_tb) {
        let _span = tracing::trace_span! {
            "on_tb_trans",
            id = id,
            address = %log::Hex(unsafe { qemu::qemu_plugin_tb_vaddr(tb)})
        }
        .entered();

        let mut i = 0;
        translation_block::insert_and(tb, move |instruction| {
            let insn = unsafe { qemu::qemu_plugin_tb_get_insn(tb, i) };

            tracing::trace! {
                address = %log::Hex(instruction.address()),
                "registering instruction callbacks"
            };

            register_on_insn_exec(instruction.clone(), insn, qemu::QEMU_PLUGIN_CB_R_REGS);
            register_on_mem(
                instruction,
                insn,
                qemu::QEMU_PLUGIN_CB_NO_REGS,
                qemu::QEMU_PLUGIN_MEM_RW,
            );

            i += 1;
        });
    }
}

pub trait OnInsnExec {
    fn on_insn_exec(&self, vcpu_index: u32);
}

impl OnInsnExec for translation_block::Instruction {
    fn on_insn_exec(&self, vcpu_index: u32) {
        let _span = tracing::trace_span! {
            "on_insn_exec",
            vcpu = vcpu_index,
        }
        .entered();

        let thread_id = unsafe { libc::gettid() };

        tracefile::with(move |trace| {
            if trace.last_tid() != thread_id {
                trace.write(ThreadId::new(thread_id as _).into());
            }

            if let Some(prev_insn) = replace_last_instruction(Some(self.clone())) {
                let mut i = 0;
                registers::for_each(|register| {
                    let regnum = i;
                    i += 1;

                    let Some(value) = register.update() else {
                        return;
                    };

                    trace.write(RegWriteNative::new(regnum, value).into());
                });
                let pc = prev_insn.address();
                let insbytes = prev_insn.bytes();
                let record = Instruction::new(pc, insbytes);
                trace.write(record.into());
            }

            let record = Pc::new(self.address());
            trace.write(record.into());
        });

        tracing::trace! {
            pc = %log::Hex(self.address()),
            instruction_bytes = %log::Hex(self.bytes()),
            "executing instruction"
        };
    }
}

pub trait OnMem {
    fn on_mem(&self, vcpu_index: u32, info: qemu::qemu_plugin_meminfo_t, vaddr: u64);
}

impl OnMem for translation_block::Instruction {
    fn on_mem(&self, vcpu_index: u32, info: qemu::qemu_plugin_meminfo_t, vaddr: u64) {
        let _span = tracing::trace_span! {
            "on_mem",
            vcpu = vcpu_index,
            pc = %log::Hex(self.address()),
        }
        .entered();

        let size_shift = unsafe { qemu::qemu_plugin_mem_size_shift(info) };
        let size = (1 << size_shift) as usize;
        let is_store = unsafe { qemu::qemu_plugin_mem_is_store(info) };

        //let hwaddr = unsafe {
        //    qemu::qemu_plugin_get_hwaddr(info, vaddr)
        //};
        //let ptr = unsafe {
        //    qemu::qemu_plugin_hwaddr_phys_addr(hwaddr) as *const u8
        //};

        let ptr = vaddr as *const u8;
        let slice = unsafe { std::slice::from_raw_parts(ptr, size) };

        tracing::trace! {
            address = %log::Hex(vaddr),
            size = size,
            access = if is_store { "write" } else { "read" },
            value = %log::Hex(slice),
        };

        let thread_id = unsafe { libc::gettid() };
        tracefile::with(move |trace| {
            if trace.last_tid() != thread_id {
                trace.write(ThreadId::new(thread_id as _).into());
            }
            let record: Record = match is_store {
                true => MemWrite::new(vaddr, slice).into(),
                false => MemRead::new(vaddr, slice).into(),
            };
            trace.write(record);
        });
    }
}

pub fn register_vcpu_init<T: OnVCpuInit>(id: qemu::qemu_plugin_id_t) {
    unsafe {
        qemu::qemu_plugin_register_vcpu_init_cb(id, qemu::vcpu_init_wrapper::<T>);
    }
}

pub fn register_on_exit<T: OnExit>(t: T, id: qemu::qemu_plugin_id_t) {
    let userdata: *mut T = Box::leak(Box::new(t)) as _;
    unsafe {
        qemu::qemu_plugin_register_atexit_cb(id, qemu::atexit_wrapper::<T>, userdata.cast());
    }
}

pub fn register_on_tb_trans<T: OnTbTrans>(id: qemu::qemu_plugin_id_t) {
    unsafe {
        qemu::qemu_plugin_register_vcpu_tb_trans_cb(id, qemu::vcpu_tb_trans_wrapper::<T>);
    }
}

pub fn register_on_insn_exec<T: OnInsnExec>(t: T, insn: *mut qemu::qemu_plugin_insn, flags: i32) {
    let userdata: *mut T = Box::leak(Box::new(t)) as _;
    unsafe {
        qemu::qemu_plugin_register_vcpu_insn_exec_cb(
            insn,
            qemu::vcpu_insn_exec_wrapper::<T>,
            flags,
            userdata as _,
        );
    }
}

pub fn register_on_mem<T: OnMem>(t: T, insn: *mut qemu::qemu_plugin_insn, flags: i32, rw: i32) {
    let userdata: *mut T = Box::leak(Box::new(t)) as _;
    unsafe {
        qemu::qemu_plugin_register_vcpu_mem_cb(
            insn,
            qemu::vcpu_mem_wrapper::<T>,
            flags,
            rw,
            userdata as _,
        );
    }
}

thread_local! {
    static LAST_INSTRUCTION: RefCell<Option<translation_block::Instruction>> = RefCell::new(None);
}

fn replace_last_instruction(
    insn: Option<translation_block::Instruction>,
) -> Option<translation_block::Instruction> {
    LAST_INSTRUCTION.with_borrow_mut(|last_insn| {
        if let Some(insn) = insn {
            last_insn.replace(insn)
        } else {
            last_insn.take()
        }
    })
}
