#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]

use crate::{glib, plugin};

pub const QEMU_PLUGIN_CB_NO_REGS: i32 = 0;
pub const QEMU_PLUGIN_CB_R_REGS: i32 = 1;

pub const QEMU_PLUGIN_MEM_RW: i32 = 3;

#[no_mangle]
pub static qemu_plugin_version: i32 = 2;

pub type qemu_plugin_id_t = u64;

pub type qemu_plugin_meminfo_t = u32;

#[repr(C)]
#[derive(Copy, Clone, PartialEq, Eq)]
pub struct qemu_info_t {
    pub target_name: *const i8,
    pub version_min: i32,
    pub version_cur: i32,
    pub system_emulation: bool,
    pub smp_vcpus: i32,
    pub max_vcpus: i32,
}

impl qemu_info_t {
    pub fn target_name(&self) -> Option<&str> {
        if self.target_name.is_null() {
            return None;
        }

        let c_str = unsafe { std::ffi::CStr::from_ptr(self.target_name) };

        let Ok(s) = c_str.to_str() else {
            tracing::warn!(target_name = ?c_str, "target name contains non-UTF-8 characters");
            return None;
        };

        Some(s)
    }
}

#[repr(C)]
pub struct qemu_plugin_register(());

#[repr(C)]
pub struct qemu_plugin_tb(());

#[repr(C)]
pub struct qemu_plugin_insn(());

#[repr(C)]
pub struct qemu_plugin_hwaddr(());

#[repr(C)]
#[derive(Copy, Clone)]
pub struct qemu_plugin_reg_descriptor {
    pub handle: *mut qemu_plugin_register,
    pub name: *const i8,
    pub feature: *const i8,
}

impl qemu_plugin_reg_descriptor {
    pub fn name(&self) -> Option<&str> {
        if self.name.is_null() {
            return None;
        }

        let c_str = unsafe { std::ffi::CStr::from_ptr(self.name) };

        let Ok(s) = c_str.to_str() else {
            tracing::warn!(name = ?c_str, "register name contains non-UTF-8 characters");
            return None;
        };

        Some(s)
    }
}

pub type qemu_plugin_udata_cb_t = extern "C" fn(qemu_plugin_id_t, *mut std::os::raw::c_void);
pub type qemu_plugin_vcpu_simple_cb_t = extern "C" fn(qemu_plugin_id_t, u32);
pub type qemu_plugin_vcpu_udata_cb_t = extern "C" fn(u32, *mut std::os::raw::c_void);
pub type qemu_plugin_vcpu_tb_trans_cb_t = extern "C" fn(qemu_plugin_id_t, *mut qemu_plugin_tb);
pub type qemu_plugin_vcpu_mem_cb_t =
    extern "C" fn(u32, qemu_plugin_meminfo_t, u64, *mut std::os::raw::c_void);

extern "C" {
    pub fn qemu_plugin_outs(_string: *const i8);
    pub fn qemu_plugin_register_vcpu_init_cb(
        _id: qemu_plugin_id_t,
        _cb: qemu_plugin_vcpu_simple_cb_t,
    );
    pub fn qemu_plugin_register_vcpu_tb_trans_cb(
        _id: qemu_plugin_id_t,
        _cb: qemu_plugin_vcpu_tb_trans_cb_t,
    );
    pub fn qemu_plugin_register_vcpu_insn_exec_cb(
        _insn: *mut qemu_plugin_insn,
        _cb: qemu_plugin_vcpu_udata_cb_t,
        _flags: i32,
        _userdata: *mut std::os::raw::c_void,
    );
    pub fn qemu_plugin_register_vcpu_mem_cb(
        _insn: *mut qemu_plugin_insn,
        _cb: qemu_plugin_vcpu_mem_cb_t,
        _flags: i32,
        _rw: i32,
        _userdata: *mut std::os::raw::c_void,
    );
    pub fn qemu_plugin_register_atexit_cb(
        _id: qemu_plugin_id_t,
        _cb: qemu_plugin_udata_cb_t,
        _userdata: *mut std::os::raw::c_void,
    );
    pub fn qemu_plugin_get_registers() -> glib::Owned<*mut glib::GArray<qemu_plugin_reg_descriptor>>;
    pub fn qemu_plugin_read_register(
        _handle: *mut qemu_plugin_register,
        _buf: *mut crate::glib::GByteArray,
    ) -> i32;
    pub fn qemu_plugin_tb_n_insns(_tb: *const qemu_plugin_tb) -> usize;
    pub fn qemu_plugin_tb_get_insn(
        _tb: *const qemu_plugin_tb,
        _idx: usize,
    ) -> *mut qemu_plugin_insn;
    pub fn qemu_plugin_tb_vaddr(_tb: *const qemu_plugin_tb) -> u64;
    pub fn qemu_plugin_insn_data(_insn: *const qemu_plugin_insn) -> *const u8;
    pub fn qemu_plugin_insn_size(_insn: *const qemu_plugin_insn) -> usize;
    pub fn qemu_plugin_insn_vaddr(_insn: *const qemu_plugin_insn) -> u64;
    pub fn qemu_plugin_mem_size_shift(_info: qemu_plugin_meminfo_t) -> u32;
    pub fn qemu_plugin_mem_is_store(_info: qemu_plugin_meminfo_t) -> bool;
    pub fn qemu_plugin_get_hwaddr(
        _info: qemu_plugin_meminfo_t,
        _vaddr: u64,
    ) -> *mut qemu_plugin_hwaddr;
    pub fn qemu_plugin_hwaddr_phys_addr(haddr: *const qemu_plugin_hwaddr) -> u64;
}

#[no_mangle]
pub extern "C" fn qemu_plugin_install(
    id: qemu_plugin_id_t,
    info: *const qemu_info_t,
    argc: i32,
    argv: *const *const i8,
) -> i32 {
    let result = std::panic::catch_unwind(|| {
        crate::log::initialize_logging();

        let scope = plugin::Scope;
        let args = plugin::Args::new(&scope, argc, argv);
        let info = unsafe {
            let Some(info) = info.as_ref() else {
                tracing::error!("plugin info is null");
                panic!();
            };
            info
        };

        plugin::on_plugin_install(id, info, args);
    });

    match result {
        Ok(_) => 0,
        Err(_) => 1,
    }
}

pub(crate) extern "C" fn vcpu_init_wrapper<T>(id: qemu_plugin_id_t, vcpu_index: u32)
where
    T: plugin::OnVCpuInit,
{
    let result = std::panic::catch_unwind(|| {
        T::on_vcpu_init(id, vcpu_index);
    });
    if result.is_err() {
        tracing::error!("panic occured in vcpu_init callback, exiting");
        std::process::exit(1);
    }
}

pub(crate) extern "C" fn atexit_wrapper<T>(
    id: qemu_plugin_id_t,
    userdata: *mut std::os::raw::c_void,
) where
    T: plugin::OnExit,
{
    let result = std::panic::catch_unwind(|| {
        let data = unsafe { userdata.cast::<T>().as_ref().unwrap() };
        data.on_exit(id)
    });
    if result.is_err() {
        tracing::error!("panic occured in atexit callback, exiting");
        std::process::exit(1);
    }
}

pub(crate) extern "C" fn vcpu_tb_trans_wrapper<T>(id: qemu_plugin_id_t, tb: *mut qemu_plugin_tb)
where
    T: plugin::OnTbTrans,
{
    let result = std::panic::catch_unwind(|| {
        T::on_tb_trans(id, tb);
    });
    if result.is_err() {
        tracing::error!("panic occured in tb_trans callback, exiting");
        std::process::exit(1);
    }
}

pub(crate) extern "C" fn vcpu_insn_exec_wrapper<T>(
    vcpu_index: u32,
    userdata: *mut std::os::raw::c_void,
) where
    T: plugin::OnInsnExec,
{
    let result = std::panic::catch_unwind(|| {
        let data = unsafe { userdata.cast::<T>().as_ref().unwrap() };
        data.on_insn_exec(vcpu_index)
    });
    if result.is_err() {
        tracing::error!("panic occured in insn_exec callback, exiting");
        std::process::exit(1);
    }
}

pub(crate) extern "C" fn vcpu_mem_wrapper<T>(
    vcpu_index: u32,
    info: qemu_plugin_meminfo_t,
    vaddr: u64,
    userdata: *mut std::os::raw::c_void,
) where
    T: plugin::OnMem,
{
    let result = std::panic::catch_unwind(|| {
        let data = unsafe { userdata.cast::<T>().as_ref().unwrap() };
        data.on_mem(vcpu_index, info, vaddr)
    });
    if result.is_err() {
        tracing::error!("panic occured in mem callback, exiting");
        std::process::exit(1);
    }
}
