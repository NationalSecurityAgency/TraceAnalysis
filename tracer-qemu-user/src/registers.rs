use std::sync::{Arc, OnceLock};
use std::cell::RefCell;

use trace::record::{Record, RegisterNameMap};

use crate::qemu::qemu_plugin_get_registers;
use crate::{glib, log, qemu, tracefile};

static REGISTERS: OnceLock<Vec<RegisterDesc>> = OnceLock::new();

thread_local! {
    static REGISTER_VALUES: RefCell<Vec<Register>> = RefCell::new(Vec::new());
}

#[derive(Clone)]
pub struct RegisterDesc {
    handle: *mut qemu::qemu_plugin_register,
    name: Arc<String>,
}

unsafe impl Send for RegisterDesc {}
unsafe impl Sync for RegisterDesc {}

pub struct Register {
    desc: RegisterDesc,
    prev: Vec<u8>,
    curr: glib::Owned<*mut glib::GByteArray>,
}

impl Register {
    pub fn update(&mut self) -> Option<&[u8]> {
        let size = unsafe {
            glib::g_byte_array_set_size(*self.curr, 0);
            qemu::qemu_plugin_read_register(self.desc.handle, *self.curr)
        };

        if size < 0 {
            return None;
        }

        let current = self.curr.as_slice()?.get(..size as usize)?;

        if current == self.prev.as_slice() {
            return None;
        }
        
        self.prev.clear();
        self.prev.extend_from_slice(current);

        tracing::trace! {
            register = self.desc.name.as_str(),
            value = %log::Hex(self.prev.as_slice()),
            "writing register"
        };
        
        Some(self.prev.as_slice())
    }

    pub fn name(&self) -> &str {
        self.desc.name.as_str()
    }
}

impl From<&RegisterDesc> for Register {
    fn from(desc: &RegisterDesc) -> Self {
        Self {
            desc: desc.clone(),
            prev: Vec::new(),
            curr: unsafe { glib::g_byte_array_new() },
        }
    }
}

pub fn initialize() {
    let registers = unsafe {
        qemu_plugin_get_registers()
    };
    
    let Some(registers) = registers.as_slice() else {
        tracing::error!("register list is null");
        panic!()
    };

    REGISTERS.get_or_init(|| {
        let registers: Vec<RegisterDesc> = registers
            .iter()
            .copied()
            .filter_map(|desc| {
                let name = desc.name()?;
                Some(RegisterDesc {
                    handle: desc.handle,
                    name: Arc::new(String::from(name)),
                })
            })
            .collect();

        let record = RegisterNameMap::new(registers
            .iter()
            .enumerate()
            .map(|(i, desc)| {
                (i as u16, desc.name.as_bytes())
            })
        );

        tracefile::with(move |trace| {
            trace.write(Record::from(record))
        });

        registers
    });
}


pub fn for_each<F>(f: F)
where
    F: FnMut(&mut Register)
{
    REGISTER_VALUES.with_borrow_mut(|registers| {
        if registers.len() == 0 {
            let Some(desc) = REGISTERS.get() else {
                return;
            };
            registers.extend(desc.into_iter().map(Register::from));
        }

        registers.iter_mut().for_each(f);
    })
}
