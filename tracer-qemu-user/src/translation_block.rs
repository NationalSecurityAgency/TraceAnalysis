use crate::qemu;
use std::{ptr::NonNull, sync::Mutex};

static TRANSLATION_BLOCKS: Mutex<Vec<TranslationBlock>> = Mutex::new(Vec::new());

pub(crate) fn insert_and<F>(tb: *mut qemu::qemu_plugin_tb, f: F)
where
    F: FnMut(Instruction),
{
    let Ok(mut translation_blocks) = TRANSLATION_BLOCKS.lock() else {
        tracing::error!("translation block mutex is poisoned");
        panic!()
    };

    let index = translation_blocks.len();
    translation_blocks.push(TranslationBlock::from(tb));

    translation_blocks[index].iter().for_each(f);
}

pub(crate) struct TranslationBlock {
    ptr: NonNull<u8>,
    len: usize,
}

unsafe impl Send for TranslationBlock {}

impl From<*mut qemu::qemu_plugin_tb> for TranslationBlock {
    fn from(tb: *mut qemu::qemu_plugin_tb) -> Self {
        let mut instructions: Vec<u8> = Vec::new();

        let count = unsafe { qemu::qemu_plugin_tb_n_insns(tb) };

        for i in 0..count {
            let insn = unsafe { qemu::qemu_plugin_tb_get_insn(tb as _, i) };

            let vaddr = unsafe { qemu::qemu_plugin_insn_vaddr(insn) };

            let bytes = unsafe {
                let size = qemu::qemu_plugin_insn_size(insn);
                let data = qemu::qemu_plugin_insn_data(insn);
                std::slice::from_raw_parts(data, size)
            };

            instructions.extend_from_slice(vaddr.to_ne_bytes().as_slice());
            instructions.extend_from_slice(bytes.len().to_ne_bytes().as_slice());
            instructions.extend_from_slice(bytes);
        }

        let slice = Box::leak(instructions.into_boxed_slice());

        Self {
            ptr: unsafe { NonNull::new_unchecked(slice.as_mut_ptr()) },
            len: slice.len(),
        }
    }
}

impl TranslationBlock {
    pub(crate) fn iter(&self) -> impl Iterator<Item = Instruction> {
        InstructionIter {
            ptr: self.ptr,
            len: self.len,
        }
    }
}

struct InstructionIter {
    ptr: NonNull<u8>,
    len: usize,
}

impl Iterator for InstructionIter {
    type Item = Instruction;

    fn next(&mut self) -> Option<Self::Item> {
        if self.len == 0 {
            return None;
        }

        let instruction = Instruction(self.ptr);
        let size = std::mem::size_of::<u64>() + std::mem::size_of::<usize>() + instruction.length();
        self.ptr = unsafe { self.ptr.add(size) };
        self.len = self.len.saturating_sub(size);

        Some(instruction)
    }
}

#[derive(Clone)]
pub(crate) struct Instruction(NonNull<u8>);

impl Instruction {
    pub(crate) fn address(&self) -> u64 {
        unsafe { self.0.cast().read_unaligned() }
    }

    pub(crate) fn length(&self) -> usize {
        unsafe {
            self.0
                .add(std::mem::size_of::<u64>())
                .cast()
                .read_unaligned()
        }
    }

    pub(crate) fn bytes(&self) -> &[u8] {
        let length = self.length();
        unsafe {
            std::slice::from_raw_parts(
                self.0
                    .add(std::mem::size_of::<u64>() + std::mem::size_of::<usize>())
                    .as_ptr(),
                length,
            )
        }
    }
}
