use std::cell::RefCell;

use tracing_subscriber::EnvFilter;

pub struct Hex<T>(pub T);

impl std::fmt::Display for Hex<u64> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:x?}", self.0)
    }
}

impl std::fmt::Display for Hex<&[u8]> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:02x?}", self.0)
    }
}

pub fn initialize_logging() {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .with_writer(debug_writer)
        .init();
}

pub fn debug_writer() -> impl std::io::Write {
    struct QemuDebugWriter;

    impl std::io::Write for QemuDebugWriter {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            match std::ffi::CStr::from_bytes_until_nul(buf) {
                Ok(s) => unsafe {
                    crate::qemu::qemu_plugin_outs(s.as_ptr());
                },
                Err(_) => DEBUG_BUFFER.with_borrow_mut(|debug_buffer| {
                    debug_buffer.extend_from_slice(buf);
                    debug_buffer.push(0);
                    // SAFETY: Trailing null bytes has just been added to the buffer
                    unsafe {
                        let s =
                            std::ffi::CStr::from_bytes_with_nul_unchecked(debug_buffer.as_slice());
                        crate::qemu::qemu_plugin_outs(s.as_ptr());
                    }
                    debug_buffer.clear();
                }),
            }
            Ok(buf.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    QemuDebugWriter
}

thread_local! {
    static DEBUG_BUFFER: RefCell<Vec<u8>> = RefCell::new(Vec::new());
}
