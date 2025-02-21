
use std::path::PathBuf;

use icicle_fuzzing::FuzzConfig;
use icicle_linux::KernelConfig;
use icicle_vm::{env, Vm};

use tracer_icicle::TraceInjector;

///
/// Initializes the icicle logger and tells it to log all debug messages to
/// stderr.
///
fn init_logger() {
    let logger = tracing_subscriber::fmt().without_time();
    logger
        .with_max_level(tracing::Level::DEBUG)
        .with_writer(std::io::stderr)
        .init();
}

///
/// Initializes an icicle VM.
///
fn init_linux_vm() -> Result<Vm, String> {
    let mut config = FuzzConfig::load().expect("Invalid config");
    config.enable_shadow_stack = false;

    let mut vm = icicle_vm::build(&config.cpu_config()).map_err(|e| format!("{:?}", e))?;

    let linux_config = KernelConfig::default();
    let sysroot = std::env::var_os("ICICLE_SYSROOT")
        .map_or_else(|| PathBuf::from("/"), PathBuf::from);
    let kernel = env::build_linux_env(&mut vm, &linux_config, sysroot, true)
        .map_err(|e| format!("{:?}", e))?;

    vm.icount_limit = config.icount_limit;
    vm.set_env(kernel);
    vm.env.load(vm.cpu.as_mut(), config.guest_args[0].as_bytes())?;

    Ok(vm)
}

fn main() -> Result<(), String> {
    init_logger();

    let mut vm = init_linux_vm()?;

    TraceInjector::create_default().attach_to_vm(&mut vm);

    println!("Done! Status: {:?}", vm.run());

    Ok(())
}
