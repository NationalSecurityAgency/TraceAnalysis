use std::env;

fn main() {
    let profile = std::env::var("PROFILE").unwrap();
    let is_debug = profile.as_str() == "debug";

    let jobs = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(1);

    let status = std::process::Command::new("make")
        .arg("-C")
        .arg("vendor/decompile/cpp")
        .arg("-j")
        .arg(format!("{}", jobs))
        .arg(if is_debug {
            "libdecomp_dbg.a"
        } else {
            "libdecomp.a"
        })
        .status()
        .expect("failed to execute make");
    assert!(status.success());

    let crate_path = env::current_dir().expect("could not get crate path");
    let decomp_path = crate_path.join("vendor/decompile/cpp");

    cxx_build::bridge("src/lib.rs")
        .file("src/lifter.cc")
        .include(decomp_path.as_path())
        .flag_if_supported("-Wno-unused-variable")
        .flag_if_supported("-Wno-unused-parameter")
        .flag_if_supported("-Wno-deprecated-copy")
        .flag_if_supported("-Wno-sign-compare")
        .extra_warnings(false)
        .flag_if_supported("-std=c++14")
        .compile("lift");

    println!(
        "cargo:rustc-link-search={}",
        decomp_path.as_path().display()
    );
    println!(
        "cargo:rustc-link-lib=static={}",
        if is_debug { "decomp_dbg" } else { "decomp" }
    );
    println!("cargo:rustc-link-lib=stdc++");
    println!("cargo:rustc-link-lib=m");
    println!("cargo:rustc-link-lib=bfd");
    println!("cargo:rerun-if-changed=src/lib.rs");
    println!("cargo:rerun-if-changed=src/lifter.cc");
    println!("cargo:rerun-if-changed=include/lifter.h");
}
