use std::env;
use std::path::PathBuf;

fn main() {
    println!("cargo:rerun-if-changed=wrapper_qemu.h");
    println!("cargo:rerun-if-changed=wrapper_s3k.h");

    let glib = pkg_config::probe_library("glib-2.0").expect("Could not find glib-2.0");

    let mut builder_qemu = bindgen::builder()
        .header("wrapper_qemu.h")
        // Don't generate declarations for these (we do this in lib)
        .blocklist_function("qemu_plugin_install")
        .blocklist_function("qemu_plugin_version")
        .allowlist_function("qemu_plugin_.*")
        .allowlist_function("g_byte_array_.*")
        .allowlist_function("g_new.*")
        .allowlist_type("qemu_plugin_.*")
        .allowlist_var("QEMU_PLUGIN_.*")
        .parse_callbacks(Box::new(bindgen::CargoCallbacks::new()));

    for path in &glib.include_paths {
        builder_qemu = builder_qemu.clang_arg(format!("-I{}", path.display()));
    }

    let bindings_qemu = builder_qemu
        .generate()
        .expect("Unable to generate QEMU bindings");
    let out_path = PathBuf::from(env::var("OUT_DIR").unwrap());
    bindings_qemu
        .write_to_file(out_path.join("bindings_qemu.rs"))
        .expect("Couldn't write QEMU bindings!");

    // S3k bindings
    let max_pid = std::env::var("MAX_PID").unwrap_or_else(|_| num_cpus::get().to_string());
    let mut builder_s3k = bindgen::builder()
        .header("wrapper_s3k.h")
        .clang_arg(format!("-D_MAX_PID={max_pid}"))
        .parse_callbacks(Box::new(bindgen::CargoCallbacks::new()));

    builder_s3k = builder_s3k.clang_arg("-I../s3k/kern/include");

    let bindings_s3k = builder_s3k
        .generate()
        .expect("Unable to generate S3K bindings");
    bindings_s3k
        .write_to_file(out_path.join("bindings_s3k.rs"))
        .expect("Couldn't write S3K bindings!");
}
