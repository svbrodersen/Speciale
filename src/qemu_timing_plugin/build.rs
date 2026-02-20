use std::env;
use std::path::PathBuf;

fn main() {
    println!("cargo:rerun-if-changed=wrapper.h");

    let glib = pkg_config::probe_library("glib-2.0").expect("Could not find glib-2.0");

    let mut builder = bindgen::builder()
        .header("wrapper.h") // We'll create this file next
        // Don;t generate declarations for these (we do this in lib)
        .blocklist_function("qemu_plugin_install")
        .blocklist_function("qemu_plugin_version")
        // Optimization: Only generate bindings for QEMU-related things
        // This stops the bindings file from being 17,000+ lines of GLib code
        .allowlist_function("qemu_plugin_.*")
        .allowlist_type("qemu_plugin_.*")
        .allowlist_var("QEMU_PLUGIN_.*")
        .parse_callbacks(Box::new(bindgen::CargoCallbacks::new()));

    for path in glib.include_paths {
        builder = builder.clang_arg(format!("-I{}", path.display()));
    }

    let bindings = builder.generate().expect("Unable to generate bindings");

    let out_path = PathBuf::from(env::var("OUT_DIR").unwrap());
    bindings
        .write_to_file(out_path.join("bindings.rs"))
        .expect("Couldn't write bindings!");
}
