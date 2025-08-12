use std::env;
use std::path::PathBuf;

fn main() {
    // Rebuild if the C plugin or headers change
    println!("cargo:rerun-if-changed=../src/core_r2yara.c");
    println!("cargo:rerun-if-changed=../yara-x/capi/include/yara_x.h");

    // Resolve radare2 include dir and lib dir
    let r2_include = env::var("R2_INCLUDE").ok().unwrap_or_else(|| "/usr/local/include/libr".to_string());
    let r2_libdir = env::var("R2_LIBDIR").ok().unwrap_or_else(|| "/usr/local/lib".to_string());

    // Try to use pkg-config if available to locate r2 libs; fall back to common defaults
    let mut have_pkg = false;
    let pkg = match pkg_config::Config::new().env_metadata(true).probe("r_core") {
        Ok(p) => {
            have_pkg = true;
            Some(p)
        }
        Err(_) => None,
    };

    // Link against radare2 libraries (order matches config.mk)
    let r2_libs = [
        "r_core",
        "r_config",
        "r_debug",
        "r_bin",
        "r_lang",
        "r_anal",
        "r_bp",
        "r_egg",
        "r_asm",
        "r_arch",
        "r_esil",
        "r_flag",
        "r_reg",
        "r_search",
        "r_syscall",
        "r_fs",
        "r_io",
        "r_socket",
        "r_cons",
        "r_magic",
        "r_muta",
        "r_util",
    ];

    if !have_pkg {
        // Fallback: manual link search path + libs
        println!("cargo:rustc-link-search=native={}", r2_libdir);
        for lib in r2_libs.iter() {
            println!("cargo:rustc-link-lib={}", lib);
        }
        // Some platforms need libdl
        if cfg!(target_os = "linux") {
            println!("cargo:rustc-link-lib=dl");
        }
    }

    // Include paths for compiling the C plugin
    let mut cc_build = cc::Build::new();
    cc_build
        .file("../src/core_r2yara.c")
        .include(&r2_include)
        .include("../yara-x/capi/include")
        .define("USE_YARAX", Some("1"))
        .define("R2Y_VERSION", Some(env!("CARGO_PKG_VERSION")))
        .flag_if_supported("-fPIC");
    if let Some(p) = &pkg {
        for ip in &p.include_paths {
            cc_build.include(ip);
        }
    }

    // Allow extra CFLAGS from env if the user needs custom tweaks
    if let Ok(extra) = env::var("EXTRA_CFLAGS") {
        for tok in extra.split_whitespace() {
            cc_build.flag(tok);
        }
    }

    // Compile C code into a static library that will be linked into this cdylib
    cc_build.compile("r2yara_c");

    // Nothing else needed for YARA-X linking: depending on `yara-x-capi`
    // ensures its Rust objects (providing the `yrx_*` C symbols) are linked
    // into the final cdylib to satisfy references from the C object.

    // For convenience, print where Cargo will place the final artifact
    let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());
    println!("cargo:warning=core_r2yara will be built as a cdylib; find it under target/<profile>/");
    println!("cargo:warning=OUT_DIR={} (intermediate)", out_dir.display());
}
