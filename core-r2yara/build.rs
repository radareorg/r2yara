use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

fn main() {
    // Rebuild if the C plugin or headers change
    println!("cargo:rerun-if-changed=../src/core_r2yara.c");
    println!("cargo:rerun-if-changed=../yara-x/capi/include/yara_x.h");

    let mut r2_cflags: Vec<String> = vec![];
    match pkg_config::probe_library("r_core") {
        Ok(lib) => {
            for path in lib.include_paths {
                r2_cflags.push("-I".to_string());
                r2_cflags.push(path.to_string_lossy().to_string());
            }
        }
        Err(_) => {
            // Resolve radare2 include dir and lib dir
            let r2_include = env::var("R2_INCLUDE")
                .ok()
                .unwrap_or_else(|| "/usr/local/include/libr".to_string());
            let r2_libdir = env::var("R2_LIBDIR")
                .ok()
                .unwrap_or_else(|| "/usr/local/lib".to_string());
            r2_cflags.push("-I".to_string());
            r2_cflags.push(r2_include.clone());

            // Link against radare2 libraries (order matches config.mk)
            let r2_libs = [
                "r_core", "r_config", "r_debug", "r_bin", "r_lang", "r_anal", "r_bp", "r_egg",
                "r_asm", "r_arch", "r_esil", "r_flag", "r_reg", "r_search", "r_syscall", "r_fs",
                "r_io", "r_socket", "r_cons", "r_magic", "r_muta", "r_util",
            ];
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
    }

    // Compile C code into a static library that will be linked into this cdylib
    let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());
    let c_src = Path::new("../src/core_r2yara.c");
    let obj = out_dir.join("core_r2yara.o");
    let staticlib = out_dir.join("libr2yara_c.a");

    let cc = env::var("CC").unwrap_or_else(|_| "cc".to_string());
    let mut cflags: Vec<String> = vec![
        "-fPIC".into(),
        "-I".into(),
        "../yara-x/capi/include".into(),
        "-DUSE_YARAX=1".into(),
        "-c".into(),
    ];
    for flag in r2_cflags {
        cflags.push(flag);
    }
    if let Ok(extra) = env::var("EXTRA_CFLAGS") {
        cflags.extend(extra.split_whitespace().map(|s| s.to_string()));
    }
    // R2Y_VERSION define
    cflags.push(format!(
        "-DR2Y_VERSION=\"{}\"",
        env!("CARGO_PKG_VERSION")
    ));
    cflags.push(c_src.to_string_lossy().to_string());
    cflags.push("-o".into());
    cflags.push(obj.to_string_lossy().to_string());

    let status = Command::new(&cc)
        .args(cflags.iter())
        .status()
        .expect("failed to spawn C compiler");
    if !status.success() {
        panic!("C compilation failed: {:?} {:?}", cc, cflags);
    }

    // Create static archive from the object file
    let ar = env::var("AR").unwrap_or_else(|_| "ar".to_string());
    if staticlib.exists() {
        let _ = fs::remove_file(&staticlib);
    }
    let status = Command::new(&ar)
        .args(["crus", staticlib.to_str().unwrap(), obj.to_str().unwrap()])
        .status()
        .expect("failed to spawn ar");
    if !status.success() {
        panic!("ar failed to create static lib");
    }

    println!("cargo:rustc-link-search=native={}", out_dir.display());
    println!("cargo:rustc-link-lib=static=r2yara_c");

    // Link with prebuilt YARA-X C API if present.
    let yx_libdir = Path::new("../yara-x/target/release");
    let yx_static = yx_libdir.join("libyara_x_capi.a");
    if yx_static.exists() {
        println!("cargo:rustc-link-search=native={}", yx_libdir.display());
        println!("cargo:rustc-link-lib=static=yara_x_capi");
    } else {
        println!(
            "cargo:warning=Missing YARA-X C API static lib at {}",
            yx_static.display()
        );
        println!("cargo:warning=Build it with: (cd yara-x/capi && cargo build -r)");
        // Try to link dynamically if available
        let yx_dylib = yx_libdir.join(if cfg!(target_os = "macos") {
            "libyara_x_capi.dylib"
        } else if cfg!(target_os = "windows") {
            "yara_x_capi.dll"
        } else {
            "libyara_x_capi.so"
        });
        if yx_dylib.exists() {
            println!("cargo:rustc-link-search=native={}", yx_libdir.display());
            println!("cargo:rustc-link-lib=dylib=yara_x_capi");
        } else {
            panic!("YARA-X C API library not found; please build yara-x/capi first");
        }
    }

    // For convenience, print where Cargo places artifacts
    println!("cargo:warning=core_r2yara built as cdylib under target/<profile>/");
}
