use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

fn main() {
    // Rebuild if the C plugin or headers change
    println!("cargo:rerun-if-changed=../src/core_r2yara.c");
    // Rebuild if env-provided include path changes (from yara-x-capi dep)
    println!("cargo:rerun-if-env-changed=DEP_YARA_X_CAPI_INCLUDE");
    println!("cargo:rerun-if-env-changed=YARAX_CAPI_INCLUDE");

    let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());
    let project_root = manifest_dir.parent().unwrap();
    // Resolve YARA-X C API include directory from dependency metadata or env.
    // Prefer env overrides, then metadata exported by the yara-x-capi crate's build script.
    // The crate should declare `links = "yara_x_capi"`, so Cargo will expose
    // `DEP_YARA_X_CAPI_INCLUDE` (or at least `DEP_YARA_X_CAPI_ROOT`). We try both.
    let mut yx_include_dirs: Vec<PathBuf> = vec![];
    if let Ok(inc) = env::var("YARAX_CAPI_INCLUDE").or_else(|_| env::var("YARAX_INCLUDE")) {
        yx_include_dirs.push(PathBuf::from(inc));
    }
    if let Ok(dep_inc) = env::var("DEP_YARA_X_CAPI_INCLUDE") {
        yx_include_dirs.push(PathBuf::from(dep_inc));
    }
    if let Ok(dep_root) = env::var("DEP_YARA_X_CAPI_ROOT") {
        yx_include_dirs.push(PathBuf::from(dep_root).join("include"));
    }
    // Fallbacks for inconsistent naming, just in case.
    if let Ok(dep_inc) = env::var("DEP_YARAX_CAPI_INCLUDE") {
        yx_include_dirs.push(PathBuf::from(dep_inc));
    }
    if let Ok(dep_root) = env::var("DEP_YARAX_CAPI_ROOT") {
        yx_include_dirs.push(PathBuf::from(dep_root).join("include"));
    }
    // Fallback for local yoroxoldo
    let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());
    let local_include = manifest_dir.parent().unwrap().join("yoroxoldo").join("capi").join("include");
    if local_include.exists() {
        yx_include_dirs.push(local_include);
    }

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
    let mut cflags: Vec<String> = vec!["-fPIC".into(), "-DUSE_YARAX=1".into(), "-c".into()];
    // Add YARA-X include directories
    for dir in &yx_include_dirs {
        cflags.push("-I".into());
        cflags.push(dir.to_string_lossy().to_string());
    }
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

    // Linking to YARA-X C API is handled automatically by the `yara-x-capi`
    // Rust dependency via its own build script. We only need headers for C.
    // If no include dir was found, fail with a clear message.
    if yx_include_dirs.is_empty() {
        println!("cargo:warning=Could not determine YARA-X C API include directory");
        println!("cargo:warning=Set YARAX_CAPI_INCLUDE env var to the directory containing yara_x.h");
    }

    // For convenience, print where Cargo places artifacts
    println!("cargo:warning=core_r2yara built as cdylib under target/<profile>/");
}
