// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::path::PathBuf;
use std::process::Command;
use std::{env, fs};

fn main() {
    let out_dir = env::var("OUT_DIR").unwrap();
    println!("cargo:rerun-if-changed=.");
    let success = Command::new("make")
        .spawn()
        .expect("Error invoking Make")
        .wait()
        .unwrap()
        .success();
    assert!(success, "Error making pinweaver");
    println!("cargo:rustc-link-lib=static=pinweaver");
    println!("cargo:rustc-link-search=native={out_dir}");
    for env in ["RV_CLANG", "V"] {
        println!("cargo:rerun-if-env-changed={env}");
    }

    let pinweaver_root = fs::canonicalize("../..").expect("invalid pinweaver root");
    let mut builder = bindgen::builder()
        .header(pinweaver_root.join("pinweaver.h").to_string_lossy())
        .use_core()
        .ctypes_prefix("cty")
        .rustfmt_bindings(true)
        .size_t_is_usize(true)
        .clang_arg(&format!("-I{}", pinweaver_root.to_string_lossy()));

    if let Ok(sysroot) = env::var("RV_CLANG") {
        // TODO(b/260111841, kupiakos): investigate turning LIBCLANG_PATH
        // back on once Rust llvm updated.
        // Tell clang-sys to use our libclang that knows about RISC-V.
        // env::set_var("LIBCLANG_PATH", format!("{sysroot}/lib"));
        builder = builder
            // Needed for `#include <stdint.h>` to work.
            .clang_arg(format!("--sysroot={sysroot}"))
            // Clang requires we call the target riscv32-unknown-none-elf, and *not* riscv32imc.
            // See https://github.com/rust-lang/rust-bindgen/issues/2136.
            .clang_arg("--target=riscv32-unknown-none-elf");
    }
    if env::var("V").as_deref() == Ok("1") {
        builder = builder.clang_arg("--verbose")
    }

    let bindings: bindgen::Bindings = builder.generate().expect("Unable to generate bindings");

    // Write the bindings to the $OUT_DIR/bindings.rs file.
    let out_path = PathBuf::from(env::var("OUT_DIR").unwrap());
    bindings
        .write_to_file(out_path.join("bindings.rs"))
        .expect("Couldn't write bindings!");
}
