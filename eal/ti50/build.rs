// Copyright 2022 The ChromiumOS Authors.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::env;
use std::process::Command;

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
    println!("cargo:rustc-link-search=native={}", out_dir);
    println!("cargo:rustc-link-lib=static=pinweaver");
}
