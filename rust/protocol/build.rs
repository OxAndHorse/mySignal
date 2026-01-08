//
// Copyright 2020 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

fn main() {


     // 1. 读取并打印 OUT_DIR（编译时会以 warning 输出到终端）
     let out_dir = match std::env::var("OUT_DIR") {
        Ok(path) => {
            println!("cargo:warning=【build.rs】OUT_DIR: {}", path);
            path
        }
        Err(e) => {
            println!("cargo:warning=【build.rs】读取 OUT_DIR 失败: {}", e);
            panic!("build.rs 必须拿到 OUT_DIR，错误：{}", e);
        }
    };

    // 2. 打印生成文件的预期路径（验证路径拼接）
    let wire_rs_path = std::path::Path::new(&out_dir).join("wire.rs");
    println!("cargo:warning=【build.rs】生成的 wire.rs 路径: {:?}", wire_rs_path);

    let protos = [
        "src/proto/fingerprint.proto",
        "src/proto/sealed_sender.proto",
        "src/proto/service.proto",
        "src/proto/storage.proto",
        "src/proto/wire.proto",
    ];
    let mut prost_build = prost_build::Config::new();
    prost_build.protoc_arg("--experimental_allow_proto3_optional");
    prost_build
        .compile_protos(&protos, &["src"])
        .expect("Protobufs in src are valid");
    for proto in &protos {
        println!("cargo:rerun-if-changed={proto}");
    }
}
