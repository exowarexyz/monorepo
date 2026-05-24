use std::path::{Path, PathBuf};
use std::process::Command;

const QMDB_PROTO_FILES: &[&str] = &[
    "qmdb/v1/proof.proto",
    "qmdb/v1/key_lookup.proto",
    "qmdb/v1/key_range.proto",
    "qmdb/v1/operation_log.proto",
    "qmdb/v1/current_operation.proto",
];

fn main() {
    println!("cargo:rerun-if-env-changed=PROTO_GEN");
    println!("cargo:rerun-if-changed=../../proto");

    if std::env::var("PROTO_GEN").is_err() {
        return;
    }

    let manifest_dir =
        PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR"));
    let gen_dir = manifest_dir.join("src/gen");
    let workspace_root = manifest_dir
        .parent()
        .and_then(|path| path.parent())
        .expect("qmdb/rs should be two levels below workspace root")
        .to_path_buf();

    let descriptor = gen_dir.join("descriptor.bin");
    buf_build(&workspace_root, &descriptor);

    let mut buffa_config = connectrpc_build::CodeGenConfig::default();
    buffa_config.generate_json = true;
    buffa_config.file_per_package = true;
    buffa_config.bytes_fields = vec![".".into()];

    connectrpc_build::Config::new()
        .files(QMDB_PROTO_FILES)
        .descriptor_set(&descriptor)
        .buffa_config(buffa_config)
        .emit_register_fn(false)
        .out_dir(&gen_dir)
        .compile()
        .expect("connectrpc codegen");

    std::fs::remove_file(&descriptor).expect("cleanup descriptor");
}

fn buf_build(workspace_root: &Path, descriptor_out: &Path) {
    let output = Command::new("buf")
        .current_dir(workspace_root)
        .args(["build", "proto", "--as-file-descriptor-set", "-o"])
        .arg(descriptor_out)
        .output()
        .expect("failed to run buf");
    if !output.status.success() {
        panic!(
            "buf build failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
}
