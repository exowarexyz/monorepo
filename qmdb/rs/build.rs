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

    connectrpc_build::Config::new()
        .files(QMDB_PROTO_FILES)
        .descriptor_set(&descriptor)
        .emit_register_fn(false)
        .out_dir(&gen_dir)
        .compile()
        .expect("connectrpc codegen");

    combine_generated_protos(&gen_dir, QMDB_PROTO_FILES, "qmdb.v1.rs");

    std::fs::remove_file(&descriptor).expect("cleanup descriptor");
}

fn combine_generated_protos(gen_dir: &Path, proto_paths: &[&str], to: &str) {
    let to_path = gen_dir.join(to);
    if to_path.exists() {
        std::fs::remove_file(&to_path).expect("remove stale generated proto file");
    }
    let mut combined = String::new();
    for (index, proto_path) in proto_paths.iter().enumerate() {
        if index > 0 {
            combined.push('\n');
        }
        let from_path = gen_dir.join(generated_rust_filename(proto_path));
        let content = std::fs::read_to_string(&from_path).unwrap_or_else(|err| {
            panic!("read generated proto file {}: {}", from_path.display(), err)
        });
        combined.push_str(&content);
        if !combined.ends_with('\n') {
            combined.push('\n');
        }
        std::fs::remove_file(&from_path).expect("remove split generated proto file");
    }
    std::fs::write(&to_path, combined).expect("write combined generated proto file");
}

fn generated_rust_filename(proto_path: &str) -> String {
    let stem = proto_path.strip_suffix(".proto").unwrap_or(proto_path);
    format!("{}.rs", stem.replace('/', "."))
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
