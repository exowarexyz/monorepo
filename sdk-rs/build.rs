use std::path::{Path, PathBuf};
use std::process::Command;

fn main() {
    let workspace_root = PathBuf::from(
        std::env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR should be set"),
    )
    .parent()
    .expect("sdk-rs crate should live one level below workspace root")
    .to_path_buf();
    let out_dir =
        PathBuf::from(std::env::var("OUT_DIR").expect("OUT_DIR should be set for build scripts"));

    let google_rpc_descriptor_path = out_dir.join("buf-google-rpc-descriptor.bin");
    let store_descriptor_path = out_dir.join("buf-store-descriptor.bin");

    // Buf remote dependencies resolve imports from googleapis, but they are not
    // targetable as local module paths for files_to_generate. Generate the
    // standard google.rpc detail types from the remote module directly, then
    // generate store protos from the local module.
    buf_build_remote(
        "buf.build/googleapis/googleapis",
        "google/rpc/error_details.proto",
        &google_rpc_descriptor_path,
    );
    buf_build_local(&workspace_root, &store_descriptor_path);

    connectrpc_build::Config::new()
        .files(&["google/rpc/error_details.proto"])
        .descriptor_set(&google_rpc_descriptor_path)
        .emit_register_fn(false)
        .compile()
        .expect("connectrpc codegen for google rpc should succeed");

    connectrpc_build::Config::new()
        .files(&[
            "store/v1/compact.proto",
            "store/v1/ingest.proto",
            "store/v1/query.proto",
        ])
        .descriptor_set(&store_descriptor_path)
        .emit_register_fn(false)
        .include_file("_connectrpc.rs")
        .compile()
        .expect("connectrpc codegen should succeed");
}

fn buf_build_remote(module: &str, path: &str, descriptor_out: &Path) {
    let output = Command::new("buf")
        .arg("build")
        .arg(module)
        .arg("--path")
        .arg(path)
        .arg("--as-file-descriptor-set")
        .arg("-o")
        .arg(descriptor_out)
        .output()
        .expect("failed to spawn buf for remote module");
    if !output.status.success() {
        panic!(
            "buf build for remote module failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
}

fn buf_build_local(workspace_root: &Path, descriptor_out: &Path) {
    let output = Command::new("buf")
        .current_dir(workspace_root)
        .arg("build")
        .arg("proto")
        .arg("--as-file-descriptor-set")
        .arg("-o")
        .arg(descriptor_out)
        .output()
        .expect("failed to spawn buf for local module");
    if !output.status.success() {
        panic!(
            "buf build for local module failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
}
