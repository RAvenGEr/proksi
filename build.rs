fn main() {
    println!("cargo:rerun-if-changed=src/plugins/external_auth/external_auth.capnp");
    let out_dir = std::env::var("OUT_DIR").expect("OUT_DIR is not set");

    capnpc::CompilerCommand::new()
        .src_prefix("src/plugins/external_auth")
        .file("src/plugins/external_auth/external_auth.capnp")
        .output_path(&out_dir)
        .run()
        .expect("failed to compile Cap'n Proto schema");
}
