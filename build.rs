fn main() {
    println!("cargo:rerun-if-changed=src/user_presence_shim.m");

    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() != Ok("macos") {
        return;
    }

    cc::Build::new()
        .file("src/user_presence_shim.m")
        .flag("-fobjc-arc")
        .flag("-fblocks")
        .compile("kpexec_user_presence");

    println!("cargo:rustc-link-lib=framework=Foundation");
    println!("cargo:rustc-link-lib=framework=LocalAuthentication");
}
