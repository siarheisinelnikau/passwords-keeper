fn main() {
    println!("cargo:rerun-if-changed=assets/app.ico");
    if std::env::var_os("CARGO_CFG_WINDOWS").is_some() {
        let mut resource = winresource::WindowsResource::new();
        resource.set("ProductName", "Passwords Keeper");
        resource.set(
            "FileDescription",
            "Passwords Keeper — local encrypted vault",
        );
        resource.set(
            "LegalCopyright",
            "Copyright © 2026 Passwords Keeper contributors",
        );
        if std::path::Path::new("assets/app.ico").exists() {
            resource.set_icon("assets/app.ico");
        }
        resource
            .compile()
            .expect("compile Windows application resources");
    }
}
