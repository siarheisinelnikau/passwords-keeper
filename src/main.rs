#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]
#[cfg(windows)]
mod desktop;
#[cfg(windows)]
mod preferences_worker;
#[cfg(windows)]
mod ui;
fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match passwords_keeper::updates::run_helper(&args) {
        Ok(true) => return,
        Err(error) => {
            #[cfg(windows)]
            passwords_keeper::native::error_dialog(&error.to_string());
            return;
        }
        Ok(false) => {}
    }
    passwords_keeper::updates::cleanup_helper(&args);
    #[cfg(windows)]
    if let Err(error) = desktop::run() {
        passwords_keeper::native::error_dialog(&error.to_string());
    }
    #[cfg(not(windows))]
    eprintln!("Passwords Keeper currently supports Windows only.");
}
