#[path = "crypto/mod.rs"]
mod crypto;

mod utils;

fn main() {
    if compilation::dev_compile_args::handle_args() {
        return;
    }
}
