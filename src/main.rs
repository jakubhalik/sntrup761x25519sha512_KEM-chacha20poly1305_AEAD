#[path = "crypto/mod.rs"]
mod crypto;

mod utils;
mod compilation;

fn main() {
    if compilation::dev_compile_args::handle_args() {
        println!("compiled via dev compile args")
    } else {
        println!("nope")
    }
}
