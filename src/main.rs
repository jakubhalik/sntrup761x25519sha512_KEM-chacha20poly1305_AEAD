use std::env;
use std::net::TcpListener;
mod compilation;
mod crypto;
mod utils;
mod traffic;
mod client;
mod server;
#[cfg(test)]
mod tests;

const LOCALHOST: &str = "127.0.0.1";
const IP: &str = LOCALHOST;
const DEFAULT_PORT: u16 = 1024;

fn run() {
    let args: Vec<String> = env::args().collect();
    let debug_flags = [
        "-d", "-debug", "--debug", "-m", "-monitor", "--monitor"
    ];
    let debug: bool = args.iter().any(|arg| debug_flags.contains(&arg.as_str()));

    let client_port: Option<u16> = args.iter()
        .find(|arg| arg.starts_with('@'))
        .and_then(|arg| arg[1..].parse().ok());
    if let Some(port) = client_port {
        client::run(IP, port, debug);
    } else {
        let mut port: u16 = args.iter()
            .find(|arg| arg.parse::<u16>().is_ok())
            .and_then(|arg| arg.parse().ok())
            .unwrap_or_else(|| {
                println!("No port provided, using {DEFAULT_PORT}");
                DEFAULT_PORT
            });
        while TcpListener::bind((IP, port)).is_err() {
            println!("Port {} is taken, trying {}", port, port + 1);
            port += 1;
        }
        server::run(IP, port, debug);
    }
}

fn main() {
    if compilation::dev_compile_args::handle_args() {
        println!("compiled via dev compile args");
        run();
    }
    run();
}
