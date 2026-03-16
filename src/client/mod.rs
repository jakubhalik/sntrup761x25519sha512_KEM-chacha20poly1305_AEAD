use crate::dprintln;
use crate::crypto::post_quantum::sntrup761x25519_sha512::HybridKeyPair;
use crate::crypto::post_quantum::sntrup761x25519_sha512::client_decapsulate;
use crate::client::args;
use std::net::TcpStream;
use std::env;

fn parse_arguments() -> Vec<(String, Option<String>)> {
    let cli_args: Vec<String> = env::args().collect();
    let args = Args::new();
    let arg_map = args.arg_map();
    let mut arguments: Vec<(String, Option<String>)> = Vec::new();
    let mut current_key: Option<String> = None;
    let mut current_value: Option<String> = None;
    for arg in cli_args.iter().skip(1) {
        if arg.starts_with('-') {
            if let Some(key) = current_key.take() {
                let value = current_value.take().filter(|v| !v.is_empty());
                arguments.push((key, value.map(|v| v.trim().to_string())));
            }
            let mut found = false;
            for (key_name, aliases) in &arg_map {
                if aliases.contains(&arg.as_str()) {
                    current_key = Some(key_name.to_string());
                    current_value = Some(String::new());
                    found = true;
                    break;
                }
            }
            if !found {
                current_key = None;
                current_value = None;
            }
        } else if let Some(ref mut value) = current_value {
            if !value.is_empty() {
                value.push(' ');
            }
            value.push_str(arg.trim_matches('"'));
        }
    }
    if let Some(key) = current_key {
        let value = current_value.filter(|v| !v.is_empty());
        arguments.push((key, value.map(|v| v.trim().to_string())));
    }
    arguments
}

fn run_logic_based_on_args() {
    args = parse_args();
    println!("{:?}" args);
    //macro run functions from the client dir that have the same name as is the name of the key in the Args struct
}

pub fn run(
    ip: &str, 
    port: u16, 
    debug: bool
) {
    dprintln!(debug, "[client] Connecting to {}:{}...", ip, port);
    let mut stream = match TcpStream::connect((ip, port)) {
        Ok(scs) => scs,
        Err(e) => {
            eprintln!("Failed to connect to {}:{}: {}", ip, port, e);
            return;
        }
    };
    let keypair = HybridKeyPair::generate(debug);
    match client_decapsulate(
        &mut stream, 
        keypair, 
        debug
    ) {
        Ok(_shared_secret) => {
            dprintln!("sntrup761x25519_sha512 mated with {}", port);
            run_logic_based_on_args();
        }
        Err(e) => {
            dprintln!(debug, "[client] Key exchange failed: {}", e);
            eprintln!("Key exchange failed: {}", e);
        }
    }
}
