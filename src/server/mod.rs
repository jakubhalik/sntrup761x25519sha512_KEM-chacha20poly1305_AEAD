use crate::dprintln;
use crate::crypto::post_quantum::sntrup761x25519_sha512::server_encapsulate;
use crate::crypto::post_quantum::sntrup761x25519_sha512::shared_secret_hex;
use std::net::{TcpListener, TcpStream};

fn initiate_client(
    mut stream: TcpStream, 
    debug: bool
) {
    match server_encapsulate(&mut stream, debug) {
        Ok(shared_secret) => {
            let peer = stream.peer_addr().unwrap();
            println!("{peer} sntrup761x25519_sha512 mated with me");
            dprintln!(
                debug, 
                "[server] Shared secret (first 16 bytes): {}", 
                &shared_secret_hex(&shared_secret)[..32]
            );
        }
        Err(e) => {
            dprintln!(debug, "[server] Key exchange failed: {}", e);
            eprintln!("Key exchange failed: {}", e);
        }
    }
}

pub fn run(
    ip: &str, 
    port: u16, 
    debug: bool
) {
    dprintln!(debug, "[server] Starting server on {}:{}", ip, port);
    let listener = match TcpListener::bind((ip, port)) {
        Ok(l) => l,
        Err(e) => {
            eprintln!("Failed to bind to {}:{}: {}", ip, port, e);
            return;
        }
    };
    println!("Server listening on {}:{}", ip, port);
    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                dprintln!(debug, "[server] Incoming connection from {:?}", stream.peer_addr());
                initiate_client(stream, debug);
            }
            Err(e) => {
                dprintln!(debug, "[server] Connection error: {}", e);
            }
        }
    }
}
