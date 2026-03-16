use crate::dprintln;
use crate::crypto::post_quantum::sntrup761x25519_sha512::server_encapsulate;
use std::net::{TcpListener, TcpStream};

fn initiate_client(
    mut stream: TcpStream, 
    debug: bool
) {
    match server_encapsulate(&mut stream, debug) {
        Ok(_shared_secret) => {
            let peer = stream.peer_addr().unwrap();
            println!("{peer} sntrup761x25519_sha512 mated with me");
            //traffic();
        }
        Err(e) => {
            eprintln!("Key exchange failed: {}", e);
        }
    }
}

pub fn run(
    ip: &str, 
    port: u16, 
    debug: bool
) {
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
                initiate_client(stream, debug);
            }
            Err(e) => {
                dprintln!(debug, "[server] Connection error: {}", e);
            }
        }
    }
}
