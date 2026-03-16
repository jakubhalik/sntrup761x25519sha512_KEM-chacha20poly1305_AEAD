use crate::dprintln;
use crate::crypto::post_quantum::sntrup761x25519_sha512::HybridKeyPair;
use crate::crypto::post_quantum::sntrup761x25519_sha512::client_decapsulate;
use crate::crypto::post_quantum::sntrup761x25519_sha512::shared_secret_hex;
use std::net::TcpStream;

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
        Ok(shared_secret) => {
            println!("sntrup761x25519_sha512 mated with {}", port);
            dprintln!(debug, "[client] Shared secret (first 16 bytes): {}", 
                &shared_secret_hex(&shared_secret)[..32]);
        }
        Err(e) => {
            dprintln!(debug, "[client] Key exchange failed: {}", e);
            eprintln!("Key exchange failed: {}", e);
        }
    }
}
