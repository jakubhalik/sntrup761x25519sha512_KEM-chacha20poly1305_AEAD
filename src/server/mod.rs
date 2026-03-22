use tokio::net::{TcpListener, TcpStream};
use crate::dprintln;
use crate::crypto::post_quantum::sntrup761x25519_sha512::server_encapsulate;
mod traffic;

async fn initiate_server(
    mut stream: TcpStream, 
    debug: bool
) {
    match server_encapsulate(&mut stream, debug).await {
        Ok(_shared_secret) => {
            let peer = stream.peer_addr().unwrap();
            println!("{peer} sntrup761x25519_sha512 mated with me");
            traffic(&mut stream, &_shared_secret);
        }
        Err(e) => {
            eprintln!("Key exchange failed: {}", e);
        }
    }
}

#[tokio::main]
pub async fn run(
    ip: &str, 
    port: u16, 
    debug: bool
) {
    let listener = match TcpListener::bind((ip, port)).await {
        Ok(l) => l,
        Err(e) => {
            eprintln!("Failed to bind to {}:{}: {}", ip, port, e);
            return;
        }
    };
    println!("Server listening on {}:{}", ip, port);
    loop {
        match listener.accept().await {
            Ok((stream, _)) => {
                tokio::spawn(async move {
                    initiate_server(stream, debug).await;
                });
            }
            Err(e) => {
                dprintln!(debug, "[server] Connection error: {}", e);
            }
        }
    }
}
