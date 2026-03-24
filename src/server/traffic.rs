use tokio::io::AsyncReadExt;
use tokio::net::TcpStream;
use crate::crypto::post_quantum::chacha20poly1305::{
    decrypt, symm_key_from_shared_secret,
};

pub async fn traffic(
    stream: &mut TcpStream,
    shared_secret: &[u8; 64],
) {
    match read_decrypt_and_dispatch(stream, shared_secret).await {
        Ok(()) => {}
        Err(e) => {
            eprintln!("[traffic] {}", e);
        }
    }
}

async fn read_decrypt_and_dispatch(
    stream: &mut TcpStream,
    shared_secret: &[u8; 64],
) -> Result<(), String> {

    let mut len_bytes = [0u8; 4];
    stream.read_exact(&mut len_bytes)
        .await
        .map_err(|e| e.to_string())?;

    let encrypted_len = u32::from_be_bytes(len_bytes) as usize;
    if encrypted_len == 0 {
        return Err("Incoming encrypted payload is empty".to_string());
    }

    let mut encrypted = vec![0u8; encrypted_len];
    stream.read_exact(&mut encrypted)
        .await
        .map_err(|e| e.to_string())?;

    let symm_key = symm_key_from_shared_secret(shared_secret);
    let plaintext = decrypt(&symm_key, &encrypted)?;
    if plaintext.is_empty() {
        return Err("Decrypted traffic payload is empty".to_string());
    }

    let arg_len = plaintext[0] as usize;
    if plaintext.len() < 1 + arg_len {
        return Err("Decrypted payload too short for declared traffic name length".to_string());
    }
    let arg_bytes = &plaintext[1..1 + arg_len];
    let message_bytes = &plaintext[1 + arg_len..];
    let arg = std::str::from_utf8(arg_bytes)
        .map_err(|_| "Traffic name is not valid UTF-8".to_string())?;
    let message = std::str::from_utf8(message_bytes)
        .map_err(|_| "Traffic message is not valid UTF-8".to_string())?;

    crate::client::args::Args::dispatch_server_traffic(&arg, message_bytes);

    Ok(())
}
