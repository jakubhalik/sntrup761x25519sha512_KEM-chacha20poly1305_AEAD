use std::io::{Read, Write};
use std::net::TcpStream;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream as TokioTcpStream;
use crate::crypto::post_quantum::chacha20poly1305::{
    symm_key_from_shared_secret, encrypt, decrypt, NONCE_SIZE
};

const MAX_MESSAGE_LEN: usize = u8::MAX as usize;
fn validate_safe_text(text: &str) -> Result<(), String> {
    if text.is_empty() {
        return Err("Message is empty".to_string());
    }
    if text.len() > MAX_MESSAGE_LEN {
        return Err(format!(
            "Message too long: {} bytes (max {})",
            text.len(),
            MAX_MESSAGE_LEN
        ));
    }
    if text.chars().any(|c| c.is_control()) {
        return Err("Control characters are not allowed".to_string());
    }
    Ok(())
}

pub fn client(
    stream: &mut TcpStream,
    shared_secret: &[u8; 64],
    message: &str,
) -> Result<(), String> {
    let key = symm_key_from_shared_secret(shared_secret);
    let encrypted = encrypt(&key, message.as_bytes())?;
    let len = (encrypted.len() as u32).to_be_bytes();
    stream.write_all(&len).map_err(|e| e.to_string())?;
    stream.write_all(&encrypted).map_err(|e| e.to_string())?;
    stream.flush().map_err(|e| e.to_string())?;
    Ok(())
}

pub fn server(text: &str) -> Result<(), String> {
    if text.len() > MAX_MESSAGE_LEN {
        return Err(format!(
            "Message too long: {} bytes (max {})",
            text.len(),
            MAX_MESSAGE_LEN
        ));
    }
    validate_safe_text(text)?;
    println!("[mess_test_without_auth] {}", text);
    Ok(())
}
