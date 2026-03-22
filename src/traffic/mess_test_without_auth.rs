use std::io::{Read, Write};
use std::net::TcpStream;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream as TokioTcpStream;
use crate::crypto::post_quantum::chacha20poly1305::{
    symm_key_from_shared_secret, encrypt, decrypt,
};

const MAX_MESSAGE_LEN: usize = 255;
fn validate_safe_text(text: &str) -> Result<(), String> {
    if text.len() > MAX_MESSAGE_LEN {
        return Err(format!(
            "Message too long: {} bytes (max {})",
            text.len(),
            MAX_MESSAGE_LEN
        ));
    }
    if text.is_empty() {
        return Err("Message is empty".to_string());
    }
    for (i, c) in text.chars().enumerate() {
        if c.is_control() && c != ' ' {
            return Err(format!(
                "Disallowed control character at position {}: U+{:04X}",
                i,
                c as u32
            ));
        }
        match c {
            ';' | '|' | '&' | '`' | '$' | '\\' | '\'' | '"'
            | '<' | '>' | '{' | '}' | '\0' | '\n' | '\r' | '\t' => {
                return Err(format!(
                    "Disallowed character '{}' at position {}",
                    c, i
                ));
            }
            _ => {}
        }
    }
    Ok(())
}

pub fn client_send(
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

pub async fn server_receive(
    stream: &mut TokioTcpStream,
    shared_secret: &[u8; 64],
) -> Result<(), String> {
    let key = symm_key_from_shared_secret(shared_secret);
    let mut len_bytes = [0u8; 4];
    stream
        .read_exact(&mut len_bytes)
        .await
        .map_err(|e| e.to_string())?;
    let len = u32::from_be_bytes(len_bytes) as usize;
    if len > MAX_MESSAGE_LEN + 12 + 16 + 64 {
        return Err(format!("Incoming payload too large: {} bytes", len));
    }
    let mut encrypted = vec![0u8; len];
    stream
        .read_exact(&mut encrypted)
        .await
        .map_err(|e| e.to_string())?;
    let plaintext_bytes = decrypt(&key, &encrypted)?;
    let text = String::from_utf8(plaintext_bytes)
        .map_err(|_| "Decrypted data is not valid UTF-8".to_string())?;
    validate_safe_text(&text)?;
    println!("[mess_test_without_auth] {}", text);
    Ok(())
}
