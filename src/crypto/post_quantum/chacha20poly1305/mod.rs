use chacha20poly1305::{
    ChaCha20Poly1305, Key, Nonce,
    aead::{Aead, KeyInit},
};
use rand::RngCore;
use rand::rngs::OsRng;
use std::net::TcpStream;
use tokio::io::AsyncWriteExt;
//nonce=number only once
const KEY_SIZE: usize = 32;
pub const NONCE_SIZE: usize = 12;

pub fn symm_key_from_shared_secret(
    shared_secret: &[u8; 64]
) -> [u8; KEY_SIZE] {
    let mut key = [0u8; KEY_SIZE];
    key.copy_from_slice(&shared_secret[..KEY_SIZE]);
    key
}

pub fn encrypt(
    key_bytes: &[u8; KEY_SIZE],
    plaintext: &[u8]
) -> Result<Vec<u8>, String> {
    let key = Key::from_slice(key_bytes);
    let cipher = ChaCha20Poly1305::new(key);
    let mut nonce_bytes = [0u8; NONCE_SIZE];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);
    let ciphertext = cipher
        .encrypt(nonce, plaintext)
        .map_err(|e| format!("Encryption failed: {}", e))?;
    let mut output = Vec::with_capacity(NONCE_SIZE + ciphertext.len());
    output.extend_from_slice(&nonce_bytes);
    output.extend_from_slice(&ciphertext);
    Ok(output)
}

pub fn decrypt(
    key_bytes: &[u8; KEY_SIZE], 
    data: &[u8]
) -> Result<Vec<u8>, String> {
    if data.len() < NONCE_SIZE {
        return Err("Data too short to contain nonce".to_string());
    }
    let (nonce_bytes, ciphertext) = data.split_at(NONCE_SIZE);
    let key = Key::from_slice(key_bytes);
    let cipher = ChaCha20Poly1305::new(key);
    let nonce = Nonce::from_slice(nonce_bytes);
    cipher
        .decrypt(nonce, ciphertext)
        .map_err(|e| format!("Decryption failed: {}", e))
}

pub fn build_encrypt_send(
    stream: &mut TcpStream,
    shared_secret: &[u8; 64],
    traffic_name: &str,
    message: &str,
) -> Result<(), String> {

    let traffic_name_bytes = traffic_name.as_bytes();
    if traffic_name_bytes.len() > u8::MAX as usize {
        return Err("Traffic name too long".to_string());
    }

    let mut plaintext = Vec::with_capacity(
        1 + traffic_name_bytes.len() + message.len()
    );
    plaintext.push(traffic_name_bytes.len() as u8);
    plaintext.extend_from_slice(traffic_name_bytes);
    plaintext.extend_from_slice(message.as_bytes());

    let key = symm_key_from_shared_secret(shared_secret);
    let encrypted = encrypt(&key, &plaintext.as_bytes())?;
    let len = (encrypted.len() as u32).to_be_bytes();
    stream.write_all(&len).map_err(|e| e.to_string())?;
    stream.write_all(&encrypted).map_err(|e| e.to_string())?;
    stream.flush().map_err(|e| e.to_string())?;

    Ok(())

}
