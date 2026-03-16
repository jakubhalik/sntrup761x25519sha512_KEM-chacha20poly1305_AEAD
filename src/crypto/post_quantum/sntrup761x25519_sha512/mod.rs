use sha2::{Sha512, Digest};
use x25519_dalek::{EphemeralSecret, PublicKey as X25519PublicKey};
use pqcrypto_ntruprime::sntrup761;
use rand::rngs::OsRng;
use pqcrypto_traits::kem::{
    PublicKey as KemPublicKey, 
    SharedSecret as KemSharedSecret, 
    Ciphertext as KemCiphertext
};
use std::io::{Read, Write};
use std::net::TcpStream;

pub struct HybridKeyPair {
    pub sntrup_pk: sntrup761::PublicKey,
    pub sntrup_sk: sntrup761::SecretKey,
    pub x25519_secret: EphemeralSecret,
    pub x25519_public: X25519PublicKey,
}
pub struct HybridPublicKeys {
    pub sntrup_pk_bytes: Vec<u8>,
    pub x25519_pk_bytes: [u8; 32],
}
struct ReceivedPublicKeys {
    sntrup_pk: sntrup761::PublicKey,
    x25519_pk: X25519PublicKey,
}

impl HybridKeyPair {
    pub fn generate(_debug: bool) -> Self {
        let (sntrup_pk, sntrup_sk) = sntrup761::keypair();
        let x25519_secret = EphemeralSecret::random_from_rng(OsRng);
        let x25519_public = X25519PublicKey::from(&x25519_secret);
        Self {
            sntrup_pk,
            sntrup_sk,
            x25519_secret,
            x25519_public,
        }
    }
    pub fn get_public_keys(&self) -> HybridPublicKeys {
        HybridPublicKeys {
            sntrup_pk_bytes: self.sntrup_pk.as_bytes().to_vec(),
            x25519_pk_bytes: self.x25519_public.to_bytes(),
        }
    }
}

fn combine_secrets(
    sntrup_shared_secret: &[u8], 
    x25519_shared_secret: &[u8], 
    _debug: bool
) -> [u8; 64] {
    let mut hasher = Sha512::new();
    hasher.update(sntrup_shared_secret);
    hasher.update(x25519_shared_secret);
    let result = hasher.finalize();
    let mut output = [0u8; 64];
    output.copy_from_slice(&result);
    output
}

fn receive_public_keys(
    stream: &mut TcpStream, 
    _debug: bool
) -> Result<ReceivedPublicKeys, String> {

    let mut len_buf = [0u8; 4];
    stream.read_exact(&mut len_buf).map_err(|e| e.to_string())?;
    let sntrup_pk_len = u32::from_be_bytes(len_buf) as usize;
    const SNTRUP761_PK_SIZE: usize = 1158;
    if sntrup_pk_len != SNTRUP761_PK_SIZE {
        return Err(format!("Invalid sntrup761 public key size: expected {}, got {}", SNTRUP761_PK_SIZE, sntrup_pk_len));
    }
    let mut sntrup_pk_bytes = vec![0u8; sntrup_pk_len];
    stream.read_exact(&mut sntrup_pk_bytes).map_err(|e| e.to_string())?;
    let mut x25519_pk_bytes = [0u8; 32];
    stream.read_exact(&mut x25519_pk_bytes).map_err(|e| e.to_string())?;
    let sntrup_pk = sntrup761::PublicKey::from_bytes(&sntrup_pk_bytes)
        .map_err(|_| "Invalid sntrup761 public key")?;
    let x25519_pk = X25519PublicKey::from(x25519_pk_bytes);
    Ok(ReceivedPublicKeys { sntrup_pk, x25519_pk })

}

pub fn server_encapsulate(
    stream: &mut TcpStream,
    _debug: bool,
) -> Result<[u8; 64], String> {
    let client_keys = receive_public_keys(stream, _debug)?;
    let (sntrup_shared_secret, sntrup_ciphertext) = sntrup761::encapsulate(&client_keys.sntrup_pk);
    let server_x25519_secret = EphemeralSecret::random_from_rng(OsRng);
    let server_x25519_public = X25519PublicKey::from(&server_x25519_secret);
    let x25519_shared_secret = server_x25519_secret.diffie_hellman(&client_keys.x25519_pk);
    let sntrup_ciphertext_bytes = sntrup_ciphertext.as_bytes();
    
    stream.write_all(&(sntrup_ciphertext_bytes.len() as u32).to_be_bytes()).map_err(|e| e.to_string())?;
    stream.write_all(sntrup_ciphertext_bytes).map_err(|e| e.to_string())?;
    stream.write_all(&server_x25519_public.to_bytes()).map_err(|e| e.to_string())?;
    stream.flush().map_err(|e| e.to_string())?;
    
    let shared_secret = combine_secrets(
        sntrup_shared_secret.as_bytes(),
        x25519_shared_secret.as_bytes(),
        _debug
    );
    Ok(shared_secret)
}

pub fn client_decapsulate(
    stream: &mut TcpStream,
    keypair: HybridKeyPair,
    _debug: bool,
) -> Result<[u8; 64], String> {

    let public_keys = keypair.get_public_keys();
    stream.write_all(&(public_keys.sntrup_pk_bytes.len() as u32).to_be_bytes()).map_err(|e| e.to_string())?;
    stream.write_all(&public_keys.sntrup_pk_bytes).map_err(|e| e.to_string())?;
    stream.write_all(&public_keys.x25519_pk_bytes).map_err(|e| e.to_string())?;
    stream.flush().map_err(|e| e.to_string())?;
    
    let mut len_buf = [0u8; 4];
    stream.read_exact(&mut len_buf).map_err(|e| e.to_string())?;
    let sntrup_ciphertext_len = u32::from_be_bytes(len_buf) as usize;
    const SNTRUP761_CT_SIZE: usize = 1039;
    if sntrup_ciphertext_len != SNTRUP761_CT_SIZE {
        return Err(format!("Invalid sntrup761 ciphertext size: expected {}, got {}", SNTRUP761_CT_SIZE, sntrup_ciphertext_len));
    }
    let mut sntrup_ciphertext_bytes = vec![0u8; sntrup_ciphertext_len];
    stream.read_exact(&mut sntrup_ciphertext_bytes).map_err(|e| e.to_string())?;
    let mut server_x25519_pk_bytes = [0u8; 32];
    stream.read_exact(&mut server_x25519_pk_bytes).map_err(|e| e.to_string())?;
    let sntrup_ciphertext = sntrup761::Ciphertext::from_bytes(&sntrup_ciphertext_bytes)
        .map_err(|_| "Invalid sntrup761 ciphertext")?;
    let server_x25519_pk = X25519PublicKey::from(server_x25519_pk_bytes);
    let sntrup_shared_secret = sntrup761::decapsulate(&sntrup_ciphertext, &keypair.sntrup_sk);
    let x25519_shared_secret = keypair.x25519_secret.diffie_hellman(&server_x25519_pk);
    
    let shared_secret = combine_secrets(
        sntrup_shared_secret.as_bytes(), 
        x25519_shared_secret.as_bytes(), 
        _debug
    );
    Ok(shared_secret)
}

pub fn shared_secret_hex(secret: &[u8; 64]) -> String {
    secret.iter().map(|b| format!("{:02x}", b)).collect()
}
