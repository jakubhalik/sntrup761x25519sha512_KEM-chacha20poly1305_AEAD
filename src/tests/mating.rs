use std::net::TcpListener as StdTcpListener;
use std::thread;
use std::time::{Duration, Instant};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use tokio::net::TcpListener as TokioTcpListener;
use tokio::sync::Notify;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use pqcrypto_ntruprime::sntrup761;
use pqcrypto_traits::kem::{PublicKey as KemPublicKey, SharedSecret as KemSharedSecret, Ciphertext as KemCiphertext};
use x25519_dalek::{EphemeralSecret, PublicKey as X25519PublicKey};
use rand::rngs::OsRng;
use sha2::{Sha512, Digest};

const SNTRUP761_PK_SIZE: usize = 1158;
const SNTRUP761_CT_SIZE: usize = 1039;

fn combine_secrets(sntrup_ss: &[u8], x25519_ss: &[u8]) -> [u8; 64] {
    let mut hasher = Sha512::new();
    hasher.update(sntrup_ss);
    hasher.update(x25519_ss);
    let result = hasher.finalize();
    let mut output = [0u8; 64];
    output.copy_from_slice(&result);
    output
}

fn sync_server_encapsulate(stream: &mut std::net::TcpStream) -> Result<[u8; 64], String> {
    use std::io::{Read, Write};

    let mut sntrup_pk_bytes = vec![0u8; SNTRUP761_PK_SIZE];
    stream.read_exact(&mut sntrup_pk_bytes).map_err(|e| e.to_string())?;
    let mut x25519_pk_bytes = [0u8; 32];
    stream.read_exact(&mut x25519_pk_bytes).map_err(|e| e.to_string())?;

    let sntrup_pk = sntrup761::PublicKey::from_bytes(&sntrup_pk_bytes)
        .map_err(|_| "Invalid sntrup761 public key".to_string())?;
    let x25519_pk = X25519PublicKey::from(x25519_pk_bytes);

    let (sntrup_ss, sntrup_ct) = sntrup761::encapsulate(&sntrup_pk);

    let server_x25519_secret = EphemeralSecret::random_from_rng(OsRng);
    let server_x25519_public = X25519PublicKey::from(&server_x25519_secret);
    let x25519_ss = server_x25519_secret.diffie_hellman(&x25519_pk);

    stream.write_all(sntrup_ct.as_bytes()).map_err(|e| e.to_string())?;
    stream.write_all(&server_x25519_public.to_bytes()).map_err(|e| e.to_string())?;
    stream.flush().map_err(|e| e.to_string())?;

    Ok(combine_secrets(sntrup_ss.as_bytes(), x25519_ss.as_bytes()))
}

fn sync_client_decapsulate(stream: &mut std::net::TcpStream) -> Result<[u8; 64], String> {
    use std::io::{Read, Write};

    let (sntrup_pk, sntrup_sk) = sntrup761::keypair();
    let x25519_secret = EphemeralSecret::random_from_rng(OsRng);
    let x25519_public = X25519PublicKey::from(&x25519_secret);

    stream.write_all(sntrup_pk.as_bytes()).map_err(|e| e.to_string())?;
    stream.write_all(&x25519_public.to_bytes()).map_err(|e| e.to_string())?;
    stream.flush().map_err(|e| e.to_string())?;

    let mut sntrup_ct_bytes = vec![0u8; SNTRUP761_CT_SIZE];
    stream.read_exact(&mut sntrup_ct_bytes).map_err(|e| e.to_string())?;
    let mut server_x25519_pk_bytes = [0u8; 32];
    stream.read_exact(&mut server_x25519_pk_bytes).map_err(|e| e.to_string())?;

    let sntrup_ct = sntrup761::Ciphertext::from_bytes(&sntrup_ct_bytes)
        .map_err(|_| "Invalid ciphertext".to_string())?;
    let server_x25519_pk = X25519PublicKey::from(server_x25519_pk_bytes);

    let sntrup_ss = sntrup761::decapsulate(&sntrup_ct, &sntrup_sk);
    let x25519_ss = x25519_secret.diffie_hellman(&server_x25519_pk);

    Ok(combine_secrets(sntrup_ss.as_bytes(), x25519_ss.as_bytes()))
}

async fn async_server_encapsulate(stream: &mut tokio::net::TcpStream) -> Result<[u8; 64], String> {
    let mut sntrup_pk_bytes = vec![0u8; SNTRUP761_PK_SIZE];
    stream.read_exact(&mut sntrup_pk_bytes).await.map_err(|e| e.to_string())?;
    let mut x25519_pk_bytes = [0u8; 32];
    stream.read_exact(&mut x25519_pk_bytes).await.map_err(|e| e.to_string())?;

    let sntrup_pk = sntrup761::PublicKey::from_bytes(&sntrup_pk_bytes)
        .map_err(|_| "Invalid sntrup761 public key".to_string())?;
    let x25519_pk = X25519PublicKey::from(x25519_pk_bytes);

    let (sntrup_ss, sntrup_ct) = tokio::task::spawn_blocking(move || {
        sntrup761::encapsulate(&sntrup_pk)
    }).await.map_err(|e| e.to_string())?;

    let server_x25519_secret = EphemeralSecret::random_from_rng(OsRng);
    let server_x25519_public = X25519PublicKey::from(&server_x25519_secret);
    let x25519_ss = server_x25519_secret.diffie_hellman(&x25519_pk);

    stream.write_all(sntrup_ct.as_bytes()).await.map_err(|e| e.to_string())?;
    stream.write_all(&server_x25519_public.to_bytes()).await.map_err(|e| e.to_string())?;
    stream.flush().await.map_err(|e| e.to_string())?;

    Ok(combine_secrets(sntrup_ss.as_bytes(), x25519_ss.as_bytes()))
}

async fn async_client_decapsulate(stream: &mut tokio::net::TcpStream) -> Result<[u8; 64], String> {
    let (sntrup_pk, sntrup_sk) = tokio::task::spawn_blocking(|| {
        sntrup761::keypair()
    }).await.map_err(|e| e.to_string())?;

    let x25519_secret = EphemeralSecret::random_from_rng(OsRng);
    let x25519_public = X25519PublicKey::from(&x25519_secret);

    stream.write_all(sntrup_pk.as_bytes()).await.map_err(|e| e.to_string())?;
    stream.write_all(&x25519_public.to_bytes()).await.map_err(|e| e.to_string())?;
    stream.flush().await.map_err(|e| e.to_string())?;

    let mut sntrup_ct_bytes = vec![0u8; SNTRUP761_CT_SIZE];
    stream.read_exact(&mut sntrup_ct_bytes).await.map_err(|e| e.to_string())?;
    let mut server_x25519_pk_bytes = [0u8; 32];
    stream.read_exact(&mut server_x25519_pk_bytes).await.map_err(|e| e.to_string())?;

    let sntrup_ct = sntrup761::Ciphertext::from_bytes(&sntrup_ct_bytes)
        .map_err(|_| "Invalid ciphertext".to_string())?;
    let server_x25519_pk = X25519PublicKey::from(server_x25519_pk_bytes);

    let sntrup_ss = tokio::task::spawn_blocking(move || {
        sntrup761::decapsulate(&sntrup_ct, &sntrup_sk)
    }).await.map_err(|e| e.to_string())?;

    let x25519_ss = x25519_secret.diffie_hellman(&server_x25519_pk);

    Ok(combine_secrets(sntrup_ss.as_bytes(), x25519_ss.as_bytes()))
}

fn find_available_port() -> u16 {
    let listener = StdTcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    drop(listener);
    port
}

fn sync_stress_test(duration: Duration) -> (u64, u64) {
    let port = find_available_port();
    let shutdown = Arc::new(AtomicBool::new(false));
    let shutdown_clone = shutdown.clone();

    thread::spawn(move || {
        let listener = StdTcpListener::bind(("127.0.0.1", port)).unwrap();
        listener.set_nonblocking(true).unwrap();

        while !shutdown_clone.load(Ordering::Relaxed) {
            match listener.accept() {
                Ok((mut stream, _)) => {
                    stream.set_nonblocking(false).unwrap();
                    stream.set_read_timeout(Some(Duration::from_secs(10))).ok();
                    stream.set_write_timeout(Some(Duration::from_secs(10))).ok();
                    let _ = sync_server_encapsulate(&mut stream);
                }
                Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(1));
                }
                Err(_) => {}
            }
        }
    });

    thread::sleep(Duration::from_millis(50));

    let successes = Arc::new(AtomicU64::new(0));
    let failures = Arc::new(AtomicU64::new(0));
    let start = Instant::now();

    while start.elapsed() < duration {
        let mut stream = match std::net::TcpStream::connect(("127.0.0.1", port)) {
            Ok(s) => s,
            Err(_) => {
                failures.fetch_add(1, Ordering::Relaxed);
                continue;
            }
        };
        stream.set_read_timeout(Some(Duration::from_secs(10))).ok();
        stream.set_write_timeout(Some(Duration::from_secs(10))).ok();

        match sync_client_decapsulate(&mut stream) {
            Ok(_) => { successes.fetch_add(1, Ordering::Relaxed); }
            Err(_) => { failures.fetch_add(1, Ordering::Relaxed); }
        }
    }

    shutdown.store(true, Ordering::Relaxed);
    thread::sleep(Duration::from_millis(100));

    (successes.load(Ordering::Relaxed), failures.load(Ordering::Relaxed))
}

async fn async_stress_test(duration: Duration, num_clients: usize) -> (u64, u64) {
    let listener = TokioTcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let shutdown = Arc::new(Notify::new());

    let shutdown_clone = shutdown.clone();
    tokio::spawn(async move {
        loop {
            tokio::select! {
                result = listener.accept() => {
                    if let Ok((mut stream, _)) = result {
                        tokio::spawn(async move {
                            let _ = async_server_encapsulate(&mut stream).await;
                        });
                    }
                }
                _ = shutdown_clone.notified() => { break; }
            }
        }
    });

    let successes = Arc::new(AtomicU64::new(0));
    let failures = Arc::new(AtomicU64::new(0));
    let start = Instant::now();

    let mut handles = Vec::new();
    for _ in 0..num_clients {
        let cs = successes.clone();
        let cf = failures.clone();
        let handle = tokio::spawn(async move {
            while start.elapsed() < duration {
                match tokio::net::TcpStream::connect(("127.0.0.1", port)).await {
                    Ok(mut stream) => {
                        match async_client_decapsulate(&mut stream).await {
                            Ok(_) => { cs.fetch_add(1, Ordering::Relaxed); }
                            Err(_) => { cf.fetch_add(1, Ordering::Relaxed); }
                        }
                    }
                    Err(_) => { cf.fetch_add(1, Ordering::Relaxed); }
                }
            }
        });
        handles.push(handle);
    }

    for handle in handles {
        handle.await.unwrap();
    }

    shutdown.notify_one();
    tokio::time::sleep(Duration::from_millis(50)).await;

    (successes.load(Ordering::Relaxed), failures.load(Ordering::Relaxed))
}

#[test]
fn test_sync_single_exchange() {
    let port = find_available_port();

    let server = thread::spawn(move || {
        let listener = StdTcpListener::bind(("127.0.0.1", port)).unwrap();
        let (mut stream, _) = listener.accept().unwrap();
        stream.set_read_timeout(Some(Duration::from_secs(10))).ok();
        stream.set_write_timeout(Some(Duration::from_secs(10))).ok();
        sync_server_encapsulate(&mut stream).unwrap()
    });

    thread::sleep(Duration::from_millis(50));

    let mut stream = std::net::TcpStream::connect(("127.0.0.1", port)).unwrap();
    stream.set_read_timeout(Some(Duration::from_secs(10))).ok();
    stream.set_write_timeout(Some(Duration::from_secs(10))).ok();
    let client_secret = sync_client_decapsulate(&mut stream).unwrap();

    let server_secret = server.join().unwrap();

    assert_eq!(client_secret, server_secret);
    assert!(client_secret.iter().any(|&b| b != 0));
    println!("[sync_single] secrets match: {:02x?}", &client_secret[..16]);
}

#[tokio::test]
async fn test_async_single_exchange() {
    let listener = TokioTcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        async_server_encapsulate(&mut stream).await.unwrap()
    });
    let mut stream = tokio::net::TcpStream::connect(("127.0.0.1", port)).await.unwrap();
    let client_secret = async_client_decapsulate(&mut stream).await.unwrap();
    let server_secret = server.await.unwrap();
    assert_eq!(client_secret, server_secret);
    assert!(client_secret.iter().any(|&b| b != 0));
    println!("[async_single] secrets match: {:02x?}", &client_secret[..16]);
}

#[test]
fn test_sync_stress_1_second() {
    let duration = Duration::from_secs(1);
    let (successes, failures) = sync_stress_test(duration);
    let rate = successes as f64 / duration.as_secs_f64();
    println!(
        "[sync_1s] {} successes, {} failures, {:.1} exchanges/sec (1 server thread, 1 client thread)",
        successes, failures, rate
    );
    assert!(successes > 0);
}

#[test]
fn test_sync_stress_5_seconds() {
    let duration = Duration::from_secs(5);
    let (successes, failures) = sync_stress_test(duration);
    let rate = successes as f64 / duration.as_secs_f64();
    println!(
        "[sync_5s] {} successes, {} failures, {:.1} exchanges/sec (1 server thread, 1 client thread)",
        successes, failures, rate
    );
    assert!(successes > 0);
}

#[tokio::test(flavor = "multi_thread")]
async fn test_async_stress_1_second() {
    let duration = Duration::from_secs(1);
    let num_clients = 16;
    let (successes, failures) = async_stress_test(duration, num_clients).await;
    let rate = successes as f64 / duration.as_secs_f64();
    println!(
        "[async_1s] {} successes, {} failures, {:.1} exchanges/sec ({} concurrent clients, 8 worker threads)",
        successes, failures, rate, num_clients
    );
    assert!(successes > 0);
}

#[tokio::test(flavor = "multi_thread")]
async fn test_async_stress_5_seconds() {
    let duration = Duration::from_secs(5);
    let num_clients = 16;
    let (successes, failures) = async_stress_test(duration, num_clients).await;
    let rate = successes as f64 / duration.as_secs_f64();
    println!(
        "[async_5s] {} successes, {} failures, {:.1} exchanges/sec ({} concurrent clients, 8 worker threads)",
        successes, failures, rate, num_clients
    );
    assert!(successes > 0);
}
