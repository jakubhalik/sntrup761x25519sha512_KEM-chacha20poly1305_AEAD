use crate::crypto::post_quantum::sntrup761x25519_sha512::*;

pub fn run() {
    let debug_flag = true;

    println!("Starting SNTRUP761x25519-SHA512 end-to-end test");

    let key_encapsulation_mechanism =
        Sntrup761X25519Sha512KeyEncapsulationMechanism::new(debug_flag);

    println!("Generating random bytes for key generation");
    let mut keygen_random_bytes =
        vec![0u8; 2 * SNTRUP761_PRIME_DEGREE + X25519_SCALAR_SIZE + 100];
    for (byte_index, byte_value) in keygen_random_bytes.iter_mut().enumerate() {
        *byte_value = ((byte_index * 17 + 31) % 256) as u8;
    }

    println!("Generating keypair");
    let keypair = key_encapsulation_mechanism.generate_keypair(&keygen_random_bytes);

    println!("Public key size: {} bytes", keypair.public_key.len());
    println!("Secret key size: {} bytes", keypair.secret_key.len());

    println!("Generating random bytes for encapsulation");
    let mut encapsulation_random_bytes =
        vec![0u8; SNTRUP761_PRIME_DEGREE + X25519_SCALAR_SIZE + 100];
    for (byte_index, byte_value) in encapsulation_random_bytes.iter_mut().enumerate() {
        *byte_value = ((byte_index * 23 + 47) % 256) as u8;
    }

    println!("Performing encapsulation");
    let (ciphertext, shared_secret_sender) = key_encapsulation_mechanism
        .encapsulate(&keypair.public_key, &encapsulation_random_bytes);

    println!("Ciphertext size: {} bytes", ciphertext.len());
    println!(
        "Sender shared secret: {:02x?}",
        &shared_secret_sender[..8]
    );

    println!("Performing decapsulation");
    let shared_secret_receiver =
        key_encapsulation_mechanism.decapsulate(
            &keypair.secret_key, 
            &ciphertext
        );

    println!(
        "Receiver shared secret: {:02x?}",
        &shared_secret_receiver[..8]
    );

    if shared_secret_sender == shared_secret_receiver {
        println!("SUCCESS: Shared secrets match!");
    } else {
        println!("FAILURE: Shared secrets do not match!");
        std::process::exit(1);
    }
}
