use crate::crypto::post_quantum::sntrup761x25519_sha512::*;

#[cfg(test)]
mod tests {
    #[test]
    fn test_finite_field_element_operations() {
        let debug_flag = false;
        let element_a = FiniteFieldElement::new(100, debug_flag);
        let element_b = FiniteFieldElement::new(200, debug_flag);
        
        let sum_result = element_a.clone() + element_b.clone();
        assert_eq!(sum_result.value, 300);
        
        let difference_result = element_b.clone() - element_a.clone();
        assert_eq!(difference_result.value, 100);
        
        let product_result = element_a.clone() * element_b.clone();
        assert_eq!(product_result.value, 20000 % SNTRUP761_FIELD_MODULUS);
    }

    #[test]
    fn test_secure_hash_algorithm_512() {
        let debug_flag = false;
        let test_message = b"test message";
        let hash_result = SecureHashAlgorithm512::hash(test_message, debug_flag);
        assert_eq!(hash_result.len(), 64);
    }

    #[test]
    fn test_curve25519_key_generation() {
        let debug_flag = false;
        let curve25519_engine = Curve25519DiffieHellman::new(debug_flag);
        
        let private_key: [u8; 32] = [
            0x77, 0x07, 0x6d, 0x0a, 0x73, 0x18, 0xa5, 0x7d,
            0x3c, 0x16, 0xc1, 0x72, 0x51, 0xb2, 0x66, 0x45,
            0xdf, 0x4c, 0x2f, 0x87, 0xeb, 0xc0, 0x99, 0x2a,
            0xb1, 0x77, 0xfb, 0xa5, 0x1d, 0xb9, 0x2c, 0x2a,
        ];
        
        let public_key = curve25519_engine.generate_public_key(&private_key);
        assert_eq!(public_key.len(), 32);
    }

    #[test]
    fn test_polynomial_ring_element_encode_decode() {
        let debug_flag = false;
        let mut test_coefficients = Vec::with_capacity(SNTRUP761_PRIME_DEGREE);
        for index in 0..SNTRUP761_PRIME_DEGREE {
            test_coefficients.push(FiniteFieldElement::new(
                (index % 100) as i32 - 50, debug_flag
            ));
        }
        
        let original_polynomial = 
            PolynomialRingElement::from_coefficients(
                test_coefficients, 
                debug_flag
            );
        let encoded_bytes = original_polynomial.encode(debug_flag);
        let decoded_polynomial = 
            PolynomialRingElement::decode(&encoded_bytes, debug_flag);
        
        for coefficient_index in 0..SNTRUP761_PRIME_DEGREE {
            assert_eq!(
                original_polynomial.coefficients[coefficient_index].value,
                decoded_polynomial.coefficients[coefficient_index].value
            );
        }
    }

    #[test]
    fn test_small_polynomial_encode_decode() {
        let debug_flag = false;
        let mut test_coefficients = Vec::with_capacity(SNTRUP761_PRIME_DEGREE);
        for index in 0..SNTRUP761_PRIME_DEGREE {
            let value = match index % 3 {
                0 => -1,
                1 => 0,
                _ => 1,
            };
            test_coefficients.push(SmallCoefficient::new(value, debug_flag));
        }
        
        let original_polynomial = 
            SmallPolynomial::from_coefficients(
                test_coefficients, 
                debug_flag
            );
        let encoded_bytes = original_polynomial.encode(debug_flag);
        let decoded_polynomial = 
            SmallPolynomial::decode(&encoded_bytes, debug_flag);
        
        for coefficient_index in 0..SNTRUP761_PRIME_DEGREE {
            assert_eq!(
                original_polynomial.coefficients[coefficient_index].value,
                decoded_polynomial.coefficients[coefficient_index].value
            );
        }
    }

    #[test]
    fn test_full_key_exchange() {
        let debug_flag = false;
        let key_encapsulation_mechanism = Sntrup761X25519Sha512KeyEncapsulationMechanism::new(debug_flag);
        
        let mut keygen_random_bytes = vec![0u8; 2 * SNTRUP761_PRIME_DEGREE + X25519_SCALAR_SIZE + 100];
        for (byte_index, byte_value) in keygen_random_bytes.iter_mut().enumerate() {
            *byte_value = ((byte_index * 17 + 31) % 256) as u8;
        }
        
        let keypair = key_encapsulation_mechanism.generate_keypair(&keygen_random_bytes);
        
        assert_eq!(keypair.public_key.len(), PUBLIC_KEY_SIZE);
        assert_eq!(keypair.secret_key.len(), SECRET_KEY_SIZE);
        
        let mut encapsulation_random_bytes = vec![0u8; SNTRUP761_PRIME_DEGREE + X25519_SCALAR_SIZE + 100];
        for (byte_index, byte_value) in encapsulation_random_bytes.iter_mut().enumerate() {
            *byte_value = ((byte_index * 23 + 47) % 256) as u8;
        }
        
        let (ciphertext, shared_secret_sender) = 
            key_encapsulation_mechanism.encapsulate(&keypair.public_key, &encapsulation_random_bytes);
        
        assert_eq!(ciphertext.len(), CIPHERTEXT_SIZE);
        assert_eq!(shared_secret_sender.len(), SHARED_SECRET_SIZE);
        
        let shared_secret_receiver = key_encapsulation_mechanism.decapsulate(&keypair.secret_key, &ciphertext);
        
        assert_eq!(shared_secret_receiver.len(), SHARED_SECRET_SIZE);
        assert_eq!(shared_secret_sender, shared_secret_receiver);
    }

    #[test]
    fn test_rounded_polynomial_encode_decode() {
        let debug_flag = false;
        let mut test_coefficients = Vec::with_capacity(SNTRUP761_PRIME_DEGREE);
        for index in 0..SNTRUP761_PRIME_DEGREE {
            test_coefficients.push(FiniteFieldElement::new(((index % 200) as i32 - 100) * 3, debug_flag));
        }
        
        let ring_element_polynomial = PolynomialRingElement::from_coefficients(test_coefficients, debug_flag);
        let rounded = RoundedPolynomial::from_ring_element(&ring_element_polynomial, debug_flag);
        let encoded_bytes = rounded.encode(debug_flag);
        let decoded = RoundedPolynomial::decode(&encoded_bytes, debug_flag);
        
        for coefficient_index in 0..SNTRUP761_PRIME_DEGREE {
            assert_eq!(rounded.coefficients[coefficient_index], decoded.coefficients[coefficient_index]);
        }
    }
}

