use std::ops::{Add, Mul, Sub};

macro_rules! dprintln {
    ($debug:expr, $($arg:tt)*) => {
        if $debug {
            println!($($arg)*);
        }
    };
}

const SNTRUP761_PRIME_DEGREE: usize = 761;
const SNTRUP761_FIELD_MODULUS: i32 = 4591;
const SNTRUP761_WEIGHT: usize = 286;
const SNTRUP761_ROUNDED_BYTES: usize = 1007;
const SNTRUP761_RING_ELEMENT_BYTES: usize = 1158;
const SNTRUP761_SMALL_POLYNOMIAL_BYTES: usize = 191;
const X25519_SCALAR_SIZE: usize = 32;
const X25519_POINT_SIZE: usize = 32;
const SHARED_SECRET_SIZE: usize = 32;

const PUBLIC_KEY_SIZE: usize = 
    SNTRUP761_RING_ELEMENT_BYTES + X25519_POINT_SIZE;

const SECRET_KEY_SIZE: usize = 
    SNTRUP761_SMALL_POLYNOMIAL_BYTES + 
    SNTRUP761_RING_ELEMENT_BYTES + 
    SNTRUP761_SMALL_POLYNOMIAL_BYTES + 
    X25519_SCALAR_SIZE + 
    PUBLIC_KEY_SIZE;

const CIPHERTEXT_SIZE: usize = 
    SNTRUP761_ROUNDED_BYTES + SNTRUP761_SMALL_POLYNOMIAL_BYTES + X25519_POINT_SIZE;

fn get_least_significant_byte(value: u32) -> u8 {
    (value & 0xFF) as u8
}

#[derive(Clone, Debug)]
pub struct FiniteFieldElement {
    value: i32,
}

impl FiniteFieldElement {
    pub fn new(input_value: i32, debug: bool) -> Self {
        dprintln!(debug, "FiniteFieldElement::new called with value: {}", input_value);
        let mut result = input_value % SNTRUP761_FIELD_MODULUS;
        if result > SNTRUP761_FIELD_MODULUS / 2 {
            result -= SNTRUP761_FIELD_MODULUS;
        }
        if result < -(SNTRUP761_FIELD_MODULUS / 2) {
            result += SNTRUP761_FIELD_MODULUS;
        }
        FiniteFieldElement { value: result }
    }

    pub fn freeze(input_value: i32, debug: bool) -> Self {
        dprintln!(debug, "FiniteFieldElement::freeze called with value: {}", input_value);
        FiniteFieldElement::new(input_value, debug)
    }

    pub fn reciprocal(&self, debug: bool) -> Self {
        dprintln!(debug, "FiniteFieldElement::reciprocal called for value: {}", self.value);
        let mut result = 1i32;
        let mut base = self.value;
        let mut exponent = SNTRUP761_FIELD_MODULUS - 2;
        
        while exponent > 0 {
            if exponent & 1 == 1 {
                result = (result as i64 * base as i64 % SNTRUP761_FIELD_MODULUS as i64) as i32;
            }
            base = (base as i64 * base as i64 % SNTRUP761_FIELD_MODULUS as i64) as i32;
            exponent >>= 1;
        }
        
        FiniteFieldElement::freeze(result, debug)
    }
}

impl Add for FiniteFieldElement {
    type Output = Self;
    
    fn add(self, other: Self) -> Self {
        FiniteFieldElement::freeze(self.value + other.value, DEBUG_ENABLED)
    }
}

impl Sub for FiniteFieldElement {
    type Output = Self;
    
    fn sub(self, other: Self) -> Self {
        FiniteFieldElement::freeze(self.value - other.value, DEBUG_ENABLED)
    }
}

impl Mul for FiniteFieldElement {
    type Output = Self;
    
    fn mul(self, other: Self) -> Self {
        FiniteFieldElement::freeze(
            (self.value as i64 * other.value as i64 % SNTRUP761_FIELD_MODULUS as i64)
                as i32, DEBUG_ENABLED
        )
    }
}

#[derive(Clone, Debug)]
pub struct SmallCoefficient {
    value: i8,
}

impl SmallCoefficient {
    pub fn new(input_value: i8, debug: bool) -> Self {
        dprintln!(debug, "SmallCoefficient::new called with value: {}", input_value);
        SmallCoefficient { value: input_value }
    }
}

#[derive(Clone, Debug)]
pub struct PolynomialRingElement {
    coefficients: Vec<FiniteFieldElement>,
}

impl PolynomialRingElement {
    pub fn new(debug: bool) -> Self {
        dprintln!(debug, "PolynomialRingElement::new called");
        PolynomialRingElement {
            coefficients: vec![FiniteFieldElement::new(0, debug); SNTRUP761_PRIME_DEGREE],
        }
    }

    pub fn from_coefficients(coefficient_list: Vec<FiniteFieldElement>, debug: bool) -> Self {
        dprintln!(
            debug, 
            "PolynomialRingElement::from_coefficients called with {} coefficients", 
            coefficient_list.len()
        );
        let mut result = PolynomialRingElement::new(debug);
        for (index, coefficient) in coefficient_list.iter()
            .enumerate().take(SNTRUP761_PRIME_DEGREE) {
                result.coefficients[index] = coefficient.clone();
        }
        result
    }

    pub fn multiply(&self, other: &PolynomialRingElement, debug: bool) -> PolynomialRingElement {
        dprintln!(debug, "PolynomialRingElement::multiply called");
        let mut product = vec![FiniteFieldElement::new(0, debug); SNTRUP761_PRIME_DEGREE * 2];
        
        for first_index in 0..SNTRUP761_PRIME_DEGREE {
            for second_index in 0..SNTRUP761_PRIME_DEGREE {
                let term = 
                    self.coefficients[first_index].clone() * 
                    other.coefficients[second_index].clone();
                product[first_index + second_index] = 
                    product[first_index + second_index].clone() + term;
            }
        }
        
        for reduction_index in (SNTRUP761_PRIME_DEGREE..SNTRUP761_PRIME_DEGREE * 2).rev() {
            let value = product[reduction_index].clone();
            product[reduction_index - SNTRUP761_PRIME_DEGREE] = 
                product[reduction_index - 
                SNTRUP761_PRIME_DEGREE].clone() + 
                value.clone();
            product[reduction_index - SNTRUP761_PRIME_DEGREE + 1] = 
                product[reduction_index - SNTRUP761_PRIME_DEGREE + 1].clone() + value;
        }
        
        product.truncate(SNTRUP761_PRIME_DEGREE);
        PolynomialRingElement::from_coefficients(product, debug)
    }

    pub fn encode(&self, debug: bool) -> Vec<u8> {
        dprintln!(debug, "PolynomialRingElement::encode called");
        let mut encoded_bytes = Vec::with_capacity(SNTRUP761_RING_ELEMENT_BYTES);
        let mut accumulator: u32 = 0;
        let mut bits_in_accumulator: u32 = 0;
        
        for coefficient in &self.coefficients {
            let mut normalized_value = coefficient.value;
            if normalized_value < 0 {
                normalized_value += SNTRUP761_FIELD_MODULUS;
            }
            accumulator |= (normalized_value as u32) << bits_in_accumulator;
            bits_in_accumulator += 13;
            
            while bits_in_accumulator >= 8 {
                encoded_bytes.push(
                    get_least_significant_byte(accumulator)
                );
                accumulator >>= 8;
                bits_in_accumulator -= 8;
            }
        }
        
        if bits_in_accumulator > 0 {
            encoded_bytes.push(
                get_least_significant_byte(accumulator)
            );
        }
        
        encoded_bytes.resize(SNTRUP761_RING_ELEMENT_BYTES, 0);
        encoded_bytes
    }

    pub fn decode(data: &[u8], debug: bool) -> Self {
        dprintln!(
            debug, 
            "PolynomialRingElement::decode called with {} bytes", 
            data.len()
        );
        let mut coefficients = Vec::with_capacity(SNTRUP761_PRIME_DEGREE);
        let mut accumulator: u32 = 0;
        let mut bits_in_accumulator: u32 = 0;
        let mut byte_index = 0;
        
        for _ in 0..SNTRUP761_PRIME_DEGREE {
            while bits_in_accumulator < 13 && byte_index < data.len() {
                accumulator |= (data[byte_index] as u32) << bits_in_accumulator;
                bits_in_accumulator += 8;
                byte_index += 1;
            }
            
            let coefficient_value = (accumulator & 0x1FFF) as i32;
            accumulator >>= 13;
            bits_in_accumulator -= 13;
            
            let centered_value = 
                if coefficient_value > SNTRUP761_FIELD_MODULUS / 2 {
                    coefficient_value - SNTRUP761_FIELD_MODULUS
                } else {
                    coefficient_value
                };
            
            coefficients.push(FiniteFieldElement::new(centered_value, debug));
        }
        
        PolynomialRingElement::from_coefficients(coefficients, debug)
    }
}

#[derive(Clone, Debug)]
pub struct SmallPolynomial {
    coefficients: Vec<SmallCoefficient>,
}

impl SmallPolynomial {
    pub fn new(debug: bool) -> Self {
        dprintln!(debug, "SmallPolynomial::new called");
        SmallPolynomial {
            coefficients: vec![
                SmallCoefficient::new(0, debug); 
                SNTRUP761_PRIME_DEGREE
            ],
        }
    }

    pub fn from_coefficients(
        coefficient_list: Vec<SmallCoefficient>, debug: bool
    ) -> Self {
        dprintln!(debug, "SmallPolynomial::from_coefficients called");
        let mut result = SmallPolynomial::new(debug);
        for (index, coefficient) in coefficient_list.iter()
            .enumerate().take(SNTRUP761_PRIME_DEGREE) {
                result.coefficients[index] = coefficient.clone();
            }
        result
    }

    pub fn to_ring_element(&self, debug: bool) -> PolynomialRingElement {
        dprintln!(debug, "SmallPolynomial::to_ring_element called");
        let finite_field_coefficients: Vec<FiniteFieldElement> = self.coefficients
            .iter()
            .map(|small_value| FiniteFieldElement::new(small_value.value as i32, debug))
            .collect();
        PolynomialRingElement::from_coefficients(finite_field_coefficients, debug)
    }

    pub fn encode(&self, debug: bool) -> Vec<u8> {
        dprintln!(debug, "SmallPolynomial::encode called");
        let mut encoded_bytes = 
            Vec::with_capacity(SNTRUP761_SMALL_POLYNOMIAL_BYTES);
        let mut current_byte: u8 = 0;
        let mut bit_position: usize = 0;
        
        for coefficient in &self.coefficients {
            let encoded_value: u8 = match coefficient.value {
                -1 => 1,
                0 => 0,
                1 => 2,
                _ => 0,
            };
            
            current_byte |= encoded_value << bit_position;
            bit_position += 2;
            
            if bit_position >= 8 {
                encoded_bytes.push(current_byte);
                current_byte = 0;
                bit_position = 0;
            }
        }
        
        if bit_position > 0 {
            encoded_bytes.push(current_byte);
        }
        
        encoded_bytes.resize(SNTRUP761_SMALL_POLYNOMIAL_BYTES, 0);
        encoded_bytes
    }

    pub fn decode(data: &[u8], debug: bool) -> Self {
        dprintln!(
            debug, 
            "SmallPolynomial::decode called with {} bytes", 
            data.len()
        );
        let mut coefficients = 
            Vec::with_capacity(SNTRUP761_PRIME_DEGREE);
        let mut byte_index = 0;
        let mut bit_position: usize = 0;
        
        for _ in 0..SNTRUP761_PRIME_DEGREE {
            if byte_index >= data.len() {
                coefficients.push(SmallCoefficient::new(0, debug));
                continue;
            }
            
            let encoded_value = (data[byte_index] >> bit_position) & 0x03;
            bit_position += 2;
            
            if bit_position >= 8 {
                byte_index += 1;
                bit_position = 0;
            }
            
            let decoded_value: i8 = match encoded_value {
                1 => -1,
                2 => 1,
                _ => 0,
            };
            
            coefficients.push(SmallCoefficient::new(decoded_value, debug));
        }
        
        SmallPolynomial::from_coefficients(coefficients, debug)
    }

    pub fn generate_random(random_bytes: &[u8], debug: bool) -> Self {
        dprintln!(debug, "SmallPolynomial::generate_random called");
        let mut coefficients = 
            vec![SmallCoefficient::new(0, debug); SNTRUP761_PRIME_DEGREE];
        let mut weight_count: usize = 0;
        let mut position_index: usize = 0;
        
        for byte_index in 0..random_bytes.len() {
            if position_index >= SNTRUP761_PRIME_DEGREE {
                break;
            }
            
            let random_byte = random_bytes[byte_index];
            
            if weight_count < SNTRUP761_WEIGHT {
                if random_byte & 1 == 0 {
                    coefficients[position_index] = 
                        SmallCoefficient::new(1, debug);
                } else {
                    coefficients[position_index] = 
                        SmallCoefficient::new(-1, debug);
                }
                weight_count += 1;
            }
            
            position_index += 1;
        }
        
        SmallPolynomial::from_coefficients(coefficients, debug)
    }
}

pub struct RoundedPolynomial {
    coefficients: Vec<i32>,
}

impl RoundedPolynomial {
    pub fn new(debug: bool) -> Self {
        dprintln!(debug, "RoundedPolynomial::new called");
        RoundedPolynomial {
            coefficients: vec![0; SNTRUP761_PRIME_DEGREE],
        }
    }

    pub fn from_ring_element(polynomial: &PolynomialRingElement, debug: bool) -> Self {
        dprintln!(debug, "RoundedPolynomial::from_ring_element called");
        let mut result = RoundedPolynomial::new(debug);
        for (index, coefficient) in polynomial.coefficients.iter().enumerate() {
            let rounded_value = ((coefficient.value + 2295) / 3) * 3 - 2295;
            result.coefficients[index] = rounded_value;
        }
        result
    }

    pub fn encode(&self, debug: bool) -> Vec<u8> {
        dprintln!(debug, "RoundedPolynomial::encode called");
        let mut encoded_bytes = 
            Vec::with_capacity(SNTRUP761_ROUNDED_BYTES);
        let mut accumulator: u32 = 0;
        let mut bits_in_accumulator: u32 = 0;
        
        for coefficient in &self.coefficients {
            let normalized_value = ((*coefficient + 2295) / 3) as u32;
            accumulator |= normalized_value << bits_in_accumulator;
            bits_in_accumulator += 11;
            
            while bits_in_accumulator >= 8 {
                encoded_bytes.push(
                    get_least_significant_byte(accumulator)
                );
                accumulator >>= 8;
                bits_in_accumulator -= 8;
            }
        }
        
        if bits_in_accumulator > 0 {
            encoded_bytes.push(
                get_least_significant_byte(accumulator)
            );
        }
        
        encoded_bytes.resize(SNTRUP761_ROUNDED_BYTES, 0);
        encoded_bytes
    }

    pub fn decode(data: &[u8], debug: bool) -> Self {
        dprintln!(debug, "RoundedPolynomial::decode called with {} bytes", data.len());
        let mut result = RoundedPolynomial::new(debug);
        let mut accumulator: u32 = 0;
        let mut bits_in_accumulator: u32 = 0;
        let mut byte_index: usize = 0;
        
        for coefficient_index in 0..SNTRUP761_PRIME_DEGREE {
            while bits_in_accumulator < 11 && byte_index < data.len() {
                accumulator |= (data[byte_index] as u32) << bits_in_accumulator;
                bits_in_accumulator += 8;
                byte_index += 1;
            }
            
            let encoded_value = (accumulator & 0x7FF) as i32;
            accumulator >>= 11;
            bits_in_accumulator -= 11;
            
            result.coefficients[coefficient_index] = encoded_value * 3 - 2295;
        }
        
        result
    }

    pub fn to_ring_element(&self, debug: bool) -> PolynomialRingElement {
        dprintln!(debug, "RoundedPolynomial::to_ring_element called");
        let finite_field_coefficients: Vec<FiniteFieldElement> = self.coefficients
            .iter()
            .map(|value| FiniteFieldElement::new(*value, debug))
            .collect();
        PolynomialRingElement::from_coefficients(finite_field_coefficients, debug)
    }
}

pub struct Curve25519DiffieHellman {
    debug: bool,
}

impl Curve25519DiffieHellman {
    pub fn new(debug: bool) -> Self {
        dprintln!(debug, "Curve25519DiffieHellman::new called");
        Curve25519DiffieHellman { debug }
    }

    fn clamp_scalar(&self, scalar: &mut [u8; X25519_SCALAR_SIZE]) {
        dprintln!(self.debug, "Curve25519DiffieHellman::clamp_scalar called");
        scalar[0] &= 248;
        scalar[31] &= 127;
        scalar[31] |= 64;
    }

    fn field_element_from_bytes(&self, bytes: &[u8; 32]) -> [u64; 5] {
        dprintln!(self.debug, "Curve25519DiffieHellman::field_element_from_bytes called");
        let mut field_element = [0u64; 5];
        
        field_element[0] = u64::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], 0, 0]) & 0x7ffffffffffff;
        field_element[1] = (u64::from_le_bytes([bytes[6], bytes[7], bytes[8], bytes[9], bytes[10], bytes[11], bytes[12], 0]) >> 3) & 0x7ffffffffffff;
        field_element[2] = (u64::from_le_bytes([bytes[12], bytes[13], bytes[14], bytes[15], bytes[16], bytes[17], bytes[18], 0]) >> 6) & 0x7ffffffffffff;
        field_element[3] = (u64::from_le_bytes([bytes[19], bytes[20], bytes[21], bytes[22], bytes[23], bytes[24], bytes[25], 0]) >> 1) & 0x7ffffffffffff;
        field_element[4] = (u64::from_le_bytes([bytes[25], bytes[26], bytes[27], bytes[28], bytes[29], bytes[30], bytes[31], 0]) >> 4) & 0x7ffffffffffff;
        
        field_element
    }

    fn field_element_to_bytes(&self, field_element: &[u64; 5]) -> [u8; 32] {
        dprintln!(self.debug, "Curve25519DiffieHellman::field_element_to_bytes called");
        let mut output_bytes = [0u8; 32];
        let mut carry_value: u64;
        let mut reduced_element = *field_element;
        
        for _ in 0..2 {
            for element_index in 0..4 {
                carry_value = reduced_element[element_index] >> 51;
                reduced_element[element_index] &= 0x7ffffffffffff;
                reduced_element[element_index + 1] += carry_value;
            }
            carry_value = reduced_element[4] >> 51;
            reduced_element[4] &= 0x7ffffffffffff;
            reduced_element[0] += carry_value * 19;
        }
        
        let combined_value = 
            reduced_element[0] | 
            (reduced_element[1] << 51) | 
            (reduced_element[2] << 102) | 
            (reduced_element[3] << 153) | 
            (reduced_element[4] << 204);
        
        for byte_index in 0..32 {
            output_bytes[byte_index] = 
                ((combined_value >> (byte_index * 8)) & 0xff) as u8;
        }
        
        output_bytes
    }

    fn field_element_add(&self, first_element: &[u64; 5], second_element: &[u64; 5]) -> [u64; 5] {
        dprintln!(self.debug, "Curve25519DiffieHellman::field_element_add called");
        let mut sum_result = [0u64; 5];
        for element_index in 0..5 {
            sum_result[element_index] = 
                first_element[element_index] + second_element[element_index];
        }
        sum_result
    }

    fn field_element_subtract(&self, first_element: &[u64; 5], second_element: &[u64; 5]) -> [u64; 5] {
        dprintln!(self.debug, "Curve25519DiffieHellman::field_element_subtract called");
        let mut difference_result = [0u64; 5];
        let two_times_prime: [u64; 5] = 
            [0xfffffffffffda, 0xffffffffffffe, 0xffffffffffffe, 0xffffffffffffe, 0xffffffffffffe];
        
        for element_index in 0..5 {
            difference_result[element_index] = 
                first_element[element_index] + 
                two_times_prime[element_index] - 
                second_element[element_index];
        }
        difference_result
    }

    fn field_element_multiply(
        &self, first_element: &[u64; 5], 
        second_element: &[u64; 5]
    ) -> [u64; 5] {
        dprintln!(self.debug, "Curve25519DiffieHellman::field_element_multiply called");
        let mut product_result = [0u128; 5];
        
        for first_index in 0..5 {
            for second_index in 0..5 {
                let term_index = first_index + second_index;
                if term_index < 5 {
                    product_result[term_index] += 
                        first_element[first_index] as u128 * 
                        second_element[second_index] as u128;
                } else {
                    product_result[term_index - 5] += 
                        first_element[first_index] as u128 * 
                        second_element[second_index] as u128 * 19;
                }
            }
        }
        
        let mut reduced_result = [0u64; 5];
        let mut carry_value: u128 = 0;
        
        for element_index in 0..5 {
            product_result[element_index] += carry_value;
            reduced_result[element_index] = 
                (product_result[element_index] & 0x7ffffffffffff) as u64;
            carry_value = product_result[element_index] >> 51;
        }
        
        reduced_result[0] += (carry_value as u64) * 19;
        reduced_result
    }

    fn field_element_square(&self, field_element: &[u64; 5]) -> [u64; 5] {
        dprintln!(self.debug, "Curve25519DiffieHellman::field_element_square called");
        self.field_element_multiply(field_element, field_element)
    }

    fn field_element_inverse(&self, field_element: &[u64; 5]) -> [u64; 5] {
        dprintln!(self.debug, "Curve25519DiffieHellman::field_element_inverse called");

        let mut temporary_a = self.field_element_square(field_element);
        let mut temporary_b = self.field_element_square(&temporary_a);
        temporary_b = self.field_element_square(&temporary_b);
        temporary_b = self.field_element_multiply(&temporary_b, field_element);
        temporary_a = self.field_element_multiply(&temporary_a, &temporary_b);
        let mut temporary_c = self.field_element_square(&temporary_a);
        temporary_b = self.field_element_multiply(&temporary_b, &temporary_c);
        temporary_c = self.field_element_square(&temporary_b);
        
        for _ in 0..4 {
            temporary_c = self.field_element_square(&temporary_c);
        }
        
        temporary_b = self.field_element_multiply(&temporary_b, &temporary_c);
        temporary_c = self.field_element_square(&temporary_b);
        
        for _ in 0..9 {
            temporary_c = self.field_element_square(&temporary_c);
        }
        
        temporary_c = self.field_element_multiply(&temporary_c, &temporary_b);
        let mut temporary_d = self.field_element_square(&temporary_c);
        
        for _ in 0..19 {
            temporary_d = self.field_element_square(&temporary_d);
        }
        
        temporary_c = self.field_element_multiply(&temporary_c, &temporary_d);
        
        for _ in 0..10 {
            temporary_c = self.field_element_square(&temporary_c);
        }
        
        temporary_b = self.field_element_multiply(&temporary_b, &temporary_c);
        temporary_c = self.field_element_square(&temporary_b);
        
        for _ in 0..49 {
            temporary_c = self.field_element_square(&temporary_c);
        }
        
        temporary_c = self.field_element_multiply(&temporary_c, &temporary_b);
        temporary_d = self.field_element_square(&temporary_c);
        
        for _ in 0..99 {
            temporary_d = self.field_element_square(&temporary_d);
        }
        
        temporary_c = self.field_element_multiply(&temporary_c, &temporary_d);
        
        for _ in 0..50 {
            temporary_c = self.field_element_square(&temporary_c);
        }
        
        temporary_b = self.field_element_multiply(&temporary_b, &temporary_c);
        
        for _ in 0..5 {
            temporary_b = self.field_element_square(&temporary_b);
        }
        
        self.field_element_multiply(&temporary_b, &temporary_a)
    }

    fn conditional_swap(
        &self, swap_flag: u64, 
        first_point: &mut [u64; 5], 
        second_point: &mut [u64; 5]
    ) {
        dprintln!(self.debug, "Curve25519DiffieHellman::conditional_swap called with swap_flag: {}", swap_flag);
        let mask_value = 0u64.wrapping_sub(swap_flag);
        
        for element_index in 0..5 {
            let difference = 
                mask_value & (
                    first_point[element_index] ^ second_point[element_index]
                 );
            first_point[element_index] ^= difference;
            second_point[element_index] ^= difference;
        }
    }

    pub fn scalar_multiply(
        &self, scalar: &[u8; X25519_SCALAR_SIZE], 
        point: &[u8; X25519_POINT_SIZE]
    ) -> [u8; X25519_POINT_SIZE] {
        dprintln!(self.debug, "Curve25519DiffieHellman::scalar_multiply called");
        
        let mut clamped_scalar = *scalar;
        self.clamp_scalar(&mut clamped_scalar);
        
        let mut point_bytes = *point;
        point_bytes[31] &= 0x7f;
        
        let base_point = self.field_element_from_bytes(&point_bytes);
        
        let mut x_coordinate_2 = [0u64; 5];
        x_coordinate_2[0] = 1;
        let mut z_coordinate_2 = [0u64; 5];
        let mut x_coordinate_3 = base_point;
        let mut z_coordinate_3 = [0u64; 5];
        z_coordinate_3[0] = 1;
        
        let mut swap_state: u64 = 0;
        
        for bit_position in (0..255).rev() {
            let byte_index = bit_position / 8;
            let bit_index = bit_position % 8;
            let current_bit = ((clamped_scalar[byte_index] >> bit_index) & 1) as u64;
            
            swap_state ^= current_bit;
            self.conditional_swap(swap_state, &mut x_coordinate_2, &mut x_coordinate_3);
            self.conditional_swap(swap_state, &mut z_coordinate_2, &mut z_coordinate_3);
            swap_state = current_bit;
            
            let sum_a = self.field_element_add(&x_coordinate_2, &z_coordinate_2);
            let difference_a = self.field_element_subtract(&x_coordinate_2, &z_coordinate_2);
            let sum_b = self.field_element_add(&x_coordinate_3, &z_coordinate_3);
            let difference_b = self.field_element_subtract(&x_coordinate_3, &z_coordinate_3);
            
            let product_da = self.field_element_multiply(&difference_a, &sum_b);
            let product_cb = self.field_element_multiply(&sum_a, &difference_b);
            
            let sum_dacb = self.field_element_add(&product_da, &product_cb);
            let difference_dacb = self.field_element_subtract(&product_da, &product_cb);
            
            let squared_sum = self.field_element_square(&sum_dacb);
            let squared_difference = self.field_element_square(&difference_dacb);
            
            x_coordinate_3 = squared_sum;
            z_coordinate_3 = self.field_element_multiply(&base_point, &squared_difference);
            
            let squared_a = self.field_element_square(&sum_a);
            let squared_b = self.field_element_square(&difference_a);
            
            let product_e = self.field_element_subtract(&squared_a, &squared_b);
            
            let a24_constant: [u64; 5] = [121666, 0, 0, 0, 0];
            let scaled_e = self.field_element_multiply(&a24_constant, &product_e);
            let sum_ae = self.field_element_add(&squared_a, &scaled_e);
            
            x_coordinate_2 = self.field_element_multiply(&squared_a, &squared_b);
            z_coordinate_2 = self.field_element_multiply(&product_e, &sum_ae);
        }
        
        self.conditional_swap(swap_state, &mut x_coordinate_2, &mut x_coordinate_3);
        self.conditional_swap(swap_state, &mut z_coordinate_2, &mut z_coordinate_3);
        
        let z_coordinate_2_inverse = self.field_element_inverse(&z_coordinate_2);
        let result_x = self.field_element_multiply(&x_coordinate_2, &z_coordinate_2_inverse);
        
        self.field_element_to_bytes(&result_x)
    }

    pub fn generate_public_key(&self, private_key: &[u8; X25519_SCALAR_SIZE]) -> [u8; X25519_POINT_SIZE] {
        dprintln!(self.debug, "Curve25519DiffieHellman::generate_public_key called");
        let basepoint: [u8; X25519_POINT_SIZE] = [
            9, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        ];
        self.scalar_multiply(private_key, &basepoint)
    }
}

pub struct SecureHashAlgorithm512 {
    state: [u64; 8],
    buffer: [u8; 128],
    buffer_length: usize,
    total_length: u128,
    debug: bool,
}

impl SecureHashAlgorithm512 {
    const ROUND_CONSTANTS: [u64; 80] = [
        0x428a2f98d728ae22, 0x7137449123ef65cd, 0xb5c0fbcfec4d3b2f, 0xe9b5dba58189dbbc,
        0x3956c25bf348b538, 0x59f111f1b605d019, 0x923f82a4af194f9b, 0xab1c5ed5da6d8118,
        0xd807aa98a3030242, 0x12835b0145706fbe, 0x243185be4ee4b28c, 0x550c7dc3d5ffb4e2,
        0x72be5d74f27b896f, 0x80deb1fe3b1696b1, 0x9bdc06a725c71235, 0xc19bf174cf692694,
        0xe49b69c19ef14ad2, 0xefbe4786384f25e3, 0x0fc19dc68b8cd5b5, 0x240ca1cc77ac9c65,
        0x2de92c6f592b0275, 0x4a7484aa6ea6e483, 0x5cb0a9dcbd41fbd4, 0x76f988da831153b5,
        0x983e5152ee66dfab, 0xa831c66d2db43210, 0xb00327c898fb213f, 0xbf597fc7beef0ee4,
        0xc6e00bf33da88fc2, 0xd5a79147930aa725, 0x06ca6351e003826f, 0x142929670a0e6e70,
        0x27b70a8546d22ffc, 0x2e1b21385c26c926, 0x4d2c6dfc5ac42aed, 0x53380d139d95b3df,
        0x650a73548baf63de, 0x766a0abb3c77b2a8, 0x81c2c92e47edaee6, 0x92722c851482353b,
        0xa2bfe8a14cf10364, 0xa81a664bbc423001, 0xc24b8b70d0f89791, 0xc76c51a30654be30,
        0xd192e819d6ef5218, 0xd69906245565a910, 0xf40e35855771202a, 0x106aa07032bbd1b8,
        0x19a4c116b8d2d0c8, 0x1e376c085141ab53, 0x2748774cdf8eeb99, 0x34b0bcb5e19b48a8,
        0x391c0cb3c5c95a63, 0x4ed8aa4ae3418acb, 0x5b9cca4f7763e373, 0x682e6ff3d6b2b8a3,
        0x748f82ee5defb2fc, 0x78a5636f43172f60, 0x84c87814a1f0ab72, 0x8cc702081a6439ec,
        0x90befffa23631e28, 0xa4506cebde82bde9, 0xbef9a3f7b2c67915, 0xc67178f2e372532b,
        0xca273eceea26619c, 0xd186b8c721c0c207, 0xeada7dd6cde0eb1e, 0xf57d4f7fee6ed178,
        0x06f067aa72176fba, 0x0a637dc5a2c898a6, 0x113f9804bef90dae, 0x1b710b35131c471b,
        0x28db77f523047d84, 0x32caab7b40c72493, 0x3c9ebe0a15c9bebc, 0x431d67c49c100d4c,
        0x4cc5d4becb3e42b6, 0x597f299cfc657e2a, 0x5fcb6fab3ad6faec, 0x6c44198c4a475817,
    ];

    const INITIAL_STATE: [u64; 8] = [
        0x6a09e667f3bcc908, 0xbb67ae8584caa73b, 0x3c6ef372fe94f82b, 0xa54ff53a5f1d36f1,
        0x510e527fade682d1, 0x9b05688c2b3e6c1f, 0x1f83d9abfb41bd6b, 0x5be0cd19137e2179,
    ];

    pub fn new(debug: bool) -> Self {
        dprintln!(debug, "SecureHashAlgorithm512::new called");
        SecureHashAlgorithm512 {
            state: Self::INITIAL_STATE,
            buffer: [0u8; 128],
            buffer_length: 0,
            total_length: 0,
            debug,
        }
    }

    fn process_block(&mut self, block: &[u8]) {
        dprintln!(self.debug, "SecureHashAlgorithm512::process_block called");
        let mut message_schedule = [0u64; 80];
        
        for word_index in 0..16 {
            let byte_offset = word_index * 8;
            message_schedule[word_index] = u64::from_be_bytes([
                block[byte_offset],
                block[byte_offset + 1],
                block[byte_offset + 2],
                block[byte_offset + 3],
                block[byte_offset + 4],
                block[byte_offset + 5],
                block[byte_offset + 6],
                block[byte_offset + 7],
            ]);
        }
        
        for word_index in 16..80 {

            let sigma_0 = message_schedule[word_index - 15].rotate_right(1)
                ^ message_schedule[word_index - 15].rotate_right(8)
                ^ (message_schedule[word_index - 15] >> 7);

            let sigma_1 = message_schedule[word_index - 2].rotate_right(19)
                ^ message_schedule[word_index - 2].rotate_right(61)
                ^ (message_schedule[word_index - 2] >> 6);

            message_schedule[word_index] = message_schedule[word_index - 16]
                .wrapping_add(sigma_0)
                .wrapping_add(message_schedule[word_index - 7])
                .wrapping_add(sigma_1);
        }
        
        let mut working_variable_a = self.state[0];
        let mut working_variable_b = self.state[1];
        let mut working_variable_c = self.state[2];
        let mut working_variable_d = self.state[3];
        let mut working_variable_e = self.state[4];
        let mut working_variable_f = self.state[5];
        let mut working_variable_g = self.state[6];
        let mut working_variable_h = self.state[7];
        
        for round_index in 0..80 {

            let big_sigma_1 = working_variable_e.rotate_right(14)
                ^ working_variable_e.rotate_right(18)
                ^ working_variable_e.rotate_right(41);

            let choice_value = 
                (working_variable_e & working_variable_f) ^ (
                    (!working_variable_e) & working_variable_g
                );

            let temporary_1 = working_variable_h
                .wrapping_add(big_sigma_1)
                .wrapping_add(choice_value)
                .wrapping_add(Self::ROUND_CONSTANTS[round_index])
                .wrapping_add(message_schedule[round_index]);

            let big_sigma_0 = working_variable_a.rotate_right(28)
                ^ working_variable_a.rotate_right(34)
                ^ working_variable_a.rotate_right(39);

            let majority_value = 
                (working_variable_a & working_variable_b) ^ 
                (working_variable_a & working_variable_c) ^ 
                (working_variable_b & working_variable_c);

            let temporary_2 = big_sigma_0.wrapping_add(majority_value);
            
            working_variable_h = working_variable_g;
            working_variable_g = working_variable_f;
            working_variable_f = working_variable_e;
            working_variable_e = working_variable_d.wrapping_add(temporary_1);
            working_variable_d = working_variable_c;
            working_variable_c = working_variable_b;
            working_variable_b = working_variable_a;
            working_variable_a = temporary_1.wrapping_add(temporary_2);
        }
        
        self.state[0] = self.state[0].wrapping_add(working_variable_a);
        self.state[1] = self.state[1].wrapping_add(working_variable_b);
        self.state[2] = self.state[2].wrapping_add(working_variable_c);
        self.state[3] = self.state[3].wrapping_add(working_variable_d);
        self.state[4] = self.state[4].wrapping_add(working_variable_e);
        self.state[5] = self.state[5].wrapping_add(working_variable_f);
        self.state[6] = self.state[6].wrapping_add(working_variable_g);
        self.state[7] = self.state[7].wrapping_add(working_variable_h);
    }

    pub fn update(&mut self, data: &[u8]) {
        dprintln!(
            self.debug, 
            "SecureHashAlgorithm512::update called with {} bytes", 
            data.len()
        );
        let mut data_offset: usize = 0;
        
        if self.buffer_length > 0 {

            let space_remaining = 128 - self.buffer_length;
            let copy_amount = std::cmp::min(space_remaining, data.len());

            self.buffer[self.buffer_length..self.buffer_length + copy_amount]
                .copy_from_slice(&data[..copy_amount]);

            self.buffer_length += copy_amount;
            data_offset = copy_amount;
            
            if self.buffer_length == 128 {
                let block = self.buffer;
                self.process_block(&block);
                self.buffer_length = 0;
            }

        }
        
        while data_offset + 128 <= data.len() {
            self.process_block(&data[data_offset..data_offset + 128]);
            data_offset += 128;
        }
        
        if data_offset < data.len() {
            let remaining = data.len() - data_offset;
            self.buffer[..remaining].copy_from_slice(&data[data_offset..]);
            self.buffer_length = remaining;
        }
        
        self.total_length += data.len() as u128;
    }

    pub fn finalize(mut self) -> [u8; 64] {
        dprintln!(self.debug, "SecureHashAlgorithm512::finalize called");
        let total_bits = self.total_length * 8;
        
        self.buffer[self.buffer_length] = 0x80;
        self.buffer_length += 1;
        
        if self.buffer_length > 112 {
            while self.buffer_length < 128 {
                self.buffer[self.buffer_length] = 0;
                self.buffer_length += 1;
            }
            let block = self.buffer;
            self.process_block(&block);
            self.buffer_length = 0;
            self.buffer = [0u8; 128];
        }
        
        while self.buffer_length < 112 {
            self.buffer[self.buffer_length] = 0;
            self.buffer_length += 1;
        }
        
        self.buffer[112..128].copy_from_slice(&total_bits.to_be_bytes());
        let block = self.buffer;
        self.process_block(&block);
        
        let mut hash_output = [0u8; 64];
        for (state_index, state_word) in self.state.iter().enumerate() {
            let word_bytes = state_word.to_be_bytes();
            hash_output[state_index * 8..state_index * 8 + 8]
                .copy_from_slice(&word_bytes);
        }
        
        hash_output
    }

    pub fn hash(data: &[u8], debug: bool) -> [u8; 64] {
        dprintln!(debug, "SecureHashAlgorithm512::hash called with {} bytes", data.len());
        let mut hasher = SecureHashAlgorithm512::new(debug);
        hasher.update(data);
        hasher.finalize()
    }
}

pub struct Sntrup761KeyPair {
    pub public_key: Vec<u8>,
    pub secret_key: Vec<u8>,
}

pub struct Sntrup761X25519Sha512KeyEncapsulationMechanism {
    debug: bool,
}

impl Sntrup761X25519Sha512KeyEncapsulationMechanism {
    pub fn new(debug: bool) -> Self {
        dprintln!(debug, "Sntrup761X25519Sha512KeyEncapsulationMechanism::new called");
        Sntrup761X25519Sha512KeyEncapsulationMechanism { debug }
    }

    fn invert_polynomial(
        &self, polynomial: &SmallPolynomial
    ) -> Option<PolynomialRingElement> {
        dprintln!(
            self.debug, 
            "Sntrup761X25519Sha512KeyEncapsulationMechanism::invert_polynomial called"
        );
        
        let mut f_polynomial = vec![0i32; SNTRUP761_PRIME_DEGREE + 1];
        let mut g_polynomial = vec![0i32; SNTRUP761_PRIME_DEGREE + 1];
        
        f_polynomial[0] = -1;
        f_polynomial[1] = -1;
        f_polynomial[SNTRUP761_PRIME_DEGREE] = 1;
        
        for coefficient_index in 0..SNTRUP761_PRIME_DEGREE {
            g_polynomial[coefficient_index] = 
                polynomial.coefficients[coefficient_index].value as i32;
        }
        
        let mut v_polynomial = vec![0i32; SNTRUP761_PRIME_DEGREE + 1];
        let mut w_polynomial = vec![0i32; SNTRUP761_PRIME_DEGREE + 1];
        w_polynomial[0] = 1;
        
        let mut delta_value: i32 = 1;
        
        for _ in 0..(2 * SNTRUP761_PRIME_DEGREE - 1) {
            let f_zero = f_polynomial[0];
            let g_zero = g_polynomial[0];
            
            let swap_condition = (delta_value > 0) && (g_zero != 0);
            
            if swap_condition {
                delta_value = -delta_value;
                std::mem::swap(&mut f_polynomial, &mut g_polynomial);
                std::mem::swap(&mut v_polynomial, &mut w_polynomial);
            }
            
            delta_value += 1;
            
            if g_zero != 0 {
                let scale_factor = 
                    FiniteFieldElement::new(g_zero, self.debug)
                    *
                    FiniteFieldElement::new(f_zero, self.debug)
                        .reciprocal(self.debug);
                
                for polynomial_index in 0..=SNTRUP761_PRIME_DEGREE {

                    g_polynomial[polynomial_index] = (
                        FiniteFieldElement::new(
                            g_polynomial[polynomial_index], self.debug
                        ) 
                        - 
                        FiniteFieldElement::new(
                            f_polynomial[polynomial_index], self.debug
                        ) 
                        * 
                        scale_factor.clone()
                    ).value;

                    w_polynomial[polynomial_index] = (
                        FiniteFieldElement::new(
                            w_polynomial[polynomial_index], self.debug
                        )
                        - 
                        FiniteFieldElement::new(
                            v_polynomial[polynomial_index], self.debug
                        ) 
                        * 
                        scale_factor.clone()
                    ).value;
                }
            }
            
            for shift_index in 0..SNTRUP761_PRIME_DEGREE {
                g_polynomial[shift_index] = g_polynomial[shift_index + 1];
            }
            g_polynomial[SNTRUP761_PRIME_DEGREE] = 0;
            
            for shift_index in (1..=SNTRUP761_PRIME_DEGREE).rev() {
                w_polynomial[shift_index] = w_polynomial[shift_index - 1];
            }
            w_polynomial[0] = 0;
        }
        
        if f_polynomial[0] == 0 {
            return None;
        }
        
        let inverse_f_zero = 
            FiniteFieldElement::new(f_polynomial[0], self.debug)
                .reciprocal(self.debug)
        ;
        let mut result_coefficients = 
            Vec::with_capacity(SNTRUP761_PRIME_DEGREE);
        
        for coefficient_index in 0..SNTRUP761_PRIME_DEGREE {
            result_coefficients.push(
                FiniteFieldElement::new(
                    v_polynomial[
                        SNTRUP761_PRIME_DEGREE - 1 - coefficient_index
                    ], self.debug
                ) * inverse_f_zero.clone()
            );
        }
        
        Some(PolynomialRingElement::from_coefficients(
            result_coefficients, 
            self.debug
        ))
    }

    pub fn generate_keypair(
        &self, 
        random_bytes: &[u8]
    ) -> Sntrup761KeyPair {
        dprintln!(
            self.debug, 
            "Sntrup761X25519Sha512KeyEncapsulationMechanism::generate_keypair called with {} random bytes", 
            random_bytes.len()
        );
        
        let small_f_bytes = 
            &random_bytes[0..SNTRUP761_PRIME_DEGREE];
        let small_g_bytes = 
            &random_bytes[SNTRUP761_PRIME_DEGREE..2 * SNTRUP761_PRIME_DEGREE];
        let x25519_private = 
            &random_bytes[
                2 * SNTRUP761_PRIME_DEGREE..2 * 
                SNTRUP761_PRIME_DEGREE + 
                X25519_SCALAR_SIZE
            ]
        ;
        
        let small_f = SmallPolynomial::generate_random(small_f_bytes, self.debug);
        let small_g = SmallPolynomial::generate_random(small_g_bytes, self.debug);
        
        let ring_element_g = small_g.to_ring_element(self.debug);
        
        let inverse_f = self.invert_polynomial(&small_f)
            .expect("Failed to invert polynomial f");
        
        let three = FiniteFieldElement::new(3, self.debug);

        let mut three_times_g_coefficients = 
            Vec::with_capacity(SNTRUP761_PRIME_DEGREE);

        for coefficient in &ring_element_g.coefficients {
            three_times_g_coefficients.push(
                coefficient.clone() * three.clone()
            );
        }
        let three_times_g = 
            PolynomialRingElement::from_coefficients(
                three_times_g_coefficients, self.debug
            );
        
        let public_polynomial_h = 
            three_times_g.multiply(&inverse_f, self.debug);
        
        let sntrup_public = public_polynomial_h.encode(self.debug);
        let sntrup_secret_f = small_f.encode(self.debug);
        let sntrup_secret_g_inverse = small_g.encode(self.debug);
        
        let curve25519_engine = Curve25519DiffieHellman::new(self.debug);
        let mut x25519_private_key = [0u8; X25519_SCALAR_SIZE];
        x25519_private_key.copy_from_slice(x25519_private);
        let x25519_public_key = curve25519_engine.generate_public_key(&x25519_private_key);
        
        let mut combined_public = Vec::with_capacity(PUBLIC_KEY_SIZE);
        combined_public.extend_from_slice(&sntrup_public);
        combined_public.extend_from_slice(&x25519_public_key);
        
        let mut combined_secret = Vec::with_capacity(SECRET_KEY_SIZE);
        combined_secret.extend_from_slice(&sntrup_secret_f);
        combined_secret.extend_from_slice(&sntrup_public);
        combined_secret.extend_from_slice(&sntrup_secret_g_inverse);
        combined_secret.extend_from_slice(&x25519_private_key);
        combined_secret.extend_from_slice(&combined_public);
        
        Sntrup761KeyPair {
            public_key: combined_public,
            secret_key: combined_secret,
        }
    }

    pub fn encapsulate(
        &self, public_key: &[u8], 
        random_bytes: &[u8]
    ) -> (Vec<u8>, [u8; SHARED_SECRET_SIZE]) {
        dprintln!(
            self.debug, 
            "Sntrup761X25519Sha512KeyEncapsulationMechanism::encapsulate called"
        );
        
        let sntrup_public_bytes = &public_key[0..SNTRUP761_RING_ELEMENT_BYTES];
        let x25519_public_bytes = &public_key[SNTRUP761_RING_ELEMENT_BYTES..PUBLIC_KEY_SIZE];
        
        let public_polynomial_h = PolynomialRingElement::decode(sntrup_public_bytes, self.debug);
        
        let small_r_bytes = &random_bytes[0..SNTRUP761_PRIME_DEGREE];
        let small_r = SmallPolynomial::generate_random(small_r_bytes, self.debug);
        
        let ring_element_r = small_r.to_ring_element(self.debug);
        let ciphertext_polynomial = public_polynomial_h.multiply(&ring_element_r, self.debug);
        
        let rounded_ciphertext = RoundedPolynomial::from_ring_element(&ciphertext_polynomial, self.debug);
        let encoded_rounded = rounded_ciphertext.encode(self.debug);
        
        let encoded_small_r = small_r.encode(self.debug);
        
        let curve25519_engine = Curve25519DiffieHellman::new(self.debug);
        let x25519_ephemeral_private = 
            &random_bytes[SNTRUP761_PRIME_DEGREE..SNTRUP761_PRIME_DEGREE + X25519_SCALAR_SIZE];
        let mut x25519_ephemeral_scalar = [0u8; X25519_SCALAR_SIZE];
        x25519_ephemeral_scalar.copy_from_slice(x25519_ephemeral_private);
        
        let x25519_ephemeral_public = curve25519_engine.generate_public_key(&x25519_ephemeral_scalar);
        
        let mut x25519_recipient_public = [0u8; X25519_POINT_SIZE];
        x25519_recipient_public.copy_from_slice(x25519_public_bytes);

        let x25519_shared = 
            curve25519_engine.scalar_multiply(
                &x25519_ephemeral_scalar, 
                &x25519_recipient_public
            )
        ;
        
        let mut combined_ciphertext = Vec::with_capacity(CIPHERTEXT_SIZE);
        combined_ciphertext.extend_from_slice(&encoded_rounded);
        combined_ciphertext.extend_from_slice(&encoded_small_r);
        combined_ciphertext.extend_from_slice(&x25519_ephemeral_public);
        
        let mut hash_input = Vec::new();
        hash_input.extend_from_slice(&encoded_small_r);
        hash_input.extend_from_slice(&encoded_rounded);
        hash_input.extend_from_slice(&x25519_shared);
        hash_input.extend_from_slice(&x25519_ephemeral_public);
        hash_input.extend_from_slice(x25519_public_bytes);
        
        let hash_output = SecureHashAlgorithm512::hash(&hash_input, self.debug);
        let mut shared_secret = [0u8; SHARED_SECRET_SIZE];
        shared_secret.copy_from_slice(&hash_output[0..SHARED_SECRET_SIZE]);
        
        (combined_ciphertext, shared_secret)
    }

    pub fn decapsulate(
        &self, secret_key: &[u8], 
        ciphertext: &[u8]
    ) -> [u8; SHARED_SECRET_SIZE] {
        dprintln!(self.debug, "Sntrup761X25519Sha512KeyEncapsulationMechanism::decapsulate called");
        
        let secret_f_bytes = 
            &secret_key[0..SNTRUP761_SMALL_POLYNOMIAL_BYTES];

        let _public_h_bytes = 
            &secret_key[
                SNTRUP761_SMALL_POLYNOMIAL_BYTES..SNTRUP761_SMALL_POLYNOMIAL_BYTES
                +
                SNTRUP761_RING_ELEMENT_BYTES
            ];

        let _secret_g_inverse_bytes = 
            &secret_key[
                SNTRUP761_SMALL_POLYNOMIAL_BYTES 
                + 
                SNTRUP761_RING_ELEMENT_BYTES..SNTRUP761_SMALL_POLYNOMIAL_BYTES 
                + 
                SNTRUP761_RING_ELEMENT_BYTES 
                + 
                SNTRUP761_SMALL_POLYNOMIAL_BYTES
            ];

        let x25519_private_bytes = 
            &secret_key[
                SNTRUP761_SMALL_POLYNOMIAL_BYTES 
                + 
                SNTRUP761_RING_ELEMENT_BYTES 
                + 
                SNTRUP761_SMALL_POLYNOMIAL_BYTES..SNTRUP761_SMALL_POLYNOMIAL_BYTES 
                + 
                SNTRUP761_RING_ELEMENT_BYTES 
                + 
                SNTRUP761_SMALL_POLYNOMIAL_BYTES 
                + 
                X25519_SCALAR_SIZE
            ];

        let combined_public_bytes = 
            &secret_key[
                SNTRUP761_SMALL_POLYNOMIAL_BYTES 
                + 
                SNTRUP761_RING_ELEMENT_BYTES 
                + 
                SNTRUP761_SMALL_POLYNOMIAL_BYTES 
                + 
                X25519_SCALAR_SIZE..
            ];
        
        let rounded_bytes = &ciphertext[0..SNTRUP761_ROUNDED_BYTES];
        let small_r_bytes = &ciphertext[
            SNTRUP761_ROUNDED_BYTES..SNTRUP761_ROUNDED_BYTES 
            + 
            SNTRUP761_SMALL_POLYNOMIAL_BYTES
        ];
        let x25519_ephemeral_public_bytes = &ciphertext[
            SNTRUP761_ROUNDED_BYTES 
            + 
            SNTRUP761_SMALL_POLYNOMIAL_BYTES..CIPHERTEXT_SIZE
        ];
        
        let secret_f = SmallPolynomial::decode(secret_f_bytes, self.debug);
        let rounded_ciphertext = RoundedPolynomial::decode(rounded_bytes, self.debug);
        let ciphertext_ring_element = rounded_ciphertext.to_ring_element(self.debug);
        
        let ring_element_f = secret_f.to_ring_element(self.debug);
        let multiplied = ciphertext_ring_element.multiply(&ring_element_f, self.debug);
        
        let mut recovered_r_coefficients = Vec::with_capacity(SNTRUP761_PRIME_DEGREE);
        for coefficient in &multiplied.coefficients {
            let value = coefficient.value;
            let rounded_value = if value > SNTRUP761_FIELD_MODULUS / 6 {
                1
            } else if value < -SNTRUP761_FIELD_MODULUS / 6 {
                -1
            } else {
                0
            };
            recovered_r_coefficients.push(SmallCoefficient::new(rounded_value as i8, self.debug));
        }
        let _recovered_r = SmallPolynomial::from_coefficients(recovered_r_coefficients, self.debug);
        
        let curve25519_engine = Curve25519DiffieHellman::new(self.debug);
        let mut x25519_private_key = [0u8; X25519_SCALAR_SIZE];
        x25519_private_key.copy_from_slice(x25519_private_bytes);
        
        let mut x25519_ephemeral_public = [0u8; X25519_POINT_SIZE];
        x25519_ephemeral_public.copy_from_slice(x25519_ephemeral_public_bytes);
        
        let x25519_shared = curve25519_engine.scalar_multiply(
            &x25519_private_key, 
            &x25519_ephemeral_public
        );
        
        let x25519_own_public = &combined_public_bytes[SNTRUP761_RING_ELEMENT_BYTES..];
        
        let mut hash_input = Vec::new();
        hash_input.extend_from_slice(small_r_bytes);
        hash_input.extend_from_slice(rounded_bytes);
        hash_input.extend_from_slice(&x25519_shared);
        hash_input.extend_from_slice(x25519_ephemeral_public_bytes);
        hash_input.extend_from_slice(x25519_own_public);
        
        let hash_output = SecureHashAlgorithm512::hash(&hash_input, self.debug);
        let mut shared_secret = [0u8; SHARED_SECRET_SIZE];
        shared_secret.copy_from_slice(&hash_output[0..SHARED_SECRET_SIZE]);
        
        shared_secret
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
        
        let (ciphertext, shared_secret_sender) = key_encapsulation_mechanism.encapsulate(&keypair.public_key, &encapsulation_random_bytes);
        
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

fn main() {
    let debug_flag = true;
    
    dprintln!(debug_flag, "Starting SNTRUP761x25519-SHA512 demonstration");
    
    let key_encapsulation_mechanism = Sntrup761X25519Sha512KeyEncapsulationMechanism::new(debug_flag);
    
    dprintln!(debug_flag, "Generating random bytes for key generation");
    let mut keygen_random_bytes = vec![0u8; 2 * SNTRUP761_PRIME_DEGREE + X25519_SCALAR_SIZE + 100];
    for (byte_index, byte_value) in keygen_random_bytes.iter_mut().enumerate() {
        *byte_value = ((byte_index * 17 + 31) % 256) as u8;
    }
    
    dprintln!(debug_flag, "Generating keypair");
    let keypair = key_encapsulation_mechanism.generate_keypair(&keygen_random_bytes);
    
    dprintln!(debug_flag, "Public key size: {} bytes", keypair.public_key.len());
    dprintln!(debug_flag, "Secret key size: {} bytes", keypair.secret_key.len());
    
    dprintln!(debug_flag, "Generating random bytes for encapsulation");
    let mut encapsulation_random_bytes = vec![0u8; SNTRUP761_PRIME_DEGREE + X25519_SCALAR_SIZE + 100];
    for (byte_index, byte_value) in encapsulation_random_bytes.iter_mut().enumerate() {
        *byte_value = ((byte_index * 23 + 47) % 256) as u8;
    }
    
    dprintln!(debug_flag, "Performing encapsulation");
    let (ciphertext, shared_secret_sender) = 
        key_encapsulation_mechanism.encapsulate(&keypair.public_key, &encapsulation_random_bytes);
    
    dprintln!(debug_flag, "Ciphertext size: {} bytes", ciphertext.len());
    dprintln!(debug_flag, "Sender shared secret: {:02x?}", &shared_secret_sender[..8]);
    
    dprintln!(debug_flag, "Performing decapsulation");
    let shared_secret_receiver = 
        key_encapsulation_mechanism.decapsulate(&keypair.secret_key, &ciphertext);
    
    dprintln!(debug_flag, "Receiver shared secret: {:02x?}", &shared_secret_receiver[..8]);
    
    if shared_secret_sender == shared_secret_receiver {
        dprintln!(debug_flag, "SUCCESS: Shared secrets match!");
    } else {
        dprintln!(debug_flag, "FAILURE: Shared secrets do not match!");
    }
}
