use crate::crypto;

const E2E_TESTS: &[(&str, fn())] = &[
    ("sntrup761x25519_sha512", crypto::post_quantum::sntrup761x25519_sha512::e2e::run),
];

pub fn find_test(name: &str) -> Option<fn()> {
    E2E_TESTS
        .iter()
        .find(|(test_name, _)| *test_name == name)
        .map(|(_, test_function)| *test_function)
}

pub fn all_tests() -> &'static [(&'static str, fn())] {
    E2E_TESTS
}
