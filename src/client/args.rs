use crate::define_args;

define_args! {
    mess_test_without_auth: &["--mess_test_without_auth", "--messtestwithoutauth", "messagetestwithoutauth", "--message_test_without_auth"], // will be in production auto-disabled on server, so if u won't run the server with special test flags to run with this, don't use - will be rendered useless - it is for development in its early stages to test that sntrup761x25519sha512 KEM worked well and can encrypt and decrypt on both sides well with ChaCha20-Poly1305 before programming the actual authentication mechanisms
    proxy: &["--proxy"],
    reverse_tunnel: &["-R", "--reverse", "--reverse_tunnel", "--reversetunnel", "--reversetnl", "--reverse_tnl", "--rvrstnl", "--reverse_tunel", "--reversetunel"],
}
