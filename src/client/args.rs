use crate::define_args;

define_args! {
    mess_test_without_auth: &["--mess_test_without_auth", "--messtestwithoutauth", "messagetestwithoutauth", "--message_test_without_auth"],
    proxy: &["--proxy"],
    reverse_tunnel: &["-R", "--reverse", "--reverse_tunnel", "--reversetunnel", "--reversetnl", "--reverse_tnl", "--rvrstnl", "--reverse_tunel", "--reversetunel"],
}
