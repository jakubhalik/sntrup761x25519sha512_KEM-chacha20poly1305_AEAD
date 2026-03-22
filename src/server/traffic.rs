use tokio::net::TcpStream;
use crate::traffic::mess_test_without_auth;

pub async fn traffic(
    stream: &mut TcpStream,
    shared_secret: &[u8; 64],
) {
    match mess_test_without_auth::server(stream, shared_secret).await {
        Ok(()) => {}
        Err(e) => {
            eprintln!("[traffic] mess_test_without_auth error: {}", e);
        }
    }
}
