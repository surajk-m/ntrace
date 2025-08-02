use ntrace::protocol::{Protocol, ProtocolAnalyzer};
use tokio::io::AsyncWriteExt;
use tokio::net::{TcpListener, TcpStream};
use tokio_test::block_on;

#[test]
fn test_detect_service() {
    block_on(async {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let analyzer = ProtocolAnalyzer::new();

        tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let _ = stream.write_all(b"HTTP/1.1 200 OK\r\n\r\n").await;
        });

        let mut stream = TcpStream::connect(addr).await.unwrap();
        let service = analyzer
            .detect_service(&mut stream, Protocol::Tcp)
            .await
            .unwrap();
        assert_eq!(service, Some("HTTP".to_string()));
    });
}
