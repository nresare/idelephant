#![cfg(unix)]

use std::{
    io,
    net::TcpListener,
    process::{Child, Command, Stdio},
    time::{Duration, Instant},
};

struct Server(Child);

impl Drop for Server {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

#[test]
fn sigterm_and_sigint_exit_cleanly_even_while_database_startup_is_stuck() {
    for signal in ["TERM", "INT"] {
        // Accept TCP but never respond to the database WebSocket handshake.
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let config_path = std::env::temp_dir().join(format!(
            "idelephant-shutdown-{}-{signal}.toml",
            std::process::id()
        ));
        std::fs::write(
            &config_path,
            format!(
                "origin = 'http://localhost:8080'\nroot_key = 'test'\n\
             [email]\nrelay_host = 'localhost'\nsender_email = 'test@example.com'\n\
             [persistence]\nuri = 'ws://{}'\n",
                listener.local_addr().unwrap()
            ),
        )
        .unwrap();
        let mut server = Server(
            Command::new(env!("CARGO_BIN_EXE_idelephant"))
                .arg("-c")
                .arg(&config_path)
                .env("RUST_LOG", "idelephant=info,idp_server=info")
                .env("NO_COLOR", "1")
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()
                .unwrap(),
        );
        let deadline = Instant::now() + Duration::from_secs(10);
        let _connection = loop {
            match listener.accept() {
                Ok(connection) => break connection,
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                    assert!(
                        server.0.try_wait().unwrap().is_none(),
                        "server exited before connecting"
                    );
                    assert!(Instant::now() < deadline, "database connection timed out");
                    std::thread::sleep(Duration::from_millis(10));
                }
                Err(e) => panic!("accept failed: {e}"),
            }
        };
        std::fs::remove_file(config_path).unwrap();
        assert!(Command::new("kill")
            .arg(format!("-{signal}"))
            .arg(server.0.id().to_string())
            .status()
            .unwrap()
            .success());
        let deadline = Instant::now() + Duration::from_secs(5);
        let status = loop {
            if let Some(status) = server.0.try_wait().unwrap() {
                break status;
            }
            assert!(Instant::now() < deadline, "server ignored SIG{signal}");
            std::thread::sleep(Duration::from_millis(10));
        };
        assert!(status.success(), "server did not exit cleanly: {status}");
        let mut output = String::new();
        std::io::Read::read_to_string(&mut server.0.stdout.take().unwrap(), &mut output).unwrap();
        assert!(
            output.contains(&format!("SIG{signal}")),
            "missing signal log: {output}"
        );
        assert!(
            output.contains("shutdown complete during startup"),
            "missing completion log: {output}"
        );
    }
}
