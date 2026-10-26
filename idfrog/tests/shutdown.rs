//! Forked from idElephant: termination must work during startup discovery too.
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
fn sigterm_and_sigint_exit_cleanly_even_while_upstream_discovery_is_stuck() {
    for (signal, traces) in [
        ("TERM", false),
        ("INT", false),
        ("TERM", true),
        ("INT", true),
    ] {
        // Accept TCP but never respond to the OIDC discovery request.
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let directory =
            std::env::temp_dir().join(format!("idfrog-shutdown-{}-{signal}", std::process::id()));
        std::fs::create_dir(&directory).unwrap();
        let config_path = directory.join("idfrog.toml");
        idfrog::signing::generate(&directory.join("key.pem")).unwrap();
        std::fs::write(directory.join("secret"), "test-secret").unwrap();
        std::fs::write(&config_path, format!(
            "origin = 'http://localhost:8081'\nlisten = '127.0.0.1:8081'\nsigning-key-file = 'key.pem'\n[[resource]]\nuri = 'https://tools.example/mcp'\napplication-id = '0816f759-d89d-4319-a8d7-d88b5d751dc9'\n[upstream]\nissuer = 'http://{}'\nclient-id = 'test'\n[upstream.authentication]\nmethod = 'client-secret-post'\nclient-secret-file = 'secret'\n",
            listener.local_addr().unwrap()
        )).unwrap();
        if traces {
            use std::io::Write;
            writeln!(
                std::fs::OpenOptions::new()
                    .append(true)
                    .open(&config_path)
                    .unwrap(),
                "\n[traces]\nendpoint = 'http://127.0.0.1:9'"
            )
            .unwrap();
        }
        let mut server = Server(
            Command::new(env!("CARGO_BIN_EXE_idfrog"))
                .arg("-c")
                .arg(&config_path)
                .env("RUST_LOG", "idfrog=info,idp_server=info")
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
                    assert!(Instant::now() < deadline, "upstream connection timed out");
                    std::thread::sleep(Duration::from_millis(10));
                }
                Err(e) => panic!("accept failed: {e}"),
            }
        };
        std::fs::remove_dir_all(directory).unwrap();
        assert!(
            Command::new("kill")
                .arg(format!("-{signal}"))
                .arg(server.0.id().to_string())
                .status()
                .unwrap()
                .success()
        );
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
