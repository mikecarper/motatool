#![cfg(target_os = "linux")]

use std::io::{Read, Write};
use std::net::{Shutdown, TcpListener, TcpStream};
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

struct Server(Child);

impl Drop for Server {
    fn drop(&mut self) {
        if !matches!(self.0.try_wait(), Ok(None)) {
            return;
        }
        // Always resume before cleanup, including when a test assertion fails while stopped.
        let _ = Command::new("kill")
            .args(["-CONT", &self.0.id().to_string()])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn signal(server: &Server, name: &str) {
    let result = Command::new("kill")
        .args([name, &server.0.id().to_string()])
        .output()
        .unwrap();
    assert!(result.status.success(), "{result:?}");
}

fn accept(listener: &TcpListener, server: &mut Server) -> TcpStream {
    listener.set_nonblocking(true).unwrap();
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        match listener.accept() {
            Ok((stream, _)) => return stream,
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                assert!(
                    server.0.try_wait().unwrap().is_none(),
                    "server exited before connecting"
                );
                assert!(Instant::now() < deadline, "server did not connect");
                thread::sleep(Duration::from_millis(10));
            }
            Err(error) => panic!("accept failed: {error}"),
        }
    }
}

fn assert_count_reply(stream: &mut TcpStream) {
    let mut response = [0u8; 6];
    stream.read_exact(&mut response).unwrap();
    assert_eq!(response, [b'm', b's', 1, 0, 0, 0x1f]);
}

fn assert_serving_survives_pause(prefix: &[u8], suffix: &[u8]) {
    let folder = tempfile::tempdir().unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap().to_string();
    let mut server = Server(
        Command::new(env!("CARGO_BIN_EXE_motatool"))
            .arg("serve")
            .arg("--dir")
            .arg(folder.path())
            .args(["--tcp", &address, "--verbose"])
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap(),
    );
    let mut stream = accept(&listener, &mut server);
    stream
        .set_read_timeout(Some(Duration::from_secs(3)))
        .unwrap();
    stream.set_nodelay(true).unwrap();
    stream.write_all(b"MS\x01\x01").unwrap();
    assert_count_reply(&mut stream);

    stream.write_all(prefix).unwrap();
    // Let the seeder block in its next timed read, optionally within a partial binary frame.
    thread::sleep(Duration::from_millis(50));
    signal(&server, "-STOP");
    let status_path = format!("/proc/{}/status", server.0.id());
    let stopped_by = Instant::now() + Duration::from_secs(2);
    loop {
        let status = std::fs::read_to_string(&status_path).unwrap();
        if status
            .lines()
            .any(|line| line.starts_with("State:") && line.contains("T (stopped)"))
        {
            break;
        }
        assert!(Instant::now() < stopped_by, "server did not stop: {status}");
        thread::sleep(Duration::from_millis(5));
    }
    // Linux can return EINTR when this timed socket read resumes, even without a signal handler.
    thread::sleep(Duration::from_secs(1));
    signal(&server, "-CONT");
    stream.write_all(suffix).unwrap();
    assert_count_reply(&mut stream);
    assert!(
        server.0.try_wait().unwrap().is_none(),
        "resumed server exited"
    );

    stream.shutdown(Shutdown::Both).unwrap();
    drop(stream);
    let exit_by = Instant::now() + Duration::from_secs(3);
    let exit = loop {
        if let Some(exit) = server.0.try_wait().unwrap() {
            break exit;
        }
        assert!(
            Instant::now() < exit_by,
            "server did not stop after actual EOF"
        );
        thread::sleep(Duration::from_millis(10));
    };
    assert!(exit.success(), "{exit}");
    let mut stdout = String::new();
    server
        .0
        .stdout
        .take()
        .unwrap()
        .read_to_string(&mut stdout)
        .unwrap();
    assert_eq!(stdout.matches("COUNT -> 0").count(), 2, "{stdout}");
    assert!(stdout.contains("\nbye\n"), "{stdout}");
}

#[test]
fn tcp_seeder_survives_stop_continue_during_idle_read() {
    assert_serving_survives_pause(b"", b"MS\x01\x01");
}

#[test]
fn tcp_seeder_preserves_partial_frame_across_stop_continue() {
    assert_serving_survives_pause(b"MS\x01", b"\x01");
}
