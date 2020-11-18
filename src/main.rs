use std::env;
use std::io::{BufRead, BufReader, Error, Write};
use std::net::{Shutdown, TcpStream};
const SERVER_NAME: &str = "trash";

// workaround for Rust Analyzer not supporting cfg_attr
mod config;
#[path = "os/windows.rs"]
mod windows;
//use config::Config;
#[cfg(windows)]
use windows as os;
#[cfg(target_os = "linux")]
#[path = "os/linux.rs"]
mod linux;
#[cfg(target_os = "linux")]
use linux as os;
mod request;
mod response;

// TODO config file
// TODO log level
// TODO more robust error handling

fn main() {
    let args = env::args().collect::<Vec<_>>();

    let mut pid = None;
    let args = &args[1..];
    if !args.is_empty() {
        pid = match &*args[0] {
            "--p" => Some(args[1].parse().unwrap()),
            _ => None,
        };
    }
    os::start(pid);
}

fn handle_request(stream: &mut TcpStream) {
    let input = match read_request(stream) {
        Ok(s) => s,
        Err(e) => {
            log::error!("Failed to read from stream: {}", e);
            return;
        }
    };

    let (request, response) = request::Request::parse(&input).unwrap();

    match stream.write_all(
        format!(
            "{}\r\nServer: {}\r\n\r\n<h1>Uh-oh, Not Found!</h1>",
            response, SERVER_NAME
        )
        .as_bytes(),
    ) {
        Ok(_) => (),
        Err(e) => log::error!("Failed to write to socket: {}", e),
    }

    match stream.flush() {
        Ok(_) => (),
        Err(e) => log::error!("Failed to flush stream: {}", e),
    }
    match stream.shutdown(Shutdown::Both) {
        Ok(_) => (),
        Err(e) => log::error!("Failed to shutdown stream: {}", e),
    }
}

fn read_request(stream: &mut TcpStream) -> Result<String, Error> {
    let mut buf = String::new();
    let reader = BufReader::new(stream.try_clone().unwrap());

    log::debug!("{:?}", reader);

    // TODO remove unwrap here
    for line in reader.lines().map(|l| l.unwrap()) {
        if !line.is_empty() {
            buf.push_str(&format!("{}\r\n", &line))
        } else {
            break;
        }
    }

    Ok(buf)
}
