use log::LevelFilter;
use std::fmt::Display;
use std::io::{BufRead, BufReader, Error, Write};
use std::net::{Shutdown, TcpListener, TcpStream, ToSocketAddrs};
use std::process::exit;
use thread_pool::ThreadPool;

const SERVER_NAME: &str = "hyper";

mod request;
mod response;

// TODO config file
// TODO log level
// TODO more robust error handling

fn main() {
    simple_logging::log_to_stderr(LevelFilter::Debug);

    let thread_pool = ThreadPool::new(15); // TODO get worker count from config

    let listener = bind("127.0.0.1:8080");

    for stream in listener.incoming() {
        match stream {
            Ok(mut stream) => thread_pool.execute(move || handle_request(&mut stream)),
            Err(e) => log::warn!("Connection failed: {}", e),
        }
    }
}

fn bind<A>(addr: A) -> TcpListener
where
    A: ToSocketAddrs + Copy + Display,
{
    match TcpListener::bind(addr) {
        Ok(listener) => listener,
        Err(e) => {
            log::error!("Failed to bind {}: {}", addr, e);

            exit(0x420)
        }
    }
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

    log::debug!("{}", request)
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
