#![feature(backtrace)]

use std::fmt::Display;
use std::net::{TcpListener, TcpStream, ToSocketAddrs, Shutdown};
use std::process::exit;
use std::io::{Read, Write, BufReader, BufRead, Error};
use thread_pool::ThreadPool;
use log::LevelFilter;

mod methods;

// TODO config file
// TODO log level

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

            exit(0x420);
        }
    }
}

fn handle_request(stream: &mut TcpStream) {
    let input = read_request(stream).unwrap();
    let request = methods::Request::parse(&input).unwrap();

    let _bytes_written = stream.write(b"Good Job!").unwrap();
    stream.flush().unwrap();
    stream.shutdown(Shutdown::Both).unwrap();

    log::debug!("{:?}", request)
}

fn read_request(stream: &mut TcpStream) -> Result<String, Error>  {
    let mut buf = String::new();
    let reader = BufReader::new(stream.try_clone().unwrap());

    log::debug!("{:?}", reader);

    for line in reader.lines().map(|l| l.unwrap()) {
        if line != "" {
            buf.push_str(&format!("{}\r\n", &line))
        } else {
            break
        }
    }

    Ok(buf)
}