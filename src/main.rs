use config::Config;
use log::LevelFilter;
use serde_json::from_reader;
use std::fmt::Display;
#[cfg(not(debug_assertions))]
use std::fs::create_dir;
use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, Error, Write};
use std::net::{Shutdown, TcpListener, TcpStream, ToSocketAddrs};
use std::process::exit;
use thread_pool::ThreadPool;

const SERVER_NAME: &str = "trash";
const CONFIG_NAME: &str = "config.json";

#[cfg(not(debug_assertions))]
const CONFIG_PATH: &str = if cfg!(linux) {
    "/etc/http-server"
} else if cfg!(windows) {
    "C:\\Program Files\\Common Files\\http-server\\"
} else {
    "config.json"
};

#[cfg(debug_assertions)]
const CONFIG_PATH: &str = "./";

mod config;
mod request;
mod response;

// TODO config file
// TODO log level
// TODO more robust error handling

fn main() {
    simple_logging::log_to_stderr(LevelFilter::Error);
    #[cfg(not(debug_assertions))]
    match create_dir(CONFIG_PATH) {
        Ok(_) => log::debug!("Created config directory: {}", CONFIG_PATH),
        Err(e) => log::error!("Could not create config directory: {}", e),
    }

    let mut config_file = match OpenOptions::new()
        .create(true)
        .write(true)
        .read(true)
        .open(format!("{}/{}", CONFIG_PATH, CONFIG_NAME))
    {
        Ok(conf_file) => conf_file,
        Err(e) => {
            log::error!("Unable to create {}: {}", CONFIG_NAME, e);
            exit(-0x1)
        }
    };

    if let Ok(config_meta) = config_file.metadata() {
        if config_meta.len() < 75 {
            config_file
                .write_all(
                    serde_json::to_string_pretty(&Config::default())
                        .unwrap()
                        .as_bytes(),
                )
                .unwrap();
        }
    }

    let config = load_config(config_file);
    simple_logging::log_to_stderr(config.log_level());

    let thread_pool = ThreadPool::new(config.thread_count());

    let listener = bind(&config.address());

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

            exit(-0x420)
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

fn load_config(reader: File) -> config::Config {
    match from_reader::<File, config::Config>(reader) {
        Ok(config) => config,
        Err(e) => {
            log::error!("Failed to read config file: {}", e);
            exit(-0x69)
        }
    }
}
