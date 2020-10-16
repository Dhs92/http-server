use std::fmt;
use std::error;
use std::backtrace::Backtrace;
use std::collections::HashMap;

#[derive(Debug)]
pub enum Method {
    GET,
    PUT,
    HEAD,
    POST,
    DELETE,
    OPTIONS,
}

#[derive(Debug)]
pub enum ParseError {
    InvalidMethod(Backtrace),
    InvalidInput,
}

#[derive(Debug)]
pub struct Request<'a> {
    method: Method,
    resource: &'a str,
    version: Option<&'a str>,
    headers: HashMap<String, String>
}

impl fmt::Display for Method {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error>{
        let result = match self {
            Method::GET => "GET".to_owned(),
            Method::PUT => "PUT".to_owned(),
            Method::HEAD => "HEAD".to_owned(),
            Method::POST => "POST".to_owned(),
            Method::DELETE => "DELETE".to_owned(),
            Method::OPTIONS => "OPTIONS".to_owned(),
        };

        write!(f, "{}", result)

    }
}
// TODO remove backtrace
impl Method {
    fn parse(method: &str) -> Result<Self, ParseError> {
        let method = method.trim_start().trim_end();
        match method {
            "GET" => Ok(Self::GET),
            "PUT" => Ok(Self::PUT),
            "HEAD" => Ok(Self::HEAD),
            "POST" => Ok(Self::POST),
            "DELETE" => Ok(Self::DELETE),
            "OPTIONS" => Ok(Self::OPTIONS),
            _ => {
                let backtrace = Backtrace::capture();
                Err(ParseError::InvalidMethod(backtrace))
            },
        }
    }
}

impl<'a> fmt::Display for Request<'a> {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {

        if let Some(version) = self.version {
            write!(f, "{} {} {}\r\n", self.method, self.resource, version)
        } else {
            write!(f, "{} {}\r\n", self.method, self.resource)
        }
    }
}

impl<'a> Request<'a> {
    pub fn parse(request: &'a str) -> Result<Self, ParseError> {
        let mut tokens = request.split_ascii_whitespace();
        let mut headers = HashMap::new();

        let result = Self {
            method: match tokens.next() {
                Some(method) =>{
                    Method::parse(method)? 
                },
                None => return Err(ParseError::InvalidInput),
            },
            resource: match tokens.next() {
                Some(resource) => resource,
                None => return Err(ParseError::InvalidInput),
            },
            version: match tokens.next() {
                Some(version) => Some(version),
                None => None,
            },
            headers: { // TODO sort out issues with recollecting the string
                for line in request.split("\r\n").skip(1) {
                    if !line.is_empty() {
                        let tokens = line.splitn(2, ": ").collect::<Vec<_>>();
                        //log::debug!("Line: {}", line);
                        log::debug!("Tokens: {:?}", tokens);
                        headers.insert(tokens[0].to_owned(), tokens[1].to_owned());
                    }
                }

                headers
            }
        };

        Ok(result)
    }
}

impl<'a> fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        write!(f, "{:#?}", self)
    }
}

impl<'a> error::Error for ParseError {
    fn backtrace(&self) -> Option<&Backtrace> {
        match self {
            ParseError::InvalidMethod(b) => Some(b),
            ParseError::InvalidInput => None
        }
    }
}