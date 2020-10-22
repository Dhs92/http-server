use crate::response;
use std::collections::HashMap;
use std::error;
use std::fmt;

#[derive(Debug)]
pub enum Method {
    Get,
    Put,
    Head,
    Post,
    Delete,
    Options,
}

#[derive(Debug)]
pub enum ParseError {
    InvalidMethod,
    InvalidInput,
}

#[derive(Debug)]
pub struct Request<'a> {
    method: Method,
    resource: &'a str,
    version: Option<&'a str>,
    headers: HashMap<String, String>,
}

impl fmt::Display for Method {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        let result = match self {
            Method::Get => "GET".to_owned(),
            Method::Put => "PUT".to_owned(),
            Method::Head => "HEAD".to_owned(),
            Method::Post => "POST".to_owned(),
            Method::Delete => "DELETE".to_owned(),
            Method::Options => "OPTIONS".to_owned(),
        };

        write!(f, "{}", result)
    }
}
// TODO remove backtrace
impl Method {
    fn parse(method: &str) -> Result<Self, ParseError> {
        let method = method.trim_start().trim_end();
        match method {
            "GET" => Ok(Self::Get),
            "PUT" => Ok(Self::Put),
            "HEAD" => Ok(Self::Head),
            "POST" => Ok(Self::Post),
            "DELETE" => Ok(Self::Delete),
            "OPTIONS" => Ok(Self::Options),
            _ => Err(ParseError::InvalidMethod),
        }
    }
}

impl<'a> fmt::Display for Request<'a> {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        if let Some(version) = self.version {
            writeln!(f, "{} {} {}\r", self.method, self.resource, version)?; // TODO unwrap bad
            for (key, field) in &self.headers {
                writeln!(f, "{}: {}\r", key, field)?;
            }
        } else {
            writeln!(f, "{} {}\r", self.method, self.resource)?;
            for (key, field) in &self.headers {
                writeln!(f, "{}: {}\r", key, field)?;
            }
        }
        Ok(())
    }
}

impl<'a> Request<'a> {
    pub fn parse(request: &'a str) -> Result<(Self, response::ResponseCode), ParseError> {
        let mut tokens = request.split_ascii_whitespace();
        let mut headers = HashMap::new();

        let result = Self {
            method: match tokens.next() {
                Some(method) => Method::parse(method)?,
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
            headers: {
                for line in request.split("\r\n").skip(1) {
                    if !line.is_empty() {
                        let tokens = line.splitn(2, ": ").collect::<Vec<_>>();

                        log::debug!("Header: {:?}", tokens);

                        headers.insert(tokens[0].to_owned(), tokens[1].to_owned());
                    }
                }

                headers
            },
        };

        Ok((result, response::ResponseCode::NotFound))
    }
}

impl<'a> fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        write!(f, "{:#?}", self)
    }
}

impl<'a> error::Error for ParseError {}
