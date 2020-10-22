use std::fmt;

pub enum ResponseCode {
    Continue,
    Switch,
    EarlyHints,
    Ok,
    Created,
    Accepted,
    NoContent,
    ResetContent,
    PartialContent,
    MultiChoice,
    MovedPerm,
    Found,
    SeeOther,
    NotModified,
    TempRedirect,
    PermRedirect,
    BadRequest,
    Unauthorized,
    Forbidden,
    NotFound,
    MethodNotAllowed,
    NotAcceptable,
    RequestTimeout,
    // ...
}

impl fmt::Display for ResponseCode {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let response_str = match self {
            Self::Continue => "100 Continue",
            Self::Switch => "101 Switching Protocol",
            Self::EarlyHints => "103 Early Hints",
            Self::Ok => "200 OK",
            Self::Created => "201 Created",
            Self::Accepted => "202 Accepted",
            Self::NoContent => "204 No Content",
            Self::ResetContent => "205 Reset Content",
            Self::PartialContent => "206 Partial Content",
            Self::MultiChoice => "300 Multiple Choice",
            Self::MovedPerm => "301 Moved Permanently",
            Self::Found => "302 Found",
            Self::SeeOther => "303 See Other",
            Self::NotModified => "304 Not Modified",
            Self::TempRedirect => "307 Temporary Redirect",
            Self::PermRedirect => "308 Permanent Redirect",
            Self::BadRequest => "400 Bad Request",
            Self::Unauthorized => "401 Unauthorized",
            Self::Forbidden => "403 Forbidden",
            Self::NotFound => "404 Not Found",
            Self::MethodNotAllowed => "405 Method Not Allowed",
            Self::NotAcceptable => "406 Not Acceptable",
            Self::RequestTimeout => "408 Request Timeout",
        };

        write!(f, "HTTP/1.0 {}", response_str)
    }
}
