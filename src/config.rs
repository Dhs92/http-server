use serde::{Deserialize, Serialize};
use std::fmt::Display;
use std::net::ToSocketAddrs;

#[derive(Debug, Deserialize, Serialize, PartialOrd, PartialEq)]
pub struct Config<'s, A>
where
    A: ToSocketAddrs + Copy + Display,
{
    server_name: &'s str,
    address: A,
    thread_count: usize,
}
