use serde::{Deserialize, Serialize};
use std::fmt::Display;
use std::net::ToSocketAddrs;

#[derive(Debug, Deserialize, Serialize, PartialOrd, PartialEq)]
pub struct Config<A>
where
    A: ToSocketAddrs + Copy + Display,
{
    address: A,
    thread_count: usize,
}
