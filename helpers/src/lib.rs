// #![no_main]
// #![no_std]
#![cfg_attr(not(test), no_std, no_main)]

pub mod bitcoin;
pub mod bridge;
pub mod config;
pub mod constant;
pub mod env;
pub mod hashes;
pub mod incremental_merkle;
