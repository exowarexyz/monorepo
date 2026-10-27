//! Authenticated Commonware QMDB interfaces through Store and Connect

// These futures hold whole servers and stores inline. Boxing them in tests would only add noise.
#![allow(clippy::large_futures)]

#[macro_use]
#[path = "variants/source.rs"]
mod source;

#[path = "variants/append.rs"]
mod append;
#[path = "variants/browser.rs"]
mod browser;
mod common;
#[path = "variants/ordered.rs"]
mod ordered;
#[path = "variants/unordered.rs"]
mod unordered;
