# smoltcp Network Abstraction Layer (NAL)

[![QUARTIQ Matrix Chat](https://img.shields.io/matrix/quartiq:matrix.org)](https://matrix.to/#/#quartiq:matrix.org)
![Continuous Integration](https://github.com/quartiq/smoltcp-nal/workflows/Continuous%20Integration/badge.svg)

An [`embedded-nal`](https://crates.io/crates/embedded-nal) implementation for [`smoltcp`](https://crates.io/crates/smoltcp).

This repository provides an implementation of a TCP- and UDP-capable network stack that can be used
for any library that leverages the `embedded-nal`.

This crate also supports DHCP management internally if DHCP via smoltcp is used.
