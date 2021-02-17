# smoltcp Network Abstraction Layer (NAL)

[![QUARTIQ Matrix Chat](https://img.shields.io/matrix/quartiq:matrix.org)](https://matrix.to/#/#quartiq:matrix.org)
![Continuous Integration](https://github.com/quartiq/smoltcp-nal/workflows/Continuous%20Integration/badge.svg)

An [`embedded-nal`](https://crates.io/crates/embedded-nal) implementation for [`smoltcp`](https://crates.io/crates/smoltcp).

This repository provides an implementation of a TCP-capable network stack that can be used for any
library that leverages the `embedded-nal`.


## Limitations

This currently only supports TCP network stacks.
