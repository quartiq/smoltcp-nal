# Changelog

This document describes the changes to smoltcp-nal between releases.

# [Unreleased]
## Added
## Fixed

# [0.2.1]
## Added
* Public access to the smoltcp network interface

## Fixed
* Link reset when not using DHCP no longer removes IP address configuration

# [0.2.0] - 2021-12-13

## Added
* Added a reset API to close all sockets and reset DHCP whenever a link is lost. Updated DHCP to
  close sockets if local address changes.
* Adding support for DHCP IP assignment and management.
* Added UDP client support
* Added polling via an `embedded_time::Clock`
* Added `shared-stack` feature for the new `shared` module

## Fixed
* Fixed multiple bugs causing mismatch between ports in used_sockets and actual ports used by
  sockets
* Upgraded to 0.6.1 of heapless to address security vulnerability
* Updated `nanorand` to 0.6
* Updating `embedded-nal` to 0.6
* Updated to `smoltcp` version 0.8

# Version [0.1.0] - 2021-02-17
* Initial library release and publish to crates.io

[Unreleased]: https://github.com/quartiq/smoltcp-nal/compare/0.2.1...HEAD
[0.2.1]: https://github.com/quartiq/smoltcp-nal/tree/0.2.1
[0.2.0]: https://github.com/quartiq/smoltcp-nal/tree/0.2.0
[0.1.0]: https://github.com/quartiq/smoltcp-nal/tree/0.1.0
