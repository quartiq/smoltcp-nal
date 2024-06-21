# Changelog

This document describes the changes to smoltcp-nal between releases.

# [0.5.1] - 2024-06-21

## Fixed
* Fixed an issue where attempting to open sockets before DHCP was completed wwould result in an
internal panic.

# [0.5.0] - 2024-04-22

## Changed
* [breaking] Updated to `embedded-nal` v0.8
* Updated to smoltcp 0.11

# [0.4.1] - 2023-08-22

## Added
* Added support for `embedded_nal::Dns` traits

# [0.4.0] - 2023-07-21

## Added
* Updated to smoltcp 0.10

# [0.3.0]

## Added
* Implemented full UDP socket
* [breaking] Updated to smoltcp 0.9

## Changed
* [breaking] embedded-nal updated to 0.7

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

[Unreleased]: https://github.com/quartiq/smoltcp-nal/compare/0.5.1...HEAD
[0.5.1]: https://github.com/quartiq/smoltcp-nal/tree/0.5.1
[0.5.0]: https://github.com/quartiq/smoltcp-nal/tree/0.5.0
[0.4.1]: https://github.com/quartiq/smoltcp-nal/tree/0.4.1
[0.4.0]: https://github.com/quartiq/smoltcp-nal/tree/0.4.0
[0.3.0]: https://github.com/quartiq/smoltcp-nal/tree/0.3.0
[0.2.1]: https://github.com/quartiq/smoltcp-nal/tree/0.2.1
[0.2.0]: https://github.com/quartiq/smoltcp-nal/tree/0.2.0
[0.1.0]: https://github.com/quartiq/smoltcp-nal/tree/0.1.0
