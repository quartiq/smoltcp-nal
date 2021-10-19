# Changelog

This document describes the changes to smoltcp-nal between releases.

# Unreleased
* Added a reset API to close all sockets and reset DHCP whenever a link is lost. Updated DHCP to
  close sockets if local address changes.
* Upgraded to 0.6.1 of heapless to address security vulnerability
* Adding support for DHCP IP assignment and management.
* Fixed multiple bugs causing mismatch between ports in used_sockets and actual ports used by
  sockets
* Updating `embedded-nal` to 0.6
* Added UDP client support
* Updated `nanorand` to 0.6
* Added support for the new `rand` requirement from `smoltcp`

## Version 0.1.0
Version 0.1.0 was published on 2021-02-17

* Initial library release and publish to crates.io
