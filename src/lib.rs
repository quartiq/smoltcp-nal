//! A [embedded_nal]-compatible network stack for [smoltcp]
//!
//! # Usage
//! To use this library, first instantiate the [smoltcp::iface::Interface] and add sockets to
//! it. Once sockets have been added, pass the interface to [NetworkStack::new()].
//!
//! # Sharing the Stack
//! If you have multiple users of the network stack, you can use the [shared::NetworkManager] by
//! enabling the `shared-stack` feature. Note that this implementation does not employ any mutually
//! exclusive access mechanism. For information on how to use this manager, refer to
//! [shared_bus::AtomicCheckMutex]'s documentation.
//!
//! When sharing the stack, it is the users responsibility to ensure that access to the network
//! stack is mutually exclusive. For example, this can be done when using RTIC by storing all of
//! the resources that use the network stack in a single resource.
#![no_std]

use core::convert::TryFrom;
pub use embedded_nal;
use nanorand::Rng;
pub use smoltcp;

use embedded_nal::{TcpClientStack, UdpClientStack};
use embedded_time::duration::Milliseconds;
use smoltcp::{
    iface::SocketHandle,
    socket::{Dhcpv4Event, Dhcpv4Socket},
    wire::{IpAddress, IpCidr, IpEndpoint, Ipv4Address, Ipv4Cidr},
};

use heapless::Vec;
use nanorand::wyrand::WyRand;

#[cfg(feature = "shared-stack")]
pub mod shared;

// The start of TCP port dynamic range allocation.
const TCP_PORT_DYNAMIC_RANGE_START: u16 = 49152;

#[derive(Debug, Copy, Clone)]
pub enum NetworkError {
    NoSocket,
    ConnectionFailure,
    ReadFailure,
    WriteFailure,
    Unsupported,
    NoIpAddress,
}

/// Combination error used for polling the network stack
#[derive(Debug)]
pub enum Error {
    Network(smoltcp::Error),
    Time(embedded_time::TimeError),
}

impl From<smoltcp::Error> for Error {
    fn from(e: smoltcp::Error) -> Self {
        Error::Network(e)
    }
}

impl From<embedded_time::TimeError> for Error {
    fn from(e: embedded_time::TimeError) -> Self {
        Error::Time(e)
    }
}

impl From<embedded_time::clock::Error> for Error {
    fn from(e: embedded_time::clock::Error) -> Self {
        Error::Time(e.into())
    }
}

impl From<embedded_time::ConversionError> for Error {
    fn from(e: embedded_time::ConversionError) -> Self {
        Error::Time(e.into())
    }
}

#[derive(Debug)]
pub struct UdpSocket {
    handle: SocketHandle,
    destination: IpEndpoint,
}

/// Network abstraction layer for smoltcp.
pub struct NetworkStack<'a, DeviceT, Clock>
where
    DeviceT: for<'x> smoltcp::phy::Device<'x>,
    Clock: embedded_time::Clock,
    u32: From<Clock::T>,
{
    network_interface: smoltcp::iface::Interface<'a, DeviceT>,
    dhcp_handle: Option<SocketHandle>,
    unused_tcp_handles: Vec<SocketHandle, 16>,
    unused_udp_handles: Vec<SocketHandle, 16>,
    name_servers: Vec<Ipv4Address, 3>,
    clock: Clock,
    last_poll: Option<embedded_time::Instant<Clock>>,
    stack_time: smoltcp::time::Instant,
    rand: WyRand,
}

impl<'a, DeviceT, Clock> NetworkStack<'a, DeviceT, Clock>
where
    DeviceT: for<'x> smoltcp::phy::Device<'x>,
    Clock: embedded_time::Clock,
    u32: From<Clock::T>,
{
    /// Construct a new network stack.
    ///
    /// # Note
    /// This implementation only supports up to 16 usable sockets.
    ///
    /// Any handles provided to this function must not be used after constructing the network
    /// stack.
    ///
    /// This implementation currently only supports IPv4.
    ///
    /// # Args
    /// * `stack` - The ethernet interface to construct the network stack from.
    /// * `clock` - A clock to use for determining network time.
    ///
    /// # Returns
    /// A [embedded_nal] compatible network stack.
    pub fn new(stack: smoltcp::iface::Interface<'a, DeviceT>, clock: Clock) -> Self {
        let mut unused_tcp_handles: Vec<SocketHandle, 16> = Vec::new();
        let mut unused_udp_handles: Vec<SocketHandle, 16> = Vec::new();
        let mut dhcp_handle: Option<SocketHandle> = None;

        for (handle, socket) in stack.sockets() {
            match socket {
                smoltcp::socket::Socket::Tcp(_) => {
                    unused_tcp_handles.push(handle).ok();
                }
                smoltcp::socket::Socket::Udp(_) => {
                    unused_udp_handles.push(handle).ok();
                }
                smoltcp::socket::Socket::Dhcpv4(_) => {
                    dhcp_handle.replace(handle);
                }

                // This branch may be enabled through cargo feature unification (e.g. if an
                // application enables raw-sockets). To accomodate this, we provide a default match
                // arm.
                #[allow(unreachable_patterns)]
                _ => {}
            }
        }

        NetworkStack {
            network_interface: stack,
            dhcp_handle,
            unused_tcp_handles,
            unused_udp_handles,
            name_servers: Vec::new(),
            last_poll: None,
            clock,
            stack_time: smoltcp::time::Instant::from_secs(0),
            rand: WyRand::new_seed(0),
        }
    }

    /// Seed the TCP port randomizer.
    ///
    /// # Args
    /// * `seed` - A seed of random data to use for randomizing local TCP port selection.
    pub fn seed_random_port(&mut self, seed: &[u8]) {
        self.rand.reseed(seed);
    }

    /// Poll the network stack for potential updates.
    ///
    /// # Returns
    /// A boolean indicating if the network stack updated in any way.
    pub fn poll(&mut self) -> Result<bool, Error> {
        let now = self.clock.try_now()?;

        // We can only start using the clock once we call `poll()`, as it may not be initialized
        // beforehand. In these cases, the last_poll may be uninitialized. If this is the case,
        // populate it now.
        if self.last_poll.is_none() {
            self.last_poll.replace(now);
        }

        // Note(unwrap): We guarantee that the last_poll value is set above.
        let elapsed_system_time = now - *self.last_poll.as_ref().unwrap();

        let elapsed_ms: Milliseconds<u32> = Milliseconds::try_from(elapsed_system_time)?;

        if elapsed_ms.0 > 0 {
            self.stack_time += smoltcp::time::Duration::from_millis(elapsed_ms.0.into());

            // In order to avoid quantization noise, instead of setting the previous poll instant
            // to the current time, we set it to the last poll instant plus the number of millis
            // that we incremented smoltcps time by. This ensures that if e.g. we had 1.5 millis
            // elapse, we don't accidentally discard the 500 microseconds by fast-forwarding
            // smoltcp by 1ms, but moving our internal timer by 1.5ms.
            //
            // Note(unwrap): We guarantee that last_poll is always some time above.
            self.last_poll.replace(self.last_poll.unwrap() + elapsed_ms);
        }

        let updated = self.network_interface.poll(self.stack_time)?;

        // Service the DHCP client.
        if let Some(handle) = self.dhcp_handle {
            let mut close_sockets = false;

            if let Some(event) = self
                .network_interface
                .get_socket::<Dhcpv4Socket>(handle)
                .poll()
            {
                match event {
                    Dhcpv4Event::Configured(config) => {
                        if config.address.address().is_unicast()
                            && self.network_interface.ipv4_address().unwrap()
                                != config.address.address()
                        {
                            close_sockets = true;
                            Self::set_ipv4_addr(&mut self.network_interface, config.address);
                        }

                        // Store DNS server addresses for later read-back
                        self.name_servers.clear();
                        for server in config.dns_servers.iter() {
                            if let Some(server) = server {
                                // Note(unwrap): The name servers vector is at least as long as the
                                // number of DNS servers reported via DHCP.
                                self.name_servers.push(*server).unwrap();
                            }
                        }

                        if let Some(route) = config.router {
                            // Note: If the user did not provide enough route storage, we may not be
                            // able to store the gateway.
                            self.network_interface
                                .routes_mut()
                                .add_default_ipv4_route(route)?;
                        } else {
                            self.network_interface
                                .routes_mut()
                                .remove_default_ipv4_route();
                        }
                    }
                    Dhcpv4Event::Deconfigured => {
                        self.network_interface
                            .routes_mut()
                            .remove_default_ipv4_route();
                        Self::set_ipv4_addr(
                            &mut self.network_interface,
                            Ipv4Cidr::new(Ipv4Address::UNSPECIFIED, 0),
                        );
                    }
                }
            }

            if close_sockets {
                self.close_sockets();
            }
        }

        Ok(updated)
    }

    /// Force-close all sockets.
    pub fn close_sockets(&mut self) {
        // Close all sockets.
        for (_handle, socket) in self.network_interface.sockets_mut() {
            match socket {
                smoltcp::socket::Socket::Udp(sock) => {
                    sock.close();
                }
                smoltcp::socket::Socket::Tcp(sock) => {
                    sock.abort();
                }

                _ => {}
            }
        }
    }

    fn set_ipv4_addr(interface: &mut smoltcp::iface::Interface<'a, DeviceT>, address: Ipv4Cidr) {
        interface.update_ip_addrs(|addrs| {
            // Note(unwrap): This stack requires at least 1 Ipv4 Address.
            let addr = addrs
                .iter_mut()
                .filter(|cidr| match cidr.address() {
                    IpAddress::Ipv4(_) => true,
                    _ => false,
                })
                .next()
                .unwrap();

            *addr = IpCidr::Ipv4(address);
        });
    }

    /// Handle a disconnection of the physical interface.
    pub fn handle_link_reset(&mut self) {
        // Close all of the sockets and de-configure the interface.
        self.close_sockets();

        // Reset the DHCP client.
        if let Some(handle) = self.dhcp_handle {
            self.network_interface
                .get_socket::<Dhcpv4Socket>(handle)
                .reset();

            self.network_interface.update_ip_addrs(|addrs| {
                addrs.iter_mut().next().map(|addr| {
                    *addr = IpCidr::Ipv4(Ipv4Cidr::new(Ipv4Address::UNSPECIFIED, 0));
                });
            });
        }
    }

    /// Access the underlying network interface.
    pub fn interface(&self) -> &smoltcp::iface::Interface<'a, DeviceT> {
        &self.network_interface
    }

    /// Mutably access the underlying network interface.
    ///
    /// # Note
    /// Modification of the underlying network interface may unintentionally interfere with
    /// operation of this library (e.g. through reset, modification of IP addresses, etc.). Mutable
    /// access to the interface should be done with care.
    pub fn interface_mut(&mut self) -> &mut smoltcp::iface::Interface<'a, DeviceT> {
        &mut self.network_interface
    }

    /// Check if a port is currently in use.
    ///
    /// # Returns
    /// True if the port is in use. False otherwise.
    fn is_port_in_use(&mut self, port: u16) -> bool {
        for (_handle, socket) in self.network_interface.sockets_mut() {
            match socket {
                smoltcp::socket::Socket::Tcp(sock) => {
                    let endpoint = sock.local_endpoint();
                    if endpoint.is_specified() {
                        if endpoint.port == port {
                            return true;
                        }
                    }
                }
                smoltcp::socket::Socket::Udp(sock) => {
                    let endpoint = sock.endpoint();
                    if endpoint.is_specified() {
                        if endpoint.port == port {
                            return true;
                        }
                    }
                }
                _ => {}
            }
        }

        return false;
    }

    // Get an ephemeral port number.
    fn get_ephemeral_port(&mut self) -> u16 {
        loop {
            // Get the next ephemeral port by generating a random, valid TCP port continuously
            // until an unused port is found.
            let random_offset = {
                let random_data = self.rand.rand();
                u16::from_be_bytes([random_data[0], random_data[1]])
            };

            let port = TCP_PORT_DYNAMIC_RANGE_START
                + random_offset % (u16::MAX - TCP_PORT_DYNAMIC_RANGE_START);
            if !self.is_port_in_use(port) {
                return port;
            }
        }
    }

    fn is_ip_unspecified(&self) -> bool {
        // Note(unwrap): This stack only supports Ipv4.
        self.network_interface.ipv4_addr().unwrap().is_unspecified()
    }
}

impl<'a, DeviceT, Clock> TcpClientStack for NetworkStack<'a, DeviceT, Clock>
where
    DeviceT: for<'x> smoltcp::phy::Device<'x>,
    Clock: embedded_time::Clock,
    u32: From<Clock::T>,
{
    type Error = NetworkError;
    type TcpSocket = SocketHandle;

    fn socket(&mut self) -> Result<SocketHandle, NetworkError> {
        // If we do not have a valid IP address yet, do not open the socket.
        if self.is_ip_unspecified() {
            return Err(NetworkError::NoIpAddress);
        }

        match self.unused_tcp_handles.pop() {
            Some(handle) => {
                // Abort any active connections on the handle.
                let internal_socket: &mut smoltcp::socket::TcpSocket =
                    self.network_interface.get_socket(handle);
                internal_socket.abort();

                Ok(handle)
            }
            None => Err(NetworkError::NoSocket),
        }
    }

    fn connect(
        &mut self,
        socket: &mut SocketHandle,
        remote: embedded_nal::SocketAddr,
    ) -> embedded_nal::nb::Result<(), NetworkError> {
        // If there is no longer an IP address assigned to the interface, do not allow usage of the
        // socket.
        if self.is_ip_unspecified() {
            return Err(embedded_nal::nb::Error::Other(NetworkError::NoIpAddress));
        }

        {
            let internal_socket = self
                .network_interface
                .get_socket::<smoltcp::socket::TcpSocket>(*socket);

            // If we're already in the process of connecting, ignore the request silently.
            if internal_socket.is_open() {
                return Ok(());
            }
        }

        match remote.ip() {
            embedded_nal::IpAddr::V4(addr) => {
                let octets = addr.octets();
                let address =
                    smoltcp::wire::Ipv4Address::new(octets[0], octets[1], octets[2], octets[3]);

                let local_port = self.get_ephemeral_port();
                let (internal_socket, context) = self
                    .network_interface
                    .get_socket_and_context::<smoltcp::socket::TcpSocket>(*socket);
                internal_socket
                    .connect(context, (address, remote.port()), local_port)
                    .map_err(|_| embedded_nal::nb::Error::Other(NetworkError::ConnectionFailure))
            }

            // We only support IPv4.
            _ => Err(embedded_nal::nb::Error::Other(NetworkError::Unsupported)),
        }
    }

    fn is_connected(&mut self, socket: &SocketHandle) -> Result<bool, NetworkError> {
        // If there is no longer an IP address assigned to the interface, do not allow usage of the
        // socket.
        if self.is_ip_unspecified() {
            return Err(NetworkError::NoIpAddress);
        }

        let socket: &mut smoltcp::socket::TcpSocket = self.network_interface.get_socket(*socket);
        Ok(socket.may_send() && socket.may_recv())
    }

    fn send(
        &mut self,
        socket: &mut SocketHandle,
        buffer: &[u8],
    ) -> embedded_nal::nb::Result<usize, NetworkError> {
        // If there is no longer an IP address assigned to the interface, do not allow usage of the
        // socket.
        if self.is_ip_unspecified() {
            return Err(embedded_nal::nb::Error::Other(NetworkError::NoIpAddress));
        }

        let socket: &mut smoltcp::socket::TcpSocket = self.network_interface.get_socket(*socket);
        socket
            .send_slice(buffer)
            .map_err(|_| embedded_nal::nb::Error::Other(NetworkError::WriteFailure))
    }

    fn receive(
        &mut self,
        socket: &mut SocketHandle,
        buffer: &mut [u8],
    ) -> embedded_nal::nb::Result<usize, NetworkError> {
        // If there is no longer an IP address assigned to the interface, do not allow usage of the
        // socket.
        if self.is_ip_unspecified() {
            return Err(embedded_nal::nb::Error::Other(NetworkError::NoIpAddress));
        }

        let socket: &mut smoltcp::socket::TcpSocket = self.network_interface.get_socket(*socket);
        socket
            .recv_slice(buffer)
            .map_err(|_| embedded_nal::nb::Error::Other(NetworkError::ReadFailure))
    }

    fn close(&mut self, socket: SocketHandle) -> Result<(), NetworkError> {
        let internal_socket: &mut smoltcp::socket::TcpSocket =
            self.network_interface.get_socket(socket);

        internal_socket.close();
        self.unused_tcp_handles.push(socket).unwrap();
        Ok(())
    }
}

impl<'a, DeviceT, Clock> UdpClientStack for NetworkStack<'a, DeviceT, Clock>
where
    DeviceT: for<'x> smoltcp::phy::Device<'x>,
    Clock: embedded_time::Clock,
    u32: From<Clock::T>,
{
    type Error = NetworkError;
    type UdpSocket = UdpSocket;

    fn socket(&mut self) -> Result<UdpSocket, NetworkError> {
        // If we do not have a valid IP address yet, do not open the socket.
        if self.is_ip_unspecified() {
            return Err(NetworkError::NoIpAddress);
        }

        let handle = self
            .unused_udp_handles
            .pop()
            .ok_or(NetworkError::NoSocket)?;

        // Make sure the socket is in a closed state before handing it to the user.
        let internal_socket: &mut smoltcp::socket::UdpSocket =
            self.network_interface.get_socket(handle);
        internal_socket.close();

        Ok(UdpSocket {
            handle,
            destination: IpEndpoint::UNSPECIFIED,
        })
    }

    fn connect(
        &mut self,
        socket: &mut UdpSocket,
        remote: embedded_nal::SocketAddr,
    ) -> Result<(), NetworkError> {
        if self.is_ip_unspecified() {
            return Err(NetworkError::NoIpAddress);
        }
        // Store the route for this socket.
        match remote {
            embedded_nal::SocketAddr::V4(addr) => {
                let octets = addr.ip().octets();
                socket.destination = IpEndpoint::new(
                    IpAddress::v4(octets[0], octets[1], octets[2], octets[3]),
                    addr.port(),
                )
            }

            // We only support IPv4.
            _ => return Err(NetworkError::Unsupported),
        }

        // Select a random port to bind to locally.
        let local_port = self.get_ephemeral_port();

        let local_address = self
            .network_interface
            .ip_addrs()
            .iter()
            .filter(|item| matches!(item, smoltcp::wire::IpCidr::Ipv4(_)))
            .next()
            .unwrap()
            .address();

        let local_endpoint = IpEndpoint::new(local_address, local_port);

        let internal_socket: &mut smoltcp::socket::UdpSocket =
            self.network_interface.get_socket(socket.handle);
        internal_socket
            .bind(local_endpoint)
            .map_err(|_| NetworkError::ConnectionFailure)?;

        Ok(())
    }

    fn send(
        &mut self,
        socket: &mut UdpSocket,
        buffer: &[u8],
    ) -> embedded_nal::nb::Result<(), NetworkError> {
        if self.is_ip_unspecified() {
            return Err(embedded_nal::nb::Error::Other(NetworkError::NoIpAddress));
        }

        let internal_socket: &mut smoltcp::socket::UdpSocket =
            self.network_interface.get_socket(socket.handle);
        internal_socket
            .send_slice(buffer, socket.destination)
            .map_err(|_| embedded_nal::nb::Error::Other(NetworkError::WriteFailure))
    }

    fn receive(
        &mut self,
        socket: &mut UdpSocket,
        buffer: &mut [u8],
    ) -> embedded_nal::nb::Result<(usize, embedded_nal::SocketAddr), NetworkError> {
        if self.is_ip_unspecified() {
            return Err(embedded_nal::nb::Error::Other(NetworkError::NoIpAddress));
        }

        let internal_socket: &mut smoltcp::socket::UdpSocket =
            self.network_interface.get_socket(socket.handle);
        let (size, source) = internal_socket
            .recv_slice(buffer)
            .map_err(|_| embedded_nal::nb::Error::Other(NetworkError::ReadFailure))?;

        let source = {
            let octets = source.addr.as_bytes();

            embedded_nal::SocketAddr::new(
                embedded_nal::IpAddr::V4(embedded_nal::Ipv4Addr::new(
                    octets[0], octets[1], octets[2], octets[3],
                )),
                source.port,
            )
        };

        Ok((size, source))
    }

    fn close(&mut self, socket: UdpSocket) -> Result<(), NetworkError> {
        let internal_socket: &mut smoltcp::socket::UdpSocket =
            self.network_interface.get_socket(socket.handle);

        internal_socket.close();

        // There should always be room to return the socket handle to the unused handle list.
        self.unused_udp_handles.push(socket.handle).unwrap();

        Ok(())
    }
}
