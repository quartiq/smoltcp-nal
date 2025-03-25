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

use core::{
    convert::TryFrom,
    net::{IpAddr, SocketAddr},
};
pub use embedded_nal;
use nanorand::{Rng, SeedableRng};
pub use smoltcp;

use embedded_nal::{TcpClientStack, UdpClientStack, UdpFullStack};
use embedded_time::duration::Milliseconds;
use smoltcp::{
    iface::{PollResult, SocketHandle},
    socket::dhcpv4,
    wire::{IpAddress, IpCidr, IpEndpoint, Ipv4Address, Ipv4Cidr},
};

use heapless::Vec;
use nanorand::wyrand::WyRand;

#[cfg(feature = "shared-stack")]
pub mod shared;

// The start of TCP port dynamic range allocation.
const TCP_PORT_DYNAMIC_RANGE_START: u16 = 49152;

#[derive(Debug, Copy, Clone)]
pub enum SmoltcpError {
    RouteTableFull,
}

#[derive(Debug, Copy, Clone)]
pub enum NetworkError {
    NoSocket,
    DnsStart(smoltcp::socket::dns::StartQueryError),
    DnsFailure,
    UdpConnectionFailure(smoltcp::socket::udp::BindError),
    TcpConnectionFailure(smoltcp::socket::tcp::ConnectError),
    TcpReadFailure(smoltcp::socket::tcp::RecvError),
    TcpWriteFailure(smoltcp::socket::tcp::SendError),
    UdpReadFailure(smoltcp::socket::udp::RecvError),
    UdpWriteFailure(smoltcp::socket::udp::SendError),
    Unsupported,
    NotConnected,
    NoAddress,
}

impl embedded_nal::TcpError for NetworkError {
    fn kind(&self) -> embedded_nal::TcpErrorKind {
        match self {
            NetworkError::TcpReadFailure(_) => embedded_nal::TcpErrorKind::PipeClosed,
            NetworkError::TcpWriteFailure(_) => embedded_nal::TcpErrorKind::PipeClosed,
            _ => embedded_nal::TcpErrorKind::Other,
        }
    }
}

impl From<smoltcp::iface::RouteTableFull> for SmoltcpError {
    fn from(_: smoltcp::iface::RouteTableFull) -> SmoltcpError {
        SmoltcpError::RouteTableFull
    }
}

/// Combination error used for polling the network stack
#[derive(Debug)]
pub enum Error {
    Network(SmoltcpError),
    Time(embedded_time::TimeError),
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
    destination: Option<IpEndpoint>,
}

/// Network abstraction layer for smoltcp.
pub struct NetworkStack<'a, Device, Clock>
where
    Device: smoltcp::phy::Device,
    Clock: embedded_time::Clock,
    u32: From<Clock::T>,
{
    network_interface: smoltcp::iface::Interface,
    device: Device,
    sockets: smoltcp::iface::SocketSet<'a>,
    dhcp_handle: Option<SocketHandle>,
    dns_handle: Option<SocketHandle>,
    dns_lookups: heapless::LinearMap<heapless::String<255>, smoltcp::socket::dns::QueryHandle, 2>,
    unused_tcp_handles: Vec<SocketHandle, 16>,
    unused_udp_handles: Vec<SocketHandle, 16>,
    clock: Clock,
    last_poll: Option<embedded_time::Instant<Clock>>,
    stack_time: smoltcp::time::Instant,
    rand: WyRand,
}

impl<'a, Device, Clock> NetworkStack<'a, Device, Clock>
where
    Device: smoltcp::phy::Device,
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
    pub fn new(
        stack: smoltcp::iface::Interface,
        device: Device,
        sockets: smoltcp::iface::SocketSet<'a>,
        clock: Clock,
    ) -> Self {
        let mut unused_tcp_handles: Vec<SocketHandle, 16> = Vec::new();
        let mut unused_udp_handles: Vec<SocketHandle, 16> = Vec::new();
        let mut dhcp_handle: Option<SocketHandle> = None;
        let mut dns_handle: Option<SocketHandle> = None;

        for (handle, socket) in sockets.iter() {
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
                smoltcp::socket::Socket::Dns(_) => {
                    dns_handle.replace(handle);
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
            sockets,
            device,
            dhcp_handle,
            dns_handle,
            unused_tcp_handles,
            unused_udp_handles,
            last_poll: None,
            dns_lookups: heapless::LinearMap::new(),
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
        let mut s = [0; 8];
        let n = seed.len().min(s.len());
        s[..n].copy_from_slice(&seed[..n]);
        self.rand.reseed(s);
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

        let updated = matches!(
            self.network_interface
                .poll(self.stack_time, &mut self.device, &mut self.sockets),
            PollResult::SocketStateChanged
        );

        // Service the DHCP client.
        if let Some(handle) = self.dhcp_handle {
            let mut close_sockets = false;
            let mut dns_server = None;

            if let Some(event) = self.sockets.get_mut::<dhcpv4::Socket>(handle).poll() {
                match event {
                    dhcpv4::Event::Configured(config) => {
                        let is_unicast = {
                            let address = config.address.address();
                            !(address.is_broadcast()
                                || address.is_multicast()
                                || address.is_unspecified())
                        };
                        if is_unicast
                            && self.network_interface.ipv4_addr().unwrap()
                                != config.address.address()
                        {
                            close_sockets = true;
                            Self::set_ipv4_addr(&mut self.network_interface, config.address);
                        }

                        if let Some(server) = config
                            .dns_servers
                            .iter()
                            .next()
                            .map(|ipv4| smoltcp::wire::IpAddress::Ipv4(*ipv4))
                        {
                            dns_server.replace(server);
                        }

                        if let Some(route) = config.router {
                            // Note: If the user did not provide enough route storage, we may not be
                            // able to store the gateway.
                            self.network_interface
                                .routes_mut()
                                .add_default_ipv4_route(route)
                                .map_err(|e| Error::Network(e.into()))?;
                        } else {
                            self.network_interface
                                .routes_mut()
                                .remove_default_ipv4_route();
                        }
                    }
                    dhcpv4::Event::Deconfigured => {
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

            if let Some((server, handle)) = dns_server.zip(self.dns_handle) {
                let dns = self.sockets.get_mut::<smoltcp::socket::dns::Socket>(handle);

                // Clear out all pending DNS queries now that we have a new server.
                for (_query, handle) in self.dns_lookups.iter() {
                    dns.cancel_query(*handle);
                }
                self.dns_lookups.clear();

                dns.update_servers(&[server]);
            }
        }

        Ok(updated)
    }

    /// Force-close all sockets.
    pub fn close_sockets(&mut self) {
        // Close all sockets.
        for (_handle, socket) in self.sockets.iter_mut() {
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

    fn set_ipv4_addr(interface: &mut smoltcp::iface::Interface, address: Ipv4Cidr) {
        interface.update_ip_addrs(|addrs| {
            // Note(unwrap): This stack requires at least 1 Ipv4 Address.
            match addrs
                .iter_mut()
                .find(|cidr| matches!(cidr.address(), IpAddress::Ipv4(_)))
            {
                Some(addr) => *addr = IpCidr::Ipv4(address),
                None => addrs.push(IpCidr::Ipv4(address)).unwrap(),
            }
        });
    }

    /// Handle a disconnection of the physical interface.
    pub fn handle_link_reset(&mut self) {
        // Close all of the sockets and de-configure the interface.
        self.close_sockets();

        // Reset the DHCP client.
        if let Some(handle) = self.dhcp_handle {
            self.sockets.get_mut::<dhcpv4::Socket>(handle).reset();

            self.network_interface.update_ip_addrs(|addrs| {
                if let Some(addr) = addrs.iter_mut().next() {
                    *addr = IpCidr::Ipv4(Ipv4Cidr::new(Ipv4Address::UNSPECIFIED, 0));
                };
            });
        }
    }

    /// Access the underlying network interface.
    pub fn interface(&self) -> &smoltcp::iface::Interface {
        &self.network_interface
    }

    /// Mutably access the underlying network interface.
    ///
    /// # Note
    /// Modification of the underlying network interface may unintentionally interfere with
    /// operation of this library (e.g. through reset, modification of IP addresses, etc.). Mutable
    /// access to the interface should be done with care.
    pub fn interface_mut(&mut self) -> &mut smoltcp::iface::Interface {
        &mut self.network_interface
    }

    /// Check if a port is currently in use.
    ///
    /// # Returns
    /// True if the port is in use. False otherwise.
    fn is_port_in_use(&mut self, port: u16) -> bool {
        for (_handle, socket) in self.sockets.iter_mut() {
            match socket {
                smoltcp::socket::Socket::Tcp(sock) => {
                    if sock
                        .local_endpoint()
                        .map(|endpoint| endpoint.port == port)
                        .unwrap_or(false)
                    {
                        return true;
                    }
                }
                smoltcp::socket::Socket::Udp(sock) => {
                    let endpoint = sock.endpoint();
                    if endpoint.is_specified() && endpoint.port == port {
                        return true;
                    }
                }
                _ => {}
            }
        }

        false
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
}

impl<Device, Clock> TcpClientStack for NetworkStack<'_, Device, Clock>
where
    Device: smoltcp::phy::Device,
    Clock: embedded_time::Clock,
    u32: From<Clock::T>,
{
    type Error = NetworkError;
    type TcpSocket = SocketHandle;

    fn socket(&mut self) -> Result<SocketHandle, NetworkError> {
        match self.unused_tcp_handles.pop() {
            Some(handle) => {
                // Abort any active connections on the handle.
                let internal_socket: &mut smoltcp::socket::tcp::Socket =
                    self.sockets.get_mut(handle);
                internal_socket.abort();

                Ok(handle)
            }
            None => Err(NetworkError::NoSocket),
        }
    }

    fn connect(
        &mut self,
        socket: &mut SocketHandle,
        remote: SocketAddr,
    ) -> embedded_nal::nb::Result<(), NetworkError> {
        let dest_addr = match remote.ip() {
            IpAddr::V4(addr) => {
                let octets = addr.octets();
                smoltcp::wire::Ipv4Address::new(octets[0], octets[1], octets[2], octets[3])
            }

            // We only support IPv4.
            _ => return Err(embedded_nal::nb::Error::Other(NetworkError::Unsupported)),
        };

        let local_port = self.get_ephemeral_port();
        let internal_socket = self
            .sockets
            .get_mut::<smoltcp::socket::tcp::Socket>(*socket);

        if !internal_socket.is_open() {
            let context = self.network_interface.context();
            internal_socket
                .connect(context, (dest_addr, remote.port()), local_port)
                .map_err(|e| {
                    embedded_nal::nb::Error::Other(NetworkError::TcpConnectionFailure(e))
                })?;
        }

        if internal_socket.state() == smoltcp::socket::tcp::State::Established {
            Ok(())
        } else {
            Err(embedded_nal::nb::Error::WouldBlock)
        }
    }

    fn send(
        &mut self,
        socket: &mut SocketHandle,
        buffer: &[u8],
    ) -> embedded_nal::nb::Result<usize, NetworkError> {
        let socket: &mut smoltcp::socket::tcp::Socket = self.sockets.get_mut(*socket);
        socket
            .send_slice(buffer)
            .map_err(|e| embedded_nal::nb::Error::Other(NetworkError::TcpWriteFailure(e)))
    }

    fn receive(
        &mut self,
        socket: &mut SocketHandle,
        buffer: &mut [u8],
    ) -> embedded_nal::nb::Result<usize, NetworkError> {
        let socket: &mut smoltcp::socket::tcp::Socket = self.sockets.get_mut(*socket);
        socket
            .recv_slice(buffer)
            .map_err(|e| embedded_nal::nb::Error::Other(NetworkError::TcpReadFailure(e)))
    }

    fn close(&mut self, socket: SocketHandle) -> Result<(), NetworkError> {
        let internal_socket: &mut smoltcp::socket::tcp::Socket = self.sockets.get_mut(socket);

        internal_socket.close();
        self.unused_tcp_handles.push(socket).unwrap();
        Ok(())
    }
}

impl<Device, Clock> UdpClientStack for NetworkStack<'_, Device, Clock>
where
    Device: smoltcp::phy::Device,
    Clock: embedded_time::Clock,
    u32: From<Clock::T>,
{
    type Error = NetworkError;
    type UdpSocket = UdpSocket;

    fn socket(&mut self) -> Result<UdpSocket, NetworkError> {
        let handle = self
            .unused_udp_handles
            .pop()
            .ok_or(NetworkError::NoSocket)?;

        // Make sure the socket is in a closed state before handing it to the user.
        let internal_socket: &mut smoltcp::socket::udp::Socket = self.sockets.get_mut(handle);
        internal_socket.close();

        Ok(UdpSocket {
            handle,
            destination: None,
        })
    }

    fn connect(&mut self, socket: &mut UdpSocket, remote: SocketAddr) -> Result<(), NetworkError> {
        // Store the route for this socket.
        match remote {
            SocketAddr::V4(addr) => {
                let octets = addr.ip().octets();
                socket.destination.replace(IpEndpoint::new(
                    IpAddress::v4(octets[0], octets[1], octets[2], octets[3]),
                    addr.port(),
                ));
            }

            // We only support IPv4.
            _ => return Err(NetworkError::Unsupported),
        }

        // Select a random port to bind to locally.
        let local_port = self.get_ephemeral_port();

        let Some(cidr) = self
            .network_interface
            .ip_addrs()
            .iter()
            .find(|item| matches!(item, smoltcp::wire::IpCidr::Ipv4(_)))
        else {
            return Err(NetworkError::NoAddress);
        };

        let local_endpoint = IpEndpoint::new(cidr.address(), local_port);

        let internal_socket: &mut smoltcp::socket::udp::Socket =
            self.sockets.get_mut(socket.handle);
        internal_socket
            .bind(local_endpoint)
            .map_err(NetworkError::UdpConnectionFailure)?;

        Ok(())
    }

    fn send(
        &mut self,
        socket: &mut UdpSocket,
        buffer: &[u8],
    ) -> embedded_nal::nb::Result<(), NetworkError> {
        let internal_socket: &mut smoltcp::socket::udp::Socket =
            self.sockets.get_mut(socket.handle);
        let destination = socket.destination.ok_or(NetworkError::NotConnected)?;
        internal_socket
            .send_slice(buffer, destination)
            .map_err(|e| embedded_nal::nb::Error::Other(NetworkError::UdpWriteFailure(e)))
    }

    fn receive(
        &mut self,
        socket: &mut UdpSocket,
        buffer: &mut [u8],
    ) -> embedded_nal::nb::Result<(usize, SocketAddr), NetworkError> {
        let internal_socket: &mut smoltcp::socket::udp::Socket =
            self.sockets.get_mut(socket.handle);
        let (size, source) = internal_socket
            .recv_slice(buffer)
            .map_err(|e| embedded_nal::nb::Error::Other(NetworkError::UdpReadFailure(e)))?;

        let source = {
            let addr = match source.endpoint.addr {
                IpAddress::Ipv4(addr) => IpAddr::V4(addr),
                IpAddress::Ipv6(addr) => IpAddr::V6(addr),
            };

            SocketAddr::new(addr, source.endpoint.port)
        };

        Ok((size, source))
    }

    fn close(&mut self, socket: UdpSocket) -> Result<(), NetworkError> {
        let internal_socket: &mut smoltcp::socket::udp::Socket =
            self.sockets.get_mut(socket.handle);

        internal_socket.close();

        // There should always be room to return the socket handle to the unused handle list.
        self.unused_udp_handles.push(socket.handle).unwrap();

        Ok(())
    }
}

impl<Device, Clock> UdpFullStack for NetworkStack<'_, Device, Clock>
where
    Device: smoltcp::phy::Device,
    Clock: embedded_time::Clock,
    u32: From<Clock::T>,
{
    /// Bind a UDP socket to a specific port.
    fn bind(&mut self, socket: &mut UdpSocket, local_port: u16) -> Result<(), NetworkError> {
        let Some(cidr) = self
            .network_interface
            .ip_addrs()
            .iter()
            .find(|item| matches!(item, smoltcp::wire::IpCidr::Ipv4(_)))
        else {
            return Err(NetworkError::NoAddress);
        };

        let local_endpoint = IpEndpoint::new(cidr.address(), local_port);

        let internal_socket: &mut smoltcp::socket::udp::Socket =
            self.sockets.get_mut(socket.handle);
        internal_socket
            .bind(local_endpoint)
            .map_err(NetworkError::UdpConnectionFailure)?;

        Ok(())
    }

    /// Send a packet to a remote host/port.
    fn send_to(
        &mut self,
        socket: &mut Self::UdpSocket,
        remote: SocketAddr,
        buffer: &[u8],
    ) -> embedded_nal::nb::Result<(), NetworkError> {
        let destination = match remote {
            SocketAddr::V4(addr) => {
                let octets = addr.ip().octets();
                IpEndpoint::new(
                    IpAddress::v4(octets[0], octets[1], octets[2], octets[3]),
                    addr.port(),
                )
            }
            // We only support IPv4.
            _ => return Err(embedded_nal::nb::Error::Other(NetworkError::Unsupported)),
        };

        let internal_socket: &mut smoltcp::socket::udp::Socket =
            self.sockets.get_mut(socket.handle);
        internal_socket
            .send_slice(buffer, destination)
            .map_err(|e| embedded_nal::nb::Error::Other(NetworkError::UdpWriteFailure(e)))
    }
}

impl<Device, Clock> embedded_nal::Dns for NetworkStack<'_, Device, Clock>
where
    Device: smoltcp::phy::Device,
    Clock: embedded_time::Clock,
    u32: From<Clock::T>,
{
    type Error = NetworkError;
    fn get_host_by_name(
        &mut self,
        hostname: &str,
        _addr_type: embedded_nal::AddrType,
    ) -> embedded_nal::nb::Result<IpAddr, Self::Error> {
        let handle = self.dns_handle.ok_or(NetworkError::Unsupported)?;
        let dns_socket: &mut smoltcp::socket::dns::Socket = self.sockets.get_mut(handle);
        let context = self.network_interface.context();
        let key = heapless::String::try_from(hostname).map_err(|_| NetworkError::Unsupported)?;

        if let Some(handle) = self.dns_lookups.get(&key) {
            match dns_socket.get_query_result(*handle) {
                Ok(addrs) => {
                    self.dns_lookups.remove(&key);
                    let addr = addrs.iter().next().ok_or(NetworkError::DnsFailure)?;
                    let smoltcp::wire::IpAddress::Ipv4(addr) = addr else {
                        panic!("Unexpected address return type");
                    };
                    return Ok(IpAddr::V4(*addr));
                }
                Err(smoltcp::socket::dns::GetQueryResultError::Pending) => {}
                Err(smoltcp::socket::dns::GetQueryResultError::Failed) => {
                    self.dns_lookups.remove(&key);
                    return Err(embedded_nal::nb::Error::Other(NetworkError::DnsFailure));
                }
            }
        } else {
            // Note: We only support A types because we are an Ipv4-only stack
            let dns_query = dns_socket
                .start_query(context, hostname, smoltcp::wire::DnsQueryType::A)
                .map_err(NetworkError::DnsStart)?;
            if self.dns_lookups.insert(key, dns_query).is_err() {
                dns_socket.cancel_query(dns_query);
                return Err(embedded_nal::nb::Error::Other(NetworkError::Unsupported));
            }
        }

        Err(embedded_nal::nb::Error::WouldBlock)
    }

    fn get_host_by_address(
        &mut self,
        _addr: IpAddr,
        _: &mut [u8],
    ) -> Result<usize, embedded_nal::nb::Error<Self::Error>> {
        unimplemented!()
    }
}
