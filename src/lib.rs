#![no_std]

pub use embedded_nal;
pub use smoltcp;

use embedded_nal::TcpClientStack;
use smoltcp::dhcp::Dhcpv4Client;
use smoltcp::socket::AnySocket;
use smoltcp::wire::{IpAddress, IpCidr, Ipv4Address, Ipv4Cidr};

use heapless::Vec;
use nanorand::{wyrand::WyRand, RNG};

// The start of TCP port dynamic range allocation.
const TCP_PORT_DYNAMIC_RANGE_START: u16 = 49152;

#[derive(Debug)]
pub enum NetworkError {
    NoSocket,
    ConnectionFailure,
    ReadFailure,
    WriteFailure,
    Unsupported,
    NoIpAddress,
}

///! Network abstraction layer for smoltcp.
pub struct NetworkStack<'a, 'b, DeviceT>
where
    DeviceT: for<'c> smoltcp::phy::Device<'c>,
{
    network_interface: smoltcp::iface::EthernetInterface<'b, DeviceT>,
    dhcp_client: Option<Dhcpv4Client>,
    sockets: smoltcp::socket::SocketSet<'a>,
    used_ports: Vec<u16, 16>,
    unused_handles: Vec<smoltcp::socket::SocketHandle, 16>,
    randomizer: WyRand,
    name_servers: Vec<Ipv4Address, 3>,
}

impl<'a, 'b, DeviceT> NetworkStack<'a, 'b, DeviceT>
where
    DeviceT: for<'c> smoltcp::phy::Device<'c>,
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
    /// * `sockets` - The socket set to contain any socket state for the stack.
    /// * `handles` - A list of socket handles that can be used.
    /// * `dhcp` - An optional DHCP client if DHCP usage is desired. If None, DHCP will not be used.
    ///
    /// # Returns
    /// A embedded-nal-compatible network stack.
    pub fn new(
        stack: smoltcp::iface::EthernetInterface<'b, DeviceT>,
        sockets: smoltcp::socket::SocketSet<'a>,
        handles: &[smoltcp::socket::SocketHandle],
        dhcp: Option<Dhcpv4Client>,
    ) -> Self {
        let mut unused_handles: Vec<smoltcp::socket::SocketHandle, 16> = Vec::new();
        for handle in handles.iter() {
            // Note: If the user supplies too many handles, we choose to silently drop them.
            unused_handles.push(*handle).ok();
        }

        NetworkStack {
            network_interface: stack,
            sockets,
            used_ports: Vec::new(),
            randomizer: WyRand::new_seed(0),
            dhcp_client: dhcp,
            unused_handles,
            name_servers: Vec::new(),
        }
    }

    /// Seed the TCP port randomizer.
    ///
    /// # Args
    /// * `seed` - A seed of random data to use for randomizing local TCP port selection.
    pub fn seed_random_port(&mut self, seed: &[u8]) {
        self.randomizer.reseed(seed)
    }

    /// Poll the network stack for potential updates.
    ///
    /// # Returns
    /// A boolean indicating if the network stack updated in any way.
    pub fn poll(&mut self, time: u32) -> Result<bool, smoltcp::Error> {
        let now = smoltcp::time::Instant::from_millis(time as i64);
        let updated = self.network_interface.poll(&mut self.sockets, now)?;

        // Service the DHCP client.
        if let Some(ref mut dhcp_client) = self.dhcp_client {
            match dhcp_client.poll(&mut self.network_interface, &mut self.sockets, now) {
                Ok(Some(config)) => {
                    if let Some(cidr) = config.address {
                        if cidr.address().is_unicast() {
                            // Note(unwrap): This stack only supports IPv4 and the client must have
                            // provided an address.
                            if cidr.address().is_unspecified()
                                || self.network_interface.ipv4_address().unwrap() != cidr.address()
                            {
                                self.close_sockets();

                                self.network_interface.update_ip_addrs(|addrs| {
                                    // Note(unwrap): This stack requires at least 1 Ipv4 Address.
                                    let addr = addrs
                                        .iter_mut()
                                        .filter(|cidr| match cidr.address() {
                                            IpAddress::Ipv4(_) => true,
                                            _ => false,
                                        })
                                        .next()
                                        .unwrap();

                                    *addr = IpCidr::Ipv4(cidr);
                                });
                            }
                        }
                    }

                    // Store DNS server addresses for later read-back
                    self.name_servers.clear();
                    config
                        .dns_servers
                        .iter()
                        .filter_map(|server| server.as_ref())
                        .for_each(|server| self.name_servers.push(*server).unwrap());

                    if let Some(route) = config.router {
                        // Note: If the user did not provide enough route storage, we may not be
                        // able to store the gateway.
                        self.network_interface
                            .routes_mut()
                            .add_default_ipv4_route(route)?;
                    }
                }
                Ok(None) => {}
                Err(err) => return Err(err),
            }
        }

        Ok(updated)
    }

    /// Force-close all sockets.
    pub fn close_sockets(&mut self) {
        // Close all sockets.
        for mut socket in self.sockets.iter_mut() {
            // We only explicitly can close TCP sockets because we cannot access other socket types.
            if let Some(ref mut socket) =
                smoltcp::socket::TcpSocket::downcast(smoltcp::socket::SocketRef::new(&mut socket))
            {
                socket.abort();
            }
        }
    }

    /// Handle a disconnection of the physical interface.
    pub fn handle_link_reset(&mut self) {
        // Reset the DHCP client.
        if let Some(ref mut client) = self.dhcp_client {
            client.reset(smoltcp::time::Instant::from_millis(-1));
        }

        // Close all of the sockets and de-configure the interface.
        self.close_sockets();

        self.network_interface.update_ip_addrs(|addrs| {
            addrs.iter_mut().next().map(|addr| {
                *addr = IpCidr::Ipv4(Ipv4Cidr::new(Ipv4Address::UNSPECIFIED, 0));
            });
        });
    }

    // Get an ephemeral TCP port number.
    fn get_ephemeral_port(&mut self) -> u16 {
        loop {
            // Get the next ephemeral port by generating a random, valid TCP port continuously
            // until an unused port is found.
            let random_offset = {
                let random_data = self.randomizer.rand();
                u16::from_be_bytes([random_data[0], random_data[1]])
            };

            let port = TCP_PORT_DYNAMIC_RANGE_START
                + random_offset % (u16::MAX - TCP_PORT_DYNAMIC_RANGE_START);
            if self.used_ports.iter().find(|&x| *x == port).is_none() {
                return port;
            }
        }
    }

    fn is_ip_unspecified(&self) -> bool {
        // Note(unwrap): This stack only supports Ipv4.
        self.network_interface.ipv4_addr().unwrap().is_unspecified()
    }
}

impl<'a, 'b, DeviceT> TcpClientStack for NetworkStack<'a, 'b, DeviceT>
where
    DeviceT: for<'c> smoltcp::phy::Device<'c>,
{
    type Error = NetworkError;
    type TcpSocket = smoltcp::socket::SocketHandle;

    fn socket(&mut self) -> Result<smoltcp::socket::SocketHandle, NetworkError> {
        // If we do not have a valid IP address yet, do not open the socket.
        if self.is_ip_unspecified() {
            return Err(NetworkError::NoIpAddress);
        }

        match self.unused_handles.pop() {
            Some(handle) => {
                // Abort any active connections on the handle.
                let internal_socket: &mut smoltcp::socket::TcpSocket =
                    &mut *self.sockets.get(handle);
                internal_socket.abort();

                Ok(handle)
            }
            None => Err(NetworkError::NoSocket),
        }
    }

    fn connect(
        &mut self,
        socket: &mut smoltcp::socket::SocketHandle,
        remote: embedded_nal::SocketAddr,
    ) -> embedded_nal::nb::Result<(), NetworkError> {
        // If there is no longer an IP address assigned to the interface, do not allow usage of the
        // socket.
        if self.is_ip_unspecified() {
            return Err(embedded_nal::nb::Error::Other(NetworkError::NoIpAddress));
        }

        let local_port = self.get_ephemeral_port();

        let internal_socket: &mut smoltcp::socket::TcpSocket = &mut *self.sockets.get(*socket);

        // If we're already in the process of connecting, ignore the request silently.
        if internal_socket.is_open() {
            return Ok(());
        }

        match remote.ip() {
            embedded_nal::IpAddr::V4(addr) => {
                let octets = addr.octets();
                let address =
                    smoltcp::wire::Ipv4Address::new(octets[0], octets[1], octets[2], octets[3]);

                // Note(unwrap): Only one port is allowed per socket, so this push should never
                // fail.
                self.used_ports.push(local_port).unwrap();

                internal_socket
                    .connect((address, remote.port()), local_port)
                    .map_err(|_| embedded_nal::nb::Error::Other(NetworkError::ConnectionFailure))?;
                Ok(())
            }

            // We only support IPv4.
            _ => Err(embedded_nal::nb::Error::Other(NetworkError::Unsupported)),
        }
    }

    fn is_connected(
        &mut self,
        socket: &smoltcp::socket::SocketHandle,
    ) -> Result<bool, NetworkError> {
        // If there is no longer an IP address assigned to the interface, do not allow usage of the
        // socket.
        if self.is_ip_unspecified() {
            return Err(NetworkError::NoIpAddress);
        }

        let socket: &mut smoltcp::socket::TcpSocket = &mut *self.sockets.get(*socket);
        Ok(socket.may_send() && socket.may_recv())
    }

    fn send(
        &mut self,
        socket: &mut smoltcp::socket::SocketHandle,
        buffer: &[u8],
    ) -> embedded_nal::nb::Result<usize, NetworkError> {
        // If there is no longer an IP address assigned to the interface, do not allow usage of the
        // socket.
        if self.is_ip_unspecified() {
            return Err(embedded_nal::nb::Error::Other(NetworkError::NoIpAddress));
        }

        let socket: &mut smoltcp::socket::TcpSocket = &mut *self.sockets.get(*socket);
        socket
            .send_slice(buffer)
            .map_err(|_| embedded_nal::nb::Error::Other(NetworkError::WriteFailure))
    }

    fn receive(
        &mut self,
        socket: &mut smoltcp::socket::SocketHandle,
        buffer: &mut [u8],
    ) -> embedded_nal::nb::Result<usize, NetworkError> {
        // If there is no longer an IP address assigned to the interface, do not allow usage of the
        // socket.
        if self.is_ip_unspecified() {
            return Err(embedded_nal::nb::Error::Other(NetworkError::NoIpAddress));
        }

        let socket: &mut smoltcp::socket::TcpSocket = &mut *self.sockets.get(*socket);
        socket
            .recv_slice(buffer)
            .map_err(|_| embedded_nal::nb::Error::Other(NetworkError::ReadFailure))
    }

    fn close(&mut self, socket: smoltcp::socket::SocketHandle) -> Result<(), NetworkError> {
        let internal_socket: &mut smoltcp::socket::TcpSocket = &mut *self.sockets.get(socket);

        // Remove the bound port from the used_ports buffer.
        let local_port = internal_socket.local_endpoint().port;

        let index = self
            .used_ports
            .iter()
            .position(|&port| port == local_port)
            .unwrap();
        self.used_ports.swap_remove(index);

        internal_socket.close();
        self.unused_handles.push(socket).unwrap();
        Ok(())
    }
}
