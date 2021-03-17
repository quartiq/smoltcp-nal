#![no_std]

pub use embedded_nal;
pub use smoltcp;

use smoltcp::dhcp::Dhcpv4Client;
use smoltcp::socket::AnySocket;
use smoltcp::wire::IpCidr;

use core::cell::RefCell;
use heapless::{consts, Vec};

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
    network_interface: RefCell<smoltcp::iface::EthernetInterface<'b, DeviceT>>,
    dhcp_client: RefCell<Option<Dhcpv4Client>>,
    sockets: RefCell<smoltcp::socket::SocketSet<'a>>,
    next_port: RefCell<u16>,
    unused_handles: RefCell<Vec<smoltcp::socket::SocketHandle, consts::U16>>,
    name_servers: RefCell<[Option<smoltcp::wire::Ipv4Address>; 3]>,
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
        let mut unused_handles: Vec<smoltcp::socket::SocketHandle, consts::U16> = Vec::new();
        for handle in handles.iter() {
            // Note: If the user supplies too many handles, we choose to silently drop them.
            unused_handles.push(*handle).ok();
        }

        NetworkStack {
            network_interface: RefCell::new(stack),
            sockets: RefCell::new(sockets),
            dhcp_client: RefCell::new(dhcp),
            next_port: RefCell::new(49152),
            unused_handles: RefCell::new(unused_handles),
            name_servers: RefCell::new([None, None, None]),
        }
    }

    /// Poll the network stack for potential updates.
    ///
    /// # Returns
    /// A boolean indicating if the network stack updated in any way.
    pub fn poll(&self, time: u32) -> Result<bool, smoltcp::Error> {
        let now = smoltcp::time::Instant::from_millis(time as i64);
        let updated = match self
            .network_interface
            .borrow_mut()
            .poll(&mut self.sockets.borrow_mut(), now)
        {
            Ok(updated) => updated,
            err => return err,
        };

        // Service the DHCP client.
        if let Some(dhcp_client) = &mut *self.dhcp_client.borrow_mut() {
            let mut interface = self.network_interface.borrow_mut();
            match dhcp_client.poll(&mut interface, &mut self.sockets.borrow_mut(), now) {
                Ok(Some(config)) => {
                    if let Some(cidr) = config.address {
                        if cidr.address().is_unicast() {
                            interface.update_ip_addrs(|addrs| {
                                // If our address has updated, close all sockets.
                                if addrs[0] == IpCidr::Ipv4(cidr) {
                                    self.close_sockets();
                                }

                                addrs.iter_mut().next().map(|addr| {
                                    *addr = IpCidr::Ipv4(cidr);
                                });
                            });
                        }
                    }

                    if let Some(route) = config.router {
                        // TODO: Determine if this unwrap is safe?
                        interface
                            .routes_mut()
                            .add_default_ipv4_route(route)
                            .unwrap();
                    }

                    // Store DNS server addresses for later read-back
                    *self.name_servers.borrow_mut() = config.dns_servers;
                }
                Ok(None) => {}
                Err(err) => return Err(err),
            }
        }

        Ok(updated)
    }

    // Force-close all sockets.
    fn close_sockets(&self) {
        // Close all sockets.
        for mut socket in self.sockets.borrow_mut().iter_mut() {
            // We only explicitly can close TCP sockets because we cannot access other socket types.
            if let Some(ref mut socket) =
                smoltcp::socket::TcpSocket::downcast(smoltcp::socket::SocketRef::new(&mut socket))
            {
                socket.close();
            }
        }
    }

    /// Reset the network stack and close all opened sockets.
    pub fn reset(&mut self) {
        // Reset the DHCP client. We will forget any previous lease that we had.
        if let Some(ref mut client) = *self.dhcp_client.borrow_mut() {
            client.reset(smoltcp::time::Instant::from_millis(-1));
        }

        self.close_sockets();
    }

    // Get an ephemeral TCP port number.
    fn get_ephemeral_port(&self) -> u16 {
        // Get the next ephemeral port
        let current_port = self.next_port.borrow().clone();

        let (next, wrap) = self.next_port.borrow().overflowing_add(1);
        *self.next_port.borrow_mut() = if wrap { 49152 } else { next };

        return current_port;
    }

    fn is_ip_unspecified(&self) -> bool {
        // Note(unwrap): This stack only supports Ipv4.
        self.network_interface
            .borrow_mut()
            .ipv4_addr()
            .unwrap()
            .is_unspecified()
    }
}

impl<'a, 'b, DeviceT> embedded_nal::TcpStack for NetworkStack<'a, 'b, DeviceT>
where
    DeviceT: for<'c> smoltcp::phy::Device<'c>,
{
    type Error = NetworkError;
    type TcpSocket = smoltcp::socket::SocketHandle;

    fn open(
        &self,
        _mode: embedded_nal::Mode,
    ) -> Result<smoltcp::socket::SocketHandle, NetworkError> {
        // If we do not have a valid IP address yet, do not open the socket.
        if self.is_ip_unspecified() {
            return Err(NetworkError::NoIpAddress);
        }

        match self.unused_handles.borrow_mut().pop() {
            Some(handle) => {
                // Abort any active connections on the handle.
                let mut sockets = self.sockets.borrow_mut();
                let internal_socket: &mut smoltcp::socket::TcpSocket = &mut *sockets.get(handle);
                internal_socket.abort();

                Ok(handle)
            }
            None => Err(NetworkError::NoSocket),
        }
    }

    fn connect(
        &self,
        socket: smoltcp::socket::SocketHandle,
        remote: embedded_nal::SocketAddr,
    ) -> Result<smoltcp::socket::SocketHandle, NetworkError> {
        // If there is no longer an IP address assigned to the interface, do not allow usage of the
        // socket.
        if self.is_ip_unspecified() {
            self.close(socket)?;
            return Err(NetworkError::NoIpAddress);
        }

        let mut sockets = self.sockets.borrow_mut();
        let internal_socket: &mut smoltcp::socket::TcpSocket = &mut *sockets.get(socket);

        // If we're already in the process of connecting, ignore the request silently.
        if internal_socket.is_open() {
            return Ok(socket);
        }

        match remote.ip() {
            embedded_nal::IpAddr::V4(addr) => {
                let octets = addr.octets();
                let address =
                    smoltcp::wire::Ipv4Address::new(octets[0], octets[1], octets[2], octets[3]);
                internal_socket
                    .connect((address, remote.port()), self.get_ephemeral_port())
                    .map_err(|_| NetworkError::ConnectionFailure)?;
                Ok(socket)
            }

            // We only support IPv4.
            _ => Err(NetworkError::Unsupported),
        }
    }

    fn is_connected(&self, socket: &smoltcp::socket::SocketHandle) -> Result<bool, NetworkError> {
        // If there is no longer an IP address assigned to the interface, do not allow usage of the
        // socket.
        if self.is_ip_unspecified() {
            return Err(NetworkError::NoIpAddress);
        }

        let mut sockets = self.sockets.borrow_mut();
        let socket: &mut smoltcp::socket::TcpSocket = &mut *sockets.get(*socket);
        Ok(socket.may_send() && socket.may_recv())
    }

    fn write(
        &self,
        socket: &mut smoltcp::socket::SocketHandle,
        buffer: &[u8],
    ) -> embedded_nal::nb::Result<usize, NetworkError> {
        // If there is no longer an IP address assigned to the interface, do not allow usage of the
        // socket.
        if self.is_ip_unspecified() {
            return Err(embedded_nal::nb::Error::Other(NetworkError::NoIpAddress));
        }

        let mut sockets = self.sockets.borrow_mut();
        let socket: &mut smoltcp::socket::TcpSocket = &mut *sockets.get(*socket);
        socket
            .send_slice(buffer)
            .map_err(|_| embedded_nal::nb::Error::Other(NetworkError::WriteFailure))
    }

    fn read(
        &self,
        socket: &mut smoltcp::socket::SocketHandle,
        buffer: &mut [u8],
    ) -> embedded_nal::nb::Result<usize, NetworkError> {
        // If there is no longer an IP address assigned to the interface, do not allow usage of the
        // socket.
        if self.is_ip_unspecified() {
            return Err(embedded_nal::nb::Error::Other(NetworkError::NoIpAddress));
        }

        let mut sockets = self.sockets.borrow_mut();
        let socket: &mut smoltcp::socket::TcpSocket = &mut *sockets.get(*socket);
        socket
            .recv_slice(buffer)
            .map_err(|_| embedded_nal::nb::Error::Other(NetworkError::ReadFailure))
    }

    fn close(&self, socket: smoltcp::socket::SocketHandle) -> Result<(), NetworkError> {
        let mut sockets = self.sockets.borrow_mut();
        let internal_socket: &mut smoltcp::socket::TcpSocket = &mut *sockets.get(socket);
        internal_socket.close();

        self.unused_handles.borrow_mut().push(socket).unwrap();
        Ok(())
    }
}
