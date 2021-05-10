#![no_std]

pub use embedded_nal;
pub use smoltcp;

use smoltcp::socket::{AnySocket, Dhcpv4Event};
use smoltcp::wire::{IpAddress, IpCidr, Ipv4Address, Ipv4Cidr};

use core::cell::RefCell;
use heapless::{consts, Vec};
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
    network_interface: RefCell<smoltcp::iface::Interface<'b, DeviceT>>,
    dhcp_handle: RefCell<Option<smoltcp::socket::SocketHandle>>,
    sockets: RefCell<smoltcp::socket::SocketSet<'a>>,
    used_ports: RefCell<Vec<u16, consts::U16>>,
    unused_handles: RefCell<Vec<smoltcp::socket::SocketHandle, consts::U16>>,
    randomizer: RefCell<WyRand>,
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
        stack: smoltcp::iface::Interface<'b, DeviceT>,
        sockets: smoltcp::socket::SocketSet<'a>,
        handles: &[smoltcp::socket::SocketHandle],
        dhcp: Option<smoltcp::socket::SocketHandle>,
    ) -> Self {
        let mut unused_handles: Vec<smoltcp::socket::SocketHandle, consts::U16> = Vec::new();
        for handle in handles.iter() {
            // Note: If the user supplies too many handles, we choose to silently drop them.
            unused_handles.push(*handle).ok();
        }

        NetworkStack {
            network_interface: RefCell::new(stack),
            sockets: RefCell::new(sockets),
            used_ports: RefCell::new(Vec::new()),
            randomizer: RefCell::new(WyRand::new_seed(0)),
            dhcp_handle: RefCell::new(dhcp),
            unused_handles: RefCell::new(unused_handles),
            name_servers: RefCell::new([None, None, None]),
        }
    }

    /// Seed the TCP port randomizer.
    ///
    /// # Args
    /// * `seed` - A seed of random data to use for randomizing local TCP port selection.
    pub fn seed_random_port(&mut self, seed: &[u8]) {
        self.randomizer.borrow_mut().reseed(seed)
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
        if let Some(handle) = *self.dhcp_handle.borrow() {
            let mut interface = self.network_interface.borrow_mut();
            let mut sockets = self.sockets.borrow_mut();
            let mut reconfigured = false;
            match sockets.get::<smoltcp::socket::Dhcpv4Socket>(handle).poll() {
                Dhcpv4Event::NoChange => {}
                Dhcpv4Event::Configured(config) => {
                    if interface.ipv4_address().unwrap() != config.address.address() {
                        reconfigured = true;
                        Self::set_ipv4_addr(&mut interface, config.address);
                    }

                    // Store DNS server addresses for later read-back
                    *self.name_servers.borrow_mut() = config.dns_servers;

                    if let Some(route) = config.router {
                        // Note: If the user did not provide enough route storage, we may not be
                        // able to store the gateway.
                        interface.routes_mut().add_default_ipv4_route(route)?;
                    } else {
                        interface.routes_mut().remove_default_ipv4_route();
                    }
                }
                Dhcpv4Event::Deconfigured => {
                    interface.routes_mut().remove_default_ipv4_route();
                    Self::set_ipv4_addr(&mut interface, Ipv4Cidr::new(Ipv4Address::UNSPECIFIED, 0));
                }
            }

            if reconfigured {
                Self::close_all_sockets(&mut sockets);
            }
        }

        Ok(updated)
    }

    fn set_ipv4_addr(interface: &mut smoltcp::iface::Interface<'b, DeviceT>, cidr: Ipv4Cidr) {
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

            *addr = IpCidr::Ipv4(cidr);
        });
    }

    fn close_all_sockets(sockets: &mut smoltcp::socket::SocketSet<'a>) {
        // Close all sockets.
        for mut socket in sockets.iter_mut() {
            // We only explicitly can close TCP sockets because we cannot access other socket types.
            if let Some(ref mut socket) =
                smoltcp::socket::TcpSocket::downcast(smoltcp::socket::SocketRef::new(&mut socket))
            {
                socket.abort();
            }
        }
    }

    /// Force-close all sockets.
    pub fn close_sockets(&self) {
        Self::close_all_sockets(&mut self.sockets.borrow_mut());
    }

    /// Handle a disconnection of the physical interface.
    pub fn handle_link_reset(&mut self) {
        // Reset the DHCP client.
        if let Some(handle) = *self.dhcp_handle.borrow() {
            let mut sockets = self.sockets.borrow_mut();
            sockets.get::<smoltcp::socket::Dhcpv4Socket>(handle).reset();
        }

        // Close all of the sockets and de-configure the interface.
        self.close_sockets();

        let mut interface = self.network_interface.borrow_mut();
        interface.update_ip_addrs(|addrs| {
            addrs.iter_mut().next().map(|addr| {
                *addr = IpCidr::Ipv4(Ipv4Cidr::new(Ipv4Address::UNSPECIFIED, 0));
            });
        });
    }

    // Get an ephemeral TCP port number.
    fn get_ephemeral_port(&self) -> u16 {
        loop {
            // Get the next ephemeral port by generating a random, valid TCP port continuously
            // until an unused port is found.
            let random_offset = {
                let random_data = self.randomizer.borrow_mut().rand();
                u16::from_be_bytes([random_data[0], random_data[1]])
            };

            let port = TCP_PORT_DYNAMIC_RANGE_START
                + random_offset % (u16::MAX - TCP_PORT_DYNAMIC_RANGE_START);
            if self
                .used_ports
                .borrow()
                .iter()
                .find(|&x| *x == port)
                .is_none()
            {
                return port;
            }
        }
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

                // Note(unwrap): Only one port is allowed per socket, so this push should never
                // fail.
                let local_port = self.get_ephemeral_port();
                self.used_ports.borrow_mut().push(local_port).unwrap();

                internal_socket
                    .connect((address, remote.port()), local_port)
                    .or_else(|_| {
                        self.close(socket)?;
                        Err(NetworkError::ConnectionFailure)
                    })?;
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

        // Remove the bound port from the used_ports buffer.
        let local_port = internal_socket.local_endpoint().port;
        let mut used_ports = self.used_ports.borrow_mut();

        let index = used_ports
            .iter()
            .position(|&port| port == local_port)
            .unwrap();
        used_ports.swap_remove(index);

        internal_socket.close();
        self.unused_handles.borrow_mut().push(socket).unwrap();
        Ok(())
    }
}
