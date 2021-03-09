#![no_std]

pub use embedded_nal;
pub use smoltcp;

use core::cell::RefCell;
use heapless::{consts, Vec};
use nanorand::{wyrand::WyRand, RNG};

#[derive(Debug)]
pub enum NetworkError {
    NoSocket,
    ConnectionFailure,
    ReadFailure,
    WriteFailure,
    Unsupported,
}

///! Network abstraction layer for smoltcp.
pub struct NetworkStack<'a, 'b, DeviceT>
where
    DeviceT: for<'c> smoltcp::phy::Device<'c>,
{
    network_interface: RefCell<smoltcp::iface::EthernetInterface<'b, DeviceT>>,
    sockets: RefCell<smoltcp::socket::SocketSet<'a>>,
    used_ports: RefCell<Vec<u16, consts::U16>>,
    unused_handles: RefCell<Vec<smoltcp::socket::SocketHandle, consts::U16>>,
    randomizer: RefCell<WyRand>,
}

impl<'a, 'b, DeviceT> NetworkStack<'a, 'b, DeviceT>
where
    DeviceT: for<'c> smoltcp::phy::Device<'c>,
{
    /// Construct a new network stack.
    ///
    /// # Args
    /// * `stack` - The ethernet interface to construct the network stack from.
    /// * `sockets` - The socket set to contain any socket state for the stack.
    ///
    /// # Returns
    /// A embedded-nal-compatible network stack.
    pub fn new(
        stack: smoltcp::iface::EthernetInterface<'b, DeviceT>,
        sockets: smoltcp::socket::SocketSet<'a>,
    ) -> Self {
        let mut unused_handles: Vec<smoltcp::socket::SocketHandle, consts::U16> = Vec::new();
        for socket in sockets.iter() {
            unused_handles.push(socket.handle()).unwrap();
        }

        NetworkStack {
            network_interface: RefCell::new(stack),
            sockets: RefCell::new(sockets),
            used_ports: RefCell::new(Vec::new()),
            unused_handles: RefCell::new(unused_handles),
            randomizer: RefCell::new(WyRand::new()),
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
    pub fn poll(&self, time: u32) -> bool {
        match self.network_interface.borrow_mut().poll(
            &mut self.sockets.borrow_mut(),
            smoltcp::time::Instant::from_millis(time as i64),
        ) {
            Ok(updated) => updated,

            // Ignore any errors - they indicate failures with external reception as opposed to
            // internal state management.
            // TODO: Should we ignore `Exhausted`, `Illegal`, `Unaddressable`?
            Err(_) => true,
        }
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

            let port = 49152 + random_offset % (u16::MAX - 49152);
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
                    .connect((address, remote.port()), self.get_ephemeral_port())
                    .map_err(|_| NetworkError::ConnectionFailure)?;
                Ok(socket)
            }

            // We only support IPv4.
            _ => Err(NetworkError::Unsupported),
        }
    }

    fn is_connected(&self, socket: &smoltcp::socket::SocketHandle) -> Result<bool, NetworkError> {
        let mut sockets = self.sockets.borrow_mut();
        let socket: &mut smoltcp::socket::TcpSocket = &mut *sockets.get(*socket);
        Ok(socket.may_send() && socket.may_recv())
    }

    fn write(
        &self,
        socket: &mut smoltcp::socket::SocketHandle,
        buffer: &[u8],
    ) -> embedded_nal::nb::Result<usize, NetworkError> {
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
        let mut sockets = self.sockets.borrow_mut();
        let socket: &mut smoltcp::socket::TcpSocket = &mut *sockets.get(*socket);
        socket
            .recv_slice(buffer)
            .map_err(|_| embedded_nal::nb::Error::Other(NetworkError::ReadFailure))
    }

    fn close(&self, socket: smoltcp::socket::SocketHandle) -> Result<(), NetworkError> {
        let mut sockets = self.sockets.borrow_mut();
        let internal_socket: &mut smoltcp::socket::TcpSocket = &mut *sockets.get(socket);

        // Remove the bound port form the used_ports buffer.
        let local_port = internal_socket.local_endpoint().port;
        let mut used_ports = self.used_ports.borrow_mut();
        used_ports
            .iter()
            .position(|&port| port == local_port)
            .and_then(|index| Some(used_ports.swap_remove(index)));

        internal_socket.close();
        self.unused_handles.borrow_mut().push(socket).unwrap();
        Ok(())
    }
}
