//! Bounded byte streams for running the real HTTP stack in a simulation.

use std::{
    collections::BTreeMap,
    io,
    net::SocketAddr,
    pin::Pin,
    sync::{
        atomic::{AtomicBool, AtomicUsize, Ordering},
        Arc, Mutex, Weak,
    },
    task::{Context, Poll},
};

use futures::{channel::mpsc, task::AtomicWaker, StreamExt};
use tokio::io::{AsyncRead, AsyncWrite, DuplexStream, ReadBuf};

#[derive(Default)]
struct Gate {
    blocked: AtomicBool,
    waker: AtomicWaker,
}

impl Gate {
    fn set(&self, blocked: bool) {
        self.blocked.store(blocked, Ordering::SeqCst);
        if !blocked {
            self.waker.wake();
        }
    }
    fn poll(&self, cx: &Context<'_>) -> Poll<()> {
        self.waker.register(cx.waker());
        if self.blocked.load(Ordering::SeqCst) {
            Poll::Pending
        } else {
            Poll::Ready(())
        }
    }
}

struct Controls {
    read: Gate,
    write: Gate,
    reset: Arc<AtomicBool>,
    peer: Mutex<Weak<Controls>>,
    read_limit: AtomicUsize,
    write_limit: AtomicUsize,
}

/// Controls one endpoint without reading or writing on its behalf.
#[derive(Clone)]
pub struct IoControl(Arc<Controls>);

impl IoControl {
    pub fn block_reads(&self, blocked: bool) {
        self.0.read.set(blocked);
    }
    pub fn block_writes(&self, blocked: bool) {
        self.0.write.set(blocked);
    }
    pub fn fragment(&self, read_bytes: usize, write_bytes: usize) {
        assert!(read_bytes > 0 && write_bytes > 0);
        self.0.read_limit.store(read_bytes, Ordering::SeqCst);
        self.0.write_limit.store(write_bytes, Ordering::SeqCst);
    }
    pub fn reset(&self) {
        self.0.reset.store(true, Ordering::SeqCst);
        self.0.read.set(false);
        self.0.write.set(false);
        if let Some(peer) = self.0.peer.lock().unwrap().upgrade() {
            peer.read.set(false);
            peer.write.set(false);
        }
    }
    fn check(&self) -> io::Result<()> {
        if self.0.reset.load(Ordering::SeqCst) {
            Err(io::ErrorKind::ConnectionReset.into())
        } else {
            Ok(())
        }
    }
}

pub struct SimulatedIo {
    inner: DuplexStream,
    control: IoControl,
}

impl SimulatedIo {
    fn new(inner: DuplexStream, reset: Arc<AtomicBool>) -> Self {
        Self {
            inner,
            control: IoControl(Arc::new(Controls {
                read: Gate::default(),
                write: Gate::default(),
                reset,
                peer: Mutex::new(Weak::new()),
                read_limit: AtomicUsize::new(usize::MAX),
                write_limit: AtomicUsize::new(usize::MAX),
            })),
        }
    }
    pub fn control(&self) -> IoControl {
        self.control.clone()
    }
}

impl AsyncRead for SimulatedIo {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let ready = self.control.0.read.poll(cx);
        self.control.check()?;
        std::task::ready!(ready);
        let limit = buf
            .remaining()
            .min(self.control.0.read_limit.load(Ordering::SeqCst));
        let mut part = ReadBuf::new(buf.initialize_unfilled_to(limit));
        std::task::ready!(Pin::new(&mut self.inner).poll_read(cx, &mut part))?;
        let read = part.filled().len();
        buf.advance(read);
        Poll::Ready(Ok(()))
    }
}

impl AsyncWrite for SimulatedIo {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let ready = self.control.0.write.poll(cx);
        self.control.check()?;
        std::task::ready!(ready);
        let limit = buf
            .len()
            .min(self.control.0.write_limit.load(Ordering::SeqCst));
        Pin::new(&mut self.inner).poll_write(cx, &buf[..limit])
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let ready = self.control.0.write.poll(cx);
        self.control.check()?;
        std::task::ready!(ready);
        Pin::new(&mut self.inner).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.control.check()?;
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

type Accepted = (SimulatedIo, SocketAddr);

struct Network {
    capacity: usize,
    next_port: AtomicUsize,
    listeners: Mutex<BTreeMap<SocketAddr, mpsc::UnboundedSender<Accepted>>>,
}

#[derive(Clone)]
pub struct SimulatedNetwork(Arc<Network>);

impl SimulatedNetwork {
    pub fn new(capacity: usize) -> Self {
        assert!(capacity > 0);
        Self(Arc::new(Network {
            capacity,
            next_port: AtomicUsize::new(10_000),
            listeners: Mutex::new(BTreeMap::new()),
        }))
    }
    fn port(&self) -> u16 {
        self.0
            .next_port
            .fetch_add(1, Ordering::SeqCst)
            .try_into()
            .expect("simulated ports exhausted")
    }
    pub fn bind(&self, mut address: SocketAddr) -> io::Result<SimulatedListener> {
        if address.port() == 0 {
            address.set_port(self.port());
        }
        let mut listeners = self.0.listeners.lock().unwrap();
        if listeners.contains_key(&address) {
            return Err(io::ErrorKind::AddrInUse.into());
        }
        let (sender, incoming) = mpsc::unbounded();
        listeners.insert(address, sender);
        Ok(SimulatedListener {
            network: self.clone(),
            address,
            incoming,
        })
    }
    pub async fn connect(&self, address: SocketAddr) -> io::Result<SimulatedIo> {
        let (client, server) = tokio::io::duplex(self.0.capacity);
        let reset = Arc::new(AtomicBool::new(false));
        let client = SimulatedIo::new(client, reset.clone());
        let server = SimulatedIo::new(server, reset);
        *client.control.0.peer.lock().unwrap() = Arc::downgrade(&server.control.0);
        *server.control.0.peer.lock().unwrap() = Arc::downgrade(&client.control.0);
        let peer = SocketAddr::new(address.ip(), self.port());
        self.0
            .listeners
            .lock()
            .unwrap()
            .get(&address)
            .ok_or(io::ErrorKind::ConnectionRefused)?
            .unbounded_send((server, peer))
            .map_err(|_| io::ErrorKind::ConnectionRefused)?;
        Ok(client)
    }
}

pub struct SimulatedListener {
    network: SimulatedNetwork,
    address: SocketAddr,
    incoming: mpsc::UnboundedReceiver<Accepted>,
}

impl axum::serve::Listener for SimulatedListener {
    type Io = SimulatedIo;
    type Addr = SocketAddr;
    async fn accept(&mut self) -> Accepted {
        self.incoming
            .next()
            .await
            .expect("a bound listener retains its sender")
    }
    fn local_addr(&self) -> io::Result<SocketAddr> {
        Ok(self.address)
    }
}

impl Drop for SimulatedListener {
    fn drop(&mut self) {
        self.network
            .0
            .listeners
            .lock()
            .unwrap()
            .remove(&self.address);
    }
}
