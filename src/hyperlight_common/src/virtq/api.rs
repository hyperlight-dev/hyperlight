use alloc::sync::Arc;
use alloc::vec;
use alloc::vec::Vec;

use bytes::Bytes;
use thiserror::Error;

use super::access::PhysMem;
use super::alloc::{AllocError, Allocation, BufferProvider};
use super::ring::{
    BufferChain, BufferChainBuilder, BufferElement, RingConsumer, RingError, RingProducer,
};

/// A trait for notifying about new requests in the virtqueue.
pub trait Notifier {
    fn notify(&self, stats: QueueStats);
}

/// Errors that can occur in the virtqueue operations.
#[derive(Error, Debug)]
pub enum VirtqError {
    #[error("Ring error: {0}")]
    RingError(#[from] RingError),
    #[error("Allocation error: {0}")]
    Alloc(#[from] AllocError),
    #[error("Invalid token")]
    BadToken,
    #[error("Invalid chain received")]
    BadChain,
    #[error("Request too large for allocated buffer")]
    ReqTooLarge,
    #[error("Response too large for allocated buffer")]
    RespTooLarge,
    #[error("Internal state error")]
    InvalidState,
    #[error("Memory write error")]
    MemoryWriteError,
    #[error("Memory read error")]
    MemoryReadError,
}

#[derive(Debug, Clone, Copy)]
pub struct QueueStats {
    pub num_free: usize,
    pub num_inflight: usize,
}

/// An allocation of memory for use in the virtqueue.
#[derive(Debug, Clone)]
struct ProducerInflight {
    req: Allocation,
    resp: Allocation,
    resp_cap: usize,
}

/// A token representing a sent request in the virtqueue.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct Token(pub u16);

/// A request send from driver side of the virtq
#[derive(Debug)]
pub struct Request {
    pub token: Token,
    pub data: Bytes,
}

/// A delivery received from the device side of virtq.
#[derive(Debug)]
pub struct Response {
    pub token: Token,
    pub data: Bytes,
    pub written: usize,
}

/// A virtqueue producer for sending requests and receiving responses.
pub struct VirtqProducer<'q, P, M, N> {
    ring: RingProducer<'q>,
    mem: Arc<M>,
    pool: Arc<P>,
    notifier: Arc<N>,
    inflight: Vec<Option<ProducerInflight>>,
}

impl<'q, P, M, N> VirtqProducer<'q, P, M, N>
where
    P: BufferProvider,
    M: PhysMem,
    N: Notifier,
{
    pub fn new(ring: RingProducer<'q>, pool: Arc<P>, mem: Arc<M>, notifier: Arc<N>) -> Self {
        let inflight = vec![None; ring.len()];

        Self {
            ring,
            pool,
            mem,
            notifier,
            inflight,
        }
    }

    fn alloc(&self, size: usize) -> Result<AllocGuard<P>, VirtqError> {
        Ok(AllocGuard::new(self.pool.clone(), self.pool.alloc(size)?))
    }

    pub fn send(&mut self, req: &[u8], resp_cap: usize) -> Result<Token, VirtqError> {
        // We need 2 descriptors (req + resp)
        if self.ring.num_free() < 2 {
            return Err(RingError::WouldBlock.into());
        }

        let req_len = req.len();
        let req_g = self.alloc(req_len)?;

        if req_len > req_g.inner().len {
            return Err(VirtqError::ReqTooLarge);
        }

        let resp_g = self.alloc(resp_cap)?;
        let resp_cap = resp_g.inner().len;

        self.mem
            .write(req_g.inner().addr, req)
            .map_err(|_| VirtqError::MemoryWriteError)?;

        let chain = BufferChainBuilder::new()
            .readable(req_g.inner().addr, req_len as u32)
            .writable(resp_g.inner().addr, resp_cap as u32)
            .build()?;

        let submit = self.ring.submit_available_with_notify(&chain)?;

        let id = submit.id as usize;
        let slot = self.inflight.get_mut(id).ok_or(VirtqError::InvalidState)?;

        if slot.is_some() {
            // Slot must be free here
            return Err(VirtqError::InvalidState);
        }

        *slot = Some(ProducerInflight {
            req: req_g.into_inner(),
            resp: resp_g.into_inner(),
            resp_cap,
        });

        if submit.notify {
            let stats = QueueStats {
                num_free: self.ring.num_free(),
                num_inflight: self.ring.num_inflight(),
            };

            self.notifier.notify(stats);
        }

        Ok(Token(submit.id))
    }

    pub fn poll_once(&mut self) -> Result<Option<Response>, VirtqError> {
        let used = match self.ring.poll_used() {
            Ok(u) => u,
            Err(RingError::WouldBlock) => return Ok(None),
            Err(e) => return Err(e.into()),
        };

        let id = used.id as usize;
        let inf = self
            .inflight
            .get_mut(id)
            .ok_or(VirtqError::InvalidState)?
            .take()
            .ok_or(VirtqError::InvalidState)?;

        let written = used.len as usize;
        if written > inf.resp_cap {
            // free allocations; device misbehaved or protocol mismatch
            let _ = self.pool.dealloc(inf.req);
            let _ = self.pool.dealloc(inf.resp);
            return Err(VirtqError::InvalidState);
        }

        // Free request allocation now; response is managed by Bytes owner drop
        self.pool.dealloc(inf.req)?;

        let mut buf = vec![0u8; written];
        self.mem
            .read_into(inf.resp.addr, written, &mut buf)
            .map_err(|_| VirtqError::MemoryReadError)?;

        let data = Bytes::from(buf);
        let token = Token(used.id);

        Ok(Some(Response {
            token,
            data,
            written,
        }))
    }

    pub fn drain(&mut self, mut f: impl FnMut(Token, Bytes)) -> Result<(), VirtqError> {
        while let Some(resp) = self.poll_once()? {
            f(resp.token, resp.data);
        }

        Ok(())
    }
}

#[derive(Debug, Clone, Copy)]
struct ConsumerInflight {
    resp: BufferElement,
    resp_cap: usize,
}

/// A high level virtqueue consumer
pub struct VirtqConsumer<'q, M, N> {
    ring: RingConsumer<'q>,
    mem: Arc<M>,
    notifier: Arc<N>,
    inflight: Vec<Option<ConsumerInflight>>,
}

impl<'q, M, N> VirtqConsumer<'q, M, N>
where
    M: PhysMem,
    N: Notifier,
{
    pub fn new(ring: RingConsumer<'q>, mem: Arc<M>, notifier: Arc<N>) -> Self {
        let inflight = vec![None; ring.len()];

        Self {
            ring,
            mem,
            notifier,
            inflight,
        }
    }

    /// Poll one request. Returns None if WouldBlock.
    ///
    /// For now, only accept chains shaped as:
    ///  - exactly 1 readable element
    ///  - exactly 1 writable element
    pub fn poll_once(&mut self, max_req: usize) -> Result<Option<Request>, VirtqError> {
        let (id, chain) = match self.ring.poll_available() {
            Ok(x) => x,
            Err(RingError::WouldBlock) => return Ok(None),
            Err(e) => return Err(e.into()),
        };

        let (req_elem, resp_elem) = parse_single_req_resp(&chain)?;

        let req_len = req_elem.len as usize;
        if req_len > max_req {
            return Err(VirtqError::ReqTooLarge);
        }

        let mut buf = vec![0u8; req_len];
        self.mem
            .read_into(req_elem.addr, req_len, &mut buf)
            .map_err(|_| VirtqError::MemoryReadError)?;

        // Save response buffer for later completion
        let slot = self
            .inflight
            .get_mut(id as usize)
            .ok_or(VirtqError::InvalidState)?;

        if slot.is_some() {
            return Err(VirtqError::InvalidState);
        }

        *slot = Some(ConsumerInflight {
            resp: resp_elem,
            resp_cap: resp_elem.len as usize,
        });

        let req = Request {
            token: Token(id),
            data: Bytes::from(buf),
        };

        Ok(Some(req))
    }

    pub fn complete(&mut self, tok: Token, resp: &[u8]) -> Result<(), VirtqError> {
        let id = tok.0 as usize;

        let inf = self
            .inflight
            .get_mut(id)
            .ok_or(VirtqError::InvalidState)?
            .take()
            .ok_or(VirtqError::BadToken)?;

        if resp.len() > inf.resp_cap {
            // FIXME: this has to be handled on the protocol level:
            // for example we should communicate to the driver that the allocated buffer
            // cannot hold the entire response and send truncated data. For now, just error
            // out but this will certainly lead to a deadlock if the driver cannot handle it.
            return Err(VirtqError::RespTooLarge);
        }

        self.mem
            .write(inf.resp.addr, resp)
            .map_err(|_| VirtqError::MemoryWriteError)?;

        let notify = self
            .ring
            .submit_used_with_notify(tok.0, resp.len() as u32)?;

        if notify {
            let stats = QueueStats {
                num_free: self.ring.num_free(),
                num_inflight: self.ring.num_inflight(),
            };
            self.notifier.notify(stats);
        }

        Ok(())
    }
}

#[inline]
fn parse_single_req_resp(
    chain: &BufferChain,
) -> Result<(BufferElement, BufferElement), VirtqError> {
    let r = chain.readables();
    let w = chain.writables();

    if r.len() != 1 || w.len() != 1 {
        return Err(VirtqError::BadChain);
    }

    Ok((r[0], w[0]))
}

#[derive(Debug)]
pub struct AllocGuard<P: BufferProvider> {
    pool: Arc<P>,
    inner: Option<Allocation>,
}

impl<P: BufferProvider> AllocGuard<P> {
    pub fn new(pool: Arc<P>, alloc: Allocation) -> Self {
        Self {
            pool,
            inner: Some(alloc),
        }
    }

    fn inner(&self) -> &Allocation {
        self.inner.as_ref().expect("alloc moved")
    }

    /// Prevent Drop from freeing and return the Allocation.
    fn into_inner(mut self) -> Allocation {
        self.inner.take().expect("alloc moved")
    }
}

impl<P: BufferProvider> Drop for AllocGuard<P> {
    fn drop(&mut self) {
        if let Some(a) = self.inner.take() {
            let _ = self.pool.dealloc(a);
        }
    }
}

impl From<BufferElement> for Allocation {
    fn from(value: BufferElement) -> Self {
        Allocation {
            addr: value.addr,
            len: value.len as usize,
        }
    }
}

#[cfg(all(test, loom))]
mod fuzz {
    use alloc::vec;
    use core::ptr::NonNull;

    use bytemuck::Zeroable;
    use loom::sync::RwLock;
    use loom::sync::atomic::{AtomicUsize, Ordering};
    use loom::thread;

    use super::*;
    use crate::virtq::alloc::BufferPool;
    use crate::virtq::desc::{DescTable, Descriptor};

    #[derive(Debug)]
    pub struct MemErr;

    #[derive(Debug)]
    pub struct Mem {
        base: u64,
        buf: RwLock<Vec<u8>>,
    }

    impl Mem {
        pub fn new(base: u64, len: usize) -> Self {
            Self {
                base,
                buf: vec![0; len].into(),
            }
        }

        fn idx(&self, paddr: u64) -> usize {
            let off = paddr - self.base;
            off as usize
        }
    }

    unsafe impl PhysMem for Mem {
        type Error = MemErr;

        fn read_into(&self, paddr: u64, len: usize, dst: &mut [u8]) -> Result<usize, Self::Error> {
            let start = self.idx(paddr);
            let end = start + len;

            let n = len.min(dst.len());
            let buf = self.buf.read().unwrap();

            assert!(end <= buf.len());

            dst.copy_from_slice(&buf[start..start + n]);
            Ok(n)
        }

        fn write(&self, paddr: u64, data: &[u8]) -> Result<usize, Self::Error> {
            let start = self.idx(paddr);
            let end = start + data.len();

            let mut buf = self.buf.write().unwrap();
            assert!(end <= buf.len());

            buf[start..end].copy_from_slice(data);
            Ok(data.len())
        }
    }

    pub struct SharedTable {
        ptr: NonNull<Descriptor>,
        len: usize,
    }

    impl SharedTable {
        pub fn new(len: usize) -> Self {
            let mut boxed = vec![Descriptor::zeroed(); len].into_boxed_slice();
            let ptr = NonNull::new(boxed.as_mut_ptr()).unwrap();
            core::mem::forget(boxed);
            Self { ptr, len }
        }

        pub fn table<'a>(&self) -> DescTable<'a> {
            unsafe { DescTable::from_mem(self.ptr, self.len) }
        }
    }

    #[derive(Debug)]
    pub struct Notify {
        kicks: AtomicUsize,
    }

    impl Notifier for Notify {
        fn notify(&self, _stats: QueueStats) {
            self.kicks.fetch_add(1, Ordering::Relaxed);
        }
    }

    #[test]
    fn virtq_ping_pong() {
        loom::model(|| {
            let ring_len = 8;
            let table = Arc::new(SharedTable::new(ring_len));

            let mem_base = 0x1000u64;
            let mem_len = 0x20000usize;
            let mem = Arc::new(Mem::new(mem_base, mem_len));
            let notify = Arc::new(Notify {
                kicks: AtomicUsize::new(0),
            });

            let pool = Arc::new(BufferPool::<256, 4096>::new(mem_base, mem_len).unwrap());

            let prod_ring = RingProducer::new(table.table());
            let cons_ring = RingConsumer::new(table.table());

            let mut prod = VirtqProducer::new(prod_ring, pool, mem.clone(), notify.clone());
            let mut cons = VirtqConsumer::new(cons_ring, mem, notify);

            let t_prod = thread::spawn(move || {
                let tok = prod.send(b"ping", 32).unwrap();
                loop {
                    if let Some(r) = prod.poll_once().unwrap() {
                        assert_eq!(r.token, tok);
                        assert_eq!(&r.data[..], b"pong");
                        break;
                    }
                    thread::yield_now();
                }
            });

            let t_cons = thread::spawn(move || {
                let req = loop {
                    if let Some(r) = cons.poll_once(1024).unwrap() {
                        break r;
                    }
                    thread::yield_now();
                };
                assert_eq!(&req.data[..], b"ping");
                cons.complete(req.token, b"pong").unwrap();
            });

            t_prod.join().unwrap();
            t_cons.join().unwrap();
        });
    }
}
