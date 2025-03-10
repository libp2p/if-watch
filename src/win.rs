use crate::{IfEvent, IpNet, Ipv4Net, Ipv6Net};
use fnv::FnvHashSet;
use futures::stream::{FusedStream, Stream};
use futures::task::AtomicWaker;
use if_addrs::IfAddr;
use std::collections::VecDeque;
use std::ffi::c_void;
use std::io::{Error, ErrorKind, Result};
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::task::{Context, Poll};
use windows::Win32::Foundation::{BOOLEAN, HANDLE};
use windows::Win32::NetworkManagement::IpHelper::{
    CancelMibChangeNotify2, NotifyIpInterfaceChange, MIB_IPINTERFACE_ROW, MIB_NOTIFICATION_TYPE,
};
use windows::Win32::Networking::WinSock::AF_UNSPEC;

#[cfg(feature = "tokio")]
pub mod tokio {
    //! An interface watcher.
    //! **On Windows there is no difference between `tokio` and `smol` features,**
    //! **this was done to maintain the api compatible with other platforms**.

    /// Watches for interface changes.
    pub type IfWatcher = super::IfWatcher;
}

#[cfg(feature = "smol")]
pub mod smol {
    //! An interface watcher.
    //! **On Windows there is no difference between `tokio` and `smol` features,**
    //! **this was done to maintain the api compatible with other platforms**.

    /// Watches for interface changes.
    pub type IfWatcher = super::IfWatcher;
}

/// An address set/watcher
#[derive(Debug)]
pub struct IfWatcher {
    addrs: FnvHashSet<IpNet>,
    queue: VecDeque<IfEvent>,
    #[allow(unused)]
    notif: IpChangeNotification,
    shared: Pin<Box<IfWatcherShared>>,
}

impl IfWatcher {
    /// Create a watcher.
    pub fn new() -> Result<Self> {
        let shared = IfWatcherShared {
            resync: true.into(),
            waker: Default::default(),
        };
        let shared = Box::pin(shared);
        Ok(Self {
            addrs: Default::default(),
            queue: Default::default(),
            // Safety:
            // Self referential structure, `shared` will be dropped
            // after `notif`
            notif: unsafe { IpChangeNotification::new(shared.as_ref())? },
            shared,
        })
    }

    fn resync(&mut self) -> Result<()> {
        let addrs = if_addrs::get_if_addrs()?;
        for old_addr in self.addrs.clone() {
            if addrs
                .iter()
                .find(|addr| addr.ip() == old_addr.addr())
                .is_none()
            {
                self.addrs.remove(&old_addr);
                self.queue.push_back(IfEvent::Down(old_addr));
            }
        }
        for new_addr in addrs {
            let ipnet = ifaddr_to_ipnet(new_addr.addr);
            if self.addrs.insert(ipnet) {
                self.queue.push_back(IfEvent::Up(ipnet));
            }
        }
        Ok(())
    }

    /// Iterate over current networks.
    pub fn iter(&self) -> impl Iterator<Item = &IpNet> {
        self.addrs.iter()
    }

    /// Poll for an address change event.
    pub fn poll_if_event(&mut self, cx: &mut Context) -> Poll<Result<IfEvent>> {
        loop {
            if let Some(event) = self.queue.pop_front() {
                return Poll::Ready(Ok(event));
            }

            self.shared.waker.register(cx.waker());
            if !self.shared.resync.swap(false, Ordering::AcqRel) {
                return Poll::Pending;
            }
            self.shared.waker.take();

            if let Err(error) = self.resync() {
                return Poll::Ready(Err(error));
            }
        }
    }
}

impl Stream for IfWatcher {
    type Item = Result<IfEvent>;
    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        Pin::into_inner(self).poll_if_event(cx).map(Some)
    }
}

impl FusedStream for IfWatcher {
    fn is_terminated(&self) -> bool {
        false
    }
}

fn ifaddr_to_ipnet(addr: IfAddr) -> IpNet {
    match addr {
        IfAddr::V4(ip) => {
            let prefix_len = (!u32::from_be_bytes(ip.netmask.octets())).leading_zeros();
            IpNet::V4(
                Ipv4Net::new(ip.ip, prefix_len as u8).expect("if_addrs returned a valid prefix"),
            )
        }
        IfAddr::V6(ip) => {
            let prefix_len = (!u128::from_be_bytes(ip.netmask.octets())).leading_zeros();
            IpNet::V6(
                Ipv6Net::new(ip.ip, prefix_len as u8).expect("if_addrs returned a valid prefix"),
            )
        }
    }
}

#[derive(Debug)]
struct IfWatcherShared {
    waker: AtomicWaker,
    resync: AtomicBool,
}

impl IpChangeCallback for IfWatcherShared {
    fn callback(&self, _row: &MIB_IPINTERFACE_ROW, _notification_type: MIB_NOTIFICATION_TYPE) {
        self.resync.store(true, Ordering::Release);
        self.waker.wake();
    }
}

/// IP change notifications
struct IpChangeNotification {
    handle: HANDLE,
}

impl std::fmt::Debug for IpChangeNotification {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "IpChangeNotification")
    }
}

impl IpChangeNotification {
    /// Register for route change notifications
    ///
    /// Safety: C must outlive the resulting Self
    unsafe fn new<C>(cb: Pin<&C>) -> Result<Self>
    where
        C: IpChangeCallback + Send + Sync,
    {
        unsafe extern "system" fn global_callback<C>(
            caller_context: *const c_void,
            row: *const MIB_IPINTERFACE_ROW,
            notification_type: MIB_NOTIFICATION_TYPE,
        ) where
            C: IpChangeCallback + Send + Sync,
        {
            let caller_context = &*(caller_context as *const C);
            caller_context.callback(&*row, notification_type)
        }
        let mut handle = HANDLE::default();
        let callback = cb.get_ref() as *const C;
        unsafe {
            NotifyIpInterfaceChange(
                AF_UNSPEC,
                Some(global_callback::<C>),
                Some(callback as *const c_void),
                BOOLEAN(0),
                &mut handle as _,
            )
            .map_err(|err| Error::new(ErrorKind::Other, err.to_string()))?;
        }
        Ok(Self { handle })
    }
}

impl Drop for IpChangeNotification {
    fn drop(&mut self) {
        unsafe {
            if let Err(err) = CancelMibChangeNotify2(self.handle) {
                log::error!("error deregistering notification: {}", err);
            }
        }
    }
}

unsafe impl Send for IpChangeNotification {}

trait IpChangeCallback {
    fn callback(&self, row: &MIB_IPINTERFACE_ROW, notification_type: MIB_NOTIFICATION_TYPE);
}
