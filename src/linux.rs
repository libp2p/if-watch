use crate::{IfEvent, IpNet, Ipv4Net, Ipv6Net};
use fnv::FnvHashSet;
use futures::ready;
use futures::stream::{Stream, TryStreamExt};
use futures::StreamExt;
use rtnetlink::constants::{RTMGRP_IPV4_IFADDR, RTMGRP_IPV6_IFADDR};
use rtnetlink::packet::address::nlas::Nla;
use rtnetlink::packet::{AddressMessage, RtnlMessage};
use rtnetlink::proto::{Connection, NetlinkPayload};
use rtnetlink::sys::{AsyncSocket, SmolSocket, SocketAddr};
use std::collections::VecDeque;
use std::future::Future;
use std::io::{Error, ErrorKind, Result};
use std::net::{Ipv4Addr, Ipv6Addr};
use std::pin::Pin;
use std::task::{Context, Poll};

pub struct IfWatcher {
    conn: Connection<RtnlMessage, SmolSocket>,
    messages: Pin<Box<dyn Stream<Item = Result<RtnlMessage>> + Send>>,
    addrs: FnvHashSet<IpNet>,
    queue: VecDeque<IfEvent>,
}

impl std::fmt::Debug for IfWatcher {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        f.debug_struct("IfWatcher")
            .field("addrs", &self.addrs)
            .finish_non_exhaustive()
    }
}

impl IfWatcher {
    pub fn new() -> Result<Self> {
        let (mut conn, handle, messages) = rtnetlink::new_connection_with_socket::<SmolSocket>()?;
        let groups = RTMGRP_IPV4_IFADDR | RTMGRP_IPV6_IFADDR;
        let addr = SocketAddr::new(0, groups);
        conn.socket_mut().socket_mut().bind(&addr)?;
        let get_addrs_stream = handle
            .address()
            .get()
            .execute()
            .map_ok(RtnlMessage::NewAddress)
            .map_err(|err| Error::new(ErrorKind::Other, err));
        let msg_stream = messages.filter_map(|(msg, _)| async {
            match msg.payload {
                NetlinkPayload::Error(err) => Some(Err(err.to_io())),
                NetlinkPayload::InnerMessage(msg) => Some(Ok(msg)),
                _ => None,
            }
        });
        let messages = get_addrs_stream.chain(msg_stream).boxed();
        let addrs = FnvHashSet::default();
        let queue = VecDeque::default();
        Ok(Self {
            conn,
            messages,
            addrs,
            queue,
        })
    }

    pub fn iter(&self) -> impl Iterator<Item = &IpNet> {
        self.addrs.iter()
    }

    fn add_address(&mut self, msg: AddressMessage) {
        for net in iter_nets(msg) {
            if self.addrs.insert(net) {
                self.queue.push_back(IfEvent::Up(net));
            }
        }
    }

    fn rem_address(&mut self, msg: AddressMessage) {
        for net in iter_nets(msg) {
            if self.addrs.remove(&net) {
                self.queue.push_back(IfEvent::Down(net));
            }
        }
    }

    pub fn poll_next(&mut self, cx: &mut Context) -> Poll<Result<IfEvent>> {
        loop {
            if let Some(event) = self.queue.pop_front() {
                return Poll::Ready(Ok(event));
            }
            if Pin::new(&mut self.conn).poll(cx).is_ready() {
                return Poll::Ready(Err(socket_err()));
            }
            let message = ready!(self.messages.poll_next_unpin(cx)).ok_or_else(socket_err)??;
            match message {
                RtnlMessage::NewAddress(msg) => self.add_address(msg),
                RtnlMessage::DelAddress(msg) => self.rem_address(msg),
                _ => {}
            }
        }
    }
}

fn socket_err() -> std::io::Error {
    std::io::Error::new(ErrorKind::BrokenPipe, "rtnetlink socket closed")
}

fn iter_nets(msg: AddressMessage) -> impl Iterator<Item = IpNet> {
    let prefix = msg.header.prefix_len;
    let family = msg.header.family;
    msg.nlas.into_iter().filter_map(move |nla| {
        if let Nla::Address(octets) = nla {
            match family {
                2 => {
                    let mut addr = [0; 4];
                    addr.copy_from_slice(&octets);
                    Some(IpNet::V4(
                        Ipv4Net::new(Ipv4Addr::from(addr), prefix).unwrap(),
                    ))
                }
                10 => {
                    let mut addr = [0; 16];
                    addr.copy_from_slice(&octets);
                    Some(IpNet::V6(
                        Ipv6Net::new(Ipv6Addr::from(addr), prefix).unwrap(),
                    ))
                }
                _ => None,
            }
        } else {
            None
        }
    })
}
