#![no_std]
#![no_main]

use redbpf_macros::map;
// use redbpf_probes::xdp::prelude::*;

use nethint_probes::nethint::FlowLabel;

// // TODO(cjr): use a LRU map in case of more than 10240 flows
// // also note that this BPF_MAP_TYPE_HASH is not per CPU
// // BPF_MAP_TYPE_LRU_PERCPU_HASH is the one to use if needed.
// #[map(link_section = "maps/alive_flows")]
// static mut ALIVE_FLOWS: HashMap<FlowLabel, u64> = HashMap::with_max_entries(10240);

program!(0xFFFFFFFE, "GPL");

// #[xdp]
// fn nethint_count_flows(ctx: XdpContext) -> XdpResult {
//     let ip = unsafe { &*ctx.ip()? as &iphdr };
//     let transport = ctx.transport()?;
// 
//     let proto = ip.protocol;
//     let saddr = ip.saddr;
//     let daddr = ip.daddr;
//     let sport = transport.source();
//     let dport = transport.dest();
//     let label = FlowLabel::new(proto, saddr, daddr, sport, dport);
// 
//     let bytes = ctx.data()?.len() as u64;
// 
//     unsafe {
//         if let Some(v) = ALIVE_FLOWS.get_mut(&label) {
//             *v += bytes;
//         } else {
//             // insert the flow label into the map
//             ALIVE_FLOWS.set(&label, &bytes);
//         }
//     }
// 
//     Ok(XdpAction::Pass)
// }

// use core::{
//     mem::{self, MaybeUninit},
//     ptr,
// };
// use memoffset::offset_of;
use redbpf_probes::tc::prelude::*;
use redbpf_probes::net::*;

#[map(link_section = "maps")]
static mut alive_flows: TcHashMap<FlowLabel, u64> = TcHashMap::with_max_entries(10240, TcMapPinning::GlobalNamespace);

// Since Linux 4.7, usage of `bpf_skb_load_bytes` helper has mostly
// been replaced by "direct packet access", enabling
// packet data to be manipulated with skb->data and
// skb->data_end pointing respectively to the first
// byte of packet data and to the byte after the last
// byte of packet data.
// skb.data and skb.data_end are added after linux 4.7
#[derive(Clone)]
pub struct MySkBuff {
    pub skb: *const __sk_buff,
}

impl From<SkBuff> for MySkBuff {
    #[inline]
    fn from(s: SkBuff) -> Self {
        MySkBuff {
            skb: s.skb
        }
    }
}

impl NetworkBuffer for MySkBuff {
    fn data_start(&self) -> usize {
        unsafe { (*self.skb).data as usize }
    }

    fn data_end(&self) -> usize {
        unsafe { (*self.skb).data_end as usize }
    }
}

/// BPF program type is BPF_PROG_TYPE_SCHED_CLS
#[tc_action]
fn nethint_count_flows(skb: SkBuff) -> TcActionResult {
    // // __sk_buff: see https://elixir.bootlin.com/linux/latest/source/include/uapi/linux/bpf.h 
    // // skb.protocol is u32
    // let transport_hdr_offset = match u32::from_be(unsafe { *skb.skb }.protocol << 16 ) {
    //     ETH_P_IP => {
    //         // let ipv4_hdr = skb.load::<iphdr>(mem::size_of::<ethhdr>());
    //         let protocol = skb.load::<u8>(mem::size_of::<ethhdr>(), offset_of!(iphdr, protocol))?;
    //         let saddr = skb.load::<u32>(mem::size_of::<ethhdr>(), offset_of!(iphdr, saddr))?;
    //         let daddr = skb.load::<u32>(mem::size_of::<ethhdr>(), offset_of!(iphdr, daddr))?;
    //         let ihl = skb.load::<u8>(mem::size_of::<ethhdr>() + offset_of!(iphdr, ihl))?;
    //     }
    //     ETH_P_IPV6 => {
    //         let nexthdr =
    //             skb.load::<u8>(mem::size_of::<ethhdr>() + offset_of!(ipv6hdr, nexthdr))?;
    //         mem::size_of::<ethhdr>() + mem::size_of::<ipv6hdr>()
    //     }
    //     _ => return Ok(TcAction::Ok),
    // };
    let skb = MySkBuff::from(skb);
    let ip = unsafe { &*skb.ip().map_err(|_| SocketError::LoadFailed)? as &iphdr };
    let transport = skb.transport().map_err(|_| SocketError::LoadFailed)?;

    let proto = ip.protocol;
    let saddr = ip.saddr;
    let daddr = ip.daddr;
    let sport = transport.source();
    let dport = transport.dest();
    let label = FlowLabel::new(proto, saddr, daddr, sport, dport);

    let bytes = skb.len() as u64;

    unsafe {
        if let Some(v) = alive_flows.get_mut(&label) {
            *v += bytes;
        } else {
            // insert the flow label into the map
            alive_flows.set(&label, &bytes);
        }
    }

    Ok(TcAction::Ok)
}