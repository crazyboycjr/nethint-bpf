#![no_std]
#![no_main]

use redbpf_macros::map;
use redbpf_probes::net::*;
use redbpf_probes::tc::prelude::*;

use nethint_probes::nethint::FlowLabel;

program!(0xFFFFFFFE, "GPL");

// TODO(cjr): use a LRU map in case of more than 10240 flows
// also note that this BPF_MAP_TYPE_HASH is not per CPU
// BPF_MAP_TYPE_LRU_PERCPU_HASH is the one to use if needed.
#[map(link_section = "maps")]
static mut alive_flows: TcHashMap<FlowLabel, u64> =
    TcHashMap::with_max_entries(10240, TcMapPinning::GlobalNamespace);

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
        MySkBuff { skb: s.skb }
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
