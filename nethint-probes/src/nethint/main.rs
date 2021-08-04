#![no_std]
#![no_main]

use redbpf_macros::map;
use redbpf_probes::xdp::prelude::*;

use nethint_probes::nethint::FlowLabel;

// TODO(cjr): use a LRU map in case of more than 10240 flows
// also note that this BPF_MAP_TYPE_HASH is not per CPU
// BPF_MAP_TYPE_LRU_PERCPU_HASH is the one to use if needed.
#[map(link_section = "maps/alive_flows")]
static mut ALIVE_FLOWS: HashMap<FlowLabel, u64> = HashMap::with_max_entries(10240);

program!(0xFFFFFFFE, "GPL");

#[xdp]
fn nethint_count_flows(ctx: XdpContext) -> XdpResult {
    let ip = unsafe { &*ctx.ip()? as &iphdr };
    let transport = ctx.transport()?;

    let proto = ip.protocol;
    let saddr = ip.saddr;
    let daddr = ip.daddr;
    let sport = transport.source();
    let dport = transport.dest();
    let label = FlowLabel::new(proto, saddr, daddr, sport, dport);

    let bytes = ctx.data()?.len() as u64;

    unsafe {
        if let Some(v) = ALIVE_FLOWS.get_mut(&label) {
            *v += bytes;
        } else {
            // insert the flow label into the map
            ALIVE_FLOWS.set(&label, &bytes);
        }
    }

    Ok(XdpAction::Pass)
}