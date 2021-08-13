// This program can be executed by
// # sudo -E cargo run --bin nethint-user [interface]

use std::env;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path;
use std::process;
use tokio::signal::ctrl_c;
use tokio::time::{sleep, Duration, Instant};
use tracing::{error, info, trace};
use tracing_subscriber::{EnvFilter, FmtSubscriber};

use nethint_userspace::{AutoRemovePinnedMap, TcRule};
use probes::nethint::{BytesAddr, FlowLabel};
use redbpf::HashMap as BpfHashMap;

use nethint::counterunit::{AvgCounterUnit, CounterType, CounterUnit};
use nhagent_v2::{argument::Opts, sdn_controller};
use structopt::StructOpt;

const ENV_NH_LOG: &str = "NH_LOG";

const SUB_INTERVAL_MS: Duration = Duration::from_millis(10);

const TC_FLOW_MAP_INGRESS: &str = "/sys/fs/bpf/tc/globals/flow_map_ingress";
const TC_FLOW_MAP_EGRESS: &str = "/sys/fs/bpf/tc/globals/flow_map_egress";
const TC_SECTION_INGRESS: &str = "tc_action/nethint_count_ingress";
const TC_SECTION_EGRESS: &str = "tc_action/nethint_count_egress";

fn load_tc(
    iface: &str,
    datapath: &str,
    section: &str,
    map_path: impl AsRef<path::Path>,
) -> (TcRule, AutoRemovePinnedMap) {
    let bpf_elf = probe_path();

    // tc filter add dev rdma0 ingress bpf da obj ./tc-example.o sec ingress
    let mut tc_filter = TcRule::new(
        &format!(
            "filter add dev {} {} prio 49152 bpf direct-action object-file {} section {}",
            iface, datapath, bpf_elf, section
        ),
        Some(&format!(
            "filter del dev {} {} prio 49152 bpf direct-action object-file {} section {}",
            iface, datapath, bpf_elf, section
        )),
    );

    tc_filter.apply().unwrap();

    // Load map from pinned file that is just created by tc
    let auto_remove_map = AutoRemovePinnedMap::new(map_path);

    // the drop order is from left to right no matter when they are declared, do not change the order
    (tc_filter, auto_remove_map)
}

#[tokio::main(flavor = "current_thread")]
async fn main() {
    if env::var(ENV_NH_LOG).is_err() {
        env::set_var(ENV_NH_LOG, "info");
    }
    let subscriber = FmtSubscriber::builder()
        .with_env_filter(EnvFilter::from_env(ENV_NH_LOG))
        .finish();
    tracing::subscriber::set_global_default(subscriber).unwrap();
    if unsafe { libc::geteuid() != 0 } {
        error!("You must be root to use eBPF!");
        process::exit(1);
    }

    let opts = Opts::from_args();
    let iface = opts.iface.clone().unwrap_or("rdma0".to_owned());
    let rack_leader = opts
        .rack_leader
        .unwrap_or_else(|| get_default_rack_leader(opts.sampler_listen_port));
    let interval_ms = Duration::from_millis(opts.interval_ms);
    assert!(SUB_INTERVAL_MS <= interval_ms);

    let bpf_elf = probe_path();
    info!(bpf_elf);

    info!(
        "Attaching tc BPF program to `{}' interface as direct action",
        iface
    );

    // tc qdisc replace dev rdma0 clsact
    let mut clsact = TcRule::new(
        &format!("qdisc add dev {} clsact", iface),
        Some(&format!("qdisc del dev {} clsact", iface)),
    );
    let _ = clsact.apply(); // it is okay to fail here

    let (_tc_filter_ingress, map_ingress) =
        load_tc(&iface, "ingress", TC_SECTION_INGRESS, TC_FLOW_MAP_INGRESS);
    let flow_map_ingress = BpfHashMap::<FlowLabel, BytesAddr>::new(map_ingress.as_ref())
        .expect("error on BpfHashMap::new ingress");

    let (_tc_filter_egress, map_egress) =
        load_tc(&iface, "egress", TC_SECTION_EGRESS, TC_FLOW_MAP_EGRESS);
    let flow_map_egress = BpfHashMap::<FlowLabel, BytesAddr>::new(map_egress.as_ref())
        .expect("error on BpfHashMap::new egress");

    let local_ip_table = sdn_controller::get_local_ip_table().unwrap();

    let mut counters: Vec<(IpAddr, CounterUnit)> = local_ip_table
        .clone()
        .iter()
        .map(|(&k, v)| (k, CounterUnit::new(v)))
        .collect();

    let mut avg_counters: Vec<(IpAddr, AvgCounterUnit)> = local_ip_table
        .clone()
        .iter()
        .map(|(&k, v)| (k, AvgCounterUnit::new(v)))
        .collect();

    let rack_iptable = sdn_controller::get_rack_ip_table().unwrap();

    let mut last_ts = Instant::now();
    let sock = std::net::UdpSocket::bind("0.0.0.0:34254").expect("bind failed");
    info!("rack_leader: {}", rack_leader);
    sock.connect(rack_leader).expect("connect failed");
    sock.set_write_timeout(Some(interval_ms)).unwrap();

    let event_fut = async {
        loop {
            sleep(SUB_INTERVAL_MS).await;

            // count and clear flows for ingress
            for (k, v) in flow_map_ingress.iter() {
                let sip = IpAddr::from(Ipv4Addr::from(u32::from_be(v.saddr)));
                let dip = IpAddr::from(Ipv4Addr::from(u32::from_be(v.daddr)));

                if let Some((_, c)) = counters.iter_mut().find(|(ip, _)| ip == &dip) {
                    c.add_flow(CounterType::Rx, v.bytes);
                    if rack_iptable.contains_key(&sip) {
                        c.add_flow(CounterType::RxIn, v.bytes);
                    }
                }

                flow_map_ingress.delete(k);
            }

            // count and clear flows for egress
            for (k, v) in flow_map_egress.iter() {
                let sip = IpAddr::from(Ipv4Addr::from(u32::from_be(v.saddr)));
                let dip = IpAddr::from(Ipv4Addr::from(u32::from_be(v.daddr)));

                if let Some((_, c)) = counters.iter_mut().find(|(ip, _)| ip == &sip) {
                    c.add_flow(CounterType::Tx, v.bytes);
                    if rack_iptable.contains_key(&dip) {
                        c.add_flow(CounterType::TxIn, v.bytes);
                    }
                }

                flow_map_egress.delete(k);
            }

            // moving average
            for ((_, c), (_, d)) in avg_counters.iter_mut().zip(&mut counters) {
                c.merge_counter(&d);
                d.clear();
            }

            // send the collected metrics out
            let now = Instant::now();
            if now >= last_ts + interval_ms {
                trace!("{:?}", avg_counters);
                // send the results to the collector
                let counter: Vec<CounterUnit> = avg_counters
                    .iter()
                    .cloned()
                    .map(|(_, a)| a.into())
                    .collect();
                let buf = bincode::serialize(&counter).expect("fail to serialize counter");
                assert!(buf.len() <= 65507);
                match sock.send(&buf) {
                    Ok(_nbytes) => {}
                    Err(_e) => {}
                }

                last_ts = now;
                for (_, c) in &mut avg_counters {
                    c.clear_bytes();
                }
            }
        }
    };

    let ctrlc_fut = async {
        ctrl_c().await.unwrap();
    };

    info!("Hit Ctrl-C to quit");
    tokio::select! {
        _ = event_fut => {

        }
        _ = ctrlc_fut => {
            info!("Ctrl-C received");
        }
    }

    info!("Exit nethint-user");
}

const fn probe_path() -> &'static str {
    concat!(env!("OUT_DIR"), "/target/bpf/programs/nethint/nethint.elf")
}

fn get_default_rack_leader(sampler_listen_port: u16) -> SocketAddr {
    SocketAddr::new(
        sdn_controller::get_rack_leader_ipv4().into(),
        sampler_listen_port,
    )
}
