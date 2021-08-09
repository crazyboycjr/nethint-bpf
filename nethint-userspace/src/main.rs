// This program can be executed by
// # sudo -E cargo run --bin nethint-user [interface]

use std::env;
use std::net::{IpAddr, Ipv4Addr};
use std::path;
use std::process::{self, Command};
use tokio::signal::ctrl_c;
use tokio::time::{sleep, Duration, Instant};
use tracing::{error, info, trace, Level};
use tracing_subscriber::FmtSubscriber;

use nethint_userspace::{AutoRemovePinnedMap, TcRule};
use probes::nethint::{BytesAddr, FlowLabel};
use redbpf::HashMap as BpfHashMap;

use nethint::counterunit::{AvgCounterUnit, CounterType, CounterUnit};
use nhagent_v2::{argument::Opts, sdn_controller};
use structopt::StructOpt;

const NETHINT_INTERVAL_MS: Duration = Duration::from_millis(100);
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
    let subscriber = FmtSubscriber::builder()
        .with_max_level(Level::TRACE)
        .finish();
    tracing::subscriber::set_global_default(subscriber).unwrap();
    if unsafe { libc::geteuid() != 0 } {
        error!("You must be root to use eBPF!");
        process::exit(1);
    }

    let opts = Opts::from_args();
    let iface = opts.iface.unwrap_or("lo".to_owned());

    let bpf_elf = probe_path();
    info!(bpf_elf);

    strip_bpf_elf(bpf_elf);

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

    let mut last_ts = Instant::now();

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
            if now >= last_ts + NETHINT_INTERVAL_MS {
                // send the results to the collector
                trace!("{:?}", avg_counters);
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

fn strip_bpf_elf<P: AsRef<path::Path>>(path: P) {
    // remove .BTF.ext and .eh_frame in order to remove .text
    // remove .text section because tc filter does not work if .text exists
    // remove .BTF section because it contains invalid names of BTF types
    // (currently kernel only allows valid symbol names of C)
    for sec in &[".BTF.ext", ".eh_frame", ".text", ".BTF"] {
        if !Command::new("llvm-strip")
            .arg("--strip-unneeded")
            .arg("--remove-section")
            .arg(sec)
            .arg(path.as_ref())
            .status()
            .expect("error on running command llvm-strip")
            .success()
        {
            error!("error on removing section `{}' using llvm-strip", sec);
            process::exit(2);
        }
    }
}
