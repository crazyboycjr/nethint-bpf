// This program can be executed by
// # sudo -E cargo run --bin nethint-user [interface]

use std::env;
use std::path;
use std::process::{self, Command};
use tokio::signal::ctrl_c;
use tokio::time::{sleep, Duration, Instant};
use tracing::{error, info, Level};
use tracing_subscriber::FmtSubscriber;

use redbpf::{HashMap, Map};

use probes::nethint::FlowLabel;

use nethint_userspace::{AutoRemovePinnedMap, TcRule};

const NETHINT_INTERVAL_MS: Duration = Duration::from_millis(100);
const SUB_INTERVAL_MS: Duration = Duration::from_millis(10);

const TC_ALIVE_FLOWS_MAP: &str = "/sys/fs/bpf/tc/globals/alive_flows";
const TC_SECTION_NAME: &str = "tc_action/nethint_count_flows";

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

    let args: Vec<String> = env::args().collect();
    let iface = match args.get(1) {
        Some(val) => val,
        None => "lo",
    };

    let bpf_elf = probe_path();
    info!(bpf_elf);

    strip_bpf_elf(bpf_elf);

    info!(
        "Attaching tc BPF program to `{}' interface as direct action",
        iface
    );

    // drop the map lastly, so declare it first in the scope
    let mut auto_remove_map = AutoRemovePinnedMap::new(TC_ALIVE_FLOWS_MAP);

    // tc qdisc replace dev rdma0 clsact
    let mut clsact = TcRule::new(
        &format!("qdisc add dev {} clsact", iface),
        Some(&format!("qdisc del dev {} clsact", iface)),
    );
    // tc filter add dev rdma0 ingress bpf da obj ./tc-example.o sec ingress
    let mut tc_filter = TcRule::new(
        &format!(
            "filter add dev {} ingress prio 49152 bpf direct-action object-file {} section {}",
            iface, bpf_elf, TC_SECTION_NAME
        ),
        Some(&format!(
            "filter del dev {} ingress prio 49152 bpf direct-action object-file {} section {}",
            iface, bpf_elf, TC_SECTION_NAME
        )),
    );

    let _ = clsact.apply(); // it is okay to fail here
    tc_filter.apply().unwrap();

    // Load map from pinned file that is just created by tc
    let map = Map::from_pin_file(TC_ALIVE_FLOWS_MAP).expect("error on Map::from_pin_file");
    auto_remove_map.set_map(map);
    let alive_flows =
        HashMap::<FlowLabel, u64>::new(auto_remove_map.as_ref()).expect("error on HashMap::new");

    let mut last_ts = Instant::now();
    let mut avg_flows = 0.;

    let event_fut = async {
        loop {
            sleep(SUB_INTERVAL_MS).await;

            let mut num_flows = 0;
            let mut total_bytes = 0;

            // count and clear flows
            for (k, v) in alive_flows.iter() {
                total_bytes += v;
                alive_flows.delete(k);
                num_flows += 1;
            }

            // moving average
            avg_flows = avg_flows * 0.875 + num_flows as f64 * 0.125;

            // send the collected metrics out
            info!("{} {}", avg_flows, total_bytes);
            let now = Instant::now();
            if now >= last_ts + NETHINT_INTERVAL_MS {
                last_ts = now;
                // send the results to the collector
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
