// This program can be executed by
// # sudo -E cargo run --bin nethint-user [interface]

use std::env;
use std::fs;
use std::process::{self, Command};
use tokio::signal::ctrl_c;
use tokio::time::{sleep, Duration, Instant};
use tracing::{error, info, Level};
use tracing_subscriber::FmtSubscriber;

use redbpf::load::Loader;
use redbpf::xdp;
use redbpf::{HashMap, Map};

use probes::nethint::FlowLabel;

const NETHINT_INTERVAL_MS: Duration = Duration::from_millis(100);
const SUB_INTERVAL_MS: Duration = Duration::from_millis(10);

const TC_ALIVE_FLOWS_MAP: &str = "/sys/fs/bpf/tc/globals/alive_flows";

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

    // remove .BTF.ext and .eh_frame in order to remove .text
    // remove .text section because tc filter does not work if .text exists
    // remove .BTF section because it contains invalid names of BTF types
    // (currently kernel only allows valid symbol names of C)
    for sec in &[".BTF.ext", ".eh_frame", ".text", ".BTF"] {
        if !Command::new("llvm-strip")
            .arg("--strip-unneeded")
            .arg("--remove-section")
            .arg(sec)
            .arg(&bpf_elf)
            .status()
            .expect("error on running command llvm-strip")
            .success()
        {
            error!("error on removing section `{}' using llvm-strip", sec);
            return;
        }
    }

    // tc qdisc replace dev rdma0 clsact
    let new_clsact = Command::new("tc")
        .args(format!("qdisc replace dev {} clsact", iface).split(' '))
        .status()
        .expect("error on tc qdisc replace")
        .success();

    info!(
        "Attaching tc BPF program to `{}' interface as direct action",
        iface
    );
    // tc filter add dev rdma0 ingress bpf da obj ./tc-example.o sec ingress
    Command::new("tc")
        .args(format!("filter add dev {} ingress bpf direct-action object-file {} section tc_action/nethint_count_flows", iface, bpf_elf).split(' '))
        .status()
        .expect("error on tc filter add");

    // Load map from pinned file that is just created by tc
    let map = Map::from_pin_file(TC_ALIVE_FLOWS_MAP).expect("error on Map::from_pin_file");
    let alive_flows = HashMap::<FlowLabel, u64>::new(&map).expect("error on HashMap::new");

    // println!("Attaching XDP to interface {}", iface);
    // let mut loaded = Loader::load(probe_code()).expect("error loading BPF program");

    // // attach XDP
    // for xdp in loaded.xdps_mut() {
    //     xdp.attach_xdp(iface, xdp::Flags::SkbMode)
    //         .expect("unable to attach XDP");
    // }

    // // get the alive flows map
    // let alive_flows: HashMap<FlowLabel, u64> =
    //     HashMap::new(loaded.map("alive_flows").unwrap()).unwrap();

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
            println!("{} {}", avg_flows, total_bytes);
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

    println!("Hit Ctrl-C to quit");
    tokio::select! {
        _ = event_fut => {

        }
        _ = ctrlc_fut => {
            println!("Ctrl-C received");
        }
    }

    if new_clsact {
        let _ = Command::new("tc")
            .args(format!("qdisc del dev {} clsact", iface).split(' '))
            .status();
    } else {
        let _ = Command::new("tc")
            .args(format!("filter del dev {} ingress bpf direct-action", iface).split(' '))
            .arg("object-file")
            .arg(bpf_elf)
            .args("section tc_action/nethint_count_flows".split(' '))
            .status();
    }

    fs::remove_file(TC_ALIVE_FLOWS_MAP).expect("fs::remove_file");

    println!("Exit nethint-user");
}

const fn probe_path() -> &'static str {
    concat!(
        env!("OUT_DIR"),
        "/target/bpf/programs/nethint/nethint.elf"
    )
}

fn probe_code() -> &'static [u8] {
    include_bytes!(concat!(
        env!("OUT_DIR"),
        "/target/bpf/programs/nethint/nethint.elf"
    ))
}
