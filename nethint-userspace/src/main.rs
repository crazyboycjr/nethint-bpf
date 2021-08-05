// This program can be executed by
// # sudo -E cargo run --bin nethint-user [interface]

use std::env;
use std::process;
use tokio::signal::ctrl_c;
use tokio::time::{sleep, Duration, Instant};
use tracing::{error, Level};
use tracing_subscriber::FmtSubscriber;

use redbpf::load::Loader;
use redbpf::xdp;
use redbpf::HashMap;

use probes::nethint::FlowLabel;

const NETHINT_INTERVAL_MS: Duration = Duration::from_millis(100);
const SUB_INTERVAL_MS: Duration = Duration::from_millis(10);

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

    println!("Attaching XDP to interface {}", iface);
    let mut loaded = Loader::load(probe_code()).expect("error loading BPF program");

    // attach XDP
    for xdp in loaded.xdps_mut() {
        xdp.attach_xdp(iface, xdp::Flags::SkbMode)
            .expect("unable to attach XDP");
    }

    // get the alive flows map
    let alive_flows: HashMap<FlowLabel, u64> =
        HashMap::new(loaded.map("alive_flows").unwrap()).unwrap();

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

    println!("Exit nethint-user");
}

fn probe_code() -> &'static [u8] {
    include_bytes!(concat!(
        env!("OUT_DIR"),
        "/target/bpf/programs/nethint/nethint.elf"
    ))
}
