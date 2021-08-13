use std::env;
use std::path::{Path, PathBuf};
use std::process::Command;

use cargo_bpf_lib as cargo_bpf;

fn main() {
    let cargo = PathBuf::from(env::var("CARGO").unwrap());
    let target = PathBuf::from(env::var("OUT_DIR").unwrap());
    let probes = Path::new("../nethint-probes");

    cargo_bpf::build(&cargo, &probes, &target.join("target"), Vec::new())
        .expect("couldn't compile probes");

    strip_bpf_elf(target.join("target/bpf/programs/nethint/nethint.elf"));

    cargo_bpf::probe_files(&probes)
        .expect("couldn't list probe files")
        .iter()
        .for_each(|file| {
            println!("cargo:rerun-if-changed={}", file);
        });
    println!("cargo:rerun-if-changed=../nethint-probes/Cargo.toml");
}

pub fn strip_bpf_elf<P: AsRef<Path>>(path: P) {
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
            panic!("error on removing section `{}' using llvm-strip", sec);
        }
    }
}
