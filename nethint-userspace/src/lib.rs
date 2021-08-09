#![feature(command_access)]

pub mod cmd_helper;

use redbpf::Map;
use std::path::Path;
use std::process::Command;
use tracing::{info, error};

pub struct AutoRemovePinnedMap {
    map: Map,
}

impl AutoRemovePinnedMap {
    pub fn new(path: impl AsRef<Path>) -> Self {
        let map = Map::from_pin_file(path).expect("error on Map::from_pin_file");
        AutoRemovePinnedMap { map }
    }
}

impl AsRef<Map> for AutoRemovePinnedMap {
    fn as_ref(&self) -> &Map {
        &self.map
    }
}

impl Drop for AutoRemovePinnedMap {
    fn drop(&mut self) {
        info!("unpin global BPF map");
        let _ = self.map.unpin();
    }
}

pub struct TcRule {
    add_rule: String,
    del_rule: Option<String>,
    loaded: bool,
}

impl TcRule {
    pub fn new(add: &str, del: Option<&str>) -> Self {
        TcRule {
            add_rule: add.to_owned(),
            del_rule: del.map(|x| x.to_owned()),
            loaded: false,
        }
    }

    pub fn apply(&mut self) -> anyhow::Result<()> {
        let mut tc_cmd = Command::new("tc");
        tc_cmd.args(shell_words::split(&self.add_rule).unwrap());
        cmd_helper::get_command_output(tc_cmd)?;
        self.loaded = true;
        Ok(())
    }
}

impl Drop for TcRule {
    fn drop(&mut self) {
        if self.loaded {
            if let Some(del_rule) = self.del_rule.as_ref() {
                let mut tc_cmd = Command::new("tc");
                tc_cmd.args(shell_words::split(&del_rule).unwrap());
                match cmd_helper::get_command_output(tc_cmd) {
                    Ok(_) => {}
                    Err(e) => error!("Failed to delete tc rule: {}", e),
                }
            }
        }
    }
}
