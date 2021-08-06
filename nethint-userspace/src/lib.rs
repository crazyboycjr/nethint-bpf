#![feature(command_access)]

pub mod cmd_helper;

use redbpf::Map;
use std::fs;
use std::process::Command;
use tracing::error;

pub struct AutoRemovePinnedMap {
    path: String,
    map: Option<Map>,
}

impl AutoRemovePinnedMap {
    pub fn new(path: &str) -> Self {
        AutoRemovePinnedMap {
            path: path.to_owned(),
            map: None,
        }
    }

    pub fn set_map(&mut self, map: Map) {
        self.map = Some(map);
    }
}

impl AsRef<Map> for AutoRemovePinnedMap {
    fn as_ref(&self) -> &Map {
        self.map.as_ref().unwrap()
    }
}

impl Drop for AutoRemovePinnedMap {
    fn drop(&mut self) {
        if self.map.is_some() {
            fs::remove_file(&self.path).expect("fs::remove_file");
        }
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
