//
// Project Name: server_monitor
// File Name: main.rs
// Last modified: 2017/11/12
// Author: Hiroaki Goto
//
// Copyright (c) 2017 Hiroaki Goto. All rights reserved.
//

#[macro_use]
extern crate serde_json;
extern crate regex;
extern crate procinfo;
extern crate libc;
extern crate itertools;
use std::collections::HashMap;
use std::time::SystemTime;
use std::time::UNIX_EPOCH;
use std::path::{Path, PathBuf};
use regex::Regex;
use procinfo::pid::Stat;

fn retrieve_process_stat(path: &PathBuf) -> Option<Stat> {
    let pid = str::parse::<libc::pid_t>(
        path.file_name().unwrap().to_str().unwrap());
    if let Ok(pid) = pid {
        let stat = procinfo::pid::stat(pid);
        if let Ok(stat) = stat {
            return Some(stat);
        }
    }
    return None;
}

fn retrieve_process_stats(target_process_names: &[&str]) -> HashMap<String, Vec<Stat>> {
    let escaped = target_process_names.iter().map(|s| regex::escape(s));
    let pattern = format!(r"^(?:{})$",  itertools::join(escaped, "|"));
    let re = Regex::new(&pattern).unwrap();
    let dev_path = Path::new("/proc");
    let mut stats: HashMap<String, Vec<Stat>> = HashMap::new();
    for entry in dev_path.read_dir()
        .expect("Cannot read /dev as directory") {
        if let Ok(entry) = entry {
            if let Some(stat) = retrieve_process_stat(&entry.path()) {
                if !re.is_match(&stat.command) { continue; }
                if !stats.contains_key(&stat.command) {
                    let command = stat.command.clone();
                    stats.insert(command, vec![]);
                }
                let vec = stats.get_mut(&stat.command).unwrap();
                vec.push(stat);
            }
        }
    }
    stats
}

fn main() {
    let cur_time = SystemTime::now();
    let elapsed = cur_time.duration_since(UNIX_EPOCH)
        .expect("Check system time. Something wrong.").as_secs();
    let john = json!([
        "bq.system_info",
        elapsed,
        {
            "name": "John Doe",
            "age": 43,
            "phones": [
                "+44 1234567",
                "+44 2345678"
            ]
        }
    ]);

    let process_targets = ["nginx", "http", "fish"];
    let stats = retrieve_process_stats(&process_targets);
    println!("{:#?}", stats);

    println!("first phone number: {}", john[2]["phones"][0]);
    println!("{}", john.to_string());
}