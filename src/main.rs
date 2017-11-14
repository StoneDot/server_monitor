//
// Project Name: server_monitor
// File Name: main.rs
// Last modified: 2017/11/12
// Author: Hiroaki Goto
//
// Copyright (c) 2017 Hiroaki Goto. All rights reserved.
//

extern crate serde;
extern crate serde_json;
#[macro_use]
extern crate serde_derive;
extern crate regex;
extern crate procinfo;
extern crate libc;
extern crate itertools;
extern crate fnv;

use std::time::SystemTime;
use std::time::UNIX_EPOCH;
use std::ops;
use std::path::{Path, PathBuf};
use std::thread;
use std::time::Duration;
use regex::Regex;
use procinfo::pid::Stat;
use fnv::FnvHashMap;

#[derive(Debug, Copy, Clone, Serialize, Deserialize)]
struct DiffStat {
    utime: libc::clock_t,
    stime: libc::clock_t,
    cutime: libc::clock_t,
    cstime: libc::clock_t,
    minflt: usize,
    cminflt: usize,
    majflt: usize,
    cmajflt: usize,
}

impl DiffStat {
    fn new() -> DiffStat {
        DiffStat {
            utime: 0,
            stime: 0,
            cutime: 0,
            cstime: 0,
            minflt: 0,
            cminflt: 0,
            majflt: 0,
            cmajflt: 0
        }
    }
    fn new_from(stat: &Stat) -> DiffStat {
        DiffStat {
            utime: stat.utime,
            stime: stat.stime,
            cutime: stat.cutime,
            cstime: stat.cstime,
            minflt: stat.minflt,
            cminflt: stat.cminflt,
            majflt: stat.majflt,
            cmajflt: stat.cmajflt
        }
    }
}

struct ProcessDiffStat {
    pid: libc::pid_t,
    stat: DiffStat,
}

impl ProcessDiffStat {
    fn new_from(stat: &Stat) -> ProcessDiffStat {
        ProcessDiffStat {
            pid: stat.pid,
            stat: DiffStat::new_from(stat),
        }
    }
}

impl ops::Add for DiffStat {
    type Output = DiffStat;
    fn add(self, other: DiffStat) -> DiffStat {
        DiffStat {
            utime: self.utime + other.utime,
            stime: self.stime + other.stime,
            cutime: self.cutime + other.cutime,
            cstime: self.cstime + other.cstime,
            minflt: self.minflt + other.minflt,
            cminflt: self.cminflt + other.cminflt,
            majflt: self.majflt + other.majflt,
            cmajflt: self.cmajflt + other.cmajflt
        }
    }
}

impl<'a> ops::Add<&'a Stat> for DiffStat {
    type Output = DiffStat;
    fn add(self, other: &'a Stat) -> DiffStat {
        DiffStat {
            utime: self.utime + other.utime,
            stime: self.stime + other.stime,
            cutime: self.cutime + other.cutime,
            cstime: self.cstime + other.cstime,
            minflt: self.minflt + other.minflt,
            cminflt: self.cminflt + other.cminflt,
            majflt: self.majflt + other.majflt,
            cmajflt: self.cmajflt + other.cmajflt
        }
    }
}

impl ops::Sub for DiffStat {
    type Output = DiffStat;
    fn sub(self, other: DiffStat) -> DiffStat {
        DiffStat {
            utime: self.utime - other.utime,
            stime: self.stime - other.stime,
            cutime: self.cutime - other.cutime,
            cstime: self.cstime - other.cstime,
            minflt: self.minflt - other.minflt,
            cminflt: self.cminflt - other.cminflt,
            majflt: self.majflt - other.majflt,
            cmajflt: self.cmajflt - other.cmajflt
        }
    }
}

impl ops::Sub<Stat> for DiffStat {
    type Output = DiffStat;
    fn sub(self, other: Stat) -> DiffStat {
        DiffStat {
            utime: self.utime - other.utime,
            stime: self.stime - other.stime,
            cutime: self.cutime - other.cutime,
            cstime: self.cstime - other.cstime,
            minflt: self.minflt - other.minflt,
            cminflt: self.cminflt - other.cminflt,
            majflt: self.majflt - other.majflt,
            cmajflt: self.cmajflt - other.cmajflt
        }
    }
}

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

fn retrieve_process_stats(target_process_names: &[&str]) -> FnvHashMap<String, Vec<Stat>> {
    let escaped = target_process_names.iter().map(|s| regex::escape(s));
    let pattern = format!(r"^(?:{})$", itertools::join(escaped, "|"));
    let re = Regex::new(&pattern).unwrap();
    let dev_path = Path::new("/proc");
    let mut stats: FnvHashMap<String, Vec<Stat>> =
        FnvHashMap::with_capacity_and_hasher(target_process_names.len(), Default::default());
    for entry in dev_path.read_dir()
        .expect("Could not read /proc as directory") {
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

fn calc_total_diff_using_sort(stats: &[Stat], old_stats: &[Stat]) -> DiffStat {
    let mut stats: Vec<_> = stats.iter().map(
        |x| ProcessDiffStat::new_from(x)).collect();
    stats.sort_unstable_by_key(|x| x.pid);
    let mut old_stats: Vec<_> = old_stats.iter().map(
        |x| ProcessDiffStat::new_from(x)).collect();
    old_stats.sort_unstable_by_key(|x| x.pid);
    let mut idx_s = 0;
    let mut idx_o = 0;
    let mut stats_sum = DiffStat::new();
    let mut old_stats_sum = DiffStat::new();
    while idx_s < stats.len() && idx_o < old_stats.len() {
        if stats[idx_s].pid == old_stats[idx_o].pid {
            stats_sum = stats_sum + stats[idx_s].stat;
            old_stats_sum = old_stats_sum + old_stats[idx_o].stat;
            idx_s += 1;
            idx_o += 1
        } else if stats[idx_s].pid < old_stats[idx_o].pid {
            idx_s += 1
        } else {
            idx_o += 1
        }
    }
    stats_sum - old_stats_sum
}

fn main() {
    let cur_time = SystemTime::now();
    let elapsed = cur_time.duration_since(UNIX_EPOCH)
        .expect("Check system time. Something wrong.").as_secs();

    let process_targets = ["nginx", "http", "fish", "tmux: server", "server_monitor"];
    let old_stats = retrieve_process_stats(&process_targets);
    thread::sleep(Duration::from_secs(3));
    let stats = retrieve_process_stats(&process_targets);

    let mut diff_record: FnvHashMap<String, DiffStat> =
        FnvHashMap::with_capacity_and_hasher(process_targets.len(), Default::default());
    for (key, stats) in stats.iter() {
        if let Some(old_stats) = old_stats.get(key) {
            let diff = calc_total_diff_using_sort(stats, old_stats);
            diff_record.insert(key.clone(), diff);
        }
    }
    let j = serde_json::to_string(&diff_record).unwrap();
    println!("{}", j);
}