use std::{collections::HashMap, time::Instant};

use packet_storm::{IpPacket, Protocol};

fn main() -> anyhow::Result<()> {
    let path = std::env::args_os().nth(1).unwrap_or("packet-storm.pcap".into());

    let data = fs_err::read(path)?;

    let start = Instant::now();

    let mut no_packets = 0_usize;
    let mut total_transport_level_data = 0;
    let mut dest_ips = HashMap::new();
    let mut udp = 0_usize;

    let pcap = packet_storm::Capture::new(&data)?;

    for record in pcap.records() {
        let IpPacket {
            data,
            protocol,
            source: _,
            dest,
        } = record.ip()?;
        total_transport_level_data += data.len();
        if matches!(protocol, Protocol::UDP) {
            udp += 1;
        }
        *dest_ips.entry(dest).or_insert(0_usize) += 1;
        no_packets += 1;
    }

    let taken = start.elapsed();
    println!("Took {taken:?}");

    println!("Total IP-level data: {} bytes", total_transport_level_data);
    println!("{} UDP, {} TCP", udp, no_packets - udp);
    println!(
        "Average of {:.2} bytes/packet",
        (total_transport_level_data as f64) / (no_packets as f64)
    );
    let mut ips = dest_ips.into_iter().collect::<Vec<_>>();
    ips.sort_by_key(|(_, n)| std::cmp::Reverse(*n));
    let (most_popular, taken) = ips
        .iter()
        .scan((None, 0), |(prev, count), it| {
            // Selects the first three most popular tiers of destinations, i.e. all 16 counts,
            // all 15s, all 14s.
            if let Some(prev) = prev {
                if *prev != it.1 {
                    *count += 1;
                    *prev = it.1;
                }
                if *count >= 3 {
                    None
                } else {
                    Some(it)
                }
            } else {
                *prev = Some(it.1);
                Some(it)
            }
        })
        .fold((String::new(), 0_usize), |(mut acc, taken), (ip, n)| {
            use std::fmt::Write as _;
            let _ = writeln!(acc, "{ip:15} - {n}");
            (acc, taken + 1)
        });
    println!(
        "Destination IPs by frequency:\n{most_popular}...and {} more entries",
        ips.len() - taken
    );

    Ok(())
}
