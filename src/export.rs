//! JSON/CSV export of flow snapshots.

use std::io::{self, Write};
use std::net::IpAddr;
use std::time::Instant;

use crate::flow::{format_bytes, format_rate, FlowStats, FlowTable, Globals};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OutputFormat {
    Tui,
    Json,
    Text,
}

impl OutputFormat {
    pub fn parse(s: &str) -> Option<Self> {
        match s.to_ascii_lowercase().as_str() {
            "tui" | "ui" => Some(Self::Tui),
            "json" => Some(Self::Json),
            "text" | "plain" => Some(Self::Text),
            _ => None,
        }
    }
}

pub fn write_json(
    out: &mut dyn Write,
    table: &FlowTable,
    now: Instant,
    limit: usize,
    interface: &str,
) -> io::Result<()> {
    let g = table.globals();
    let top = table.top(limit, now);
    writeln!(out, "{{")?;
    writeln!(out, "  \"interface\": \"{}\",", escape_json(interface))?;
    writeln!(out, "  \"packets_seen\": {},", g.packets_seen)?;
    writeln!(out, "  \"packets_accepted\": {},", g.packets_accepted)?;
    writeln!(out, "  \"bytes_total\": {},", g.bytes_total)?;
    writeln!(out, "  \"flow_count\": {},", table.len())?;
    writeln!(out, "  \"flows\": [")?;
    for (i, s) in top.iter().enumerate() {
        let comma = if i + 1 < top.len() { "," } else { "" };
        writeln!(
            out,
            "    {{}\"src\": \"{}\", \"dst\": \"{}\", \"sport\": {}, \"dport\": {}, \"proto\": {}, \"sent\": {}, \"recv\": {}, \"total\": {}, \"rate_2s\": {:.3}, \"rate_10s\": {:.3}, \"rate_40s\": {:.3}{}}{}",
            s.key.a,
            s.key.b,
            s.key.port_a,
            s.key.port_b,
            s.key.protocol,
            s.sent_bytes,
            s.recv_bytes,
            s.total_bytes,
            s.rate_2s(now),
            s.rate_10s(now),
            s.rate_40s(now),
            comma
        )?;
    }
    writeln!(out, "  ]")?;
    writeln!(out, "}}")?;
    Ok(())
}

pub fn write_text(
    out: &mut dyn Write,
    table: &FlowTable,
    now: Instant,
    limit: usize,
) -> io::Result<()> {
    let g = table.globals();
    writeln!(
        out,
        "# packets_seen={} accepted={} bytes={} flows={}",
        g.packets_seen,
        g.packets_accepted,
        format_bytes(g.bytes_total),
        table.len()
    )?;
    writeln!(out, "# SRC\tDST\t2s\t10s\t40s\tTOTAL")?;
    for s in table.top(limit, now) {
        writeln!(
            out,
            "{}\t{}\t{}\t{}\t{}\t{}",
            s.key.a,
            s.key.b,
            format_rate(s.rate_2s(now)),
            format_rate(s.rate_10s(now)),
            format_rate(s.rate_40s(now)),
            format_bytes(s.total_bytes)
        )?;
    }
    Ok(())
}

fn escape_json(s: &str) -> String {
    s.replace('\\', "\\\\").replace('"', "\\\"")
}

#[allow(dead_code)]
pub fn flow_row_json(s: &FlowStats, now: Instant) -> String {
    format!(
        "{{\"src\":\"{}\",\"dst\":\"{}\",\"total\":{},\"rate_10s\":{:.3}}}",
        s.key.a,
        s.key.b,
        s.total_bytes,
        s.rate_10s(now)
    )
}

#[allow(dead_code)]
pub fn ip_str(a: IpAddr) -> String {
    a.to_string()
}
