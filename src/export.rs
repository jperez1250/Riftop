//! JSON/text/CSV export of flow snapshots.

use std::io::{self, Write};
use std::time::Instant;

use crate::flow::{format_bytes, format_rate_units, FlowTable, SortBy};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OutputFormat {
    Tui,
    Json,
    Text,
    Csv,
}

impl OutputFormat {
    pub fn parse(s: &str) -> Self {
        match s.to_ascii_lowercase().as_str() {
            "json" => Self::Json,
            "text" | "plain" => Self::Text,
            "csv" => Self::Csv,
            _ => Self::Tui,
        }
    }
}

pub fn json_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if c.is_control() => {
                out.push_str(&format!("\\u{:04x}", c as u32));
            }
            c => out.push(c),
        }
    }
    out
}

pub fn write_json(
    out: &mut dyn Write,
    table: &FlowTable,
    now: Instant,
    limit: usize,
    interface: &str,
    sort_mode: SortBy,
) -> io::Result<()> {
    let g = table.globals();
    let top = table.top_sorted(limit, now, sort_mode);
    let iface = json_escape(interface);
    write!(out, "{{\"interface\":\"{iface}\",")?;
    write!(out, "\"packets_seen\":{},", g.packets_seen)?;
    write!(out, "\"packets_accepted\":{},", g.packets_accepted)?;
    write!(out, "\"bytes_total\":{},", g.bytes_total)?;
    write!(out, "\"bytes_sent\":{},", g.bytes_sent)?;
    write!(out, "\"bytes_recv\":{},", g.bytes_recv)?;
    write!(out, "\"flow_count\":{},", table.len())?;
    write!(out, "\"flows\":[")?;
    for (i, s) in top.iter().enumerate() {
        if i > 0 {
            write!(out, ",")?;
        }
        write!(
            out,
            "{{\"src\":\"{}\",\"dst\":\"{}\",\"sport\":{},\"dport\":{},\"proto\":{},\"sent\":{},\"recv\":{},\"total\":{},\"rate_2s\":{:.3},\"rate_10s\":{:.3},\"rate_40s\":{:.3}}}",
            json_escape(&s.key.a.to_string()),
            json_escape(&s.key.b.to_string()),
            s.key.port_a,
            s.key.port_b,
            s.key.protocol,
            s.sent_bytes,
            s.recv_bytes,
            s.total_bytes,
            s.rate_2s(now),
            s.rate_10s(now),
            s.rate_40s(now)
        )?;
    }
    writeln!(out, "]}}")?;
    Ok(())
}

pub fn write_text(
    out: &mut dyn Write,
    table: &FlowTable,
    now: Instant,
    limit: usize,
    sort_mode: SortBy,
    use_bytes: bool,
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
    for s in table.top_sorted(limit, now, sort_mode) {
        writeln!(
            out,
            "{}\t{}\t{}\t{}\t{}\t{}",
            s.key.a,
            s.key.b,
            format_rate_units(s.rate_2s(now), use_bytes),
            format_rate_units(s.rate_10s(now), use_bytes),
            format_rate_units(s.rate_40s(now), use_bytes),
            format_bytes(s.total_bytes)
        )?;
    }
    Ok(())
}

pub fn write_csv(
    out: &mut dyn Write,
    table: &FlowTable,
    now: Instant,
    limit: usize,
    sort_mode: SortBy,
    use_bytes: bool,
) -> io::Result<()> {
    let rate_unit_str = if use_bytes { "bytes_sec" } else { "bits_sec" };
    writeln!(out, "src,dst,sport,dport,proto,sent,recv,total,rate_2s_{rate_unit_str},rate_10s_{rate_unit_str},rate_40s_{rate_unit_str}")?;
    for s in table.top_sorted(limit, now, sort_mode) {
        let mult = if use_bytes { 1.0 } else { 8.0 };
        writeln!(
            out,
            "{},{},{},{},{},{},{},{},{:.3},{:.3},{:.3}",
            s.key.a,
            s.key.b,
            s.key.port_a,
            s.key.port_b,
            s.key.protocol,
            s.sent_bytes,
            s.recv_bytes,
            s.total_bytes,
            s.rate_2s(now) * mult,
            s.rate_10s(now) * mult,
            s.rate_40s(now) * mult
        )?;
    }
    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    #[test]
    fn test_output_format_parse() {
        assert_eq!(OutputFormat::parse("json"), OutputFormat::Json);
        assert_eq!(OutputFormat::parse("JSON"), OutputFormat::Json);
        assert_eq!(OutputFormat::parse("text"), OutputFormat::Text);
        assert_eq!(OutputFormat::parse("plain"), OutputFormat::Text);
        assert_eq!(OutputFormat::parse("csv"), OutputFormat::Csv);
        assert_eq!(OutputFormat::parse("unknown"), OutputFormat::Tui);
    }

    #[test]
    fn test_json_escape() {
        assert_eq!(json_escape("hello"), "hello");
        assert_eq!(json_escape("a\"b\\c\n\r\t"), "a\\\"b\\\\c\\n\\r\\t");
        assert_eq!(json_escape("\x07"), "\\u0007");
    }

    #[test]
    fn test_write_json_text_csv() {
        let now = Instant::now();
        let mut table = FlowTable::new();
        table.set_show_ports(true);
        let src = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 10));
        let dst = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        table.record(src, dst, 12345, 80, 6, 500, &[src], now, None);

        // JSON
        let mut json_buf = Vec::new();
        write_json(&mut json_buf, &table, now, 10, "eth0", SortBy::Total).expect("write_json");
        let json_str = String::from_utf8(json_buf).expect("utf8");
        assert!(json_str.contains("\"interface\":\"eth0\""));
        assert!(json_str.contains("\"packets_seen\":1"));
        assert!(json_str.contains("\"flows\":["));

        // Text
        let mut text_buf = Vec::new();
        write_text(&mut text_buf, &table, now, 10, SortBy::Total, true).expect("write_text");
        let text_str = String::from_utf8(text_buf).expect("utf8");
        assert!(text_str.contains("# packets_seen=1"));
        assert!(text_str.contains("192.168.1.10"));

        // CSV
        let mut csv_buf = Vec::new();
        write_csv(&mut csv_buf, &table, now, 10, SortBy::Total, false).expect("write_csv");
        let csv_str = String::from_utf8(csv_buf).expect("utf8");
        assert!(csv_str.contains("src,dst,sport,dport,proto,sent,recv,total,rate_2s_bits_sec"));
        assert!(
            csv_str.contains("10.0.0.1")
                && csv_str.contains("192.168.1.10")
                && csv_str.contains("500")
        );
    }
}
