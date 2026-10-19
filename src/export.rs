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
    use std::net::IpAddr;

    #[test]
    fn test_output_format_parse() {
        assert_eq!(OutputFormat::parse("json"), OutputFormat::Json);
        assert_eq!(OutputFormat::parse("JSON"), OutputFormat::Json);
        assert_eq!(OutputFormat::parse("text"), OutputFormat::Text);
        assert_eq!(OutputFormat::parse("plain"), OutputFormat::Text);
        assert_eq!(OutputFormat::parse("csv"), OutputFormat::Csv);
        assert_eq!(OutputFormat::parse("CSV"), OutputFormat::Csv);
        assert_eq!(OutputFormat::parse("tui"), OutputFormat::Tui);
        assert_eq!(OutputFormat::parse("anything_else"), OutputFormat::Tui);
    }

    #[test]
    fn test_json_escape() {
        assert_eq!(json_escape("hello"), "hello");
        assert_eq!(json_escape("hello \"world\""), "hello \\\"world\\\"");
        assert_eq!(
            json_escape("line1\nline2\r\ttab\\slash"),
            "line1\\nline2\\r\\ttab\\\\slash"
        );
        assert_eq!(json_escape("\x01\x1f"), "\\u0001\\u001f");
    }

    #[test]
    fn test_write_json_empty_and_with_data() {
        let now = Instant::now();
        let mut table = FlowTable::new();
        table.set_show_ports(true);

        let mut buf = Vec::new();
        write_json(&mut buf, &table, now, 10, "eth0 \"test\"", SortBy::Rate2s).unwrap();
        let json_str = String::from_utf8(buf).unwrap();
        assert!(json_str.contains("\"interface\":\"eth0 \\\"test\\\"\""));
        assert!(json_str.contains("\"packets_seen\":0"));
        assert!(json_str.contains("\"flows\":[]"));

        let ip_a: IpAddr = "10.0.0.1".parse().unwrap();
        let ip_b: IpAddr = "192.168.1.1".parse().unwrap();
        table.record(ip_a, ip_b, 80, 443, 6, 1000, &[ip_a], now, None);

        let mut buf2 = Vec::new();
        write_json(&mut buf2, &table, now, 10, "eth0", SortBy::Rate2s).unwrap();
        let json_str2 = String::from_utf8(buf2).unwrap();
        assert!(json_str2.contains("\"packets_seen\":1"));
        assert!(json_str2.contains("\"flow_count\":1"));
        assert!(json_str2.contains("\"src\":\"10.0.0.1\""));
        assert!(json_str2.contains("\"dst\":\"192.168.1.1\""));
        assert!(json_str2.contains("\"sport\":80"));
        assert!(json_str2.contains("\"dport\":443"));
    }

    #[test]
    fn test_write_text_format() {
        let now = Instant::now();
        let mut table = FlowTable::new();
        let ip_a: IpAddr = "10.0.0.1".parse().unwrap();
        let ip_b: IpAddr = "192.168.1.1".parse().unwrap();
        table.record(ip_a, ip_b, 80, 443, 6, 500, &[ip_a], now, None);

        let mut buf = Vec::new();
        write_text(&mut buf, &table, now, 5, SortBy::Rate2s, true).unwrap();
        let text_out = String::from_utf8(buf).unwrap();
        assert!(text_out.contains("# packets_seen=1 accepted=1"));
        assert!(text_out.contains("10.0.0.1\t192.168.1.1"));

        let mut buf_bits = Vec::new();
        write_text(&mut buf_bits, &table, now, 5, SortBy::Rate2s, false).unwrap();
        let text_bits_out = String::from_utf8(buf_bits).unwrap();
        assert!(text_bits_out.contains("# packets_seen=1"));
    }

    #[test]
    fn test_write_csv_format() {
        let now = Instant::now();
        let mut table = FlowTable::new();
        let ip_a: IpAddr = "10.0.0.1".parse().unwrap();
        let ip_b: IpAddr = "192.168.1.1".parse().unwrap();
        table.record(ip_a, ip_b, 80, 443, 6, 500, &[ip_a], now, None);

        let mut buf = Vec::new();
        write_csv(&mut buf, &table, now, 5, SortBy::Rate2s, true).unwrap();
        let csv_out = String::from_utf8(buf).unwrap();
        assert!(csv_out.contains("rate_2s_bytes_sec"));
        assert!(csv_out.contains("10.0.0.1,192.168.1.1,0,0,0,500,0,500"));

        let mut buf_bits = Vec::new();
        write_csv(&mut buf_bits, &table, now, 5, SortBy::Rate2s, false).unwrap();
        let csv_bits_out = String::from_utf8(buf_bits).unwrap();
        assert!(csv_bits_out.contains("rate_2s_bits_sec"));
    }
}
