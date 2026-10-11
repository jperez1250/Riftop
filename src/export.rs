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
        assert_eq!(OutputFormat::parse("unknown"), OutputFormat::Tui);
    }

    #[test]
    fn test_json_escape_edge_cases() {
        assert_eq!(json_escape("hello"), "hello");
        assert_eq!(json_escape("quote\"slash\\"), "quote\\\"slash\\\\");
        assert_eq!(
            json_escape("line\nfeed\rreturn\ttab"),
            "line\\nfeed\\rreturn\\ttab"
        );
        // Control character 0x01
        assert_eq!(json_escape("\x01"), "\\u0001");
        assert_eq!(json_escape("\x1f"), "\\u001f");
    }

    #[test]
    fn test_write_json_empty_and_populated() {
        let now = Instant::now();
        let mut table = FlowTable::new();

        // Empty table JSON export
        let mut buf = Vec::new();
        write_json(&mut buf, &table, now, 10, "eth0\"escaped", SortBy::Rate10s).unwrap();
        let json_str = String::from_utf8(buf).unwrap();
        assert!(json_str.contains("\"interface\":\"eth0\\\"escaped\""));
        assert!(json_str.contains("\"flow_count\":0"));
        assert!(json_str.contains("\"flows\":[]"));

        // Add a flow to the table with show_ports enabled
        table.set_show_ports(true);
        let src: IpAddr = "10.0.0.1".parse().unwrap();
        let dst: IpAddr = "10.0.0.2".parse().unwrap();
        table.record(src, dst, 80, 443, 6, 500, &[], now, None);

        let mut buf_populated = Vec::new();
        write_json(&mut buf_populated, &table, now, 10, "eth0", SortBy::Rate10s).unwrap();
        let json_str_pop = String::from_utf8(buf_populated).unwrap();
        assert!(json_str_pop.contains("\"flow_count\":1"));
        assert!(json_str_pop.contains("\"src\":\"10.0.0.1\""));
        assert!(json_str_pop.contains("\"dst\":\"10.0.0.2\""));
        assert!(json_str_pop.contains("\"sport\":80"));
        assert!(json_str_pop.contains("\"dport\":443"));
    }

    #[test]
    fn test_write_text_bytes_and_bits() {
        let now = Instant::now();
        let mut table = FlowTable::new();
        let src: IpAddr = "10.0.0.1".parse().unwrap();
        let dst: IpAddr = "10.0.0.2".parse().unwrap();
        table.record(src, dst, 80, 443, 6, 1024, &[], now, None);

        let mut buf_bytes = Vec::new();
        write_text(&mut buf_bytes, &table, now, 10, SortBy::Total, true).unwrap();
        let text_bytes = String::from_utf8(buf_bytes).unwrap();
        assert!(text_bytes.contains("# packets_seen=1"));
        assert!(text_bytes.contains("10.0.0.1\t10.0.0.2"));

        let mut buf_bits = Vec::new();
        write_text(&mut buf_bits, &table, now, 10, SortBy::Total, false).unwrap();
        let text_bits = String::from_utf8(buf_bits).unwrap();
        assert!(text_bits.contains("10.0.0.1\t10.0.0.2"));
    }

    #[test]
    fn test_write_csv_formatting() {
        let now = Instant::now();
        let mut table = FlowTable::new();
        table.set_show_ports(true);
        let src: IpAddr = "192.168.1.50".parse().unwrap();
        let dst: IpAddr = "1.1.1.1".parse().unwrap();
        table.record(src, dst, 12345, 53, 17, 200, &[], now, None);

        let mut buf_csv = Vec::new();
        write_csv(&mut buf_csv, &table, now, 10, SortBy::Rate2s, true).unwrap();
        let csv_str = String::from_utf8(buf_csv).unwrap();
        assert!(csv_str.starts_with("src,dst,sport,dport,proto,sent,recv,total,rate_2s_bytes_sec"));
        assert!(csv_str.contains("1.1.1.1,192.168.1.50,53,12345,17"));

        let mut buf_csv_bits = Vec::new();
        write_csv(&mut buf_csv_bits, &table, now, 10, SortBy::Rate2s, false).unwrap();
        let csv_bits_str = String::from_utf8(buf_csv_bits).unwrap();
        assert!(
            csv_bits_str.starts_with("src,dst,sport,dport,proto,sent,recv,total,rate_2s_bits_sec")
        );
    }
}
