use std::collections::HashMap;
use std::io;
use std::net::Ipv4Addr;

mod tcp;
#[derive(Clone, Copy, Debug, Hash, Eq, PartialEq)]
struct Connection {
    src: (Ipv4Addr, u16),
    dst: (Ipv4Addr, u16),
}

fn main() -> io::Result<()> {
    let mut connections: HashMap<Connection, tcp::State> = Default::default();
    let iface =
        tun_tap::Iface::new("tun0", tun_tap::Mode::Tun).expect("Failed to create a TUN device");
    let mut buf = vec![0u8; 1504];
    loop {
        let nbytes = iface.recv(&mut buf[..])?;
        let _eth_flags = u16::from_be_bytes([buf[0], buf[1]]);
        let eth_proto = u16::from_be_bytes([buf[2], buf[3]]);
        if eth_proto != 0x0800 {
            // not ipv4
            continue;
        }
        match etherparse::Ipv4HeaderSlice::from_slice(&buf[4..nbytes]) {
            Ok(iph) => {
                let ip_hdr_size = iph.slice().len();
                let ip_proto = tcp::ip_number_from_u8(iph.protocol());
                if ip_proto != etherparse::IpNumber::Tcp {
                    // not tcp
                    continue;
                }
                let ip_src = iph.source_addr();
                let ip_dst = iph.destination_addr();
                match etherparse::TcpHeaderSlice::from_slice(&buf[4 + ip_hdr_size..]) {
                    Ok(tcph) => {
                        let tcp_hdr_size = tcph.slice().len();
                        let data_idx = 4 + ip_hdr_size + tcp_hdr_size;
                        let src_port = tcph.source_port();
                        let dst_port = tcph.destination_port();
                        connections
                            .entry(Connection {
                                src: (ip_src, src_port),
                                dst: (ip_dst, dst_port),
                            })
                            .or_default()
                            .on_packet(iph, tcph, &buf[data_idx..nbytes]);
                    }
                    Err(e) => {
                        eprintln!("failed parsing TCP Header: ignoring packet - {}", e);
                    }
                }
            }
            Err(e) => {
                eprintln!("failed parsing IPv4 Header: ignoring packet - {}", e);
            }
        }
    }
}
