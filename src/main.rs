use std::{collections::HashMap, io, net::Ipv4Addr};
use tun_tap;

const ETHERTYPE_IPV4: u16 = 0x0800;
const TCP_PROTOCOL: u8 = 0x06;

pub mod tcp_state;

#[derive(Debug, Clone, Copy, Hash, PartialEq, Eq)]
struct Quad {
    src: (Ipv4Addr, u16),
    dst: (Ipv4Addr, u16),
}

fn main() -> Result<(), io::Error> {
    let mut connections: HashMap<Quad, tcp_state::State> = Default::default();

    let mut nic = tun_tap::Iface::new("tun0", tun_tap::Mode::Tun)?;
    let mut buf = [0u8; 1504];

    loop {
        let nbytes = nic.recv(&mut buf[..])?;
        let ether_flags = u16::from_be_bytes([buf[0], buf[1]]);
        let ether_proto = u16::from_be_bytes([buf[2], buf[3]]);

        if ether_proto != ETHERTYPE_IPV4 {
            // only ipv4
            continue;
        }
        let ip_hr_of = 4; // size of prefixe flags
        let ip_hr_sz = 20; // min ip header size

        match etherparse::Ipv4HeaderSlice::from_slice(&buf[ip_hr_of..nbytes]) {
            Ok(iph) => {
                println!("{:?}\n", iph.to_header());
                // let ip_buf = &buf[ip_hr_of..nbytes];

                let packet_version = iph.version();
                let src = iph.source();
                let dst = iph.destination();
                let proto = iph.protocol();
                let t_len = iph.total_len();
                let p_len = iph.payload_len();

                if proto != TCP_PROTOCOL {
                    println!("skipping a non tcp packet, proto: {:?}", proto);
                    continue;
                }

                // let src_port = u16::from_be_bytes([ip_buf[20], ip_buf[21]]);
                // let dst_port = u16::from_be_bytes([ip_buf[22], ip_buf[23]]);

                // println!("{:x?}", ip_buf);

                match etherparse::TcpHeaderSlice::from_slice(
                    &buf[ip_hr_of + iph.slice().len()..nbytes],
                ) {
                    Ok(tcph) => {
                        println!("{:?}\n", tcph.to_header());

                        let data_start = ip_hr_of + iph.slice().len() + tcph.slice().len();

                        connections
                            .entry(Quad {
                                src: (src.into(), tcph.source_port()),
                                dst: (dst.into(), tcph.destination_port()),
                            })
                            .or_default()
                            .on_packet(&mut nic, iph, tcph, &buf[data_start..nbytes])?;
                    }
                    Err(e) => eprintln!("tcp header parse error: {:?}", e),
                }

                // eprintln!(
                //     "read {} bytes (flags: {:?}, e_proto: {:?}) v: {:?}, src: {:?}, dst: {:?}, proto: {:?}, t_len: {:?},p_len: {:?}\n\n",
                //     nbytes - 4,
                //     ether_flags, ether_proto, packet_version, src, dst, proto, t_len, p_len
                // );
            }
            Err(e) => eprintln!("ignoring a packet {:?}", e),
        }
    }
    Ok(())
}
