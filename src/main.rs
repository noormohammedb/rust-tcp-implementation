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
    let mut connections: HashMap<Quad, tcp_state::Connection> = Default::default();

    let mut nic = tun_tap::Iface::without_packet_info("tun0", tun_tap::Mode::Tun)?;
    let mut buf = [0u8; 1504];

    loop {
        let nbytes = nic.recv(&mut buf[..])?;
        // let ether_flags = u16::from_be_bytes([buf[0], buf[1]]);
        // let ether_proto = u16::from_be_bytes([buf[2], buf[3]]);

        // if ether_proto != ETHERTYPE_IPV4 {
        //     // only ipv4
        //     continue;
        // }

        let ip_hr_of = 0; // size of prefixe flags
        let ip_hr_sz = 20; // min ip header size

        match etherparse::Ipv4HeaderSlice::from_slice(&buf[ip_hr_of..nbytes]) {
            Ok(iph) => {
                println!("{:?}\n", iph.to_header());

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

                match etherparse::TcpHeaderSlice::from_slice(
                    &buf[ip_hr_of + iph.slice().len()..nbytes],
                ) {
                    Ok(tcph) => {
                        println!("{:?}\n", tcph.to_header());

                        let data_start = ip_hr_of + iph.slice().len() + tcph.slice().len();
                        use std::collections::hash_map::Entry;

                        match connections.entry(Quad {
                            src: (src.into(), tcph.source_port()),
                            dst: (dst.into(), tcph.destination_port()),
                        }) {
                            Entry::Occupied(mut c) => c.get_mut().on_packet(
                                &mut nic,
                                iph,
                                tcph,
                                &buf[data_start..nbytes],
                            )?,
                            Entry::Vacant(mut e) => {
                                if let Some(c) = tcp_state::Connection::accept(
                                    &mut nic,
                                    iph,
                                    tcph,
                                    &buf[data_start..nbytes],
                                )? {
                                    e.insert(c);
                                }
                            }
                        };
                    }
                    Err(e) => eprintln!("tcp header parse error: {:?}", e),
                }
            }
            Err(e) => eprintln!("ignoring a packet {:?}", e),
        }
    }
    Ok(())
}
