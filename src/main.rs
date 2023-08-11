use std::io;
use tun_tap;

const ETHERTYPE_IPV4: u16 = 0x0800;
const TCP_PROTOCOL: u8 = 0x06;

fn main() -> Result<(), io::Error> {
    let nic = tun_tap::Iface::new("tun0", tun_tap::Mode::Tap)?;
    // let mut buf = [0u8; 1504];
    let mut buf = [0u8; 1522]; // Eth-II/802.3 with 802.1Q tagging (stackoverflow)

    loop {
        let nbytes = nic.recv(&mut buf[..])?;
        let ether_flags = u16::from_be_bytes([buf[0], buf[1]]);
        let ether_proto = u16::from_be_bytes([buf[2], buf[3]]);
        if ether_proto != ETHERTYPE_IPV4 {
            // only ipv4
            continue;
        }
        let ip_header_offset = 18; // size of the ethernet
        let ip_header_size = 20; // min ip header size

        match etherparse::Ipv4HeaderSlice::from_slice(&buf[ip_header_offset..nbytes]) {
            Ok(ip_header) => {
                println!("{:?}\n", ip_header.to_header());
                let ip_buf = &buf[ip_header_offset..nbytes];

                let packet_version = ip_header.version();
                let src = ip_header.source();
                let dst = ip_header.destination();
                let proto = ip_header.protocol();
                let t_len = ip_header.total_len();
                let p_len = ip_header.payload_len();
                if proto != TCP_PROTOCOL {
                    println!("skipping a non tcp packet, proto: {:?}", proto);
                    continue;
                }

                // let src_port = u16::from_be_bytes([ip_buf[20], ip_buf[21]]);
                // let dst_port = u16::from_be_bytes([ip_buf[22], ip_buf[23]]);

                // println!("{:x?}", ip_buf);

                match etherparse::TcpHeaderSlice::from_slice(&ip_buf[ip_header_size..]) {
                    Ok(tcp_header) => {
                        println!("{:?}\n", tcp_header.to_header());

                        eprintln!(
                            "{:?}->{:?} {}b of tcp to port {}",
                            src,
                            dst,
                            tcp_header.slice().len(),
                            tcp_header.destination_port()
                        )
                    }
                    Err(e) => eprintln!("tcp header parse error: {:?}", e),
                }

                // eprintln!(
                //     "read {} bytes (flags: {:x}, e_proto: {:x}) v: {:?}, src: {:?}, dst: {:?}, proto: {:?}, t_len: {:?},p_len: {:?}\n\n",
                //     nbytes - 4,
                //     ether_flags, ether_proto, packet_version, src, dst, proto, t_len, p_len
                // );
            }
            Err(e) => eprintln!("ignoring a packet {:?}", e),
        }
    }
    Ok(())
}
