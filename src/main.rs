use std::io;
use tun_tap;

const ETHERTYPE_IPV4: u16 = 0x0800;

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

        match etherparse::Ipv4HeaderSlice::from_slice(&buf[ip_header_offset..nbytes]) {
            Ok(packet) => {
                let packet_version = packet.version();
                let src = packet.source();
                let dst = packet.destination();
                let proto = packet.protocol();
                let t_len = packet.total_len();
                let pay_len = packet.payload_len();
                eprintln!(
                    "read {} bytes (flags: {:x}, e_proto: {:x}) v: {:?}, src: {:?}, dst: {:?}, proto: {:?}, t_len: {:?},p_len: {:?}",
                    nbytes - 4,
                    ether_flags, ether_proto, packet_version, src, dst,proto,t_len,pay_len
                );
            }
            Err(e) => eprintln!("ignoring a packet {:?}", e),
        }
    }
    Ok(())
}
