use std::io;
use tun_tap;

fn main() -> Result<(), io::Error> {
    let nic = tun_tap::Iface::new("tun0", tun_tap::Mode::Tap)?;
    let mut buf = [0u8; 1504];
    loop {
        let nbytes = nic.recv(&mut buf[..])?;
        let flags = u16::from_be_bytes([buf[0], buf[1]]);
        let proto = u16::from_be_bytes([buf[2], buf[3]]);
        if proto != 0x800 {
            // only ipv4
            continue;
        }
        eprintln!(
            "read {} bytes (flags: {:x}, proto: {:x}) {:?}",
            nbytes - 4,
            flags,
            proto,
            &buf[4..nbytes]
        );
    }
    Ok(())
}
