use std::io;
use tun_tap;

fn main() -> Result<(), io::Error> {
    let nic = tun_tap::Iface::new("tun0", tun_tap::Mode::Tap)?;
    let mut buf = [0u8; 1504];
    let nbytes = nic.recv(&mut buf[..])?;
    eprintln!("read {} bytes: {:?}", nbytes, &buf[..nbytes]);
    Ok(())
}
