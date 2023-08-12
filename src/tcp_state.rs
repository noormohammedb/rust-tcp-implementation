use std::io::Result;

use etherparse::{Ipv4Header, Ipv4HeaderSlice, TcpHeader, TcpHeaderSlice};

#[derive(Default)]
pub enum State {
    Closed,
    #[default]
    Listen,
    SynRcvd,
    Ack,
    SynAck,
    Estab,
}

impl State {
    pub fn on_packet(
        &mut self,
        nic: &mut tun_tap::Iface,
        iph: Ipv4HeaderSlice,
        tcph: TcpHeaderSlice,
        data: &[u8],
        // ) {
    ) -> Result<usize> {
        eprintln!(
            "{:?}:{:?} -> {:?}:{:?} {}b of tcp, t_h_len: {}\n",
            iph.source_addr(),
            tcph.source_port(),
            iph.destination_addr(),
            tcph.destination_port(),
            data.len(),
            iph.slice().len() + tcph.slice().len()
        );

        let mut buf = [0u8; 1500];
        match *self {
            State::Closed => {
                log::debug!("matched closed");
                return Ok(1);
            }
            State::Listen => {
                log::debug!("got packet to listenening");
                if !tcph.syn() {
                    log::debug!("droping packet, only accept SYN");
                    return Ok(2);
                }
                // need to establish a connection
                let mut syn_ack = TcpHeader::new(
                    tcph.destination_port(),
                    tcph.source_port(),
                    // tcph.sequence_number(),
                    // unimplemented!(),
                    99,
                    // unimplemented!(),
                    109,
                );
                syn_ack.syn = true;
                syn_ack.ack = true;
                syn_ack.acknowledgment_number = tcph.sequence_number() + 1;

                let mut syn_ack_ip_packet = Ipv4Header::new(
                    syn_ack.header_len(),
                    64,
                    // etherparse::IpTrafficClass::Tcp,
                    6,
                    iph.destination(),
                    iph.source(),
                );

                let ip_hr_of = 4;
                let unwritten = {
                    let mut unwritten = &mut buf[ip_hr_of..];
                    syn_ack_ip_packet.write(&mut unwritten).unwrap();
                    syn_ack.write(&mut unwritten).unwrap();
                    unwritten.len()
                };

                // println!("{:?}", &buf[..buf.len() - unwritten]);

                // dbg!(&buf.len(), &unwritten);
                // dbg!(&syn_ack_ip_packet.header_len(), &syn_ack.header_len());
                // nic.send(&buf[..buf.len() - unwritten + 4]);
                nic.send(
                    &buf[..syn_ack_ip_packet.header_len()
                        + syn_ack.header_len() as usize
                        + ip_hr_of],
                )
            }
            _ => {
                println!("_ => ");
                Ok(0)
            }
        }
    }
}
