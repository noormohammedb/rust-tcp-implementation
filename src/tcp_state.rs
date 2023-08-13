use std::io::Result;

use etherparse::{Ipv4Header, Ipv4HeaderSlice, TcpHeader, TcpHeaderSlice};

#[derive(Default, Debug)]
pub enum State {
    Closed,
    #[default]
    Listen,
    SynRcvd,
    Ack,
    SynAck,
    Estab,
}

#[derive(Debug)]
pub struct Connection {
    state: State,
    send: SendSequenceSpace,
    recv: ReceiveSequenceSpace,
}

/// State of the Send Sequence Space (RFC 793 S3.2 F4)
///
/// ```
///            1         2          3          4
///       ----------|----------|----------|----------
///              SND.UNA    SND.NXT    SND.UNA
///                                   +SND.WND
///
/// 1 - old sequence numbers which have been acknowledged
/// 2 - sequence numbers of unacknowledged data
/// 3 - sequence numbers allowed for new data transmission
/// 4 - future sequence numbers which are not yet allowed
/// ```
#[derive(Default, Debug)]
struct SendSequenceSpace {
    /// send unacknowledged
    una: u32,
    /// send next
    nxt: u32,
    /// send window
    wnd: u16,
    /// send urgent pointer
    up: bool,
    /// segment sequence number used for last window update
    wl1: u32,
    /// segment acknowledgment number used for last window update
    wl2: u32,
    /// initial send sequence number
    iss: u32,
}

/// State of the Receive Sequence Space (RFC 793 S3.2 F5)
///
/// ```
///       1          2          3
///       ----------|----------|----------
///              RCV.NXT    RCV.NXT
///                        +RCV.WND
///
/// 1 - old sequence numbers which have been acknowledged
/// 2 - sequence numbers allowed for new reception
/// 3 - future sequence numbers which are not yet allowed
/// ```
#[derive(Default, Debug)]
struct ReceiveSequenceSpace {
    /// RCV.NXT - receive next
    nxt: u32,
    /// RCV.WND - receive window
    wnd: u16,
    /// RCV.UP  - receive urgent pointer
    up: bool,
    /// IRS     - initial receive sequence number
    irs: u32,
}

impl Default for Connection {
    fn default() -> Self {
        dbg!("connection default");
        Connection {
            state: State::Listen,
            recv: Default::default(),
            send: Default::default(),
            // ..Default::default()
        }
    }
}
impl Connection {
    pub fn on_packet(
        &mut self,
        nic: &mut tun_tap::Iface,
        iph: Ipv4HeaderSlice,
        tcph: TcpHeaderSlice,
        data: &[u8],
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
        match self.state {
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

                // keep track of sender info
                self.recv.irs = tcph.sequence_number();
                self.recv.nxt = tcph.sequence_number() + 1;
                self.recv.wnd = tcph.window_size();

                // keep track of our info
                self.send.iss = 0;
                self.send.una = self.send.iss;
                self.send.nxt = self.send.una + 1;
                self.send.wnd = 10;

                // need to establish a connection
                let mut syn_ack = TcpHeader::new(
                    tcph.destination_port(),
                    tcph.source_port(),
                    self.send.iss,
                    self.send.wnd,
                );
                syn_ack.acknowledgment_number = tcph.sequence_number() + 1;
                syn_ack.syn = true;
                syn_ack.ack = true;

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
