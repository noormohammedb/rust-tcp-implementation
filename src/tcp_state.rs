use etherparse::{Ipv4HeaderSlice, TcpHeaderSlice};

pub struct State {
    //
}
impl Default for State {
    fn default() -> Self {
        State {}
    }
}

impl State {
    pub fn on_packet(&mut self, iph: Ipv4HeaderSlice, tcph: TcpHeaderSlice, data: &[u8]) {
        eprintln!(
            "{:?}:{:?} -> {:?}:{:?} {}b of tcp",
            iph.source_addr(),
            tcph.source_port(),
            iph.destination_addr(),
            tcph.destination_port(),
            data.len()
        );
    }
}
