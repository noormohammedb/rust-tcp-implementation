#!/bin/bash
cargo b -r
# sudo setcap cap_net_admin=eip $CARGO_TARGET_DIR/release/trust
# sudo setcap cap_net_admin=eip $CARGO_TARGET_DIR/debug/trust
# $CARGO_TARGET_DIR/release/trust &

sudo setcap cap_net_admin=eip $PWD/target/release/trust
sudo setcap cap_net_admin=eip $PWD/target/debug/trust
$PWD/target/release/trust &
pid=$!
sudo ip addr add 192.168.0.1/24 dev tun0 
sudo ip link set up dev tun0
trap "kill $pid" INT TERM
wait $pid
