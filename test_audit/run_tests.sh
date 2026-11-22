#!/bin/bash
export LD_LIBRARY_PATH=$HOME/deps/prefix/lib:$HOME/deps/prefix/lib64
SNORT=$PWD/../build/src/snort
run() { name=$1; conf=$2; rules=$3; pcap=$4; mkdir -p $name; (cd $name && $SNORT -c ../$conf -R ../$rules -r ../$pcap > run.log 2>&1); echo "$name exit=$?"; }
run A_tcp_audit  snort.lua     rules_audit.rules  tcp.pcap
run A_udp_audit  snort.lua     rules_audit.rules  udp.pcap
run A_icmp_audit snort.lua     rules_audit.rules  icmp.pcap
run B_tcp_alert  snort.lua     rules_compat.rules tcp.pcap
run B_udp_log    snort.lua     rules_compat.rules udp.pcap
run B_icmp_drop  snort.lua     rules_compat.rules icmp.pcap
run C_tcp_all    snort_all.lua rules_all.rules    tcp.pcap
run C_udp_all    snort_all.lua rules_all.rules    udp.pcap
run C_icmp_all   snort_all.lua rules_all.rules    icmp.pcap
