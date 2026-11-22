from scapy.all import Ether, IP, TCP, UDP, ICMP, Raw, wrpcap

# 1. TCP traffic: full 3-way handshake + payload containing "audit_tcp_secret"
syn  = Ether()/IP(src="10.1.1.1", dst="10.1.1.2")/TCP(sport=12345, dport=80, flags="S", seq=1000)
synack = Ether()/IP(src="10.1.1.2", dst="10.1.1.1")/TCP(sport=80, dport=12345, flags="SA", seq=2000, ack=1001)
ack  = Ether()/IP(src="10.1.1.1", dst="10.1.1.2")/TCP(sport=12345, dport=80, flags="A", seq=1001, ack=2001)
data = Ether()/IP(src="10.1.1.1", dst="10.1.1.2")/TCP(sport=12345, dport=80, flags="PA", seq=1001, ack=2001)/Raw(load="GET /audit_tcp_secret HTTP/1.1\r\n\r\n")
wrpcap("tcp.pcap", [syn, synack, ack, data])

# 2. UDP traffic: payload containing "audit_udp_secret"
udp = Ether()/IP(src="10.2.2.1", dst="10.2.2.2")/UDP(sport=5353, dport=53)/Raw(load="audit_udp_secret payload")
wrpcap("udp.pcap", [udp])

# 3. ICMP traffic: echo request with payload "audit_icmp_secret"
icmp = Ether()/IP(src="10.3.3.1", dst="10.3.3.2")/ICMP()/Raw(load="audit_icmp_secret")
wrpcap("icmp.pcap", [icmp])
print("pcaps written")
