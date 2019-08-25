import scapy.all as scapy
import optparse

# def scan(ip): OLD STUFF
#     arp_request = scapy.ARP(pdst=ip)
#     broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
#     arp_request_broadcast = broadcast/arp_request
#     answered, unanswered = scapy.srp(arp_request_broadcast, timeout=1)
#     print(answered.summary())

# scan("192.168.0.1/24")


def get_arguments():
    parser = optparse.OptionParser()
    parser.add_option("-t", "--target", dest="target", help="Target IP / IP range.")
    (options, arguments) = parser.parse_args()
    return options


def scan(ip):
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast/arp_request
    answered = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]    # Get only the answered ones.

    clients_list = []
    for answer in answered:
        client_dict = {"ip": answer[1].psrc, "mac": answer[1].hwsrc}
        clients_list.append(client_dict)
    return clients_list


def print_result(results_list):
    print("IP\t\t\tMAC Address\n-----------------------------------------")
    for client in results_list:
        print("{} \t\t {}".format(client["ip"], client["mac"]))


options = get_arguments()
# scan_result = scan("192.168.0.1/24")
scan_result = scan(options.target)
print_result(scan_result)