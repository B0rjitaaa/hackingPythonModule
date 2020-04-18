# python3

import subprocess
import optparse
import re
import os


def check_super_user():
    return os.geteuid() == 0


def get_current_mac(interface):
    ifconfig_result = subprocess.check_output(['ifconfig', interface])
    mac_addr = re.search(r'\w\w:\w\w:\w\w:\w\w:\w\w:\w\w', str(ifconfig_result))
    if mac_addr:
        return mac_addr.group(0)
    else:
        print('[!] Could not read MAC address.')


def get_arguments():
    parser = optparse.OptionParser()
    parser.add_option('-i', '--interface', dest='interface', help='Interface to change its MAC addr')
    parser.add_option('-m', '--mac', dest='new_mac', help='New MAC addr')
    (options, arguments) = parser.parse_args()
    if not options.interface:
        parser.error('[!] Please specify an interface, use --help for more info.')
    elif not options.new_mac:
        parser.error('[!] Please specify a MAC, use --help for more info.')
    return options


def change_mac(interface, new_mac):
    print('[+] Changing MAC addres for {} to {}'.format(interface, new_mac))
    subprocess.call(["ifconfig", interface, "hw", "ether", new_mac])


if __name__ == '__main__':
    if check_super_user():
        options = get_arguments()
        current_mac = get_current_mac(options.interface)
        print('Current MAC: {}'.format(current_mac))

        change_mac(options.interface, options.new_mac)

        if current_mac != options.new_mac:
            print('[+] MAC address was successfully changed to {}.'.format(options.new_mac))
        else:
            print('[!] MAC address did not get changed.')
    else:
        print('[!] Access denied. Please SUDO!')
