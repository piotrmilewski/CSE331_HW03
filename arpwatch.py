from python_arptable import get_arp_table
from scapy.all import *
from scapy.layers.l2 import *

orig_arp_table = []


def get_mac(ip):
    for entry in orig_arp_table:
        if entry['IP address'] == ip:
            return entry['HW address']
    return None


def checkPacket(pkt):
    if ARP in pkt and pkt[ARP].op in (1, 2):
        srcIP = pkt[ARP].psrc
        orig_mac = get_mac(srcIP)
        if orig_mac is None:
            return
        curr_mac = pkt[ARP].hwsrc
        if orig_mac != curr_mac:
            print(srcIP + " changed from " + orig_mac + " to " + curr_mac)


def main(argv):
    pOpt = "enp0s8"

    # get input from command line
    try:
        opts, args = getopt.getopt(argv, "i:")
    except getopt.GetoptError:
        print('USAGE: arpwatch.py [-i interface]')
        sys.exit(1)

    for opt, arg in opts:
        if opt == '-i':
            pOpt = arg

    # sniff for ARP packets
    try:
        sniff(prn=checkPacket, iface=pOpt, filter="arp", store=0)
    except OSError:
        print("Invalid interface, please use 'arp' to determine the correct interface to use")
        sys.exit(1)


if __name__ == '__main__':
    orig_arp_table = get_arp_table()
    main(sys.argv[1:])
