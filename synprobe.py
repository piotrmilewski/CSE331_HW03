from scapy.all import *
from scapy.layers.inet import *


def checkPort(ip, port):
    srcPort = RandShort()
    pack = IP(dst=ip) / TCP(sport=srcPort, dport=port, flags="S")
    resp = sr1(pack, verbose=0, timeout=2)
    if resp is None:
        return False
    print(hexdump(resp))
    flag = resp.getlayer(TCP).flags
    if flag == 0x12:
        return True
    else:
        return False


def main(argv):
    pOpt = ""

    # get input from command line
    try:
        opts, args = getopt.getopt(argv, "p:")
    except getopt.GetoptError:
        print('USAGE: synprobe.py [-p port_range] target')
        sys.exit(1)

    for opt, arg in opts:
        if opt == '-p':
            pOpt = arg

    if len(args) != 1:
        print('USAGE: synprobe.py [-p port_range] target')
        sys.exit(1)

    ip = args[0]
    ports = []

    if "-" in pOpt:
        split = pOpt.split('-')
        ports = range(int(split[0]), int(split[1]))
    elif "," in pOpt:
        ports = pOpt.split(',')
        for i in range(0, len(ports)):
            ports[i] = int(ports[i])
    elif pOpt != "":
        ports = [int(pOpt)]
    else:
        ports = [20, 80, 443, 21, 22]

    # check if the target is valid
    try:
        resp = sr1(IP(dst=ip) / ICMP(), verbose=0, timeout=2)
        if resp is None:
            print("Provided ip is not running")
            sys.exit(1)
    except Scapy_Exception:
        print("Provided ip is not running")
        sys.exit(1)

    openPorts = []
    # check each specified port
    for port in ports:
        ret = checkPort(ip, port)
        if ret:
            openPorts.append(port)


if __name__ == '__main__':
    main(sys.argv[1:])
