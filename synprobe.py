from scapy.all import *
from scapy.layers.inet import *
from netaddr import IPNetwork


def checkPort(ip, port):
    srcPort = RandShort()
    pack = IP(dst=ip) / TCP(sport=srcPort, dport=port, flags="S")
    resp = sr1(pack, verbose=0, timeout=2)
    # make sure response is received
    if resp is None:
        return False
    # make sure response is TCP
    if resp.getlayer(TCP) is None:
        return False
    flag = resp.getlayer(TCP).flags
    if flag == 0x12:
        return True
    else:
        return False


def sendMsg(ip, port, msg, delayTime):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((ip, port))
    try:
        s.send(msg)
        ready = select.select([s], [], [], delayTime)
        if ready[0]:
            data = s.recv(1024)
            print("Output returned from " + ip + ":" + str(port))
            hexdump(data)
            return True
        return False
    except ConnectionResetError:
        return False


def printResp(ip, port):
    # try a packet
    if sendMsg(ip, port, b'GET /\r\n', 2):
        return
    # try another packet with a longer delay
    if sendMsg(ip, port, b'GET /\r\n', 6):
        return


def checkIP(ip, ports):
    # check if the target is valid
    try:
        resp = sr1(IP(dst=ip) / ICMP(), verbose=0, timeout=2)
        if resp is None:
            print(ip + " is not running")
            return
    except Scapy_Exception:
        print(ip + " is not running")
        return

    openPorts = []
    # check each specified port
    for port in ports:
        ret = checkPort(ip, port)
        if ret:
            openPorts.append(port)

    # connect to port and dump hex
    for port in openPorts:
        printResp(ip, port)


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

    # check if requesting subnet
    if "/" in ip:
        for ip in IPNetwork(ip):
            checkIP(str(ip), ports)
    else:
        checkIP(ip, ports)


if __name__ == '__main__':
    main(sys.argv[1:])
