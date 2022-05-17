from scapy.all import *

"""
Current connected clients list: connected client doesn't seem to bother us
since the fuzzing should be before fully connecting to the ssh server.
"""
clients_ports = []


def scan_pkt(pkt) -> None:
    """
    Prints packet load for debugging purposes.
    Function also determine whether the packet belongs to ssh fuzzing attack,
    scanning the first packets to have raw data after 3 tcp handshake.
    :param pkt: given ssh packet
    :return: None
    """

    # Packet doesn't contain raw data - could be 3 handshake
    if Raw not in pkt:
        return

    try:
        load = pkt[Raw].load.decode("UTF-8")
        print(f'Payload: {load}, size: {len(load)}')
    except:
        print("It's a binary string!\n")
        return

    # Client is already connected
    if pkt['TCP'].sport in clients_ports:
        return

    # First message doesn't correspond the protocol rules
    if not load.startswith('SSH-2.0') or not load.endswith('\r\n') or not (len(load) <= 255):
        print("Fuzzing detected!")
        exit()

    # Insert port of the connected client to the global list.
    clients_ports.insert(0, pkt['TCP'].sport)


if __name__ == '__main__':
    # Take packet sniffed in destination port 22 (ssh)
    pkt = sniff(filter="dst port 22", prn=scan_pkt)
