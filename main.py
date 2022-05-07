from scapy.all import *
from gibberish_detector import detector

Detector = detector.create_from_model('big.model')


def print_pkt(pkt) -> None:
    """
    Prints packet details for debugging purposes.
    :param pkt: given packet
    :return: None
    """
    pkt.show()
    if Raw in pkt:
        if Detector.is_gibberish(pkt[Raw].load):
            print("Fuzzing detected!")
            exit()


if __name__ == '__main__':
    # Take packet sniffed in port 22 (ssh)
    pkt = sniff(filter="port 22", prn=print_pkt)
