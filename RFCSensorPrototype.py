import logging
import cryptography
from scapy.all import *
import math

logging.getLogger("scapy").setLevel(logging.CRITICAL)
OPEN_LOG=True
# check all tls packets data layer for true encrypted entropy
# Layer in Pkt
# pkt[layer]

def entropy(string):
    # Calculates the Shannon entropy of a string
    # get probability of chars in string
    prob = [float(string.count(c)) / len(string) for c in dict.fromkeys(list(string))]
    # calculate the entropy
    entropy = - sum([p * math.log(p) / math.log(2.0) for p in prob])
    return entropy


def byteStrToHex(bStr):
    # for testing purposes
    i = "".join("{:02x}".format(c) for c in bStr)
    return i


# Each protocol being analyzed would have its own module+

#TODO: also check client/server hello for anomalous cipher suites
# Module to analyze TLS RFC
def analyzeTLS(capture=None):
    load_layer('tls')
    if capture == None:
        # packets = sniff(iface='Wi-Fi', count=200, prn=lambda x: x.summary(), lfilter=lambda x: TLS in x)
        packets = AsyncSniffer(iface='Wi-Fi', count=200, lfilter=lambda x: TLS in x)
        packets.start()
        h = send(IP(dst='75.75.77.25') / TCP(dport=443, flags=16) / TLS(msg=[TLSApplicationData(
            data=b'\xe4r\x19\x7f`V\xd0\xba\x92\x9de\xffn\xff\xb6\xda\x13\xa99,]ImagineForASecondThatThisIsARealSentPacketAndItLooksLikeEncryptedTLSTrafficButInFactItIsAWeekEncryptionOrMalwareC2CommunicationAndTheEntropyJustIsntAddingUp..aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\x1ex\x85\xd5\xce\x1d\xcf\x04\xe6\n\xfbK\x9d')]),
                 iface="Wi-Fi")
        packets.join()
        packets = packets.results
        print(packets)
    else:
        packets = capture
    if OPEN_LOG:
        wrpcap('capture', packets, append=False)
        wireshark('capture')

    for pkt in packets:
        try:
            # print(pkt.summary())
            if capture:
                pkt = TLS(pkt.load)
            dataLength = len(pkt["TLS Application Data"].data)
            if dataLength < 200:
                # Entropy calculation may not be accurate enough to calculate up to 16^2 combinations
                # print("Length "+str(dataLength)+" is too short to proceed with detection.")
                continue
            # print(pkt["TLS Application Data"].data)
            # Shannon entropy:
            # 0 represents no randomness (i.e. all the bytes in the data have the same value) whereas 8, the maximum, represents a completely random string.
            # Standard English text usually falls somewhere between 3.5 and 5.
            # Properly encrypted or compressed data of a reasonable length should have an entropy of over 7.5.
            shannonEntropy = entropy(pkt["TLS Application Data"].data)
            if shannonEntropy < 7.4:
                print("Suspicious packet: " + pkt.summary() + "\n" + "Entropy of Data: " + str(shannonEntropy))
                print(pkt['TCP'].flags)
            else:
                print("Normal packet: " + pkt.summary() + "\n" + "Entropy of Data: " + str(shannonEntropy))
                print(pkt['TCP'].flags)
        except Exception as e:
            print(e)

#TODO
# Module to analyze QUIC RFC
def analyzeQUIC(capture=None):
    pass

#TODO
# Module to analyze HTTP RFC (Will be a massive amount of work)
def analyzeHTTP(capture=None):
    pass


if __name__ == "__main__":
    analyzeTLS()
