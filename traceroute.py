import argparse
import socket
import time
import re
from scapy.layers.inet import IP, ICMP, TCP, UDP
from scapy.layers.inet6 import IPv6
from scapy.all import sr1


class WhoisClient:
    def __init__(self):
        self.ipv4_whois_server = "whois.arin.net"
        self.ipv6_whois_server = "whois.ripe.net"

    def query(self, ip_address):
        query = f"n {ip_address}\r\n"
        whois_server = self.ipv6_whois_server if ':' in ip_address else self.ipv4_whois_server

        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect((whois_server, 43))
            s.send(query.encode())
            response = b""
            while True:
                data = s.recv(1024)
                if not data:
                    break
                response += data

        return response.decode()


class Traceroute:
    def __init__(self, target_ip, protocol, timeout, port, max_hops, verbose):
        self.target_ip = target_ip
        self.protocol = protocol
        self.timeout = timeout
        self.port = port
        self.max_hops = max_hops
        self.verbose = verbose
        self.whois_client = WhoisClient()

    def extract_as_info(self, whois_response):
        as_matches = re.findall(r'\bAS(\d+)\b', whois_response)
        return ', '.join(as_matches) if as_matches else "not provided"

    def send_icmp_packet(self, ttl):
        return IP(dst=self.target_ip, ttl=ttl) / ICMP()

    def send_tcp_packet(self, ttl):
        return IP(dst=self.target_ip, ttl=ttl) / TCP(dport=self.port,
                                                     flags="S")

    def send_udp_packet(self, ttl):
        return IP(dst=self.target_ip, ttl=ttl) / UDP(dport=self.port)

    def send_packet(self, ttl):
        if ':' in self.target_ip:
            return IPv6(dst=self.target_ip,
                        hlim=ttl) / self.get_transport_layer()
        else:
            return IP(dst=self.target_ip, ttl=ttl) / self.get_transport_layer()

    def get_transport_layer(self):
        if self.protocol == 'icmp':
            return ICMP()
        elif self.protocol == 'tcp':
            return TCP(dport=self.port, flags="S")
        elif self.protocol == 'udp':
            return UDP(dport=self.port)

    def print_result(self, ttl, ip, elapsed_time, as_info):
        if self.verbose:
            print(f"{ttl}\t{ip}  [{elapsed_time} ms]  [{as_info}]")
        else:
            print(f"{ttl}\t{ip}  [{elapsed_time} ms]")

    def traceroute(self):
        for ttl in range(1, self.max_hops + 1):
            packet = self.send_packet(ttl)

            try:
                start_time = time.time()
                response = sr1(packet, timeout=self.timeout, verbose=0)
                end_time = time.time()
            except Exception as e:
                print(f"{ttl} *")
                continue

            if response is None:
                print(f"{ttl} *")
            else:
                ip = response.getlayer(IP).src
                elapsed_time = round((end_time - start_time) * 1000, 2)

                whois_info = self.whois_client.query(ip)
                as_info = self.extract_as_info(whois_info)

                self.print_result(ttl, ip, elapsed_time, as_info)

                if ip == self.target_ip:
                    break


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Custom traceroute utility.")
    parser.add_argument("ip_address", help="Target IP address")
    parser.add_argument("protocol", choices=["icmp", "tcp", "udp"],
                        help="Packet protocol")
    parser.add_argument("-t", "--timeout", type=float, default=2,
                        help="Timeout for each packet")
    parser.add_argument("-p", "--port", type=int, default=80,
                        help="Port number for TCP or UDP")
    parser.add_argument("-n", "--max_requests", type=int, default=30,
                        help="Maximum number of requests")
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="Display AS information")

    args = parser.parse_args()

    traceroute_instance = Traceroute(args.ip_address, args.protocol,
                                     args.timeout, args.port,
                                     args.max_requests, args.verbose)
    traceroute_instance.traceroute()
