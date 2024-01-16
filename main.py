import logging
logger = logging.getLogger("scapy")
logger.setLevel(logging.CRITICAL)
import re
import time
import socket
import argparse
import ipaddress
from scapy.sendrecv import sr1
from scapy.layers.inet6 import IPv6
from scapy.volatile import RandShort, RandInt
from scapy.layers.inet import IP, UDP, TCP, ICMP


def is_internal_ip(ip_address):
    private_ip_ranges_ipv4 = [
        ipaddress.IPv4Network("10.0.0.0/8"),
        ipaddress.IPv4Network("172.16.0.0/12"),
        ipaddress.IPv4Network("192.168.0.0/16"),
    ]

    private_ip_ranges_ipv6 = [
        ipaddress.IPv6Network("fc00::/7"),
        ipaddress.IPv6Network("fe80::/10"),
    ]

    try:
        ip = ipaddress.ip_address(ip_address)
        if ip.version == 4:
            return any(ip in private_range for private_range in
                       private_ip_ranges_ipv4)
        elif ip.version == 6:
            return any(ip in private_range for private_range in
                       private_ip_ranges_ipv6)
    except ValueError:
        return False


def get_whois_server(ip_address):
    try:
        whois_server = "whois.iana.org"
        with socket.create_connection((whois_server, 43), timeout=2) as sock:
            sock.send(f"{ip_address}\r\n".encode())
            response = b""
            while True:
                data = sock.recv(4096)
                if not data:
                    break
                response += data

        response = response.decode("utf-8", errors="ignore").lower()
        match = re.search(r"whois:\s*(\S+)", response)
        if match:
            whois_server = match.group(1)
        else:
            return None
        return whois_server
    except Exception:
        pass
    return None


def get_asn(ip_address):
    try:
        if is_internal_ip(ip_address):
            return "Internal IP address"
        whois_server = get_whois_server(ip_address)
        if whois_server is None:
            return None
        if "arin" in whois_server:
            query = f"n + {ip_address}\r\n"
            asn_pattern = re.compile(r"originas:\s*as(\d+)", re.IGNORECASE)
        elif "ripe" in whois_server:
            query = f"-V Md5.5.7 {ip_address}\r\n"
            asn_pattern = re.compile(r"origin:\s*as(\d+)", re.IGNORECASE)
        else:
            query = f"{ip_address}\r\n"
            asn_pattern = re.compile(r"origin:\s*as(\d+)", re.IGNORECASE)

        with socket.create_connection((whois_server, 43), timeout=2) as sock:
            sock.send(query.encode())
            response = b""
            while True:
                data = sock.recv(4096)
                if not data:
                    break
                response += data
        response = response.decode("utf-8", errors="ignore").lower()
        match = asn_pattern.search(response)
        if match:
            return match.group(1)
        return "not provided"
    except Exception:
        pass
    return None


def traceroute(destination, protocol="udp", max_hops=30, timeout=2, port=33434,
               verbose=False):
    try:
        ip_version = ipaddress.ip_address(destination).version
    except ValueError:
        try:
            destination_ip = socket.gethostbyname(destination)
            ip_version = ipaddress.ip_address(destination_ip).version
        except socket.gaierror:
            print(f"Error: Unable to resolve the hostname {destination}")
            return
    else:
        if ip_version == 4:
            destination_ip = destination
        elif ip_version == 6:
            destination_ip = socket.getaddrinfo(destination, port,
                                                socket.AF_INET6)[0][4][0]
        else:
            print("Unsupported IP version")
            return
    ttl = 1
    while True:
        start_time = time.time()
        ip_layer = None
        if protocol == "icmp":
            if ip_version == 4:
                ip_layer = IP(dst=destination_ip, ttl=ttl)
            elif ip_version == 6:
                ip_layer = IPv6(dst=destination_ip, hlim=ttl)
            proto_layer = ICMP()
        elif protocol == "tcp":
            if ip_version == 4:
                ip_layer = IP(dst=destination_ip, id=RandShort(), ttl=ttl)
            elif ip_version == 6:
                ip_layer = IPv6(dst=destination_ip, id=RandShort(), hlim=ttl)
            proto_layer = TCP(seq=RandInt(), sport=RandShort(), dport=port,
                              flags="S")
        elif protocol == "udp":
            if ip_version == 4:
                ip_layer = IP(dst=destination_ip, ttl=ttl)
            elif ip_version == 6:
                ip_layer = IPv6(dst=destination_ip, hlim=ttl)
            proto_layer = UDP(sport=RandShort(), dport=port)
        else:
            print("Unsupported protocol")
            return
        packet = ip_layer / proto_layer if ip_layer and proto_layer else None
        reply = sr1(packet, timeout=timeout, verbose=0)
        end_time = time.time()

        if reply is None:
            print(f"{ttl}\t*")
        elif (protocol == "tcp" and reply.haslayer(TCP) and
              reply.getlayer(TCP).flags == 0x12) or \
                (protocol == "udp" and reply.type == 3) or \
                (protocol == "icmp" and reply.type == 0):
            print(
                f"{ttl}\t"
                f"{reply.src}\t"
                f"[{int((end_time - start_time) * 1000)} ms]")
            break
        else:
            asn = f"[{get_asn(reply.src)}]" if verbose else ""
            print(
                f"{ttl}\t"
                f"{reply.src}\t"
                f"[{int((end_time - start_time) * 1000)} ms]\t"
                f"{asn}")

        ttl += 1

        if ttl > max_hops:
            break

    
def main():
    parser = argparse.ArgumentParser(
        description="Traceroute utility for network diagnostics in Python.",
        usage="traceroute [OPTIONS] IP_ADDRESS {tcp|udp|icmp}"
    )
    parser.add_argument("destination", metavar="IP_ADDRESS",
                        help="Destination host or IP address.")
    parser.add_argument("protocol", choices=["icmp", "tcp", "udp"],
                        help="Protocol to use (icmp, tcp, udp).")
    parser.add_argument("-t", "--timeout", type=int, default=2,
                        help="Timeout for each packet in seconds (default: 2).")
    parser.add_argument("-p", "--port", type=int, default=33434,
                        help="Port for TCP or UDP.")
    parser.add_argument("-n", "--max-hops", type=int, default=30,
                        help="Maximum number of hops (default: 30).")
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="Print AS number for each IP address.")

    args = parser.parse_args()

    print(f"Traceroute to {args.destination} {args.protocol.upper()} protocol,"
          f" {args.max_hops} hops max, {args.port} port,"
          f" {args.timeout} second timeout.")
    traceroute(args.destination, protocol=args.protocol,
               max_hops=args.max_hops, timeout=args.timeout, port=args.port,
               verbose=args.verbose)


if __name__ == "__main__":
    main()
