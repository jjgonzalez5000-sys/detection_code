"""Generate deterministic test pcaps for the Suricata rules.

Each scenario is a small, synthetic network capture: a positive case that must
trigger a rule, or a benign look-alike that must not. Captures are generated
rather than committed so the repository stays small and reviewable.
"""

import argparse
from pathlib import Path

from scapy.all import DNS, DNSQR, IP, TCP, UDP, Ether, Raw, wrpcap

CLIENT = "10.0.0.10"
INTERNAL_SERVER = "10.0.0.20"
EXTERNAL_HOST = "203.0.113.10"
IMDS = "169.254.169.254"

MAC_A = "02:00:00:00:00:01"
MAC_B = "02:00:00:00:00:02"


def tcp_session(src, dst, sport, dport, client_data: bytes, server_data: bytes):
    """Build a complete TCP session: handshake, one request, one response, teardown."""
    c_seq, s_seq = 1000, 5000
    eth_c = Ether(src=MAC_A, dst=MAC_B)
    eth_s = Ether(src=MAC_B, dst=MAC_A)
    c = IP(src=src, dst=dst)
    s = IP(src=dst, dst=src)
    pkts = [
        eth_c / c / TCP(sport=sport, dport=dport, flags="S", seq=c_seq),
        eth_s / s / TCP(sport=dport, dport=sport, flags="SA", seq=s_seq, ack=c_seq + 1),
        eth_c / c / TCP(sport=sport, dport=dport, flags="A", seq=c_seq + 1, ack=s_seq + 1),
        eth_c / c / TCP(sport=sport, dport=dport, flags="PA", seq=c_seq + 1, ack=s_seq + 1) / Raw(client_data),
    ]
    c_next = c_seq + 1 + len(client_data)
    pkts += [
        eth_s / s / TCP(sport=dport, dport=sport, flags="A", seq=s_seq + 1, ack=c_next),
        eth_s / s / TCP(sport=dport, dport=sport, flags="PA", seq=s_seq + 1, ack=c_next) / Raw(server_data),
    ]
    s_next = s_seq + 1 + len(server_data)
    pkts += [
        eth_c / c / TCP(sport=sport, dport=dport, flags="A", seq=c_next, ack=s_next),
        eth_c / c / TCP(sport=sport, dport=dport, flags="FA", seq=c_next, ack=s_next),
        eth_s / s / TCP(sport=dport, dport=sport, flags="FA", seq=s_next, ack=c_next + 1),
        eth_c / c / TCP(sport=sport, dport=dport, flags="A", seq=c_next + 1, ack=s_next + 1),
    ]
    for i, p in enumerate(pkts):
        p.time = 1_700_000_000 + i * 0.01
    return pkts


def http_get(src, dst, uri: str, host: str):
    req = f"GET {uri} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: test-client/1.0\r\nAccept: */*\r\n\r\n".encode()
    body = b"ok"
    resp = b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 2\r\n\r\n" + body
    return tcp_session(src, dst, 40000, 80, req, resp)


def dns_query(name: str, qtype: str = "A"):
    pkt = Ether(src=MAC_A, dst=MAC_B) / IP(src=CLIENT, dst="10.0.0.53") / UDP(sport=53000, dport=53) / DNS(
        id=0x1234, rd=1, qd=DNSQR(qname=name, qtype=qtype)
    )
    pkt.time = 1_700_000_000
    return [pkt]


def stratum(method: str):
    req = ('{"id":1,"method":"%s","params":["client/1.0"]}\n' % method).encode()
    resp = b'{"id":1,"result":true,"error":null}\n'
    return tcp_session(CLIENT, EXTERNAL_HOST, 41000, 3333, req, resp)


SCENARIOS = {
    "imds_credentials": lambda: http_get(CLIENT, IMDS, "/latest/meta-data/iam/security-credentials/app-role", IMDS),
    "imds_instance_id": lambda: http_get(CLIENT, IMDS, "/latest/meta-data/instance-id", IMDS),
    "dns_tunnel_long_query": lambda: dns_query(
        "mzxw6ytboi2dqnrrgq3tsmbsgi3donbqgi4tmnbugy2tsojygy3tgnby.t1.exfil-example.net", "TXT"
    ),
    "dns_normal_query": lambda: dns_query("www.example.com"),
    "stratum_subscribe": lambda: stratum("mining.subscribe"),
    "jsonrpc_benign": lambda: stratum("eth_blockNumber"),
    "webshell_cmd": lambda: http_get(EXTERNAL_HOST, INTERNAL_SERVER, "/uploads/avatar.php?cmd=whoami", "app.internal"),
    "php_search_benign": lambda: http_get(EXTERNAL_HOST, INTERNAL_SERVER, "/search.php?q=whoami", "app.internal"),
}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", default="build/pcaps", help="output directory")
    args = parser.parse_args()
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    for name, build in SCENARIOS.items():
        wrpcap(str(out / f"{name}.pcap"), build())
    print(f"Generated {len(SCENARIOS)} pcaps in {out}")


if __name__ == "__main__":
    main()
