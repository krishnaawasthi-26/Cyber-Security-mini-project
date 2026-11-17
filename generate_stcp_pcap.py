#!/usr/bin/env python3
"""
STCP v1.0 — PCAP Generator (zero external dependencies)
Writes stcp_sample_capture.pcap with Ethernet + IPv4 + UDP + STCP frames
for all 8 packets (6 client + 2 server ACKs, including the bad-CRC frame).

PCAP file format: libpcap (magic 0xA1B2C3D4), Ethernet link-layer.
"""

import struct
import zlib
import time
import os

# ── STCP Protocol Helpers ───────────────────────────────────────────
MAGIC = 0x534B
HEADER_FMT = "!HBBHHI"
HEADER_SIZE = struct.calcsize(HEADER_FMT)
XOR_KEY = 0x5A

FLAG_ACK_REQ   = 0x08
FLAG_ENCRYPTED = 0x04
FLAG_URGENT    = 0x01


def xor_encrypt(data: bytes) -> bytes:
    return bytes(b ^ XOR_KEY for b in data)


def build_stcp_frame(msg_type, seq, flags, payload_str, tamper_crc=False):
    payload = payload_str.encode("utf-8")
    if flags & FLAG_ENCRYPTED:
        payload = xor_encrypt(payload)
    ver_flags = 0x10 | (flags & 0x0F)
    ts = int(time.time())
    header = struct.pack(HEADER_FMT, MAGIC, ver_flags, msg_type,
                         seq, len(payload), ts)
    crc = zlib.crc32(header + payload) & 0xFFFFFFFF
    if tamper_crc:
        crc ^= 0xDEAD0001
    return header + payload + struct.pack("!I", crc)


def build_ack_frame(seq):
    payload = f"ACK for seq={seq}".encode("utf-8")
    ver_flags = 0x10
    ts = int(time.time())
    header = struct.pack(HEADER_FMT, MAGIC, ver_flags, 0x02,
                         seq, len(payload), ts)
    crc = zlib.crc32(header + payload) & 0xFFFFFFFF
    return header + payload + struct.pack("!I", crc)


# ── Network Packet Builders ────────────────────────────────────────

def ip_checksum(header_bytes: bytes) -> int:
    """Standard RFC 1071 IP header checksum."""
    if len(header_bytes) % 2:
        header_bytes += b'\x00'
    s = 0
    for i in range(0, len(header_bytes), 2):
        s += (header_bytes[i] << 8) + header_bytes[i + 1]
    s = (s >> 16) + (s & 0xFFFF)
    s += s >> 16
    return (~s) & 0xFFFF


def build_udp_ip_eth(src_ip, dst_ip, src_port, dst_port, payload,
                     src_mac=b'\x02\x00\x00\x00\x00\x01',
                     dst_mac=b'\x02\x00\x00\x00\x00\x02'):
    """Build Ethernet + IPv4 + UDP frame encapsulating the given payload."""

    # UDP header
    udp_len = 8 + len(payload)
    udp_header = struct.pack("!HHHH", src_port, dst_port, udp_len, 0)  # checksum=0

    # IPv4 header (20 bytes, no options)
    ip_total_len = 20 + udp_len
    ip_id = 0x1234
    ip_header = struct.pack("!BBHHHBBH4s4s",
        0x45,            # version=4, IHL=5
        0x00,            # DSCP/ECN
        ip_total_len,
        ip_id,           # identification
        0x4000,          # flags=DF, frag offset=0
        64,              # TTL
        17,              # protocol = UDP
        0,               # checksum placeholder
        src_ip,
        dst_ip,
    )
    chk = ip_checksum(ip_header)
    ip_header = ip_header[:10] + struct.pack("!H", chk) + ip_header[12:]

    # Ethernet frame
    eth_header = dst_mac + src_mac + struct.pack("!H", 0x0800)

    return eth_header + ip_header + udp_header + payload


def ip_addr(s: str) -> bytes:
    return bytes(int(x) for x in s.split("."))


# ── PCAP File Writer ───────────────────────────────────────────────

PCAP_MAGIC = 0xA1B2C3D4
PCAP_VERSION_MAJOR = 2
PCAP_VERSION_MINOR = 4
PCAP_THISZONE = 0
PCAP_SIGFIGS = 0
PCAP_SNAPLEN = 65535
PCAP_LINKTYPE = 1   # LINKTYPE_ETHERNET


def write_pcap(filename, packets):
    """Write a libpcap file. packets = list of (timestamp_float, raw_bytes)."""
    with open(filename, "wb") as f:
        # Global header (24 bytes)
        f.write(struct.pack("<IHHiIII",
            PCAP_MAGIC, PCAP_VERSION_MAJOR, PCAP_VERSION_MINOR,
            PCAP_THISZONE, PCAP_SIGFIGS, PCAP_SNAPLEN, PCAP_LINKTYPE))

        for ts_float, raw in packets:
            ts_sec = int(ts_float)
            ts_usec = int((ts_float - ts_sec) * 1_000_000)
            incl_len = len(raw)
            orig_len = len(raw)
            # Packet record header (16 bytes)
            f.write(struct.pack("<IIII", ts_sec, ts_usec, incl_len, orig_len))
            f.write(raw)


# ── Main: Generate All 8 Packets ───────────────────────────────────

def main():
    CLIENT_IP = ip_addr("127.0.0.1")
    SERVER_IP = ip_addr("127.0.0.1")
    CLIENT_PORT = 12345
    SERVER_PORT = 9999
    CLIENT_MAC = b'\x02\x00\x00\x00\x00\x01'
    SERVER_MAC = b'\x02\x00\x00\x00\x00\x02'

    scenarios = [
        # (msg_type, seq, flags, payload, tamper_crc)
        (0x01, 101, FLAG_ACK_REQ,
         "user=nasir;token=abc123def456", False),
        (0x03, 102, FLAG_ENCRYPTED,
         "temp=42.5;humidity=68;pressure=1013.25", False),
        (0x04, 103, FLAG_ACK_REQ | FLAG_URGENT,
         "REBOOT sensor-node-7", False),
        (0x05, 104, FLAG_URGENT,
         "INTRUSION_DETECTED src=10.0.0.99 port=22", False),
        (0x06, 105, 0x00,
         "ping", False),
        (0x03, 106, FLAG_ACK_REQ,
         "tampered_data=evil", True),
    ]

    packets = []
    base_ts = time.time()

    for idx, (msg_type, seq, flags, payload, tamper) in enumerate(scenarios):
        ts = base_ts + idx * 0.1
        stcp_frame = build_stcp_frame(msg_type, seq, flags, payload, tamper)
        eth_frame = build_udp_ip_eth(
            CLIENT_IP, SERVER_IP, CLIENT_PORT, SERVER_PORT,
            stcp_frame, CLIENT_MAC, SERVER_MAC
        )
        packets.append((ts, eth_frame))

        # Server ACK for packets that have ACK_REQ and valid CRC
        if (flags & FLAG_ACK_REQ) and not tamper:
            ack_ts = ts + 0.005
            ack_frame = build_ack_frame(seq)
            ack_eth = build_udp_ip_eth(
                SERVER_IP, CLIENT_IP, SERVER_PORT, CLIENT_PORT,
                ack_frame, SERVER_MAC, CLIENT_MAC
            )
            packets.append((ack_ts, ack_eth))

    out_path = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                            "stcp_sample_capture.pcap")
    write_pcap(out_path, packets)
    print(f"✅ Wrote {len(packets)} packets to {out_path}")
    print(f"   ({sum(len(p[1]) for p in packets)} bytes total frame data)")

    # Breakdown
    client_count = len(scenarios)
    ack_count = len(packets) - client_count
    print(f"   {client_count} client frames + {ack_count} server ACKs "
          f"= {len(packets)} total")


if __name__ == "__main__":
    main()
