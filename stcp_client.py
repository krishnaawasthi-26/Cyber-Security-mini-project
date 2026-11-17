#!/usr/bin/env python3
"""
STCP v1.0 Client & Security Fault-Injection Script
B.Tech VII Semester Cyber Security Lab (7CS4-22 / 7CIT4-22)

Sends 6 test scenarios to 127.0.0.1:9999 over UDP.
Scenario 6 deliberately tampers the CRC-32 to trigger a checksum failure.
"""

import socket
import struct
import zlib
import time
import sys

# ── Protocol Constants ──────────────────────────────────────────────
MAGIC = 0x534B
HEADER_FMT = "!HBBHHI"          # 12 bytes
HEADER_SIZE = struct.calcsize(HEADER_FMT)
XOR_KEY = 0x5A

MSG_TYPES = {
    0x01: "AUTH_REQ",
    0x02: "ACK_RESP",
    0x03: "DATA_TELEM",
    0x04: "CMD_EXEC",
    0x05: "ALERT_SEC",
    0x06: "HEARTBEAT",
}

FLAG_ACK_REQ   = 0x08
FLAG_ENCRYPTED = 0x04
FLAG_COMPRESSED = 0x02
FLAG_URGENT    = 0x01


def xor_encrypt(data: bytes) -> bytes:
    return bytes(b ^ XOR_KEY for b in data)


def build_frame(msg_type: int, seq: int, flags: int, payload_str: str,
                tamper_crc: bool = False) -> bytes:
    """Build a complete STCP frame (header + payload + CRC-32 trailer)."""
    payload = payload_str.encode("utf-8")
    if flags & FLAG_ENCRYPTED:
        payload = xor_encrypt(payload)

    ver_flags = 0x10 | (flags & 0x0F)   # version=1 in upper nibble
    ts = int(time.time())
    header = struct.pack(HEADER_FMT, MAGIC, ver_flags, msg_type,
                         seq, len(payload), ts)
    crc = zlib.crc32(header + payload) & 0xFFFFFFFF
    if tamper_crc:
        crc ^= 0xDEAD0001
    return header + payload + struct.pack("!I", crc)


def parse_ack(data: bytes) -> str:
    """Parse an ACK_RESP frame and return a summary string."""
    if len(data) < HEADER_SIZE + 4:
        return f"[truncated ACK, {len(data)} bytes]"
    magic, ver_flags, msg_type, seq, pay_len, ts = struct.unpack_from(
        HEADER_FMT, data, 0
    )
    payload = data[HEADER_SIZE : HEADER_SIZE + pay_len].decode("utf-8", "replace")
    crc_recv = struct.unpack_from("!I", data, HEADER_SIZE + pay_len)[0]
    crc_calc = zlib.crc32(data[:HEADER_SIZE + pay_len]) & 0xFFFFFFFF
    crc_ok = "OK" if crc_recv == crc_calc else "FAIL"
    return (
        f"type={MSG_TYPES.get(msg_type, '??')} seq={seq} "
        f"payload=\"{payload}\" CRC={crc_ok}"
    )


# ── Test Scenarios ──────────────────────────────────────────────────
SCENARIOS = [
    # (description, msg_type, seq, flags, payload, tamper_crc)
    ("1. AUTH_REQ  (Seq=101, ACK_REQ)",
     0x01, 101, FLAG_ACK_REQ,
     "user=nasir;token=abc123def456", False),

    ("2. DATA_TELEM encrypted (Seq=102, ENCRYPTED)",
     0x03, 102, FLAG_ENCRYPTED,
     "temp=42.5;humidity=68;pressure=1013.25", False),

    ("3. CMD_EXEC  (Seq=103, ACK_REQ | URGENT)",
     0x04, 103, FLAG_ACK_REQ | FLAG_URGENT,
     "REBOOT sensor-node-7", False),

    ("4. ALERT_SEC urgent (Seq=104, URGENT)",
     0x05, 104, FLAG_URGENT,
     "INTRUSION_DETECTED src=10.0.0.99 port=22", False),

    ("5. HEARTBEAT (Seq=105, no flags)",
     0x06, 105, 0x00,
     "ping", False),

    ("6. TAMPERED CRC (Seq=106, ACK_REQ) — should FAIL",
     0x03, 106, FLAG_ACK_REQ,
     "tampered_data=evil", True),
]


def main():
    host = "127.0.0.1"
    port = 9999
    timeout = 2.0

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)

    print("=" * 72)
    print("  STCP v1.0 Client — Fault-Injection Test Suite")
    print("=" * 72)

    acks_received = 0
    crc_failures_expected = 0
    total = len(SCENARIOS)

    for desc, msg_type, seq, flags, payload, tamper in SCENARIOS:
        print(f"\n── {desc}")
        frame = build_frame(msg_type, seq, flags, payload, tamper_crc=tamper)
        print(f"   Sending {len(frame)} bytes → {host}:{port}")

        sock.sendto(frame, (host, port))

        if tamper:
            crc_failures_expected += 1

        # Try to receive ACK if ACK_REQ is set (server won't ACK bad CRC)
        if flags & FLAG_ACK_REQ:
            try:
                resp, _ = sock.recvfrom(65535)
                summary = parse_ack(resp)
                print(f"   ✅ ACK received: {summary}")
                acks_received += 1
            except socket.timeout:
                if tamper:
                    print(f"   ⚠ No ACK (expected — CRC was tampered)")
                else:
                    print(f"   ❌ No ACK received (timeout)")
        else:
            print(f"   (no ACK expected — ACK_REQ not set)")

        time.sleep(0.15)       # small gap for readability

    print("\n" + "=" * 72)
    print(f"  SUMMARY: {total} frames sent, {acks_received} ACKs received, "
          f"{crc_failures_expected} deliberate CRC failures")
    print("=" * 72)

    sock.close()


if __name__ == "__main__":
    main()
