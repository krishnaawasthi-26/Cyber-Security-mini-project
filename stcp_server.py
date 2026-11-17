#!/usr/bin/env python3
"""
STCP v1.0 Server — SKIT Telemetry & Command Protocol
B.Tech VII Semester Cyber Security Lab (7CS4-22 / 7CIT4-22)

UDP/TCP server on 127.0.0.1:9999.
Validates magic, CRC-32, decrypts XOR payloads, sends ACK_RESP.
"""

import socket
import struct
import zlib
import time
import argparse
import threading
import sys
from datetime import datetime, timezone

# ── Protocol Constants ──────────────────────────────────────────────
MAGIC = 0x534B
HEADER_FMT = "!HBBHHI"          # 2+1+1+2+2+4 = 12 bytes
HEADER_SIZE = struct.calcsize(HEADER_FMT)
CRC_SIZE = 4
MIN_FRAME = HEADER_SIZE + CRC_SIZE   # 16 bytes (empty payload)

FLAG_ACK_REQ   = 0x08
FLAG_ENCRYPTED = 0x04
FLAG_COMPRESSED = 0x02
FLAG_URGENT    = 0x01

XOR_KEY = 0x5A

MSG_TYPES = {
    0x01: "AUTH_REQ",
    0x02: "ACK_RESP",
    0x03: "DATA_TELEM",
    0x04: "CMD_EXEC",
    0x05: "ALERT_SEC",
    0x06: "HEARTBEAT",
}


def xor_decrypt(data: bytes) -> bytes:
    return bytes(b ^ XOR_KEY for b in data)


def build_ack(seq: int, ref_payload: str = "") -> bytes:
    """Build a signed ACK_RESP packet for the given sequence number."""
    payload = f"ACK for seq={seq}".encode("utf-8")
    ver_flags = 0x10        # version 1, no flags
    msg_type = 0x02         # ACK_RESP
    ts = int(time.time())
    header = struct.pack(HEADER_FMT, MAGIC, ver_flags, msg_type,
                         seq, len(payload), ts)
    crc = zlib.crc32(header + payload) & 0xFFFFFFFF
    return header + payload + struct.pack("!I", crc)


def log(tag: str, msg: str):
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    print(f"[{ts}] [{tag}] {msg}", flush=True)


def process_frame(data: bytes, addr):
    """Parse, validate, and log one STCP frame. Returns ACK bytes or None."""
    src = f"{addr[0]}:{addr[1]}" if addr else "tcp-client"

    if len(data) < MIN_FRAME:
        log("ERROR", f"Truncated frame from {src} ({len(data)} bytes)")
        return None

    magic, ver_flags, msg_type, seq, pay_len, ts = struct.unpack_from(
        HEADER_FMT, data, 0
    )

    if magic != MAGIC:
        log("ERROR", f"Bad magic 0x{magic:04X} from {src} (expected 0x534B)")
        return None

    version = (ver_flags >> 4) & 0x0F
    flags   = ver_flags & 0x0F
    expected_len = HEADER_SIZE + pay_len + CRC_SIZE

    if len(data) < expected_len:
        log("ERROR", f"Frame too short from {src}: need {expected_len}, got {len(data)}")
        return None

    payload_raw = data[HEADER_SIZE : HEADER_SIZE + pay_len]
    crc_recv = struct.unpack_from("!I", data, HEADER_SIZE + pay_len)[0]
    crc_calc = zlib.crc32(data[:HEADER_SIZE + pay_len]) & 0xFFFFFFFF

    crc_ok = crc_recv == crc_calc
    type_name = MSG_TYPES.get(msg_type, f"UNKNOWN(0x{msg_type:02X})")
    flag_strs = []
    if flags & FLAG_ACK_REQ:   flag_strs.append("ACK_REQ")
    if flags & FLAG_ENCRYPTED: flag_strs.append("ENCRYPTED")
    if flags & FLAG_COMPRESSED: flag_strs.append("COMPRESSED")
    if flags & FLAG_URGENT:    flag_strs.append("URGENT")

    # Decrypt if needed
    if flags & FLAG_ENCRYPTED:
        payload_text = xor_decrypt(payload_raw).decode("utf-8", errors="replace")
    else:
        payload_text = payload_raw.decode("utf-8", errors="replace")

    utc_time = datetime.fromtimestamp(ts, tz=timezone.utc).strftime(
        "%Y-%m-%d %H:%M:%S UTC"
    )

    log("RECV", (
        f"src={src}  type={type_name}  seq={seq}  ver={version}  "
        f"flags=[{','.join(flag_strs) or 'NONE'}]  "
        f"payload_len={pay_len}  ts={utc_time}  "
        f"CRC={'OK' if crc_ok else 'FAIL'}(recv=0x{crc_recv:08X} calc=0x{crc_calc:08X})"
    ))
    log("DATA", f"Payload: {payload_text}")

    if not crc_ok:
        log("ALERT", f"⚠ CRC-32 MISMATCH on seq={seq} from {src} — frame rejected")
        return None

    if flags & FLAG_URGENT:
        log("ALERT", f"🔴 URGENT flag set on seq={seq} type={type_name}")

    if flags & FLAG_ACK_REQ:
        ack = build_ack(seq)
        log("SEND", f"ACK_RESP for seq={seq} → {src}")
        return ack

    return None


# ── UDP Server ──────────────────────────────────────────────────────
def run_udp(host: str, port: int):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((host, port))
    log("SERVER", f"UDP listening on {host}:{port}")
    try:
        while True:
            data, addr = sock.recvfrom(65535)
            ack = process_frame(data, addr)
            if ack:
                sock.sendto(ack, addr)
    except KeyboardInterrupt:
        log("SERVER", "Shutting down (UDP)")
    finally:
        sock.close()


# ── TCP Server ──────────────────────────────────────────────────────
def handle_tcp_client(conn: socket.socket, addr):
    """Handle one TCP client (length-prefixed: first 2 bytes = frame size)."""
    try:
        while True:
            len_hdr = b""
            while len(len_hdr) < 2:
                chunk = conn.recv(2 - len(len_hdr))
                if not chunk:
                    return
                len_hdr += chunk
            frame_len = struct.unpack("!H", len_hdr)[0]
            data = b""
            while len(data) < frame_len:
                chunk = conn.recv(frame_len - len(data))
                if not chunk:
                    return
                data += chunk
            ack = process_frame(data, addr)
            if ack:
                conn.sendall(struct.pack("!H", len(ack)) + ack)
    except (ConnectionResetError, BrokenPipeError):
        pass
    finally:
        conn.close()
        log("SERVER", f"TCP client {addr} disconnected")


def run_tcp(host: str, port: int):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((host, port))
    sock.listen(5)
    log("SERVER", f"TCP listening on {host}:{port}")
    try:
        while True:
            conn, addr = sock.accept()
            log("SERVER", f"TCP client connected: {addr}")
            t = threading.Thread(target=handle_tcp_client, args=(conn, addr),
                                 daemon=True)
            t.start()
    except KeyboardInterrupt:
        log("SERVER", "Shutting down (TCP)")
    finally:
        sock.close()


# ── Main ────────────────────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(
        description="STCP v1.0 Server — SKIT Telemetry & Command Protocol"
    )
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=9999)
    parser.add_argument("--proto", choices=["udp", "tcp", "both"], default="udp",
                        help="Transport protocol (default: udp)")
    args = parser.parse_args()

    if args.proto == "both":
        t_udp = threading.Thread(target=run_udp, args=(args.host, args.port),
                                 daemon=True)
        t_tcp = threading.Thread(target=run_tcp, args=(args.host, args.port),
                                 daemon=True)
        t_udp.start()
        t_tcp.start()
        log("SERVER", "Running both UDP and TCP — press Ctrl+C to stop")
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            log("SERVER", "Shutting down")
    elif args.proto == "tcp":
        run_tcp(args.host, args.port)
    else:
        run_udp(args.host, args.port)


if __name__ == "__main__":
    main()
