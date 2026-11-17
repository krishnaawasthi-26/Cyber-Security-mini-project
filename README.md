# STCP v1.0 — SKIT Telemetry & Command Protocol

> **B.Tech VII Semester Cyber Security Lab (7CS4-22 / 7CIT4-22)**  
> Mini Project — Wireshark Lua Dissector for a Custom Binary Protocol  
> RTU Experiment 4 • STCP v1.0 over UDP/TCP port 9999

---

## 📁 Project Files

| File | Description |
|------|-------------|
| `stcp_server.py` | UDP/TCP server on `127.0.0.1:9999` — validates magic, CRC-32, decrypts XOR payloads, sends ACKs |
| `stcp_client.py` | Client + fault-injection test suite — sends 6 scenarios including tampered CRC |
| `stcp_dissector.lua` | Wireshark Lua dissector with ProtoField, bitmask flags, CRC verification, ProtoExpert alerts |
| `generate_stcp_pcap.py` | Standalone PCAP generator — creates `stcp_sample_capture.pcap` (8 packets, no root required) |
| `README.md` | This file |

---

## 🔧 Prerequisites

- **Python 3.6+** (standard library only — no `pip install` needed)
- **Wireshark 3.x+** or **TShark** (with Lua support enabled — default on most installs)

---

## 🚀 Quick Start

### Step 1 — Generate the Sample PCAP (No Root Required)

```bash
python3 generate_stcp_pcap.py
```

Output: `stcp_sample_capture.pcap` containing 8 packets (6 client + 2 server ACKs).

### Step 2 — Open in Wireshark with the Lua Dissector

```bash
# GUI
wireshark -X lua_script:stcp_dissector.lua -r stcp_sample_capture.pcap

# CLI (verbose decode)
tshark -X lua_script:stcp_dissector.lua -r stcp_sample_capture.pcap -V
```

### Step 3 — Run the Live Server + Client Test

**Terminal 1 — Start the Server:**
```bash
python3 stcp_server.py --proto udp
```

**Terminal 2 — Run the Client Test Suite:**
```bash
python3 stcp_client.py
```

Expected: 5 valid frames processed, 2 ACKs returned (Seq=101, Seq=103), 1 CRC failure flagged (Seq=106).

---

## 🔎 Wireshark Display Filters

| Filter | What It Shows |
|--------|---------------|
| `stcp` | All STCP packets |
| `stcp.msg_type == 0x01` | AUTH_REQ messages only |
| `stcp.msg_type == 0x02` | ACK_RESP messages only |
| `stcp.msg_type == 0x05` | ALERT_SEC messages only |
| `stcp.flags.ack_req == 1` | Frames requesting an ACK |
| `stcp.flags.enc == 1` | Encrypted (XOR) frames |
| `stcp.flags.urgent == 1` | Urgent security frames |
| `stcp.crc_status == 1` | CRC-32 verified OK |
| `stcp.crc_status == 2` | CRC-32 mismatch (tampered) |
| `stcp.seq == 106` | The specific tampered frame |

---

## 📐 Protocol Specification (STCP v1.0)

```
Network Byte Order (Big-Endian)   struct format: !HBBHHI

┌──────────────────────── HEADER (12 bytes) ────────────────────────┐
│ Offset │ Size │ Field              │ Format          │ Notes      │
│--------│------│--------------------│-----------------│------------│
│   0    │  2   │ Magic Signature    │ uint16 (HEX)    │ 0x534B     │
│   2    │  1   │ Version & Flags    │ uint8  (HEX)    │ see below  │
│   3    │  1   │ Message Type       │ uint8  (HEX)    │ see below  │
│   4    │  2   │ Sequence Number    │ uint16 (DEC)    │            │
│   6    │  2   │ Payload Length (N) │ uint16 (DEC)    │            │
│   8    │  4   │ Epoch Timestamp    │ uint32 (DEC)    │ UTC secs   │
├────────────────────── PAYLOAD (N bytes) ──────────────────────────┤
│  12    │  N   │ Payload Data       │ UTF-8 / XOR     │            │
├────────────────────── TRAILER (4 bytes) ──────────────────────────┤
│ 12+N   │  4   │ CRC-32             │ uint32 (HEX)    │ IEEE 802.3 │
└───────────────────────────────────────────────────────────────────┘

Version & Flags byte (offset 2):
  Bits 7-4 (0xF0): Protocol Version (= 1)
  Bit 3    (0x08): ACK_REQ    — request acknowledgement
  Bit 2    (0x04): ENCRYPTED  — payload XOR'd with key 0x5A
  Bit 1    (0x02): COMPRESSED — reserved for future use
  Bit 0    (0x01): URGENT     — security alert priority

Message Types:
  0x01 = AUTH_REQ      Authentication request
  0x02 = ACK_RESP      Acknowledgement response
  0x03 = DATA_TELEM    Telemetry data
  0x04 = CMD_EXEC      Command execution
  0x05 = ALERT_SEC     Security alert
  0x06 = HEARTBEAT     Keep-alive
```

---

## 🧪 Test Scenarios (stcp_client.py)

| # | Type | Seq | Flags | Purpose |
|---|------|-----|-------|---------|
| 1 | AUTH_REQ | 101 | 0x08 (ACK_REQ) | Normal auth — expect ACK reply |
| 2 | DATA_TELEM | 102 | 0x04 (ENCRYPTED) | XOR-encrypted telemetry data |
| 3 | CMD_EXEC | 103 | 0x09 (ACK_REQ+URGENT) | Urgent command — expect ACK reply |
| 4 | ALERT_SEC | 104 | 0x01 (URGENT) | Intrusion detection alert |
| 5 | HEARTBEAT | 105 | 0x00 | Simple keep-alive |
| 6 | DATA_TELEM | 106 | 0x08 (ACK_REQ) | **Tampered CRC** — should be rejected |

---

## 📌 Installing the Dissector Permanently (Optional)

Copy `stcp_dissector.lua` to your Wireshark personal plugins directory:

```bash
# macOS
cp stcp_dissector.lua ~/.local/lib/wireshark/plugins/

# Linux
cp stcp_dissector.lua ~/.local/lib/wireshark/plugins/

# Windows
copy stcp_dissector.lua %APPDATA%\Wireshark\plugins\
```

Then restart Wireshark — the dissector loads automatically for port 9999.

---

## 📄 License

Academic project — free to use for educational purposes.

---

*Built for RTU 7CS4-22 Experiment 4 — Wireshark Lua Dissector for a Custom Protocol*
