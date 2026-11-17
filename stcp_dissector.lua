--[[
    STCP v1.0 Wireshark Lua Dissector
    SKIT Telemetry & Command Protocol
    B.Tech VII Semester Cyber Security Lab (7CS4-22 / 7CIT4-22)

    Usage:
        wireshark -X lua_script:stcp_dissector.lua -r stcp_sample_capture.pcap
        tshark   -X lua_script:stcp_dissector.lua -r stcp_sample_capture.pcap -V

    Display Filters:
        stcp                        — all STCP packets
        stcp.msg_type == 0x05       — ALERT_SEC
        stcp.flags.urgent == 1      — urgent frames
        stcp.crc_status == 2        — CRC mismatches
]]

-- ╔═══════════════════════════════════════════════════════════════════╗
-- ║  Protocol Registration                                          ║
-- ╚═══════════════════════════════════════════════════════════════════╝
local stcp_proto = Proto("stcp", "SKIT Telemetry & Command Protocol (STCP v1.0)")

-- ╔═══════════════════════════════════════════════════════════════════╗
-- ║  Message Type Value-String Table                                ║
-- ╚═══════════════════════════════════════════════════════════════════╝
local msg_type_names = {
    [0x01] = "AUTH_REQ",
    [0x02] = "ACK_RESP",
    [0x03] = "DATA_TELEM",
    [0x04] = "CMD_EXEC",
    [0x05] = "ALERT_SEC",
    [0x06] = "HEARTBEAT",
}

-- CRC status values: 0=not checked, 1=Good, 2=Bad
local crc_status_names = {
    [0] = "Not Verified",
    [1] = "Good",
    [2] = "Bad",
}

-- ╔═══════════════════════════════════════════════════════════════════╗
-- ║  ProtoField Definitions                                         ║
-- ╚═══════════════════════════════════════════════════════════════════╝
local pf_magic      = ProtoField.uint16("stcp.magic",      "Magic Signature",   base.HEX)
local pf_ver_flags  = ProtoField.uint8 ("stcp.ver_flags",  "Version & Flags",   base.HEX)
local pf_version    = ProtoField.uint8 ("stcp.version",    "Protocol Version",  base.DEC, nil, 0xF0)
local pf_flags      = ProtoField.uint8 ("stcp.flags",      "Control Flags",     base.HEX, nil, 0x0F)
local pf_flag_ack   = ProtoField.bool  ("stcp.flags.ack_req", "ACK Requested",  8, nil, 0x08)
local pf_flag_enc   = ProtoField.bool  ("stcp.flags.enc",     "Encrypted",      8, nil, 0x04)
local pf_flag_comp  = ProtoField.bool  ("stcp.flags.comp",    "Compressed",     8, nil, 0x02)
local pf_flag_urg   = ProtoField.bool  ("stcp.flags.urgent",  "Urgent",         8, nil, 0x01)
local pf_msg_type   = ProtoField.uint8 ("stcp.msg_type",   "Message Type",      base.HEX, msg_type_names)
local pf_seq        = ProtoField.uint16("stcp.seq",        "Sequence Number",   base.DEC)
local pf_pay_len    = ProtoField.uint16("stcp.payload_len","Payload Length",     base.DEC)
local pf_timestamp  = ProtoField.uint32("stcp.timestamp",  "Epoch Timestamp",   base.DEC)
local pf_payload    = ProtoField.string("stcp.payload",    "Payload",           base.UNICODE)
local pf_decrypted  = ProtoField.string("stcp.decrypted",  "Decrypted Payload", base.UNICODE)
local pf_crc        = ProtoField.uint32("stcp.crc",        "CRC-32 Trailer",    base.HEX)
local pf_crc_calc   = ProtoField.uint32("stcp.crc_calc",   "CRC-32 Calculated", base.HEX)
local pf_crc_status = ProtoField.uint8 ("stcp.crc_status", "CRC Status",        base.DEC, crc_status_names)

stcp_proto.fields = {
    pf_magic, pf_ver_flags, pf_version, pf_flags,
    pf_flag_ack, pf_flag_enc, pf_flag_comp, pf_flag_urg,
    pf_msg_type, pf_seq, pf_pay_len, pf_timestamp,
    pf_payload, pf_decrypted, pf_crc, pf_crc_calc, pf_crc_status,
}

-- ╔═══════════════════════════════════════════════════════════════════╗
-- ║  Expert Info (ProtoExpert)                                      ║
-- ╚═══════════════════════════════════════════════════════════════════╝
local ef_bad_magic  = ProtoExpert.new("stcp.expert.bad_magic",  "Invalid Magic Signature",   expert.group.PROTOCOL, expert.severity.ERROR)
local ef_truncated  = ProtoExpert.new("stcp.expert.truncated",  "Truncated STCP Frame",      expert.group.MALFORMED, expert.severity.ERROR)
local ef_urgent     = ProtoExpert.new("stcp.expert.urgent",     "Urgent Security Flag Set",  expert.group.SEQUENCE,  expert.severity.WARN)
local ef_bad_crc    = ProtoExpert.new("stcp.expert.bad_crc",    "CRC-32 Checksum Mismatch",  expert.group.CHECKSUM,  expert.severity.ERROR)

stcp_proto.experts = { ef_bad_magic, ef_truncated, ef_urgent, ef_bad_crc }

-- ╔═══════════════════════════════════════════════════════════════════╗
-- ║  Pure-Lua IEEE 802.3 CRC-32 (using Wireshark's bit library)    ║
-- ╚═══════════════════════════════════════════════════════════════════╝

-- Pre-compute the CRC-32 lookup table (polynomial 0xEDB88320, reflected)
local crc32_table = {}
do
    local bxor  = bit.bxor
    local band  = bit.band
    local rshift = bit.rshift
    for i = 0, 255 do
        local crc = i
        for _ = 1, 8 do
            if band(crc, 1) == 1 then
                crc = bxor(rshift(crc, 1), 0xEDB88320)
            else
                crc = rshift(crc, 1)
            end
        end
        crc32_table[i] = crc
    end
end

--- Compute IEEE 802.3 CRC-32 over a Wireshark TvbRange (ByteArray-compatible).
--- @param tvb_range  TvbRange to hash
--- @return number    unsigned CRC-32
local function crc32_tvb(tvb_range)
    local bxor   = bit.bxor
    local band   = bit.band
    local rshift = bit.rshift
    local crc = 0xFFFFFFFF
    local len = tvb_range:len()
    for i = 0, len - 1 do
        local byte = tvb_range:range(i, 1):uint()
        local index = band(bxor(crc, byte), 0xFF)
        crc = bxor(rshift(crc, 8), crc32_table[index])
    end
    return band(bxor(crc, 0xFFFFFFFF), 0xFFFFFFFF)
end

-- ╔═══════════════════════════════════════════════════════════════════╗
-- ║  XOR Decryption Helper                                          ║
-- ╚═══════════════════════════════════════════════════════════════════╝
local XOR_KEY = 0x5A

local function xor_decrypt_tvb(tvb_range)
    local out = {}
    for i = 0, tvb_range:len() - 1 do
        local b = tvb_range:range(i, 1):uint()
        out[#out + 1] = string.char(bit.bxor(b, XOR_KEY))
    end
    return table.concat(out)
end

-- ╔═══════════════════════════════════════════════════════════════════╗
-- ║  Dissector Function                                             ║
-- ╚═══════════════════════════════════════════════════════════════════╝
local HEADER_SIZE = 12   -- 2+1+1+2+2+4
local CRC_SIZE    = 4

function stcp_proto.dissector(tvb, pinfo, tree)
    local buf_len = tvb:len()

    -- Minimum frame = header(12) + crc(4) = 16 bytes
    if buf_len < HEADER_SIZE + CRC_SIZE then
        return 0   -- not our protocol
    end

    -- ── Magic check ────────────────────────────────────────────────
    local magic = tvb:range(0, 2):uint()
    if magic ~= 0x534B then
        return 0   -- not STCP
    end

    pinfo.cols.protocol:set("STCP")

    local subtree = tree:add(stcp_proto, tvb(), "STCP v1.0")

    -- ── Header fields ──────────────────────────────────────────────
    subtree:add(pf_magic, tvb:range(0, 2))

    local ver_flags_range = tvb:range(2, 1)
    local ver_flags_val   = ver_flags_range:uint()
    local vf_tree = subtree:add(pf_ver_flags, ver_flags_range)
    vf_tree:add(pf_version,  ver_flags_range)
    vf_tree:add(pf_flags,    ver_flags_range)
    vf_tree:add(pf_flag_ack, ver_flags_range)
    vf_tree:add(pf_flag_enc, ver_flags_range)
    vf_tree:add(pf_flag_comp, ver_flags_range)
    vf_tree:add(pf_flag_urg, ver_flags_range)

    local flags = bit.band(ver_flags_val, 0x0F)

    local msg_type_range = tvb:range(3, 1)
    local msg_type_val   = msg_type_range:uint()
    subtree:add(pf_msg_type, msg_type_range)

    subtree:add(pf_seq,      tvb:range(4, 2))
    local seq_val = tvb:range(4, 2):uint()

    local pay_len_range = tvb:range(6, 2)
    local pay_len_val   = pay_len_range:uint()
    subtree:add(pf_pay_len,  pay_len_range)

    subtree:add(pf_timestamp, tvb:range(8, 4))

    -- ── Truncation check ───────────────────────────────────────────
    local expected = HEADER_SIZE + pay_len_val + CRC_SIZE
    if buf_len < expected then
        subtree:add_proto_expert_info(ef_truncated,
            string.format("Need %d bytes, have %d", expected, buf_len))
        return buf_len
    end

    -- ── Payload ────────────────────────────────────────────────────
    if pay_len_val > 0 then
        local pay_range = tvb:range(HEADER_SIZE, pay_len_val)
        subtree:add(pf_payload, pay_range)

        if bit.band(flags, 0x04) ~= 0 then
            local decrypted = xor_decrypt_tvb(pay_range)
            subtree:add(pf_decrypted, pay_range, decrypted,
                        "Decrypted Payload: " .. decrypted)
        end
    end

    -- ── CRC-32 Verification ────────────────────────────────────────
    local crc_offset = HEADER_SIZE + pay_len_val
    local crc_range  = tvb:range(crc_offset, 4)
    local crc_recv   = crc_range:uint()
    subtree:add(pf_crc, crc_range)

    local crc_calc = crc32_tvb(tvb:range(0, crc_offset))
    local crc_calc_item = subtree:add(pf_crc_calc, crc_range, crc_calc,
        string.format("CRC-32 Calculated: 0x%08X", crc_calc))

    local status_val
    if crc_recv == crc_calc then
        status_val = 1   -- Good
        subtree:add(pf_crc_status, crc_range, status_val, "CRC Status: Good")
    else
        status_val = 2   -- Bad
        local bad_item = subtree:add(pf_crc_status, crc_range, status_val,
            "CRC Status: Bad")
        subtree:add_proto_expert_info(ef_bad_crc,
            string.format("CRC mismatch: received 0x%08X, calculated 0x%08X",
                          crc_recv, crc_calc))
    end

    -- ── Expert: Urgent flag ────────────────────────────────────────
    if bit.band(flags, 0x01) ~= 0 then
        subtree:add_proto_expert_info(ef_urgent, "Urgent security flag is set")
    end

    -- ── Info Column ────────────────────────────────────────────────
    local type_name = msg_type_names[msg_type_val] or string.format("0x%02X", msg_type_val)
    local crc_tag = (status_val == 1) and "CRC:OK" or "CRC:BAD"
    pinfo.cols.info:set(string.format("STCP %s  Seq=%d  %s", type_name, seq_val, crc_tag))

    return expected
end

-- ╔═══════════════════════════════════════════════════════════════════╗
-- ║  Register on UDP & TCP port 9999                                ║
-- ╚═══════════════════════════════════════════════════════════════════╝
local udp_table = DissectorTable.get("udp.port")
local tcp_table = DissectorTable.get("tcp.port")
udp_table:add(9999, stcp_proto)
tcp_table:add(9999, stcp_proto)
