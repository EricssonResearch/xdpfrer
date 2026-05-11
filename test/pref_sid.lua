-- PREF SID dissector for Wireshark (Lua 5.4)
-- The Redundancy SID appears either as the outer IPv6 dst (nexthdr=41)
-- or as the last SID in the SRH segment list (segment[0] in wire order).

local pref = Proto("pref_sid", "PREF SID")

local f_loc    = ProtoField.bytes("pref.loc", "Locator", base.SPACE)
local f_funct  = ProtoField.uint16("pref.funct", "Function", base.HEX)
local f_flowid = ProtoField.uint32("pref.flow_id", "Flow-ID", base.HEX)
local f_seq    = ProtoField.uint16("pref.seq", "Sequence", base.DEC)
local f_resv   = ProtoField.uint16("pref.reserved", "Reserved", base.HEX)

pref.fields = { f_loc, f_funct, f_flowid, f_seq, f_resv }

local function decode_sid(sid_buf, pinfo, tree, label)
    if sid_buf(0, 2):uint() ~= 0x5f00 then return false end
    if sid_buf(8, 2):uint() == 0 then return false end

    local subtree = tree:add(pref, sid_buf, label)
    subtree:add(f_loc, sid_buf(0, 8))
    subtree:add(f_funct, sid_buf(8, 2))

    local a0 = sid_buf(10, 1):uint()
    local a1 = sid_buf(11, 1):uint()
    local a2 = sid_buf(12, 1):uint()
    local a3 = sid_buf(13, 1):uint()
    local a4 = sid_buf(14, 1):uint()
    local a5 = sid_buf(15, 1):uint()

    local flow_id  = (a0 << 12) | (a1 << 4) | (a2 >> 4)
    local seq      = ((a2 & 0xF) << 12) | (a3 << 4) | (a4 >> 4)
    local reserved = ((a4 & 0xF) << 8) | a5

    subtree:add(f_flowid, sid_buf(10, 3), flow_id):append_text(string.format(" (0x%05x)", flow_id))
    subtree:add(f_seq, sid_buf(12, 3), seq):append_text(string.format(" (0x%04x)", seq))
    subtree:add(f_resv, sid_buf(14, 2), reserved)

    pinfo.cols.info:append(" [PREF seq=" .. seq .. "]")
    return true
end

function pref.dissector(buf, pinfo, tree)
    if buf:len() < 54 then return end
    if buf(12, 2):uint() ~= 0x86dd then return end

    local nexthdr = buf(20, 1):uint()

    if nexthdr == 41 then
        -- IPv6-in-IPv6: Redundancy SID is the outer dst
        if buf:len() < 54 then return end
        decode_sid(buf(38, 16), pinfo, tree, "PREF Redundancy SID (outer IPv6 dst)")

    elseif nexthdr == 43 then
        -- SRH: Redundancy SID is segment[0] (last SID, first in wire order)
        local srh_offset = 54
        if buf:len() < srh_offset + 8 then return end
        if buf(srh_offset + 2, 1):uint() ~= 4 then return end

        -- segment[0] is at SRH + 8
        local sid_offset = srh_offset + 8
        if buf:len() < sid_offset + 16 then return end
        decode_sid(buf(sid_offset, 16), pinfo, tree, "PREF Redundancy SID (SRH last segment)")
    end
end

register_postdissector(pref)
