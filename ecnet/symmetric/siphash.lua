-- SipHash-2-4 - A very fast message authentication code

local util = require("ecnet.util")

local bxor = bit32.bxor
local band = bit32.band
local rshift = bit32.rshift
local mt = util.byteTableMT

local function pad(m)
    local len = #m
    while (#m % 8 ~= 7) do
        m[#m + 1] = 0
    end
    m[#m + 1] = len % 256
end

local function sipRound(v00, v01, v10, v11, v20, v21, v30, v31)
    local t1, t2

    v00 = v00 + v10
    v01 = (v01 + v11 + (v00 > 0xffffffff and 1 or 0)) % 0x100000000
    v00 = v00 % 0x100000000
    v20 = v20 + v30
    v21 = (v21 + v31 + (v20 > 0xffffffff and 1 or 0)) % 0x100000000
    v20 = v20 % 0x100000000
    t1 = band(v10, 0xfff80000) / 0x80000
    t2 = band(v11, 0xfff80000) / 0x80000
    v10 = v10 * 0x2000 + t2
    v11 = v11 * 0x2000 + t1
    t1 = band(v30, 0xffff0000) / 0x10000
    t2 = band(v31, 0xffff0000) / 0x10000
    v30 = v30 * 0x10000 + t2
    v31 = v31 * 0x10000 + t1
    v10 = bxor(v10, v00)
    v11 = bxor(v11, v01)
    v30 = bxor(v30, v20)
    v31 = bxor(v31, v21)
    v00, v01 = v01, v00
    v20 = v20 + v10
    v21 = (v21 + v11 + (v20 > 0xffffffff and 1 or 0)) % 0x100000000
    v20 = v20 % 0x100000000
    v00 = v00 + v30
    v01 = (v01 + v31 + (v00 > 0xffffffff and 1 or 0)) % 0x100000000
    v00 = v00 % 0x100000000
    t1 = band(v10, 0xffff8000) / 0x8000
    t2 = band(v11, 0xffff8000) / 0x8000
    v10 = v10 * 0x20000 + t2
    v11 = v11 * 0x20000 + t1
    t1 = band(v30, 0xfffff800) / 0x800
    t2 = band(v31, 0xfffff800) / 0x800
    v30 = v30 * 0x200000 + t2
    v31 = v31 * 0x200000 + t1
    v10 = bxor(v10, v20)
    v11 = bxor(v11, v21)
    v30 = bxor(v30, v00)
    v31 = bxor(v31, v01)
    v20, v21 = v21, v20

    return v00, v01, v10, v11, v20, v21, v30, v31
end

local function mac(message, key)
    local k = type(key) == "table" and {string.char(unpack(key)):byte(1, -1)} or {tostring(key):byte(1, -1)}
    local m = type(message) == "table" and {string.char(unpack(message)):byte(1, -1)} or {tostring(message):byte(1, -1)}
    assert(#k == 16, "SipHash: Invalid key length ("..#k.."), must be 16")

    -- Pad
    pad(m)

    -- Initialize
    local v00 = bxor(k[1], k[2] * 0x100, k[3] * 0x10000, k[4] * 0x1000000, 0x70736575)
    local v01 = bxor(k[5], k[6] * 0x100, k[7] * 0x10000, k[8] * 0x1000000, 0x736f6d65)
    local v10 = bxor(k[9], k[10] * 0x100, k[11] * 0x10000, k[12] * 0x1000000, 0x6e646f6d)
    local v11 = bxor(k[13], k[14] * 0x100, k[15] * 0x10000, k[16] * 0x1000000, 0x646f7261)
    local v20 = bxor(k[1], k[2] * 0x100, k[3] * 0x10000, k[4] * 0x1000000, 0x6e657261)
    local v21 = bxor(k[5], k[6] * 0x100, k[7] * 0x10000, k[8] * 0x1000000, 0x6c796765)
    local v30 = bxor(k[9], k[10] * 0x100, k[11] * 0x10000, k[12] * 0x1000000, 0x79746573)
    local v31 = bxor(k[13], k[14] * 0x100, k[15] * 0x10000, k[16] * 0x1000000, 0x74656462)

    -- Compress
    for i = 1, #m, 8 do
        v30 = bxor(m[i], m[i+1] * 0x100, m[i+2] * 0x10000, m[i+3] * 0x1000000, v30)
        v31 = bxor(m[i+4], m[i+5] * 0x100, m[i+6] * 0x10000, m[i+7] * 0x1000000, v31)
        v00, v01, v10, v11, v20, v21, v30, v31 = sipRound(v00, v01, v10, v11, v20, v21, v30, v31)
        v00, v01, v10, v11, v20, v21, v30, v31 = sipRound(v00, v01, v10, v11, v20, v21, v30, v31)
        v00 = bxor(m[i], m[i+1] * 0x100, m[i+2] * 0x10000, m[i+3] * 0x1000000, v00)
        v01 = bxor(m[i+4], m[i+5] * 0x100, m[i+6] * 0x10000, m[i+7] * 0x1000000, v01)

        if i % 64000 == 0 then
            os.queueEvent("")
            os.pullEvent("")
        end
    end

    -- Finalize
    v20 = bxor(v20, 0xff)
    v00, v01, v10, v11, v20, v21, v30, v31 = sipRound(v00, v01, v10, v11, v20, v21, v30, v31)
    v00, v01, v10, v11, v20, v21, v30, v31 = sipRound(v00, v01, v10, v11, v20, v21, v30, v31)
    v00, v01, v10, v11, v20, v21, v30, v31 = sipRound(v00, v01, v10, v11, v20, v21, v30, v31)
    v00, v01, v10, v11, v20, v21, v30, v31 = sipRound(v00, v01, v10, v11, v20, v21, v30, v31)
    
    local r0 = bxor(v00, v10, v20, v30)
    local r1 = bxor(v01, v11, v21, v31)

    local result = {
        rshift(r1, 24) % 256,
        rshift(r1, 16) % 256,
        rshift(r1, 8) % 256,
        r1 % 256,
        rshift(r0, 24) % 256,
        rshift(r0, 16) % 256,
        rshift(r0, 8) % 256,
        r0 % 256
    }

    return setmetatable(result, mt)
end

return {
    mac = mac
}
