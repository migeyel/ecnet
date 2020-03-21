-- aecrypt.lua - Authenticated encryption

local chacha20 = require("ecnet.symmetric.chacha20")
local sha256 = require("ecnet.symmetric.sha256")
local siphash = require("ecnet.symmetric.siphash")
local random = require("ecnet.symmetric.random")
local util = require("ecnet.util")

local mt = util.byteTableMT

local function getNonceFromEpoch()
    local nonce = {}
    local epoch = os.epoch("utc")
    for i = 1, 7 do
        nonce[#nonce + 1] = epoch % 256
        epoch = epoch / 256
        epoch = epoch - epoch % 1
    end
    for i = 8, 12 do
        nonce[i] = math.random(0, 255)
    end

    return nonce
end

local function encrypt(data, encKey, macKey)
    local nonce = getNonceFromEpoch()
    local ciphertext = chacha20.crypt(data, encKey, nonce, 1, 8)

    local result = nonce
    for i = 1, #ciphertext do
        result[#result + 1] = ciphertext[i]
    end
    local mac = siphash.mac(result, {unpack(macKey, 1, 16)})
    for i = 1, #mac do
        result[#result + 1] = mac[i]
    end

    return setmetatable(result, mt)
end

local function decrypt(data, encKey, macKey)
    local data = type(data) == "table" and {unpack(data)} or {tostring(data):byte(1,-1)}
    
    local mac = siphash.mac({unpack(data, 1, #data - 8)}, {unpack(macKey, 1, 16)})
    local messageMac = {unpack(data, #data - 7)}
    local ciphertext = {unpack(data, 13, #data - 8)}

    assert(mac:isEqual(messageMac), "invalid mac")
    
    local nonce = {unpack(data, 1, 12)}
    local result = chacha20.crypt(ciphertext, encKey, nonce, 1, 8)

    return setmetatable(result, mt)
end

return {
    encrypt = encrypt,
    decrypt = decrypt
}