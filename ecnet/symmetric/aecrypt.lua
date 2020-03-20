-- aecrypt.lua - Authenticated encryption (currently incompatible with pastebin ecc)

local chacha20 = require("ecnet.symmetric.chacha20")
local sha256 = require("ecnet.symmetric.sha256")
local siphash = require("ecnet.symmetric.siphash")
local random = require("ecnet.symmetric.random")
local byteTableMT = require("ecnet.util").byteTableMT

local function encrypt(data, key)
    local encKey = sha256.hmac("encKey\8\1", key)
    local macKey = sha256.hmac("macKey\8\1", key)
    
    local nonce = {unpack(random.random(), 1, 12)}
    local ciphertext = chacha20.crypt(data, encKey, nonce, 1, 8)
    
    local result = nonce
    for i = 1, #ciphertext do
        result[#result + 1] = ciphertext[i]
    end
    local mac = siphash.mac(result, {unpack(macKey, 1, 16)})
    for i = 1, #mac do
        result[#result + 1] = mac[i]
    end

    return setmetatable(result, byteTableMT)
end

local function decrypt(data, key)
    local data = type(data) == "table" and {unpack(data)} or {tostring(data):byte(1,-1)}

    local encKey = sha256.hmac("encKey\8\1", key)
    local macKey = sha256.hmac("macKey\8\1", key)
    
    local mac = siphash.mac({unpack(data, 1, #data - 8)}, {unpack(macKey, 1, 16)})
    local messageMac = {unpack(data, #data - 7)}
    local ciphertext = {unpack(data, 13, #data - 8)}
    
    assert(mac:isEqual(messageMac), "invalid mac")
    
    local nonce = {unpack(data, 1, 12)}
    local result = chacha20.crypt(ciphertext, encKey, nonce, 1, 8)

    return setmetatable(result, byteTableMT)
end

return {
    encrypt = encrypt,
    decrypt = decrypt
}