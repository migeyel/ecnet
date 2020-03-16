-- Elliptic Curve Cryptography in Computercraft

local byteTableMT = require("ecnet.util").byteTableMT
local curve = require("ecnet.ecc.curve")
local modq = require("ecnet.ecc.modq")
local sha256 = require("ecnet.symmetric.sha256")
local chacha20 = require("ecnet.symmetric.chacha20")
local siphash = require("ecnet.symmetric.siphash")
local random = require("ecnet.symmetric.random")

local function keypair(seed)
    seed = seed or random.random()
    local x = modq.hashModQ(seed)
    local Y = curve.G * x

    local privateKey = x:encode()
    local publicKey = Y:encode()

    return privateKey, publicKey
end

local function exchange(privateKey, publicKey)
    local x = modq.decodeModQ(privateKey)
    local Y = curve.pointDecode(publicKey)

    local Z = Y * x

    local sharedSecret = sha256.digest(Z:encode())

    return sharedSecret
end

local function sign(privateKey, message)
    local message = type(message) == "table" and string.char(unpack(message)) or tostring(message)
    local privateKey = type(privateKey) == "table" and string.char(unpack(privateKey)) or tostring(privateKey)
    local x = modq.decodeModQ(privateKey)
    local k = modq.hashModQ(message .. privateKey)
    local R = curve.G * k
    local e = modq.hashModQ(message .. tostring(R))
    local s = k - x * e

    e = e:encode()
    s = s:encode()

    local result = e
    for i = 1, #s do
        result[#result + 1] = s[i]
    end

    return setmetatable(result, byteTableMT)
end

local function verify(publicKey, message, signature)
    local message = type(message) == "table" and string.char(unpack(message)) or tostring(message)
    local Y = curve.pointDecode(publicKey)
    local e = modq.decodeModQ({unpack(signature, 1, #signature / 2)})
    local s = modq.decodeModQ({unpack(signature, #signature / 2 + 1)})
    local Rv = curve.G * s + Y * e
    local ev = modq.hashModQ(message .. tostring(Rv))

    return ev == e
end

return {
    keypair = keypair,
    exchange = exchange,
    sign = sign,
    verify = verify
}