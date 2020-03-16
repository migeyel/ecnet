-- Ecnet - Simple secure network messages for Computercraft

local util = require("ecnet.util")
local sha256 = require("ecnet.symmetric.sha256")
local chacha20 = require("ecnet.symmetric.chacha20")
local siphash = require("ecnet.symmetric.siphash")
local aecrypt = require("ecnet.symmetric.aecrypt")
local random = require("ecnet.symmetric.random")
local ecc = require("ecnet.ecc.ecc")

local CHANNEL = 33635
local SEED_PATH = "/.ecnet-secretseed"

local programInitEpoch = os.epoch("utc")
local sessions = {}
local listening = false

local function makeAddress(fixedKey)
    local hash = sha256.digest(fixedKey)
    local hashHex = hash:toHex()
    local address = ""
    address = address .. hashHex:sub(1, 4)
    address = address .. ":"
    address = address .. hashHex:sub(5, 8)
    address = address .. ":"
    address = address .. hashHex:sub(9, 12)
    address = address .. ":"
    address = address .. hashHex:sub(13, 16)
    address = address .. ":"
    address = address .. hashHex:sub(17, 20)

    return address
end

if not fs.exists(SEED_PATH) then
    local seed = random.random()
    seed = string.char(unpack(seed))
    util.saveFile(SEED_PATH, seed)
end
local seed = util.loadFile(SEED_PATH)
local ownSecretKey, ownPublicKey = ecc.keypair(seed)
local ownAddress = makeAddress(ownPublicKey)

-- Internal network functions

-- Makes and sends an address resolution request
local function makeAddressRequest(modem, otherAddress)
    -- Make request
    local request = {
        type = "addressRequest",
        from = ownAddress,
        to = otherAddress,
    }
    modem.transmit(CHANNEL, CHANNEL, request)

    -- Make request secrets
    local requestSecrets = {
        otherAddress = otherAddress
    }

    return requestSecrets
end

-- Makes and sends a connection request
local function makeConnectionRequest(modem, otherPublicKey)
    -- Public data
    local otherAddress = makeAddress(otherPublicKey)

    -- Private data
    local sharedSecret
    if sessions[otherAddress] then
        sharedSecret = sessions[otherAddress].sharedSecret
    else
        sharedSecret = ecc.exchange(ownSecretKey, otherPublicKey)
    end
    local ownEphemeralSecretKey, ownEphemeralPublicKey = ecc.keypair()
    local ownTagKey = sha256.hmac("senderTagKey", sharedSecret)

    -- Make request
    local counter = os.epoch("utc")
    local ownTag = sha256.hmac(
        tostring(ownEphemeralPublicKey) .. tostring(counter),
        ownTagKey
    )
    local request = {
        type = "connectionRequest",
        from = ownAddress,
        to = otherAddress,
        publicKey = tostring(ownPublicKey),
        ephemeralPublicKey = tostring(ownEphemeralPublicKey),
        tag = tostring(ownTag):sub(1, 10),
        counter = counter
    }
    modem.transmit(CHANNEL, CHANNEL, request)

    -- Make request secrets
    local requestSecrets = {
        ephemeralSecretKey = tostring(ownEphemeralSecretKey),
        sharedSecret = sharedSecret,
        otherAddress = otherAddress
    }

    return requestSecrets
end

-- Sends the response for an address resolution request
local function processAddressRequest(modem, request)
    -- Public data
    local otherAddress = request.from

    -- Make response
    local response = {
        type = "addressResponse",
        from = ownAddress,
        to = otherAddress,
        publicKey = tostring(ownPublicKey)
    }
    modem.transmit(CHANNEL, CHANNEL, response)
end

-- Verifies validity of an address resolution response
local function processAddressResponse(requestSecrets, response)
    -- Public data
    local otherAddress = response.from
    local otherPublicKey = response.publicKey

    -- Assert public validity
    assert(requestSecrets.otherAddress == otherAddress)
    assert(type(otherPublicKey) == "string" and #otherPublicKey == 22)
    assert(makeAddress(otherPublicKey) == otherAddress)

    return otherPublicKey
end

-- Verifies authenticity of a connection request
-- Sends back a connection response
-- Creates a new session from the request
local function processConnectionRequest(modem, request)
    -- Public data
    local otherPublicKey = request.publicKey
    local otherEphemeralPublicKey = request.ephemeralPublicKey
    local otherAddress = request.from
    local otherTag = request.tag
    local counter = request.counter

    -- Assert public validity
    assert(type(otherPublicKey) == "string" and #otherPublicKey == 22)
    assert(type(otherEphemeralPublicKey) == "string")
    assert(#otherEphemeralPublicKey == 22)
    assert(makeAddress(otherPublicKey) == otherAddress)
    assert(type(otherTag) == "string" and #otherTag == 10)
    assert(type(counter) == "number")
    if sessions[otherAddress] then
        assert(counter > sessions[otherAddress].counter)
    else
        assert(counter > programInitEpoch)
    end

    -- Private data
    local sharedSecret
    if sessions[otherAddress] then
        sharedSecret = sessions[otherAddress].sharedSecret
    else
        sharedSecret = ecc.exchange(ownSecretKey, otherPublicKey)
    end
    local ownEphemeralSecretKey, ownEphemeralPublicKey = ecc.keypair()
    local ephemeralSharedSecret = ecc.exchange(
        ownEphemeralSecretKey,
        otherEphemeralPublicKey
    )
    local masterKey = sha256.hmac(ephemeralSharedSecret, sharedSecret)
    local senderSymmetricKey = sha256.hmac("senderSymmetricKeyKey", masterKey)
    local receiverSymmetricKey = sha256.hmac("receiverSymmetricKey", masterKey)
    local otherTagKey = sha256.hmac("senderTagKey", sharedSecret)
    local ownTagKey = sha256.hmac("receiverTagKey", masterKey)

    -- Assert private validity
    assert(
        tostring(
            sha256.hmac(
                otherEphemeralPublicKey .. tostring(counter),
                otherTagKey
            )
        ):sub(1, 10) == otherTag
    )

    -- Make response
    local counter = os.epoch("utc")
    local ownTag = sha256.hmac(
        tostring(ownEphemeralPublicKey) .. tostring(counter),
        ownTagKey
    )
    local response = {
        type = "connectionResponse",
        from = ownAddress,
        to = otherAddress,
        publicKey = tostring(ownPublicKey),
        ephemeralPublicKey = tostring(ownEphemeralPublicKey),
        tag = tostring(ownTag):sub(1, 10),
        counter = counter
    }
    modem.transmit(CHANNEL, CHANNEL, response)

    -- Make new session
    sessions[otherAddress] = {
        publicKey = otherPublicKey,
        sharedSecret = sharedSecret,
        ownSymmetricKey = receiverSymmetricKey,
        otherSymmetricKey = senderSymmetricKey,
        counter = counter
    }
end

-- Verifies authenticity of a connection response
-- Creates a new session from the response
local function processConnectionResponse(requestSecrets, response)
    -- Public data
    local otherPublicKey = response.publicKey
    local otherEphemeralPublicKey = response.ephemeralPublicKey
    local otherAddress = response.from
    local otherTag = response.tag
    local counter = response.counter

    -- Assert public validity
    assert(requestSecrets.otherAddress == otherAddress)
    assert(type(otherPublicKey) == "string" and #otherPublicKey == 22)
    assert(type(otherEphemeralPublicKey) == "string")
    assert(#otherEphemeralPublicKey == 22)
    assert(makeAddress(otherPublicKey) == otherAddress)
    assert(type(otherTag) == "string" and #otherTag == 10)
    assert(type(counter) == "number")

    -- Private data
    local ownEphemeralSecretKey = requestSecrets.ephemeralSecretKey
    local sharedSecret = requestSecrets.sharedSecret
    local ephemeralSharedSecret = ecc.exchange(
        ownEphemeralSecretKey,
        otherEphemeralPublicKey
    )
    local masterKey = sha256.hmac(ephemeralSharedSecret, sharedSecret)
    local senderSymmetricKey = sha256.hmac("senderSymmetricKeyKey", masterKey)
    local receiverSymmetricKey = sha256.hmac("receiverSymmetricKey", masterKey)
    local otherTagKey = sha256.hmac("receiverTagKey", masterKey)

    -- Assert private validity
    assert(
        tostring(
            sha256.hmac(
                otherEphemeralPublicKey .. tostring(counter),
                otherTagKey
            )
        ):sub(1, 10) == otherTag
    )

    -- Make session
    sessions[otherAddress] = {
        publicKey = otherPublicKey,
        sharedSecret = sharedSecret,
        ownSymmetricKey = senderSymmetricKey,
        otherSymmetricKey = receiverSymmetricKey,
        counter = counter
    }
end

-- Verifies authenticity and decrypts an incoming message
local function internalProcessMessage(message)
    -- Public data    
    local ciphertext = message.ciphertext
    local otherAddress = message.from
    local unauthCounter = message.counter
    local sessionCounter = sessions[otherAddress].counter

    -- Assert public validity
    assert(type(ciphertext) == "string")
    assert(type(otherAddress) == "string")
    assert(type(unauthCounter) == "number")
    assert(sessions[otherAddress])
    assert(unauthCounter > sessionCounter)

    -- Private data
    local otherSymmetricKey = sessions[otherAddress].otherSymmetricKey

    -- Decrypt data
    local outerLayer = aecrypt.decrypt(ciphertext, otherSymmetricKey)
    outerLayer = tostring(outerLayer)
    local messageCounter = 0
    for i = 1, 6 do
        messageCounter = messageCounter * 256
        messageCounter = messageCounter + outerLayer:byte(7 - i)
    end
    local dataLengthMod256 = outerLayer:byte(7)
    local dataLength = #outerLayer - 7 - ((-dataLengthMod256 - 1) % 256)
    local data = outerLayer:sub(8, dataLength + 7)

    -- Assert private validity
    assert(messageCounter > sessionCounter)
    
    -- Increment session counter
    sessions[otherAddress].counter = messageCounter

    return data
end

-- Guarantees atomic processing of messages
local function processMessage(message)
    local coro = coroutine.create(internalProcessMessage)
    local returned = {coroutine.resume(coro, message)}

    while coroutine.status(coro) ~= "dead" do
        returned = {coroutine.resume(coro)}
    end
    assert(returned[1], returned[2])

    return unpack(returned, 2)
end

-- Listens to received messages, processes them and queues events
-- Can handle address requests, connection requests and messages
-- Queues event {"ecnet_message", address_from, message}
-- Queues event {"ecnet_connection", address_from}
local function listen(modem)
    while true do
        while true do
            local _, _, channel, _, received = os.pullEvent("modem_message")

            if channel ~= CHANNEL then break end
            if type(received) ~= "table" then break end
            if received.to ~= ownAddress then break end

            if received.type == "addressRequest" then
                pcall(processAddressRequest, modem, received)
            elseif received.type == "connectionRequest" then
                local success = pcall(
                    processConnectionRequest,
                    modem,
                    received
                )

                if success then
                    os.queueEvent("ecnet_connection", received.from)
                end
            elseif received.type == "message" then
                local success, message = pcall(processMessage, received)

                if success then
                    os.queueEvent("ecnet_message", received.from, message)
                end
            end
        end
    end
end

-- Performs the connection handshake to an address
local function connect(modem, address, timeout)
    local returned = parallel.waitForAny(
        function() sleep(timeout) end,
        function()
            -- Get public key
            local otherPublicKey
            if sessions[address] then
                otherPublicKey = sessions[address].publicKey
            else
                local requestSecrets = makeAddressRequest(modem, address)

                while true do
                    local _, _, channel, _, received = os.pullEvent("modem_message")

                    if (
                        channel == CHANNEL
                        and type(received) == "table"
                        and received.to == ownAddress
                        and received.from == address
                        and received.type == "addressResponse"
                    ) then
                        local success
                        success, otherPublicKey = pcall(
                            processAddressResponse,
                            requestSecrets,
                            received
                        )
                        if success then break end
                    end
                end
            end

            -- Connect
            local requestSecrets = makeConnectionRequest(modem, otherPublicKey)
            while true do
                local _, _, channel, _, received = os.pullEvent("modem_message")

                if (
                    channel == CHANNEL
                    and type(received) == "table"
                    and received.to == ownAddress
                    and received.from == address
                    and received.type == "connectionResponse"
                ) then
                    local success = pcall(
                        processConnectionResponse,
                        requestSecrets,
                        received
                    )
                    if success then break end
                end
            end
        end,
        listen
    )

    return (returned == 2)
end

-- Sends a message with data to an address
-- Returns false if no session is present
-- Returns true if the message has been sent
local function send(modem, otherAddress, data)
    if not sessions[otherAddress] then
        return false
    end

    -- Private data
    local ownSymmetricKey = sessions[otherAddress].ownSymmetricKey

    -- Encrypt data
    local messageCounter = os.epoch("utc")
    local counterCopy = messageCounter
    local outerLayer = ""
    for i = 1, 6 do
        outerLayer = outerLayer .. string.char(counterCopy % 256)
        counterCopy = math.floor(counterCopy / 256)
    end
    outerLayer = outerLayer .. string.char(#data % 256)
    outerLayer = outerLayer .. data
    outerLayer = outerLayer .. ("\0"):rep((-#data - 1) % 256)
    local ciphertext = aecrypt.encrypt(outerLayer, ownSymmetricKey)

    -- Send message
    local message = {
        type = "message",
        from = ownAddress,
        to = otherAddress,
        ciphertext = tostring(ciphertext),
        counter = messageCounter
    }
    modem.transmit(CHANNEL, CHANNEL, message)

    return true
end

-- Receives messages
-- Returns the sender and the message contents
-- Uses listen() internally
local function receive(modem, addressFilter, timeout)
    local from, message
    local returned = parallel.waitForAny(
        function()
            if timeout then
                sleep(timeout)
            else
                while true do
                    coroutine.yield()
                end
            end
        end,
        function()
            while true do
                local _
                _, from, message = os.pullEvent("ecnet_message")
                
                if not addressFilter or from == addressFilter then
                    return
                end
            end
        end,
        function() listen(modem) end
    )

    if returned == 2 then
        return from, message
    else
        return nil
    end
end

-- External functions

local function wrap(modem)
    modem.open(CHANNEL)

    return {
        listen = function()
            return listen(modem)
        end,
        
        connect = function(address, timeout)
            return connect(modem, address, timeout)
        end,

        send = function(address, message)
            return send(modem, address, message)
        end,

        receive = function(addressFilter, timeout)
            return receive(modem, addressFilter, timeout)
        end
    }
end

return {
    wrap = wrap,
    address = ownAddress
}
