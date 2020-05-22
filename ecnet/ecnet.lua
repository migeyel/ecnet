-- Ecnet - Simple secure network messages for Computercraft

-- Prevent two instances from exising in the same environment
if package.loaded["ecnet"] and arg[1] ~= "ecnet" then
    return package.loaded["ecnet"]
end

local util = require("ecnet.util")
local cbor = require("ecnet.cbor")
local sha256 = require("ecnet.symmetric.sha256")
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
local function makeAddressRequest(networkAPI, otherAddress)
    -- Make request
    local request = {
        type = "addressRequest",
        from = ownAddress,
        to = otherAddress,
    }
    networkAPI.send(CHANNEL, request)

    -- Make request secrets
    local requestSecrets = {
        otherAddress = otherAddress
    }

    return requestSecrets
end

-- Makes and sends a connection request
local function makeConnectionRequest(networkAPI, otherPublicKey)
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
    networkAPI.send(CHANNEL, request)

    -- Make request secrets
    local requestSecrets = {
        ephemeralSecretKey = tostring(ownEphemeralSecretKey),
        sharedSecret = sharedSecret,
        otherAddress = otherAddress
    }

    return requestSecrets
end

-- Sends the response for an address resolution request
local function processAddressRequest(networkAPI, request)
    -- Public data
    local otherAddress = request.from

    -- Make response
    local response = {
        type = "addressResponse",
        from = ownAddress,
        to = otherAddress,
        publicKey = tostring(ownPublicKey)
    }
    networkAPI.send(CHANNEL, response)
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
local function processConnectionRequest(networkAPI, request)
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
    local senderEncryptionKey = sha256.hmac("senderEncryptionKey", masterKey)
    local senderMacKey = {unpack(sha256.hmac("senderMacKey", masterKey), 1,16)}
    local receiverEncryptionKey = sha256.hmac("receiverEncryptionKey", masterKey)
    local receiverMacKey = {unpack(sha256.hmac("receiverMacKey", masterKey), 1, 16)}
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

    -- Make new session
    sessions[otherAddress] = {
        publicKey = otherPublicKey,
        sharedSecret = sharedSecret,
        ownEncryptionKey = receiverEncryptionKey,
        ownMacKey = receiverMacKey,
        otherEncryptionKey = senderEncryptionKey,
        otherMacKey = senderMacKey,
        counter = counter
    }
    networkAPI.send(CHANNEL, response)
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
    local senderEncryptionKey = sha256.hmac("senderEncryptionKey", masterKey)
    local senderMacKey = {unpack(sha256.hmac("senderMacKey", masterKey), 1,16)}
    local receiverEncryptionKey = sha256.hmac("receiverEncryptionKey", masterKey)
    local receiverMacKey = {unpack(sha256.hmac("receiverMacKey", masterKey), 1, 16)}
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

    -- Make new session
    sessions[otherAddress] = {
        publicKey = otherPublicKey,
        sharedSecret = sharedSecret,
        ownEncryptionKey = senderEncryptionKey,
        ownMacKey = senderMacKey,
        otherEncryptionKey = receiverEncryptionKey,
        otherMacKey = receiverMacKey,
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
    local otherEncryptionKey = sessions[otherAddress].otherEncryptionKey
    local otherMacKey = sessions[otherAddress].otherMacKey

    -- Decrypt data
    local outerLayer = aecrypt.decrypt(ciphertext, otherEncryptionKey, otherMacKey)
    outerLayer = tostring(outerLayer)
    local messageCounter = 0
    for i = 1, 6 do
        messageCounter = messageCounter * 256
        messageCounter = messageCounter + outerLayer:byte(7 - i)
    end
    local dataLengthMod256 = outerLayer:byte(7)
    local dataLength = #outerLayer - 7 - ((-dataLengthMod256 - 1) % 256)
    local data = outerLayer:sub(8, dataLength + 7)
    data = cbor.decode(data)

    -- Assert private validity
    assert(messageCounter > sessionCounter)
    
    -- Increment session counter
    sessions[otherAddress].counter = messageCounter

    return otherAddress, data
end

-- Adds new messages to a queue and/or processes messages from the end of it
-- Meant to be run as a coroutine
-- Add messages to the queue as the first resume argument
-- Process existing messages in the queue by resuming with a new message or nil
-- Note: The symmetric decryption functions already queue their own events, so all
-- messages will eventually be processed even if no other events are queued
local function processMessage(message)
    local internalCoro
    local messageQueue = {message}
    local isProcessing = false
    local currentMessage

    while true do
        if not isProcessing then
            -- Take a message from the queue and process it
            if #messageQueue > 0 then
                currentMessage = table.remove(messageQueue, 1)
                internalCoro = coroutine.create(internalProcessMessage)
                isProcessing = true
            end
        end
        if isProcessing then
            local success, sender, data = coroutine.resume(internalCoro, currentMessage)
            currentMessage = nil
            if coroutine.status(internalCoro) == "dead" then
                if success then
                    os.queueEvent("ecnet_message", sender, data)
                end
                isProcessing = false
            end
        end
        messageQueue[#messageQueue + 1] = coroutine.yield()
    end
end

local wrappedProcessMessage = coroutine.wrap(processMessage)

-- Listens to received messages, processes them and queues events
-- Can handle address requests, connection requests and messages
-- Queues event {"ecnet_message", address_from, message}
-- Queues event {"ecnet_connection", address_from}
local function listen(networkAPI)
    parallel.waitForAny(
        function()
            while true do
                os.pullEvent()
                wrappedProcessMessage()
            end
        end,
        function()
            while true do
                while true do
                    local channel, received = networkAPI.receive()

                    if channel ~= CHANNEL then break end
                    if type(received) ~= "table" then break end
                    if received.to ~= ownAddress then break end

                    if received.type == "addressRequest" then
                        pcall(processAddressRequest, networkAPI, received)
                    elseif received.type == "connectionRequest" then
                        local success = pcall(
                            processConnectionRequest,
                            networkAPI,
                            received
                        )

                        if success then
                            os.queueEvent("ecnet_connection", received.from)
                        end
                    elseif received.type == "message" then
                        wrappedProcessMessage(received)
                    end
                end
            end
        end
    )
end

-- Performs the connection handshake to an address
local function connect(networkAPI, address, timeout)
    local returned = parallel.waitForAny(
        function()
            sleep(timeout)
        end,
        function()
            -- Get public key
            local otherPublicKey
            if sessions[address] then
                otherPublicKey = sessions[address].publicKey
            else
                local requestSecrets = makeAddressRequest(networkAPI, address)

                while true do
                    local channel, received = networkAPI.receive()

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
            local requestSecrets = makeConnectionRequest(networkAPI, otherPublicKey)
            while true do
                local channel,received = networkAPI.receive()

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
        function()
            listen(networkAPI)
        end
    )

    return (returned == 2)
end

-- Sends a message with data to an address
-- Returns false if no session is present
-- Returns true if the message has been sent
local function send(networkAPI, otherAddress, data)
    if not sessions[otherAddress] then
        return false
    end

    -- Private data
    local ownEncryptionKey = sessions[otherAddress].ownEncryptionKey
    local ownMacKey = sessions[otherAddress].ownMacKey

    -- Encrypt data
    data = cbor.encode(data)
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
    local ciphertext = aecrypt.encrypt(outerLayer, ownEncryptionKey, ownMacKey)

    -- Send message
    local message = {
        type = "message",
        from = ownAddress,
        to = otherAddress,
        ciphertext = ciphertext,
        counter = messageCounter
    }
    networkAPI.send(CHANNEL, message)

    return true
end

-- Receives messages
-- Returns the sender and the message contents
-- Uses listen() internally
local function receive(networkAPI, addressFilter, timeout)
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
        function()
            listen(networkAPI)
        end
    )

    if returned == 2 then
        return from, message
    else
        return nil
    end
end

-- External functions

local function wrap(networkObject)
    networkObject.open(CHANNEL)
    local networkAPI = {}

    if networkObject.receive then
        -- Socket or other API
        networkAPI.send = networkObject.send
        networkAPI.receive = networkObject.receive
    else
        -- Modem
        networkAPI.send = function(channel, msg)
            return networkObject.transmit(channel, channel, msg)
        end
        networkAPI.receive = function()
            local _, _, channel, _, msg = os.pullEvent("modem_message")
            return channel, msg
        end
    end

    return {
        listen = function()
            return listen(networkAPI)
        end,

        connect = function(address, timeout)
            return connect(networkAPI, address, timeout)
        end,

        send = function(address, message)
            return send(networkAPI, address, message)
        end,

        receive = function(addressFilter, timeout)
            return receive(networkAPI, addressFilter, timeout)
        end
    }
end

local ecnet = {
    wrap = wrap,
    address = ownAddress
}

package.loaded["ecnet"] = ecnet

return ecnet
