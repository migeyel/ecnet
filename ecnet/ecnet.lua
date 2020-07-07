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
local EPHEMERAL_REFRESH_MS = 43200000 -- 12 hours
local OLD_SEED_PATH = "/.ecnet-secretseed"
local SECRETS_PATH = settings.get("ecnet.secrets_path")
SECRETS_PATH = SECRETS_PATH or "/.ecnet_secrets"

local programInitEpoch = os.epoch("utc")
local secrets = {}
local sessions = {}
local publicKeys = {}
local connections = {}

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

local function isValidAddress(address)
    if #address ~= 24 then
        return false
    end
    return not not address:find(("%x%x%x%x:"):rep(5):sub(1, -2))
end

local function toHex(str)
    return ("%02x"):rep(#str):format(str:byte(1, -1))
end

local function fromHex(str)
    local result = {}
    for i = 1, #str, 2 do
        result[#result + 1] = tonumber(str:sub(i, i + 1), 16)
    end
    return string.char(unpack(result))
end

local function saveSecrets()
    local encodedSecrets = {
        seed = toHex(secrets.seed),
        ephemeralSeed = toHex(secrets.ephemeralSeed),
        lastEphemeralUpdate = tostring(secrets.lastEphemeralUpdate)
    }
    encodedSecrets = textutils.serialize(encodedSecrets)
    util.saveFile(SECRETS_PATH, encodedSecrets)
end

local function loadSecrets()
    local encodedSecrets = util.loadFile(SECRETS_PATH)
    encodedSecrets = textutils.unserialize(encodedSecrets)
    secrets = {
        seed = fromHex(encodedSecrets.seed),
        ephemeralSeed = fromHex(encodedSecrets.ephemeralSeed),
        lastEphemeralUpdate = tonumber(encodedSecrets.lastEphemeralUpdate)
    }
end

-- Create secrets if not found
if not fs.exists(SECRETS_PATH) then
    -- Convert from 1.0 format if necessary
    local seed
    if fs.exists(OLD_SEED_PATH) then
        seed = util.loadFile(OLD_SEED_PATH)
    else
        seed = random.random()
        seed = string.char(unpack(seed))
    end
    local ephemeralSeed = random.random()

    secrets = {
        seed = seed,
        ephemeralSeed = string.char(unpack(ephemeralSeed)),
        lastEphemeralUpdate = os.epoch("utc")
    }

    saveSecrets()
    if fs.exists(OLD_SEED_PATH) then
        fs.delete(OLD_SEED_PATH)
    end
end

-- Load secrets and derive public keys
loadSecrets()
local ownEphemeralSecretKey, ownEphemeralPublicKey = ecc.keypair(secrets.ephemeralSeed)
ownEphemeralSecretKey = tostring(ownEphemeralSecretKey)
ownEphemeralPublicKey = tostring(ownEphemeralPublicKey)
local ownSecretKey, ownPublicKey = ecc.keypair(secrets.seed)
ownSecretKey = tostring(ownSecretKey)
ownPublicKey = tostring(ownPublicKey)
local ownAddress = makeAddress(ownPublicKey)

-- Utility functions

local function updateEphemeralKeysIfTimeReached()
    if os.epoch("utc") > secrets.lastEphemeralUpdate + EPHEMERAL_REFRESH_MS then
        local ephemeralSeed = random.random()

        secrets.lastEphemeralUpdate = os.epoch("utc")
        secrets.ephemeralSeed = string.char(unpack(ephemeralSeed))
        saveSecrets()
    end
end

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
    updateEphemeralKeysIfTimeReached()

    -- Public data
    local otherAddress = makeAddress(otherPublicKey)

    -- Private data
    local sharedSecret
    if sessions[otherAddress] then
        sharedSecret = sessions[otherAddress].sharedSecret
    else
        sharedSecret = ecc.exchange(ownSecretKey, otherPublicKey)
    end
    local ownTagKey = sha256.hmac("senderTagKey", sharedSecret)

    -- Make request
    local counter = os.epoch("utc")
    local ownTag = tostring(sha256.hmac(ownEphemeralPublicKey .. tostring(counter), ownTagKey)):sub(1, 10)
    local request = {
        type = "connectionRequest",
        from = ownAddress,
        to = otherAddress,
        publicKey = ownPublicKey,
        ephemeralPublicKey = ownEphemeralPublicKey,
        tag = ownTag,
        counter = counter
    }
    networkAPI.send(CHANNEL, request)

    -- Make request secrets
    local requestSecrets = {
        ephemeralSecretKey = ownEphemeralSecretKey,
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
        publicKey = ownPublicKey
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

    publicKeys[otherAddress] = otherPublicKey
end

-- Verifies authenticity of a connection request
-- Sends back a connection response
-- Creates a new session from the request if needed
local function processConnectionRequest(networkAPI, request)
    updateEphemeralKeysIfTimeReached()

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

    if ( -- The cached session is no longer valid
        not sessions[otherAddress]
        or sessions[otherAddress].ephemeralPublicKey ~= otherEphemeralPublicKey
        or sessions[otherAddress].ownEphemeralPublicKey ~= ownEphemeralPublicKey
    ) then
        -- Private data
        local sharedSecret
        if sessions[otherAddress] then
            sharedSecret = sessions[otherAddress].sharedSecret
        else
            sharedSecret = ecc.exchange(ownSecretKey, otherPublicKey)
        end
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
        local calculatedHMAC = sha256.hmac(otherEphemeralPublicKey .. tostring(counter), otherTagKey)
        local calculatedTag = {unpack(calculatedHMAC, 1, 10)}
        assert(util.byteTableMT.__index.isEqual(calculatedTag, {otherTag:byte(1, 10)}))

        -- Make new session
        sessions[otherAddress] = {
            ephemeralPublicKey = otherEphemeralPublicKey,
            ownEphemeralPublicKey = ownEphemeralPublicKey,
            ownTagKey = ownTagKey,
            sharedSecret = sharedSecret,
            ownEncryptionKey = receiverEncryptionKey,
            ownMacKey = receiverMacKey,
            otherEncryptionKey = senderEncryptionKey,
            otherMacKey = senderMacKey,
            counter = counter
        }
    end

    -- Make response
    local responseCounter = os.epoch("utc")
    local ownTagKey = sessions[otherAddress].ownTagKey
    local ownTag = tostring(sha256.hmac(ownEphemeralPublicKey .. tostring(responseCounter), ownTagKey)):sub(1, 10)
    local response = {
        type = "connectionResponse",
        from = ownAddress,
        to = otherAddress,
        publicKey = ownPublicKey,
        ephemeralPublicKey = ownEphemeralPublicKey,
        tag = ownTag,
        counter = responseCounter
    }
    networkAPI.send(CHANNEL, response)
end

-- Verifies authenticity of a connection response
-- Creates a new session from the response if needed
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
    if sessions[otherAddress] then
        assert(counter > sessions[otherAddress].counter)
    else
        assert(counter > programInitEpoch)
    end

    if ( -- The cached session is no longer valid
        not sessions[otherAddress]
        or sessions[otherAddress].ephemeralPublicKey ~= otherEphemeralPublicKey
        or sessions[otherAddress].ownEphemeralPublicKey ~= ownEphemeralPublicKey
    ) then
        -- Private data
        local ownRequestEphemeralSecretKey = requestSecrets.ephemeralSecretKey
        local sharedSecret = requestSecrets.sharedSecret
        local ephemeralSharedSecret = ecc.exchange(
            ownRequestEphemeralSecretKey,
            otherEphemeralPublicKey
        )
        local masterKey = sha256.hmac(ephemeralSharedSecret, sharedSecret)
        local senderEncryptionKey = sha256.hmac("senderEncryptionKey", masterKey)
        local senderMacKey = {unpack(sha256.hmac("senderMacKey", masterKey), 1,16)}
        local receiverEncryptionKey = sha256.hmac("receiverEncryptionKey", masterKey)
        local receiverMacKey = {unpack(sha256.hmac("receiverMacKey", masterKey), 1, 16)}
        local otherTagKey = sha256.hmac("receiverTagKey", masterKey)
        local ownTagKey = sha256.hmac("senderTagKey", masterKey)

        -- Assert private validity
        local calculatedHMAC = sha256.hmac(otherEphemeralPublicKey .. tostring(counter), otherTagKey)
        local calculatedTag = {unpack(calculatedHMAC, 1, 10)}
        assert(util.byteTableMT.__index.isEqual(calculatedTag, {otherTag:byte(1, 10)}))

        -- Make new session
        sessions[otherAddress] = {
            ephemeralPublicKey = otherEphemeralPublicKey,
            ownEphemeralPublicKey = ownEphemeralPublicKey,
            ownTagKey = ownTagKey,
            sharedSecret = sharedSecret,
            ownEncryptionKey = senderEncryptionKey,
            ownMacKey = senderMacKey,
            otherEncryptionKey = receiverEncryptionKey,
            otherMacKey = receiverMacKey,
            counter = counter
        }
    end
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
    local outerLayer = tostring(aecrypt.decrypt(ciphertext, otherEncryptionKey, otherMacKey))
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

-- Adds a connection to the connections table
local function addConnection(networkAPI, address)
    if not isValidAddress(address) then
        return
    end

    local connection = {
        address = address,
        stage = nil
    }

    if publicKeys[address] then
        connection.stage = "connect"
        connection.secrets = makeConnectionRequest(networkAPI, publicKeys[address])
    else
        connection.stage = "pk"
        connection.secrets = makeAddressRequest(networkAPI, address)
    end

    connections[address] = connection
end

-- Meant to be run as a coroutine
-- Receives connection response messages and updates the status of ongoing connections
local function handleResponse(networkAPI, message)
    if message.type == "addressResponse" then
        assert(not publicKeys[message.from])
        assert(connections[message.from].stage == "pk")
        local connection = connections[message.from]

        processAddressResponse(connection.secrets, message)
        -- address response processed without errors
        connection.stage = "connect"
        connection.secrets = makeConnectionRequest(networkAPI, publicKeys[message.from])
    elseif message.type == "connectionResponse" then
        assert(connections[message.from].stage == "connect")
        local connection = connections[message.from]

        processConnectionResponse(connection.secrets, message)
        -- connection response processed without errors
        connections[message.from] = nil
        os.queueEvent("ecnet_connection", message.from)
    end
end

-- Listens to received messages, processes them and queues events
-- Queues event {"ecnet_message", address_from, message} (in wrappedProcessMessage)
-- Queues event {"ecnet_connection", address_from} (in handleResponse and in listen)
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
                    if type(received.from) ~= "string" then break end

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
                    elseif received.type == "addressResponse" or received.type == "connectionResponse" then
                        pcall(handleResponse, networkAPI, received)
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
    if not isValidAddress(address) then
        return false
    end

    addConnection(networkAPI, address)

    local returned = parallel.waitForAny(
        function()
            while true do
                local _, connectionAddress = os.pullEvent("ecnet_connection")
                if connectionAddress == address then
                    return
                end
            end
        end,
        function()
            sleep(timeout)
        end,
        function()
            listen(networkAPI)
        end
    )

    return returned == 1
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
    local ciphertext = tostring(aecrypt.encrypt(outerLayer, ownEncryptionKey, ownMacKey))

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
            if timeout then
                return connect(networkAPI, address, timeout)
            else
                return addConnection(networkAPI, address)
            end
        end,

        send = function(address, message)
            return send(networkAPI, address, message)
        end,

        receive = function(addressFilter, timeout)
            return receive(networkAPI, addressFilter, timeout)
        end
    }
end

local function genToken()
    return ecc.random.random():toHex():sub(1, 20)
end

local ecnet = {
    wrap = wrap,
    address = ownAddress,
    genToken = genToken
}

package.loaded["ecnet"] = ecnet

return ecnet
