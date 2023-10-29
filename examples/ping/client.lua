local ecnet2 = require "ecnet2"
local random = require "ccryptolib.random"

-- Initialize the random generator.
local postHandle = assert(http.post("https://krist.dev/ws/start", "{}"))
local data = textutils.unserializeJSON(postHandle.readAll())
postHandle.close()
random.init(data.url)
http.websocket(data.url).close()

-- Open the top modem for comms.
ecnet2.open("top")

-- Define a protocol.
local ping = ecnet2.Protocol {
    -- Programs will only see packets sent on the same protocol.
    -- Only one active listener can exist at any time for a given protocol name.
    name = "ping",

    -- Objects must be serialized before they are sent over.
    serialize = textutils.serialize,
    deserialize = textutils.unserialize,
}

-- The server's address.
local server = "OWLYs4X14N2brkhiZMHAScqjEydM27DOVLmLu3jmbhg="

-- Connect to the server.
local connection = ping:connect(server, "top")

-- Wait for the greeting.
print(select(2, connection:receive()))

-- Read inputs and print ping outputs.
while true do
    connection:send(read())
    print(select(2, connection:receive()))
end
