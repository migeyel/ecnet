local ecnet2 = require "ecnet2"
local random = require "ccryptolib.random"

random.initWithTiming()

-- Open the top modem for comms.
ecnet2.open("top")

-- Define an identity.
local id = ecnet2.Identity("/.ecnet2")

-- Define a protocol.
local ping = id:Protocol {
    -- Programs will only see packets sent on the same protocol.
    -- Only one active listener can exist at any time for a given protocol name.
    name = "ping",

    -- Objects must be serialized before they are sent over.
    serialize = textutils.serialize,
    deserialize = textutils.unserialize,
}

-- The server's address.
local server = "AZ2cVrQTGDLLRodwHFS3RoNYQOW0O_iCctVWxc9IrXQ="

local function main()
    -- Connect to the server.
    local connection = ping:connect(server, "top")

    -- Wait for the greeting.
    print(select(2, connection:receive()))

    -- Read inputs and print ping outputs.
    while true do
        connection:send(read())
        print(select(2, connection:receive()))
    end
end

parallel.waitForAny(main, ecnet2.daemon)
