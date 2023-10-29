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

-- The listener so we can look for and accept incoming connections.
local listener = ping:listen()

-- The set of accepted connections.
-- For simplicity, we don't drop inactive connections.
local connections = {}

while true do
    local event, id, p2, p3 = os.pullEvent()
    if event == "ecnet2_request" and id == listener.id then
        -- Accept the request and send a greeting message.
        local connection = listener:accept("ping v1.0", p2)
        connections[connection.id] = connection
    elseif event == "ecnet2_message" and connections[id] then
        -- Reply with the same message.
        connections[id]:send(p3)
    end
end
