local constants = require "ecnet2.constants"

--- The global daemon state.

local handlers = setmetatable({}, { __mode = "v" })

--- @param message string
local function enqueue(message, side, ch, dist)
    if type(message) ~= "string" then return end
    if #message >= 2 ^ 16 then return end
    if #message < 32 then return end
    local descriptor = message:sub(1, 32)
    local etc = message:sub(33)
    local handler = handlers[descriptor]
    if handler then return handler(etc, side) end
end

local function daemon()
    while true do
        local _, side, ch, _, msg, dist = coroutine.yield("modem_message")
        if ch == constants.CHANNEL then enqueue(msg, side, ch, dist) end
    end
end

local function addHandler(name, fun)
    handlers[name] = fun
end

local function removeHandler(name)
    handlers[name] = nil
end

--- @class ecnet2.EcnetdState
--- @field daemon fun()
--- @field addHandler fun(name: string, fun: function)
--- @field removeHandler fun(name: string)
return {
    daemon = daemon,
    addHandler = addHandler,
    removeHandler = removeHandler,
}
