local constants = require "ecnet2.constants"
local Identity = require "ecnet2.Identity"
local modems = require "ecnet2.modems"
local ecnetd = require "ecnet2.ecnetd"
local expect = require "cc.expect"

local module = {}

--- @type ecnet2.Identity?
local identity

local function fetchIdentity()
    if not identity then identity = Identity(constants.IDENTITY_PATH) end
    return identity
end

--- Loads or creates an identity file in the given path.
--- @param path string The path to load or create the identity at.
--- @return ecnet2.Identity
function module.Identity(path)
    return Identity(expect(1, path, "string"))
end

--- Returns the address for this device.
--- @deprecated Use `ecnet2.Identity("/.ecnet2").address` instead.
--- @return string address The address.
function module.address()
    return fetchIdentity().address
end

module.open = modems.open
module.close = modems.close
module.isOpen = modems.isOpen

module.daemon = ecnetd.daemon

--- Creates a protocol from a given interface.
--- @deprecated Use `ecnet2.Identity("/.ecnet2"):Protocol(...)` instead.
--- @param interface ecnet2.IProtocol A table describing the protocol.
--- @return ecnet2.Protocol protocol The resulting protocol.
function module.Protocol(interface)
    return fetchIdentity():Protocol(interface)
end

return module
