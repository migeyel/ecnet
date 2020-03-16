local byteTableMT = {
    __tostring = function(a) return string.char(unpack(a)) end,
    __index = {
        toHex = function(self) return ("%02x"):rep(#self):format(unpack(self)) end,
        isEqual = function(self, t)
            if type(t) ~= "table" then return false end
            if #self ~= #t then return false end
            local ret = 0
            for i = 1, #self do
                ret = bit32.bor(ret, bit32.bxor(self[i], t[i]))
            end
            return ret == 0
        end
    }
}

local function saveFile(path, data)
    local file = fs.open(path, "wb")
    file.write(data)
    file.close()
end

local function loadFile(path)
    local file = fs.open(path, "rb")
    local result = file.readAll()
    file.close()

    return result
end

return {
    byteTableMT = byteTableMT,
    saveFile = saveFile,
    loadFile = loadFile
}