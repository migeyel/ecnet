-- random.lua - Random Byte Generator

local sha256 = require("ecnet.symmetric.sha256")

local entropy = ""
local accumulator = ""
local entropyPath = "/.random"

local function feed(data)
    accumulator = accumulator .. (data or "")
end

local function digest()
    entropy = tostring(sha256.digest(entropy .. accumulator))
    accumulator = ""
end

if fs.exists(entropyPath) then
    local entropyFile = fs.open(entropyPath, "rb")
    feed(entropyFile.readAll())
    entropyFile.close()
end

local t0 = os.epoch("utc")
local t1 = t0
local iterations = 1
feed("init")
feed(tostring(math.random(1, 2^31 - 1)))
feed("|")
feed(tostring(math.random(1, 2^31 - 1)))
feed("|")
feed(tostring(math.random(1, 2^4)))
feed("|")
feed(tostring(t0))
feed("|")
while (t1 - t0 < 500) or (iterations < 10000) do
    t1 = os.epoch("utc")
    local s = tostring({}):sub(8)
    while #s < 8 do
        s = "0" .. s
    end
    feed(string.char(t1 % 256))
    feed(string.char(tonumber(s:sub(1, 2), 16)))
    feed(string.char(tonumber(s:sub(3, 4), 16)))
    feed(string.char(tonumber(s:sub(5, 6), 16)))
    feed(string.char(tonumber(s:sub(7, 8), 16)))
    iterations = iterations + 1
end
digest()
feed(tostring(os.epoch("utc")))
digest()

local function save()
    feed("save")
    feed(tostring(os.epoch("utc")))
    feed(tostring({}))
    digest()

    local entropyFile = fs.open(entropyPath, "wb")
    entropyFile.write(tostring(sha256.hmac("save", entropy)))
    entropy = tostring(sha256.digest(entropy))
    entropyFile.close()
end
save()

local function seed(data)
    feed("seed")
    feed(tostring(os.epoch("utc")))
    feed(tostring({}))
    feed(data)
    digest()
    save()
end

local function random()
    feed("random")
    feed(tostring(os.epoch("utc")))
    feed(tostring({}))
    digest()
    save()

    local result = sha256.hmac("out", entropy)
    entropy = tostring(sha256.digest(entropy))
    
    return result
end

return {
    seed = seed,
    save = save,
    random = random
}
