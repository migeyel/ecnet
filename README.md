# ECNet
An easy encrypted communications API for ComputerCraft.

## Example Usage
Here's an example of how you would send a "hello" message from one computer to another.

First, you'll need to `require` the API in your program. **Note: Loading the file using basically anything that's not `require` may cause several instances of the API to be run at the same time. This can cause problems with performance, unreliable connections and undefined behavior in general.**
```lua
local ecnet = require("ecnet")
```
If you need to place ecnet in a different path, you'll need to add that path to your `package.path` string. Next, you will need to wrap a modem peripheral in your computer and wrap it again using ecnet.
```lua
local modem = peripheral.find("modem")
local s_modem = ecnet.wrap(modem)
```
After that, you will need to set up a second computer to be ready to receive the message. You will also need to know its address so you can send the message from the first one:
```lua
-- On the second computer
local ecnet = require("ecnet")
local modem = peripheral.find("modem")
local s_modem = ecnet.wrap(modem)
local address = ecnet.address
print("Address: " .. address)

local sender, message = s_modem.receive()
print(sender .. " sent the message: " .. message)
```
Let's say that the address was `33c2:7172:35a0:abdf:d066`. Go back to the first computer to set up the connection and send the message:
```lua
-- Back on the first computer
s_modem.connect("33c2:7172:35a0:abdf:d066", 3) -- Try to connect for 3 seconds
s_modem.send("33c2:7172:35a0:abdf:d066", "hello")
```
That's it. If everything goes well, the second computer will have printed something like this:
```
6bc2:4604:6dca:356d:c5fe sent the message: hello
```

## Actual Documentation
### Functions
`ecnet.address` is a string that returns the computer's address. Those are unique but can be reset by deleting the secret key at `/.ecnet-secretseed`

`ecnet.wrap(modem:table):table` takes a modem (or modem-like) handle and outputs another handle for sending and receiving messages. We'll call this new handle `s_modem` from now on.

`s_modem.connect(address:string, timeout:number):boolean` will attempt to connect to an address and times out after `timeout` seconds. Will return `true` if connected and `false` if timed out.

`s_modem.listen()` will listen to modem messages, answer connection requests and queue events. It is not expected to return nor error.

`s_modem.receive([addressFilter:string][, timeout:number])` will run `listen` and wait for any messages. Returns the sender and the message if received or `nil` if timed out.

`s_modem.send(address:string, message:string):boolean` will attempt to send a message to an address. Will return `true` if a session has been established after the API was `require`d (does not imply message reception) and `false` otherwise.

### Events
`"ecnet_message", sender:string, message:string` is queued when a new message is received by `listen()`.

`"ecnet_connection", sender:string` is queued when a new connection is received by `listen()`.

## Speed

When tested in CCEmuX, latency for messages shorter than 255 bytes is around 20ms round-trip. Bandwidth is at most 110 KB/s, including encryption and decryption on the other computer. Processing for sending messages is dominated by symmetric primitives and scales linearly with the size of the message.

Performing connections is considerably slower than sending messages. First-time connections take around 200ms and reconnections take around 160ms. As a note, these times are a sum of both user and server times and connections are close to being made only once per computer reboot. A program can also use the result of `send()` to see if an initial connection is needed.

## Building
SquidDev's [Howl](https://github.com/SquidDev-CC/Howl) is used to build the API. You can build it using `Howl build`.

## Installing
You can either clone and build it by yourself or download the minified version from this gist: [ecnet.min.lua](https://gist.github.com/migeyel/278f77628248ea991719f0376979b525) ([Raw](https://gist.githubusercontent.com/migeyel/278f77628248ea991719f0376979b525/raw/ecnet.min.lua))
