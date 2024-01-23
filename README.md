# ECNet2
ECNet2 is an encrypted networking library for CC:Tweaked. You can find usage
examples in the examples directory.

## Dependencies
- [CCryptolib](https://github.com/migeyel/ccryptolib) >=1.1.0 (you still need to
  initialize the random generator yourself)

## Goals
- Let the user manage the lifetime of connections.
- Minimize the work done by the responder before they accept a handshake.
- Let the user pick a "protocol" (channel, namespace, ...) to talk through.
- Strong assurances for traffic authenticity and confidentiality.
- High efficiency in both computation and bandwidth usage.
- Best-effort hiding of relevant parties' identities.
- Best-effort handling of network abuse.

## Non-goals
- Authenticated multicast or broadcast of messages.

# API Reference

### `ecnet2.open(modem: string)`
Opens a modem for communications.

### `ecnet2.close([modem: string])`
Closes a modem for communications.

### `ecnet2.isOpen([modem: string])`
Returns whether a modem is open for communications.

### `ecnet2.address(): string`
Returns the address for connecting to this device.

### `ecnet2.daemon`
Function used for managing listener and connection events.
Intended to be put in parallel with users code.

### `ecnet2.Protocol(interface: IProtocol): Protocol`
Creates a protocol from a given interface.

## Type `IProtocol`
A table containing a description for a protocol.

### `IProtocol.name: string`
The protocol's name.

### `Iprotocol.serialize(object: any): string`
A serializer for protocol objects.

### `IProtocol.deserialize(str: string): any`
A deserializer for protocol objects.

## Type `Protocol`
A namespace for interpreting messages received over connections.

### `Procotol:connect(address: string, modem: string): Connection`
Creates a new connection using this protocol and a modem.

### `Protocol:listen(): Listener`
Creates a listener for this protocol on all open modems.

## Type `Listener`
A listener for incoming connection requests.

### `Listener.id: string`
The listener's ID, used in resolving `ecnet2_request` events.

### `Listener:accept(reply: any[, request: Request]): Connection`
Accepts a request and builds a connection. Waits for the next request if none
are provided.

Throws `"invalid listener for this request"` if the supplied request isn't meant
for this listener.

Returns a dummy connection if the request is malformed, or if the request has
already been accepted.

## Type `Connection`
An encrypted tunnel operating over a network.

### `Connection.id: string`
The connection's ID, used in `ecnet2_message` events.

### `Connection:send(message: any)`
Sends a message.

Throws `"can't send on an incomplete connection"` until at least one
message has been received.

### `Connection:receive([timeout: number]): string, any`
Yields until a message is received. Returns the sender and contents, or nil on
timeout.

## Events
### `"ecnet2_request", listenerId: string, request: Request, side: string`
A connection request.
- `listenerId` - The `id` field of the listener that received this request.
- `request` - The request to pass on to the `accept` method.
- `side` - Which modem the request was received through.
- `channel` - The channel the request was received on.
- `distance` - Distance to the sender of the underlying modem message. This may not match the true originator for relayed messages.

### `"ecnet2_message", connectionId: string, sender: string, message: any`
A message in a connection.
- `connectionId` - The `id` field of the connection that received this message.
- `sender` - The sender's address.
- `message` - The deserialized message data.
- `channel` - The channel the message was received on.
- `distance` - Distance to the sender of the underlying modem message. This may not match the true originator for relayed messages.

# Technical Details

## Descriptors
Every ECNet2 packet has a 32 byte prefix known as the *descriptor*. Descriptors
allow the receiver to know whether it is supposed to process a packet.
Furthermore, secret descriptors allow for some resistance against decryption
failure denial-of-service attacks on networks with no wormholes.

The listener descriptor is defined as `BLAKE3(BLAKE3(pk .. BLAKE3(protocol)))`,
where `pk` is the listener's public key and `protocol` is the protocol name.

The connection descriptors are derived from the current decryption key, which is
ratcheted every time a new message is received.

## Handshake
We use the noise XK handshake, its pattern is:
```
XK:
  <- s
  ...
  -> e, es
  <- e, ee
  -> s, se
```

The contents of each handshake payload are:
### `-> e, es`
This payload currently contains only padding.

### `<- e, ee`
This payload contains a user-defined reply and padding. Neither the user nor
ECNet know who the initiator is. As a result, naive assumptions match exactly
what the payload security properties (2, 1) are.

### `-> s, se`
This payload contains a user-defined message and padding. The naive assumptions
match exactly what the payload security properties (2, 5) are.

### Why _K?
We need the initiator to have a secret descriptor at the first response,
otherwise an attacker could trigger decryption failures arbitrarily, throwing
the entire connection away. We could try restarting the connection again, but
that's difficult to model in the interface.

### Why not IK?
1. The initiator's identity claim is vulnerable to replay attack, so we can't
assume anything until their first transport message, making IK pointless.
2. IK has an `ss` token, which is harder to protect against timing attacks on
the result of the DH operation, while `es` and `se` are a bit safer.
3. IK hides identity more poorly than XK.

### Why not NK?
Authenticating the initiatior makes the API simpler from the user's point of
view, since they don't have to handle whether the message has a sender or not.

## Size Limits

### `accept()` Reply Argument
The message size limit is 2¹⁵ - 1 = 32767 bytes. The other half of the payload
is reserved for ECNet metadata.

### Initiator's First Message
The message size limit is 2¹⁵ - 1 = 32767 bytes. The other half of the payload
is reserved for ECNet metadata.

### Other Messages
50 bytes of overhead:
- 32 bytes for the descriptor
- 1 byte for packet type information
- At least 1 byte for padding
- 16 bytes for the message's tag

Since noise allows packets of at most 2¹⁶ - 1 bytes in length, the message size
limit is 2¹⁶ - 1 - 50 = 65485 bytes.

## Handshake Model
The XK handshake is modeled into `Connection` and `Listener` objects. The second
payload is modeled as a `reply` parameter to `accept`, while the third payload
is modeled as a regular message:
```
Handshake payloads:
connect() -> e, es, ""    -> os.pullEvent("ecnet2_request")
receive() <- e, ee, reply <- accept(reply)
send(msg) -> s, se, msg   -> receive()

Transport:
receive() <- msg <- send(msg)
send(msg) -> msg -> receive()
