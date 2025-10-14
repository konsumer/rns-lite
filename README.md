This is a light implementation of reticulum, based on the [official python library](https://github.com/markqvist/Reticulum/).

This is a light "BYO" version that is compatable, but missing transport, interfaces, packet-callbacks, and file-use.

The essential idea is that is has utilities for the basics, but no automatic-management of things, and much smaller/simpler. The original hope was that it could be usable in constrained python enviroments, like micropython. I could not find a good way to get the crypto stuff working on micropython, though. It's either too slow (and has other problems like too much recursion) or there is an implementation in C, that I could not get to run (it requires a fuill recompile of micropython, and that worked, but boot-looped when I tried to run it.) I think my future-work on micros will be in C. Arduino has a lot  of nice libraries, and it will run much better. This llibrary still has a purpose though: simplicity. I can use it to more easily port other languages.

Also, check out [cyd-nomad](https://github.com/konsumer/cyd-nomad).

## API

### get_destination_hash

```python
def get_destination_hash(identity, app_name, *aspects)
```

Get the destination-hash (LXMF address) from identity. A common app_name/aspect is `"lxmf", "delivery"`

**Arguments**:

- `identity` - Your identity dict with private/public keys
- `app_name` - String name of app.
- `*aspects` - Anything else gets joined into app_name with `.`

**Returns**:

Bytes for a destination-hash (address.)

### decode_packet

```python
def decode_packet(packet_bytes)
```

Extract basic reticulum fields (packet-object) from bytes.

**Arguments**:

- `packet_bytes` - Raw bytes for a packet (without framing)

**Returns**:

Dictionary of basic fields (data, packet_type, destination_type, etc)

### announce_parse

```python
def announce_parse(packet)
```

Parse an ANNOUNCE packet into announce-object.

**Arguments**:

- `packet` - packet dictionary (output from `decode_packet`)

**Returns**:

Dictionary of announce-specifc fields (valid, signature, app_data, etc)

### get_message_id

```python
def get_message_id(packet)
```

Get the message-id (used as destination in PROOFs) from a DATA packet (output from decode_packet.)

**Arguments**:

- `packet` - packet dictionary (output from `decode_packet`)

**Returns**:

Bytes for message-id (used in PROOF.)

### proof_validate

```python
def proof_validate(packet, identity, full_packet_hash)
```

Validate a PROOF packet.

**Arguments**:

- `packet` - packet dictionary (output from `decode_packet`)
- `identity` - Your identity dict with private/public keys
- `full_packet_hash` - message_id (un-truncated destination, so you should store what message-ids you send)

**Returns**:

Boolean of proof-validation.

### message_decrypt

```python
def message_decrypt(packet, identity, ratchets=None)
```

Decrypt a DATA message packet using identity's private key and optional ratchets.

**Arguments**:

- `packet` - The decoded DATA packet dict (from decode_packet)
- `identity` - Your identity dict with private/public keys
- `ratchets` - Optional array of ratchets (private-key bytes, output from ratchet_create_new)

**Returns**:

Returns decrypted bytes

### build_proof

```python
def build_proof(identity, packet, message_id=None)
```

Build a PROOF packet in response to a received DATA packet.

**Arguments**:

- `identity` - Your identity dict with private/public keys
- `packet` - The decoded DATA packet dict (from decode_packet)
- `message_id` - Optional pre-calculated message ID (32 bytes). If None, will be calculated.

**Returns**:

Encoded PROOF packet bytes

### build_data

```python
def build_data(identity, recipient_announce, plaintext, ratchet=None)
```

Build an encrypted DATA packet to send to a recipient.

**Arguments**:

- `identity` - Your identity dict with private/public keys
- `recipient_announce` - The parsed announce dict from announce_parse() containing recipient's keys
- `plaintext` - The message bytes to encrypt
- `ratchet` - Your ratchet private key (32 bytes). If None, uses your identity encrypt key.

**Returns**:

Encoded DATA packet bytes

### build_lxmf_message

```python
def build_lxmf_message(my_identity, my_dest, my_ratchet, recipient_announce, message)
```

Build LXMF message

**Arguments**:

- `my_identity` - Your identity dict with private/public keys
- `my_dest` - Bytes of destination address (output from `get_destination_hash`)
- `my_ratchet` - Your ratchet private key (32 bytes). If None, uses your identity encrypt key.
- `recipient_announce` - The parsed announce dict from announce_parse() containing recipient's keys
- `message` - The message dictionary (title, content, etc)

**Returns**:

Encoded DATA packet bytes

### parse_lxmf_message

```python
def parse_lxmf_message(plaintext)
```

Parse LXMF message from encrypted DATA packet.
source (16) + signature (64) + msgpack

**Arguments**:

- `plaintext` - Decrypted packet-data from a message DATA packet

**Returns**:

Dictionary with title/content/source_hash/signature/timestamp and any other fields.

### get_identity_from_bytes

```py
def get_identity_from_bytes(private_identity_bytes)
```

Load private keys for encrypt/sign and derive public keys.

**Arguments**:

- `private_identity_bytes` - Bytes loaded from some other place (file, etc) that hold your private encryption/sign keys

**Returns**:

Dictionary with public/private sign/encrypt keys

### identity_create

```py
def identity_create()
```

Create a full fresh identity (pub/private encrypt/sign.)

**Returns**:

Dictionary with public/private sign/encrypt keys

### ratchet_create_new

```py
def ratchet_create_new()
```

Generate new ratchet private key.

**Returns**:

32 Bytes for a ratchet private-key

### ratchet_get_public

```py
def ratchet_get_public(private_ratchet)
```

Get the public key for ratchet (for use in ANNOUNCEs.)

**Arguments**:

- `private_ratchet` - Bytes from private ratchet (output from ratchet_create_new)

**Returns**:

32 Bytes for a ratchet public-key

