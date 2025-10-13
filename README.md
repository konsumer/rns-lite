This is a light implementation of reticulum, based on the [official python library](https://github.com/markqvist/Reticulum/).

This is a light "BYO" version that is compatable, but missing transport, interfaces, packet-callbacks, and file-use.

The essential idea is that is has utilities for the basics, but no automatic-management of things, and much smaller/simpler. The hope is that it will be usable in constrained enviroments, like micropython. I am also working on [cyd-nomad](https://github.com/konsumer/cyd-nomad), for this purpose.

## API

#### get_destination_hash

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

#### decode_packet

```python
def decode_packet(packet_bytes)
```

Extract basic reticulum fields (packet-object) from bytes.

**Arguments**:

- `packet_bytes` - Raw bytes for a packet (without framing)

**Returns**:

Dictionary of basic fields (data, packet_type, destination_type, etc)

#### announce_parse

```python
def announce_parse(packet)
```

Parse an ANNOUNCE packet into announce-object.

**Arguments**:

- `packet` - packet dictionary (output from `decode_packet`)

**Returns**:

Dictionary of announce-specifc fields (valid, signature, app_data, etc)

#### get_message_id

```python
def get_message_id(packet)
```

Get the message-id (used as destination in PROOFs) from a DATA packet (output from decode_packet.)

**Returns**:

Bytes for message-id (used in PROOF.)

#### proof_validate

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

#### message_decrypt

```python
def message_decrypt(packet, identity, ratchets=None)
```

Decrypt a DATA message packet using identity's private key and optional ratchets.

#### build_proof

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

#### build_data

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

#### build_lxmf_message

```python
def build_lxmf_message(my_identity, my_dest, my_ratchet, recipient_announce, message)
```

Build LXMF message - destination is stripped before encryption.

**Arguments**:

- `my_identity` - Your identity dict with private/public keys
- `my_dest` - Bytes of destination address (output from `get_destination_hash`)
- `my_ratchet` - Your ratchet private key (32 bytes). If None, uses your identity encrypt key.
- `recipient_announce` - The parsed announce dict from announce_parse() containing recipient's keys
- `message` - The message object (title, content, etc)

**Returns**:

Encoded DATA packet bytes

#### parse_lxmf_message

```python
def parse_lxmf_message(plaintext)
```

Parse LXMF message from encrypted DATA packet.
source (16) + signature (64) + msgpack

**Arguments**:

- `plaintext` - Decrypted packet-data from a message DATA packet

**Returns**:

Dictionary with title/content/source_hash/signature/timestamp and any other fields.

#### get_identity_from_bytes

```py
def get_identity_from_bytes(private_identity_bytes)
```

Load private keys for encrypt/sign and derive public keys.

**Arguments**:

- `private_identity_bytes` - Bytes loaded from some other place (file, etc) that hold your private encryption/sign keys

**Returns**:

Dictionary with public/private sign/encrypt keys

#### identity_create

```py
def identity_create()
```

Create a full fresh identity (pub/private encrypt/sign.)

**Returns**:

Dictionary with public/private sign/encrypt keys

#### ratchet_create_new

```py
def ratchet_create_new()
```

Generate new ratchet private key.

**Returns**:

32 Bytes for a ratchet private-key

#### ratchet_get_public

```py
def ratchet_get_public(private_ratchet)
```

Get the public key for ratchet (for use in ANNOUNCEs.)

**Arguments**:

- `private_ratchet` - Bytes from private ratchet (output from ratchet_create_new)

**Returns**:

32 Bytes for a ratchet public-key

## Heltec v3

I started with a Heltec v3. It should work great on other things, but that is what I had on-hand that already had a lora radio attached, for testing.

### hardware

screen io:

- scl pin is 18
- sda pin is 17
- reset = 21 (must stay high to write to it)
- backlight = 36

radio io:

- chip is SX1262: [uPy lib for chip](https://github.com/git512/micropySX126X)

chip pins

- SS (CS)= 8
- SCK (CLK)= 9
- MOSI = 10
- MISO = 11
- RST = 12
- BUSY = 13
- DIO (also irq) = 14
- onboard LED GPIO = 35

- load [esp32-s3 image](https://micropython.org/download/ESP32_GENERIC_S3/)

When working with python, I have a global venv I automatically activate in my .zshrc. For most "regular things" I like to just keep it all in one place, and it makes it easier to find the source for libraries & tools. It's also easier to wipe it all, and it keeps the version locked into a single root (on mac, for example, you might have several python runtimes.)

```sh
# make a fresh venv
python -m venv ~/.venv-global

# activate. put this in your shell-config
source  ~/.venv-global/bin/activate
```

```sh
# install ESP32 CLI tools
pip install esptool

# install fresh micropython
esptool.py erase_flash
esptool.py --baud 460800 write_flash 0 ESP32_BOARD_NAME-DATE-VERSION.bin
```

To upload files:

```sh
# install ampy
pip install adafruit-ampy

# upload rns-lite
ampy --port /dev/tty.usbserial-0001 put rns.py

# these might eventually be replaced with faster versions, but these are pure-python crypto things
ampy --port /dev/tty.usbserial-0001 put x25519
ampy --port /dev/tty.usbserial-0001 put ed25519.py

# upload OLED driver
curl https://raw.githubusercontent.com/micropython/micropython-lib/refs/heads/master/micropython/drivers/display/ssd1306/ssd1306.py > /tmp/ssd1306.py
ampy --port /dev/tty.usbserial-0001 put /tmp/ssd1306.py

# upload radio driver
git clone https://github.com/git512/micropySX126X.git /tmp/micropySX126X
ampy --port /dev/tty.usbserial-0001 put /tmp/micropySX126X/lib/_sx126x.py
ampy --port /dev/tty.usbserial-0001 put /tmp/micropySX126X/lib/sx1262.py
ampy --port /dev/tty.usbserial-0001 put /tmp/micropySX126X/lib/sx126x.py

# upload msgpack
git clone https://github.com/peterhinch/micropython-msgpack.git /tmp/micropython-msgpack
ampy --port /dev/tty.usbserial-0001 put /tmp/micropython-msgpack/umsgpack

# upload test programs
ampy --port /dev/tty.usbserial-0001 put example_heltec_offline.py
```

On mac/linux, I like to use picocom for my serial-terminal:

```sh
picocom -b115200 /dev/tty.usbserial-0001
```

You can close it with Ctrl-A, Ctrl-X. Any serial program will work (`screen` is also very popular) set baude to 115200.

Now run an example, on ESP32:

```py
import example_heltec_offline
```

And you should see a decrypted message-packet on screen.

### todo

- seperate verify in ANNOUNCE, more like PROOF
- Fully implement LINK
- Node stuff (files, )
- rnsh stuff
