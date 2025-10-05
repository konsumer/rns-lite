# Initially, I verified it was working with proper RNS library
# use this to make sure your basic code is sound (for other examples)

import RNS
from umsgpack import unpackb
import datetime

# this emulates rns.py module
class rns:
  @staticmethod
  def decode_packet(raw):
    """
    Decode main parts of a reticulum packet (raw bytes) returns packet dict
    """
    packet = RNS.Packet.__new__(RNS.Packet)
    packet.raw = raw
    RNS.Packet.unpack(packet)
    packet.rssi = None
    packet.snr = None
    packet.receiving_interface = None

    # this returns a Packet object, but eventually will return a dict with basic info
    return packet

  @staticmethod
  def decode_announce(packet):
    """
    Decode an ANNOUNCE packet (output from decode_packet)
    """
    pass

  @staticmethod
  def decode_data(packet, receiverIdentity, ratchets=[]):
    """
    Decode & decrypt a DATA packet (output from decode_packet)
    """
    identity=RNS.Identity.from_bytes(receiverIdentity)
    return identity.decrypt(packet.data, ratchets=ratchets)

  @staticmethod
  def encode_data(packet, whatever):
    """
    Encrypt & encode a DATA packet
    """
    pass

# a DATA packet from 072ec44973a8dee8e28d230fb4af8fe4 to 76a93cda889a8c0a88451e02d53fd8b9
packet = rns.decode_packet(bytes.fromhex('000076a93cda889a8c0a88451e02d53fd8b900f549cccf8d574cb520c8f12ea6ea67c4f4ce34f301de611cd942acbfb6933f3f7a025d5b6d6184d04dd0279b8037f1c9c1c1c25defbdd5e62aa8fb04502101014a501b9235e62f823bbdfd4d85e7656d765802f115a01b57b823ae02cc94899ae3a0f94bf7c32f1a73c027e5c95e0dd94c72c833ea75951af517da665eff26bca45e90e2eaa18775e65799ea0b3a977645107850dbfe62bb1f3228b50ac6e775006c4f18d6f3a1474233dc9b13cd95f6a6f581ad0b85de7196ea606d393d35f1'))

# the ratchet-private (derived from public) keys for both (normally each would have 1 of these)
ratchets=[
  bytes.fromhex('205cb256c44d4d3939bdc02e2a9667de4214cbcc651bbdc0a318acf7ec68b066'),
  bytes.fromhex('28dd4da561a9bc0cb7d644a4487c01cbe32b01718a21f18905f5611b110a5c45')
]

# the private key of the receiver (encrypt/sign, 32 bytes each)
identity=bytes.fromhex('e8c5c096166f3554868de9133b0c55c7abf0318230860a142ea3f84a0aae7759142f6c0b84d9f537ceb2e8e9678fc9fb77caf91e2176278fb4c4f5c3eb7b48cd')

decrypted = rns.decode_data(packet, identity, ratchets=ratchets)
ts,title,content,fields = unpackb(decrypted[80:])

print(f"Time: {datetime.datetime.fromtimestamp(ts)}")
print(f"Title: {title.decode("utf-8")}")
print(f"Content: {content.decode("utf-8")}")
