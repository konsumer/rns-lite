# this example will parse & decrypt captured traffic

# mess with path to get local files
import os
import sys
script_dir = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(script_dir, '..'))

from test import demo_data
import RNS
from RNS.vendor import umsgpack

def load_packet(raw):
  """Load a packet from raw bytes without side effects"""
  packet = RNS.Packet.__new__(RNS.Packet)
  packet.raw = raw
  RNS.Packet.unpack(packet)
  packet.rssi = None
  packet.snr = None
  packet.receiving_interface = None
  return packet

def decrypt_data(packet, identity, ratchets):
  """Decrypt and parse DATA packet"""
  decryptedBytes = identity.decrypt(packet.data, ratchets=ratchets)
  return umsgpack.unpackb(decryptedBytes[80:])

# build dict of identities
clientA = RNS.Identity.from_bytes(demo_data.keys['clientA'])
clientB = RNS.Identity.from_bytes(demo_data.keys['clientB'])
clientA_addr = RNS.Destination.hash(clientA, "lxmf", "delivery")
clientB_addr = RNS.Destination.hash(clientB, "lxmf", "delivery")
identities = {
  clientA_addr: clientA,
  clientB_addr: clientB
}

print(f"Client A: {clientA_addr.hex()}")
print(f"Client B: {clientB_addr.hex()}")

for p in demo_data.packets:
  packet = load_packet(p)
  if packet.packet_type == RNS.Packet.ANNOUNCE:
    print(f'ANNOUNCE ({packet.destination_hash.hex()})')
  elif packet.packet_type == RNS.Packet.DATA:
    data = decrypt_data(packet, identities[packet.destination_hash], demo_data.ratchets)
    print(f'DATA ({packet.destination_hash.hex()})', data)
  elif packet.packet_type == RNS.Packet.PROOF:
    print(f'PROOF ({packet.destination_hash.hex()})')
  else:
    print(f'OTHER ({packet.destination_hash.hex()})')