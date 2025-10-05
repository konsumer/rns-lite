# Lightweight Reticulum library
# https://github.com/konsumer/rns-lite



def decode_packet(bytes):
  """
  Decode main parts of a reticulum packet, returns packet dict
  """
  pass

def decode_announce(packet):
  """
  Decode an ANNOUNCE packet (output from decode_packet)
  """
  pass

def decode_data(packet, receiverIdentity, ratchets=[]):
  """
  Decode & decrypt a DATA packet (output from decode_packet)
  """
  pass

def encode_data(packet, whatever):
  """
  Encrypt & encode a DATA packet
  """
  pass

