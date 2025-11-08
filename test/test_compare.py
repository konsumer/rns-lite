# Basic test that compares to official python-library
# I load the same packets/keys in RNS/lite and make sure they have the same data

import pytest
import RNS
import example_data as data
import sys
import os

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from rns_lite import *

# no-side-effects load Packet in RNS
def RNS_packet_unpack(raw: bytes) -> RNS.Packet:
  """Load a packet from raw bytes without side effects"""
  packet = RNS.Packet.__new__(RNS.Packet)
  packet.raw = raw
  RNS.Packet.unpack(packet)
  packet.rssi = None
  packet.snr = None
  packet.receiving_interface = None
  return packet

def RNS_identity_from_priv(addressHashHex:str) -> RNS.Identity:
  identity = RNS.Identity(create_keys=False)
  identity.load_private_key(data.keys[bytes.fromhex(addressHashHex)])
  return identity

def RNS_validate_proof(senderAddressHex:str, fullHashHex:str, packet:dict) -> bool:
  return RNS_identity_from_priv(senderAddressHex).validate(packet.data[0:64], bytes.fromhex(fullHashHex))

def RNS_validate_data(receiverAddressHex:str, packet:dict):
  return RNS_identity_from_priv(receiverAddressHex).decrypt(packet.data, ratchets=data.ratchets)

def lite_validate_proof(senderAddressHex:str, fullHashHex:str, packet:dict) -> bool:
  return validate_proof(packet, public_identity(data.keys[bytes.fromhex(senderAddressHex)]), bytes.fromhex(fullHashHex))

def lite_validate_data(receiverAddressHex:str, packet:dict) -> dict:
  return message_decrypt(packet, public_identity(data.keys[bytes.fromhex(receiverAddressHex)]), ratchets=data.ratchets)

class TestOfficialRNS:
  def test_packet0(self):
    packet = RNS_packet_unpack(data.packets[0])
    assert packet.packet_type is PACKET_ANNOUNCE
    assert packet.hops is 0
    assert packet.destination_type is DEST_SINGLE
    assert packet.destination_hash.hex() == '072ec44973a8dee8e28d230fb4af8fe4'
    assert packet.packet_hash.hex() == 'e56755f8b7405b07c12a5c25d7b9b744ca296f7349768b335c78be868530b57d'
    assert packet.transport_id is None
    assert RNS.Identity.validate_announce(packet, True)

  def test_packet1(self):
    packet = RNS_packet_unpack(data.packets[1])
    assert packet.packet_type is PACKET_ANNOUNCE
    assert packet.hops is 0
    assert packet.destination_type is DEST_SINGLE
    assert packet.destination_hash.hex() == '76a93cda889a8c0a88451e02d53fd8b9'
    assert packet.packet_hash.hex() == '1d17ee4b806f343804567c56ac9d1204e06ef9bc0d1e44b3970f4138a8ef897b'
    assert packet.transport_id is None
    assert RNS.Identity.validate_announce(packet, True)

  def test_packet2(self):
    packet = RNS_packet_unpack(data.packets[2])
    assert packet.packet_type is PACKET_DATA
    assert packet.hops is 0
    assert packet.destination_type is DEST_SINGLE
    assert packet.destination_hash.hex() == '76a93cda889a8c0a88451e02d53fd8b9'
    assert packet.packet_hash.hex() == '2831d76f1a8035638505c132fe5818c1d1d25869a973d35c197d669f0d5074d8'
    assert packet.transport_id is None
    plaintext = RNS_validate_data('76a93cda889a8c0a88451e02d53fd8b9', packet)
    assert plaintext is not None, "Decryption failed"

  def test_packet3(self):
    packet = RNS_packet_unpack(data.packets[3])
    assert packet.packet_type is PACKET_PROOF
    assert packet.hops is 0
    assert packet.destination_type is DEST_SINGLE
    assert packet.destination_hash.hex() == '2831d76f1a8035638505c132fe5818c1'
    assert packet.packet_hash.hex() == 'c6c8d3a2da7de271b3262ed73f8d07f2d9b665e6dd382c610b2761f3484a6979'
    assert packet.transport_id is None
    assert RNS_validate_proof('76a93cda889a8c0a88451e02d53fd8b9', '2831d76f1a8035638505c132fe5818c1d1d25869a973d35c197d669f0d5074d8', packet)

  def test_packet4(self):
    packet = RNS_packet_unpack(data.packets[4])
    assert packet.packet_type is PACKET_DATA
    assert packet.hops is 0
    assert packet.destination_type is DEST_SINGLE
    assert packet.destination_hash.hex() == '072ec44973a8dee8e28d230fb4af8fe4'
    assert packet.packet_hash.hex() == 'd7c0e833f0cbde9f9133cd9e7d508b1a61d2c89410e9009e4474b9212ed0370a'
    assert packet.transport_id is None
    plaintext = RNS_validate_data('072ec44973a8dee8e28d230fb4af8fe4', packet)
    assert plaintext is not None, "Decryption failed"

  def test_packet5(self):
    packet = RNS_packet_unpack(data.packets[5])
    assert packet.packet_type is PACKET_PROOF
    assert packet.hops is 0
    assert packet.destination_type is DEST_SINGLE
    assert packet.destination_hash.hex() == 'd7c0e833f0cbde9f9133cd9e7d508b1a'
    assert packet.packet_hash.hex() == '3e98d0daf2b23edece8737b0ca348a04d882b1a4800b375259a6b03a1fa3b428'
    assert packet.transport_id is None
    assert RNS_validate_proof('072ec44973a8dee8e28d230fb4af8fe4', 'd7c0e833f0cbde9f9133cd9e7d508b1a61d2c89410e9009e4474b9212ed0370a', packet)

  def test_packet6(self):
    packet = RNS_packet_unpack(data.packets[6])
    assert packet.packet_type is PACKET_ANNOUNCE
    assert packet.hops is 0
    assert packet.destination_type is DEST_SINGLE
    assert packet.destination_hash.hex() == '7d62e355cc90ec4e79569d33a8ad6c6b'
    assert packet.packet_hash.hex() == '108b781ce8b8029f8335fc4a4b8a295895c3878d36467bb88da7137c88d3c282'
    assert packet.transport_id is None
    assert RNS.Identity.validate_announce(packet, True)


class TestLite:
  def test_packet0(self):
    packet = packet_unpack(data.packets[0])
    assert packet['packet_type'] is PACKET_ANNOUNCE
    assert packet['hops'] is 0
    assert packet['destination_type'] is DEST_SINGLE
    assert packet['destination_hash'].hex() == '072ec44973a8dee8e28d230fb4af8fe4'
    assert packet['packet_hash'].hex() == 'e56755f8b7405b07c12a5c25d7b9b744ca296f7349768b335c78be868530b57d'
    assert packet['transport_id'] is None
    assert validate_announce(packet)

  def test_packet1(self):
    packet = packet_unpack(data.packets[1])
    assert packet['packet_type'] is PACKET_ANNOUNCE
    assert packet['hops'] is 0
    assert packet['destination_type'] is DEST_SINGLE
    assert packet['destination_hash'].hex() == '76a93cda889a8c0a88451e02d53fd8b9'
    assert packet['packet_hash'].hex() == '1d17ee4b806f343804567c56ac9d1204e06ef9bc0d1e44b3970f4138a8ef897b'
    assert packet['transport_id'] is None
    assert validate_announce(packet)
  
  def test_packet2(self):
    packet = packet_unpack(data.packets[2])
    assert packet['packet_type'] is PACKET_DATA
    assert packet['hops'] is 0
    assert packet['destination_type'] is DEST_SINGLE
    assert packet['destination_hash'].hex() == '76a93cda889a8c0a88451e02d53fd8b9'
    assert packet['packet_hash'].hex() == '2831d76f1a8035638505c132fe5818c1d1d25869a973d35c197d669f0d5074d8'
    assert packet['transport_id'] is None
    plaintext = lite_validate_data('76a93cda889a8c0a88451e02d53fd8b9', packet)
    assert plaintext is not None, "Decryption failed"
  
  def test_packet3(self):
    packet = packet_unpack(data.packets[3])
    assert packet['packet_type'] is PACKET_PROOF
    assert packet['hops'] is 0
    assert packet['destination_type'] is DEST_SINGLE
    assert packet['destination_hash'].hex() == '2831d76f1a8035638505c132fe5818c1'
    assert packet['packet_hash'].hex() == 'c6c8d3a2da7de271b3262ed73f8d07f2d9b665e6dd382c610b2761f3484a6979'
    assert packet['transport_id'] is None
    assert lite_validate_proof('76a93cda889a8c0a88451e02d53fd8b9', '2831d76f1a8035638505c132fe5818c1d1d25869a973d35c197d669f0d5074d8', packet)
  
  def test_packet4(self):
    packet = packet_unpack(data.packets[4])
    assert packet['packet_type'] is PACKET_DATA
    assert packet['hops'] is 0
    assert packet['destination_type'] is DEST_SINGLE
    assert packet['destination_hash'].hex() == '072ec44973a8dee8e28d230fb4af8fe4'
    assert packet['packet_hash'].hex() == 'd7c0e833f0cbde9f9133cd9e7d508b1a61d2c89410e9009e4474b9212ed0370a'
    assert packet['transport_id'] is None
    plaintext = lite_validate_data('072ec44973a8dee8e28d230fb4af8fe4', packet)
    assert plaintext is not None, "Decryption failed"
  
  def test_packet5(self):
    packet = packet_unpack(data.packets[5])
    assert packet['packet_type'] is PACKET_PROOF
    assert packet['hops'] is 0
    assert packet['destination_type'] is DEST_SINGLE
    assert packet['destination_hash'].hex() == 'd7c0e833f0cbde9f9133cd9e7d508b1a'
    assert packet['packet_hash'].hex() == '3e98d0daf2b23edece8737b0ca348a04d882b1a4800b375259a6b03a1fa3b428'
    assert packet['transport_id'] is None
    assert lite_validate_proof('072ec44973a8dee8e28d230fb4af8fe4', 'd7c0e833f0cbde9f9133cd9e7d508b1a61d2c89410e9009e4474b9212ed0370a', packet)
  
  def test_packet6(self):
    packet = packet_unpack(data.packets[6])
    assert packet['packet_type'] is PACKET_ANNOUNCE
    assert packet['hops'] is 0
    assert packet['destination_type'] is DEST_SINGLE
    assert packet['destination_hash'].hex() == '7d62e355cc90ec4e79569d33a8ad6c6b'
    assert packet['packet_hash'].hex() == '108b781ce8b8029f8335fc4a4b8a295895c3878d36467bb88da7137c88d3c282'
    assert packet['transport_id'] is None
    assert validate_announce(packet)


