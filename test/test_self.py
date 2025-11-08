# Self-tests: create packets and verify them
import pytest
import sys
import os

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from rns_lite import *
from crypto import *

class TestPacketPack:
  def test_packet_pack_unpack_roundtrip(self):
    """Test that packet_pack and packet_unpack are inverses"""
    # Create a simple packet dict
    packet = {
      'header_type': 0,
      'context_flag': 0,
      'transport_type': 0,
      'destination_type': DEST_SINGLE,
      'packet_type': PACKET_DATA,
      'hops': 0,
      'destination_hash': b'0123456789abcdef',
      'context': CONTEXT_NONE,
      'data': b'hello world'
    }

    # Pack it
    packed = packet_pack(packet)

    # Unpack it
    unpacked = packet_unpack(packed)

    # Verify key fields match
    assert unpacked['header_type'] == packet['header_type']
    assert unpacked['context_flag'] == packet['context_flag']
    assert unpacked['transport_type'] == packet['transport_type']
    assert unpacked['destination_type'] == packet['destination_type']
    assert unpacked['packet_type'] == packet['packet_type']
    assert unpacked['hops'] == packet['hops']
    assert unpacked['destination_hash'] == packet['destination_hash']
    assert unpacked['context'] == packet['context']
    assert unpacked['data'] == packet['data']

  def test_packet_pack_with_transport_id(self):
    """Test packet_pack with transport_id (header_type=1)"""
    packet = {
      'header_type': 1,
      'context_flag': 1,
      'transport_type': 1,
      'destination_type': DEST_GROUP,
      'packet_type': PACKET_ANNOUNCE,
      'hops': 5,
      'transport_id': b'fedcba9876543210',
      'destination_hash': b'0123456789abcdef',
      'context': CONTEXT_RESOURCE,
      'data': b'test data'
    }

    packed = packet_pack(packet)
    unpacked = packet_unpack(packed)

    assert unpacked['header_type'] == 1
    assert unpacked['transport_id'] == packet['transport_id']
    assert unpacked['destination_hash'] == packet['destination_hash']
    assert unpacked['data'] == packet['data']


class TestBuildAnnounce:
  def test_build_announce_basic(self):
    """Test building an ANNOUNCE packet without ratchet"""
    identity_priv = private_identity()
    identity_pub = public_identity(identity_priv)

    # Build announce
    announce_bytes = build_announce(identity_priv)

    # Unpack and validate
    packet = packet_unpack(announce_bytes)
    assert packet['packet_type'] == PACKET_ANNOUNCE
    assert packet['destination_type'] == DEST_SINGLE
    assert packet['context_flag'] == 0

    # Validate the announce
    result = validate_announce(packet)
    assert result is not False
    assert result['public_key'] == identity_pub

  def test_build_announce_with_ratchet(self):
    """Test building an ANNOUNCE packet with ratchet"""
    identity_priv = private_identity()
    identity_pub = public_identity(identity_priv)
    ratchet_priv = private_ratchet()
    ratchet_pub = public_ratchet(ratchet_priv)

    # Build announce with ratchet
    announce_bytes = build_announce(identity_priv, ratchet_priv=ratchet_priv)

    # Unpack and validate
    packet = packet_unpack(announce_bytes)
    assert packet['packet_type'] == PACKET_ANNOUNCE
    assert packet['context_flag'] == 1  # Should have ratchet

    # Validate the announce
    result = validate_announce(packet)
    assert result is not False
    assert result['public_key'] == identity_pub
    assert result['ratchet'] == ratchet_pub

  def test_build_announce_with_app_data(self):
    """Test building an ANNOUNCE packet with app data"""
    identity_priv = private_identity()
    app_data = b'test app data'

    # Build announce with app data
    announce_bytes = build_announce(identity_priv, app_data=app_data)

    # Unpack and validate
    packet = packet_unpack(announce_bytes)
    result = validate_announce(packet)
    assert result is not False
    assert result['app_data'] == app_data


class TestBuildData:
  def test_build_data_basic(self):
    """Test building and decrypting a DATA packet"""
    # Create sender and receiver identities
    sender_priv = private_identity()
    receiver_priv = private_identity()
    receiver_pub = public_identity(receiver_priv)

    # Create receiver's ratchet
    receiver_ratchet_priv = private_ratchet()
    receiver_ratchet_pub = public_ratchet(receiver_ratchet_priv)

    # Build data packet
    plaintext = b'Hello, World!'
    data_bytes = build_data(plaintext, receiver_pub, receiver_ratchet_pub)

    # Unpack
    packet = packet_unpack(data_bytes)
    assert packet['packet_type'] == PACKET_DATA
    assert packet['destination_type'] == DEST_SINGLE

    # Decrypt
    decrypted = message_decrypt(packet, receiver_pub, ratchets=[receiver_ratchet_priv])
    assert decrypted is not None
    assert decrypted == plaintext

  def test_build_data_wrong_ratchet(self):
    """Test that DATA packet cannot be decrypted with wrong ratchet"""
    receiver_priv = private_identity()
    receiver_pub = public_identity(receiver_priv)

    # Create receiver's ratchet
    receiver_ratchet_pub = public_ratchet(private_ratchet())

    # Create a different ratchet for decryption (wrong one)
    wrong_ratchet_priv = private_ratchet()

    # Build data packet
    plaintext = b'Secret message'
    data_bytes = build_data(plaintext, receiver_pub, receiver_ratchet_pub)

    # Try to decrypt with wrong ratchet
    packet = packet_unpack(data_bytes)
    decrypted = message_decrypt(packet, receiver_pub, ratchets=[wrong_ratchet_priv])
    assert decrypted is None


class TestBuildProof:
  def test_build_proof_basic(self):
    """Test building and validating a PROOF packet"""
    # Create sender identity
    sender_priv = private_identity()
    sender_pub = public_identity(sender_priv)

    # Create a dummy data packet
    receiver_priv = private_identity()
    receiver_pub = public_identity(receiver_priv)
    receiver_ratchet_pub = public_ratchet(private_ratchet())

    data_bytes = build_data(b'test', receiver_pub, receiver_ratchet_pub)
    data_packet = packet_unpack(data_bytes)
    full_message_id = data_packet['packet_hash']

    # Build proof
    proof_bytes = build_proof(data_bytes, sender_priv)

    # Unpack
    proof_packet = packet_unpack(proof_bytes)
    assert proof_packet['packet_type'] == PACKET_PROOF

    # Validate proof
    is_valid = validate_proof(proof_packet, sender_pub, full_message_id)
    assert is_valid

  def test_build_proof_wrong_sender(self):
    """Test that PROOF cannot be validated with wrong sender"""
    # Create sender and wrong identity
    sender_priv = private_identity()
    wrong_pub = public_identity(private_identity())

    # Create a dummy data packet
    receiver_priv = private_identity()
    receiver_pub = public_identity(receiver_priv)
    receiver_ratchet_pub = public_ratchet(private_ratchet())

    data_bytes = build_data(b'test', receiver_pub, receiver_ratchet_pub)
    data_packet = packet_unpack(data_bytes)
    full_message_id = data_packet['packet_hash']

    # Build proof
    proof_bytes = build_proof(data_bytes, sender_priv)
    proof_packet = packet_unpack(proof_bytes)

    # Try to validate with wrong sender
    is_valid = validate_proof(proof_packet, wrong_pub, full_message_id)
    assert not is_valid


class TestEndToEndFlow:
  def test_full_message_exchange(self):
    """Test a complete message exchange: ANNOUNCE -> DATA -> PROOF"""
    # Alice creates identity and announces
    alice_priv = private_identity()
    alice_pub = public_identity(alice_priv)
    alice_ratchet_priv = private_ratchet()
    alice_ratchet_pub = public_ratchet(alice_ratchet_priv)

    alice_announce = build_announce(alice_priv, ratchet_priv=alice_ratchet_priv)
    alice_announce_packet = packet_unpack(alice_announce)
    alice_announce_info = validate_announce(alice_announce_packet)
    assert alice_announce_info is not False

    # Bob creates identity
    bob_priv = private_identity()
    bob_pub = public_identity(bob_priv)

    # Bob sends data to Alice using her announced ratchet
    message = b'Hello Alice!'
    data_bytes = build_data(message, alice_pub, alice_announce_info['ratchet'])
    data_packet = packet_unpack(data_bytes)

    # Alice decrypts the message
    decrypted = message_decrypt(data_packet, alice_pub, ratchets=[alice_ratchet_priv])
    assert decrypted == message

    # Alice sends a proof back to Bob
    proof_bytes = build_proof(data_bytes, alice_priv)
    proof_packet = packet_unpack(proof_bytes)

    # Bob validates the proof
    is_valid = validate_proof(proof_packet, alice_pub, data_packet['packet_hash'])
    assert is_valid


class TestLXMF:
  def test_lxmf_build_basic(self):
    """Test building an LXMF message"""
    sender_priv = private_identity()
    sender_dest = get_identity_destination_hash(public_identity(sender_priv))
    receiver_dest = bytes.fromhex('0123456789abcdef0123456789abcdef')

    content = b'Hello'
    lxmf_msg = lxmf_build(content, sender_priv, receiver_dest)

    # Verify structure
    assert len(lxmf_msg) >= 80
    assert lxmf_msg[0:16] == sender_dest  # source hash
    # signature is at bytes 16-80
    # msgpack is at bytes 80+

  def test_lxmf_build_with_custom_fields(self):
    """Test building LXMF with custom timestamp and fields"""
    sender_priv = private_identity()
    receiver_dest = bytes.fromhex('0123456789abcdef0123456789abcdef')

    content = b'Test'
    timestamp = 1234567890.0
    fields = {'custom': 'data'}

    lxmf_msg = lxmf_build(content, sender_priv, receiver_dest, timestamp=timestamp, fields=fields)
    assert len(lxmf_msg) >= 80

  def test_lxmf_build_auto_source_hash(self):
    """Test that source_hash is automatically computed if not provided"""
    sender_priv = private_identity()
    sender_dest = get_identity_destination_hash(public_identity(sender_priv))
    receiver_dest = bytes.fromhex('0123456789abcdef0123456789abcdef')

    lxmf_msg = lxmf_build(b'test', sender_priv, receiver_dest)
    assert lxmf_msg[0:16] == sender_dest

  def test_lxmf_parse_basic(self):
    """Test parsing a valid LXMF message"""
    sender_priv = private_identity()
    sender_pub = public_identity(sender_priv)
    sender_dest = get_identity_destination_hash(sender_pub)
    receiver_dest = bytes.fromhex('0123456789abcdef0123456789abcdef')

    content = b'Hello World!'
    lxmf_msg = lxmf_build(content, sender_priv, receiver_dest)

    parsed = lxmf_parse(lxmf_msg, receiver_dest, sender_pub)
    assert parsed is not False
    assert parsed['source_hash'] == sender_dest
    assert parsed['content'] == content
    assert 'timestamp' in parsed
    assert 'fields' in parsed
    assert 'message_id' in parsed

  def test_lxmf_parse_invalid_signature(self):
    """Test that invalid signature fails"""
    sender_priv = private_identity()
    sender_pub = public_identity(sender_priv)
    wrong_pub = public_identity(private_identity())
    receiver_dest = bytes.fromhex('0123456789abcdef0123456789abcdef')

    lxmf_msg = lxmf_build(b'test', sender_priv, receiver_dest)

    # Try parsing with wrong public key
    parsed = lxmf_parse(lxmf_msg, receiver_dest, wrong_pub)
    assert parsed is False

  def test_lxmf_parse_too_short(self):
    """Test that messages < 80 bytes fail"""
    sender_pub = public_identity(private_identity())
    receiver_dest = bytes.fromhex('0123456789abcdef0123456789abcdef')

    parsed = lxmf_parse(b'short', receiver_dest, sender_pub)
    assert parsed is False

  def test_lxmf_parse_corrupted_msgpack(self):
    """Test that corrupted msgpack fails gracefully"""
    sender_priv = private_identity()
    sender_pub = public_identity(sender_priv)
    sender_dest = get_identity_destination_hash(sender_pub)
    receiver_dest = bytes.fromhex('0123456789abcdef0123456789abcdef')

    # Create valid structure but corrupt msgpack
    corrupted = sender_dest + (b'\x00' * 64) + b'invalid msgpack data here'

    parsed = lxmf_parse(corrupted, receiver_dest, sender_pub)
    assert parsed is False

  def test_lxmf_roundtrip(self):
    """Test build and parse roundtrip"""
    sender_priv = private_identity()
    sender_pub = public_identity(sender_priv)
    sender_dest = get_identity_destination_hash(sender_pub)
    receiver_dest = bytes.fromhex('0123456789abcdef0123456789abcdef')

    content = b'Roundtrip test message'
    lxmf_msg = lxmf_build(content, sender_priv, receiver_dest)
    parsed = lxmf_parse(lxmf_msg, receiver_dest, sender_pub)

    assert parsed is not False
    assert parsed['source_hash'] == sender_dest
    assert parsed['content'] == content


class TestLXMFIntegration:
  def test_lxmf_message_build_and_parse(self):
    """Test building and parsing LXMF messages"""
    # Create sender and receiver identities
    sender_priv = private_identity()
    sender_pub = public_identity(sender_priv)
    sender_dest = get_identity_destination_hash(sender_pub)

    receiver_priv = private_identity()
    receiver_pub = public_identity(receiver_priv)
    receiver_dest = get_identity_destination_hash(receiver_pub)

    # Build LXMF message
    content = b'Hello World!'
    lxmf_message = lxmf_build(content, sender_priv, receiver_dest)

    # Parse it back (receiver_dest is the packet destination in this case)
    parsed = lxmf_parse(lxmf_message, receiver_dest, sender_pub)

    assert parsed is not False
    assert parsed['source_hash'] == sender_dest
    assert parsed['content'] == content

  def test_lxmf_full_encrypted_flow(self):
    """Test LXMF message in an encrypted DATA packet"""
    # Create sender (Bob) and receiver (Alice) identities
    alice_priv = private_identity()
    alice_pub = public_identity(alice_priv)
    alice_dest = get_identity_destination_hash(alice_pub)
    alice_ratchet_priv = private_ratchet()
    alice_ratchet_pub = public_ratchet(alice_ratchet_priv)

    bob_priv = private_identity()
    bob_pub = public_identity(bob_priv)
    bob_dest = get_identity_destination_hash(bob_pub)
    bob_ratchet_priv = private_ratchet()

    # Bob announces with ratchet
    bob_announce = build_announce(bob_priv, ratchet_priv=bob_ratchet_priv)
    bob_announce_packet = packet_unpack(bob_announce)
    bob_announce_info = validate_announce(bob_announce_packet)

    # Alice announces with ratchet
    alice_announce = build_announce(alice_priv, ratchet_priv=alice_ratchet_priv)
    alice_announce_packet = packet_unpack(alice_announce)
    alice_announce_info = validate_announce(alice_announce_packet)

    # Bob builds LXMF message to Alice
    content = b'Hello Alice from Bob!'
    lxmf_message = lxmf_build(content, bob_priv, alice_dest)

    # Bob encrypts it in a DATA packet
    data_bytes = build_data(lxmf_message, alice_pub, alice_ratchet_pub)
    data_packet = packet_unpack(data_bytes)

    # Alice decrypts the DATA packet
    decrypted = message_decrypt(data_packet, alice_pub, [alice_ratchet_priv])
    assert decrypted is not None

    # Alice parses the LXMF message (alice_dest is the packet destination)
    parsed = lxmf_parse(decrypted, alice_dest, bob_pub)
    assert parsed is not False
    assert parsed['source_hash'] == bob_dest
    assert parsed['content'] == content

    # Alice responds with echo
    response_lxmf = lxmf_build(content, alice_priv, bob_dest)
    response_data = build_data(response_lxmf, bob_pub, bob_announce_info['ratchet'])
    response_packet = packet_unpack(response_data)

    # Bob decrypts the response
    response_decrypted = message_decrypt(response_packet, bob_pub, [bob_ratchet_priv])
    assert response_decrypted is not None

    # Bob parses the LXMF response (bob_dest is the packet destination)
    response_parsed = lxmf_parse(response_decrypted, bob_dest, alice_pub)
    assert response_parsed is not False
    assert response_parsed['source_hash'] == alice_dest
    assert response_parsed['content'] == content
