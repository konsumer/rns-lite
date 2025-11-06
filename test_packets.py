import pytest
from utils import *
from rns import *

def test_build_and_parse_data_packet():
    destination_hash = hex_to_bytes("0123456789abcdef0123456789abcdef")
    data = bytes([0xde, 0xad, 0xbe, 0xef])
    packet = build_data(destination_hash, data)
    parsed = parse_packet(packet)
    assert parsed["packetType"] == PACKET_DATA
    assert parsed["hops"] == 0
    assert parsed["transportType"] == TRANSPORT_BROADCAST
    assert parsed["destinationType"] == DEST_SINGLE
    assert parsed["destinationHash"] == destination_hash
    assert parsed["data"] == data

def test_build_packet_with_context():
    destination_hash = hex_to_bytes("0123456789abcdef0123456789abcdef")
    data = hex_to_bytes("cafebabe")
    packet = build_data(destination_hash, data, context=CONTEXT_NONE)
    parsed = parse_packet(packet)
    assert parsed["contextFlag"] == 1
    assert parsed["hops"] == 0
    assert parsed["context"] == CONTEXT_NONE

def test_build_packet_with_transport_id():
    transport_id = hex_to_bytes("fedcba9876543210fedcba9876543210")
    destination_hash = hex_to_bytes("0123456789abcdef0123456789abcdef")
    data = hex_to_bytes("1234")
    packet = build_data(destination_hash, data, context=CONTEXT_NONE, transport_id=transport_id)
    parsed = parse_packet(packet)
    assert parsed["headerType"] == 1
    assert parsed["transportType"] == TRANSPORT_TRANSPORT
    assert parsed["transportId"] == transport_id
    assert parsed["destinationHash"] == destination_hash

def test_build_and_parse_announce_no_ratchet():
    identity_priv=private_identity()
    identity_pub = public_identity(identity_priv)
    name = "lxmf.delivery"
    appdata = b"test app data"
    packet = build_announce(identity_priv, identity_pub, identity_pub[:32], appdata, name)
    parsed = parse_packet(packet)
    assert parsed["packetType"] == PACKET_ANNOUNCE
    announce = parse_announce(parsed)
    assert announce["valid"]
    assert announce["keyPubEncrypt"] == identity_pub[:32]
    assert announce["keyPubSignature"] == identity_pub[32:64]
    assert announce["appData"] == appdata

def test_build_and_parse_announce_with_ratchet():
    identity_priv = private_identity()
    identity_pub = public_identity(identity_priv)

    ratchet_priv = random_bytes(32)
    ratchet_pub = x25519_public_for_private(ratchet_priv)
    name = "test.service"
    packet = build_announce(identity_priv, identity_pub, ratchet_pub, b"", name)
    parsed = parse_packet(packet)
    assert parsed["packetType"] == PACKET_ANNOUNCE
    announce = parse_announce(parsed)
    assert announce["valid"]
    assert announce["ratchetPub"] == ratchet_pub

def test_build_and_parse_lxmf_message():
    sender_priv = private_identity()
    sender_pub = public_identity(sender_priv)
    sender_hash = get_destination_hash(sender_pub)
    receiver_priv = private_identity()
    receiver_pub = public_identity(receiver_priv)
    ratchet_priv = private_ratchet()
    ratchet_pub = public_ratchet(ratchet_priv)

    timestamp = 1234567890
    title = "Hello"
    content = "Test message"
    fields = {"priority": "high"}

    packet = build_lxmf(sender_hash, sender_priv, receiver_pub, ratchet_pub, timestamp, title, content, fields)

    parsed = parse_packet(packet)

    assert parsed["packetType"] == PACKET_DATA
    lxmf = parse_lxmf(parsed, receiver_pub, [ratchet_priv], sender_pub)
    assert lxmf is not None
    assert lxmf["title"] == title
    assert lxmf["content"] == content
    assert lxmf["valid"]

def test_build_and_parse_proof():
    # sender identity
    sender_priv = private_identity()
    sender_pub = public_identity(sender_priv)

    destination_hash = get_destination_hash(sender_pub, "lxmf.delivery")
    # create a data packet to be "proved"
    data_bytes = b'testdata'
    data_packet = build_data(destination_hash, data_bytes)
    data_packet_hash = get_message_id(data_packet)
    # build proof packet
    proof_packet = build_proof(data_packet, sender_priv)
    parsed = parse_packet(proof_packet)
    assert parsed["packetType"] == PACKET_PROOF
    assert parsed["destinationHash"] == destination_hash
    proof_valid = parse_proof(parsed, sender_pub, data_packet_hash)
    assert proof_valid

def test_build_and_parse_proof_from_parsed_packet():
    sender_priv = private_identity()
    sender_pub = public_identity(sender_priv)
    destination_hash = get_destination_hash(sender_pub, "test.app")
    data_packet = build_data(destination_hash, b'abc123')
    data_parsed = parse_packet(data_packet)
    proof_packet = build_proof(data_packet, sender_priv)
    parsed = parse_packet(proof_packet)
    proof_valid = parse_proof(parsed, sender_pub, data_parsed["packetHash"])
    assert proof_valid

def test_roundtrip_announce():
    identity_priv = private_identity()
    identity_pub = public_identity(identity_priv)
    name = "test.service"
    app_data = b'\x01\x02\x03'
    explicit_ratchet = identity_pub[:32]  # Use default (implicit) ratchet
    packet = build_announce(identity_priv, identity_pub, explicit_ratchet, app_data, name)
    parsed = parse_packet(packet)
    announce = parse_announce(parsed)
    expected_dest_hash = get_destination_hash(identity_pub, name)
    assert parsed["destinationHash"] == expected_dest_hash
    assert announce["valid"]
    assert announce["appData"] == app_data


def test_complex_packet_chain():
    # 1. Alice sends LXMF message to Bob
    alice_priv = private_identity()
    alice_pub = public_identity(alice_priv)
    alice_hash = get_destination_hash(alice_pub)

    bob_priv = private_identity()
    bob_pub = public_identity(bob_priv)

    bob_ratchet_priv = private_ratchet()
    bob_ratchet_pub = public_ratchet(bob_ratchet_priv)

    timestamp = 1234567890
    title = "Hello"
    content = "Test message"
    fields = {"priority": "high"}

    message = build_lxmf(
        alice_hash,
        alice_priv,
        bob_pub,
        bob_ratchet_pub,
        timestamp,
        title,
        content,
        fields
    )

    # 2. Bob receives and decrypts
    message_parsed = parse_packet(message)
    lxmf = parse_lxmf(message_parsed, bob_pub, [bob_ratchet_priv], alice_pub)
    assert lxmf is not None
    assert lxmf["title"] == title
    assert lxmf["content"] == content
    assert lxmf["valid"]

    # 3. Bob sends proof back to Alice
    proof_packet = build_proof(message, bob_priv)
    proof_parsed = parse_packet(proof_packet)
    proof_valid = parse_proof(proof_parsed, bob_pub, message_parsed["packetHash"])
    assert proof_valid



