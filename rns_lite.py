"""
Lightweight reticulum library
"""

from typing import Union
import msgpack

from crypto import (
    # these will be used by others
    private_identity,
    public_identity,
    private_ratchet,
    public_ratchet,
    # these are internal utils
    sha256,
    hmac_sha256,
    hkdf,
    aes_cbc_encrypt,
    aes_cbc_decrypt,
    ed25519_sign,
    ed25519_validate,
    x25519_exchange,
)

PACKET_DATA = 0x00
PACKET_ANNOUNCE = 0x01
PACKET_LINKREQUEST = 0x02
PACKET_PROOF = 0x03

DEST_SINGLE = 0x00
DEST_GROUP = 0x01
DEST_PLAIN = 0x02
DEST_LINK = 0x03

CONTEXT_NONE = 0x00  # Generic data packet
CONTEXT_RESOURCE = 0x01  # Packet is part of a resource
CONTEXT_RESOURCE_ADV = 0x02  # Packet is a resource advertisement
CONTEXT_RESOURCE_REQ = 0x03  # Packet is a resource part request
CONTEXT_RESOURCE_HMU = 0x04  # Packet is a resource hashmap update
CONTEXT_RESOURCE_PRF = 0x05  # Packet is a resource proof
CONTEXT_RESOURCE_ICL = 0x06  # Packet is a resource initiator cancel message
CONTEXT_RESOURCE_RCL = 0x07  # Packet is a resource receiver cancel message
CONTEXT_CACHE_REQUEST = 0x08  # Packet is a cache request
CONTEXT_REQUEST = 0x09  # Packet is a request
CONTEXT_RESPONSE = 0x0A  # Packet is a response to a request
CONTEXT_PATH_RESPONSE = 0x0B  # Packet is a response to a path request
CONTEXT_COMMAND = 0x0C  # Packet is a command
CONTEXT_COMMAND_STATUS = 0x0D  # Packet is a status of an executed command
CONTEXT_CHANNEL = 0x0E  # Packet contains link channel data
CONTEXT_KEEPALIVE = 0xFA  # Packet is a keepalive packet
CONTEXT_LINKIDENTIFY = 0xFB  # Packet is a link peer identification proof
CONTEXT_LINKCLOSE = 0xFC  # Packet is a link close message
CONTEXT_LINKPROOF = 0xFD  # Packet is a link packet proof
CONTEXT_LRRTT = 0xFE  # Packet is a link request round-trip time measurement
CONTEXT_LRPROOF = 0xFF  # Packet is a link request proof


def get_identity_destination_hash(
    identityPublic: bytes, full_name: str = "lxmf.delivery"
) -> bytes:
    """
    Get the destination-hash (address) from identity.
    """
    identity_hash = sha256(identityPublic)[:16]
    name_hash = sha256(full_name.encode("utf-8"))[:10]
    addr_hash_material = name_hash + identity_hash
    destination_hash = sha256(addr_hash_material)[:16]
    return destination_hash


def get_message_id(packetBytes: bytes) -> bytes:
    """
    Get the message-id (used as destination in PROOFs, for example) from a packet
    """
    hashable_part = bytes([packetBytes[0] & 0b00001111])
    hashable_part += packetBytes[2:]
    return sha256(hashable_part)


def packet_unpack(packetBytes: bytes) -> dict:
    """
    Unpack packet-bytes into dict
    """
    DST_LEN = 16
    flags = packetBytes[0]
    hops = packetBytes[1]
    header_type = (flags & 0b01000000) >> 6
    context_flag = (flags & 0b00100000) >> 5
    transport_type = (flags & 0b00010000) >> 4
    destination_type = (flags & 0b00001100) >> 2
    packet_type = flags & 0b00000011
    if header_type == 1:
        transport_id = packetBytes[2 : DST_LEN + 2]
        destination_hash = packetBytes[DST_LEN + 2 : 2 * DST_LEN + 2]
        context = ord(packetBytes[2 * DST_LEN + 2 : 2 * DST_LEN + 3])
        data = packetBytes[2 * DST_LEN + 3 :]
    else:
        transport_id = None
        destination_hash = packetBytes[2 : DST_LEN + 2]
        context = ord(packetBytes[DST_LEN + 2 : DST_LEN + 3])
        data = packetBytes[DST_LEN + 3 :]
    return {
        "header_type": header_type,
        "context_flag": context_flag,
        "transport_type": transport_type,
        "destination_type": destination_type,
        "packet_type": packet_type,
        "transport_id": transport_id,
        "destination_hash": destination_hash,
        "context": context,
        "data": data,
        "hops": hops,
        "packet_hash": get_message_id(packetBytes),
        "raw": packetBytes,
    }


def validate_announce(packet: dict) -> Union[bool, dict]:
    """
    Parse ANNOUCE, return false if it doesn't validate, and soem info if it does
    """
    keysize = 64
    ratchetsize = 32
    name_hash_len = 10
    sig_len = 64
    destination_hash = packet["destination_hash"]
    public_key = packet["data"][:keysize]
    if packet["context_flag"] == 1:
        name_hash = packet["data"][keysize : keysize + name_hash_len]
        random_hash = packet["data"][
            keysize + name_hash_len : keysize + name_hash_len + 10
        ]
        ratchet = packet["data"][
            keysize + name_hash_len + 10 : keysize + name_hash_len + 10 + ratchetsize
        ]
        signature = packet["data"][
            keysize + name_hash_len + 10 + ratchetsize : keysize
            + name_hash_len
            + 10
            + ratchetsize
            + sig_len
        ]
        app_data = b""
        if len(packet["data"]) > keysize + name_hash_len + 10 + sig_len + ratchetsize:
            app_data = packet["data"][
                keysize + name_hash_len + 10 + sig_len + ratchetsize :
            ]
    else:
        ratchet = b""
        name_hash = packet["data"][keysize : keysize + name_hash_len]
        random_hash = packet["data"][
            keysize + name_hash_len : keysize + name_hash_len + 10
        ]
        signature = packet["data"][
            keysize + name_hash_len + 10 : keysize + name_hash_len + 10 + sig_len
        ]
        app_data = b""
        if len(packet["data"]) > keysize + name_hash_len + 10 + sig_len:
            app_data = packet["data"][keysize + name_hash_len + 10 + sig_len :]
    signed_data = (
        destination_hash + public_key + name_hash + random_hash + ratchet + app_data
    )
    if not len(packet["data"]) > 64 + 10 + 10 + 64:
        app_data = None
    if not ed25519_validate(
        signature,
        signed_data,
        public_key[32:64],
    ):
        return False
    return {
        "app_data": app_data,
        "name_hash": name_hash,
        "public_key": public_key,
        "random_hash": random_hash,
        "ratchet": ratchet,
        "signature": signature,
        "signed_data": signed_data,
    }


def validate_proof(packet: dict, sender_pub: bytes, full_packet_hash: bytes) -> bool:
    """
    Validate a PROOF packet
    """
    return ed25519_validate(packet["data"][0:64], full_packet_hash, sender_pub[32:64])


def message_decrypt(packet: dict, receiver_pub: bytes, ratchets=[]) -> dict:
    """
    Decrypt a MESSAGE packet
    """
    if len(packet["data"]) < 49:
        return None
    identity_hash = sha256(receiver_pub)[:16]
    peer_pub_bytes = packet["data"][:32]
    rest = packet["data"][32:]
    if len(rest) < 48:  # 16 for IV, 32 for HMAC
        return None
    signed_data = rest[:-32]  # IV + ciphertext
    received_hmac = rest[-32:]
    for ratchet in ratchets:
        if len(ratchet) != 32:
            continue
        try:
            derived_key = hkdf(
                x25519_exchange(ratchet, peer_pub_bytes), 64, identity_hash
            )
            expected_hmac = hmac_sha256(derived_key[:32], signed_data)
            if expected_hmac != received_hmac:
                continue
            return aes_cbc_decrypt(derived_key[32:], signed_data[:16], signed_data[16:])
        except Exception as e:
            continue
    return None


def packet_pack(packet: dict) -> bytes:
    """
    Pack a packet dict into bytes
    """
    # Build flags byte
    flags = 0
    flags |= (packet.get("header_type", 0) & 0b1) << 6
    flags |= (packet.get("context_flag", 0) & 0b1) << 5
    flags |= (packet.get("transport_type", 0) & 0b1) << 4
    flags |= (packet.get("destination_type", 0) & 0b11) << 2
    flags |= packet.get("packet_type", 0) & 0b11

    # Build packet
    result = bytes([flags, packet.get("hops", 0)])

    # Add transport_id if header_type is 1
    if packet.get("header_type", 0) == 1:
        result += packet["transport_id"]

    # Add destination_hash
    result += packet["destination_hash"]

    # Add context
    result += bytes([packet.get("context", 0)])

    # Add data
    result += packet.get("data", b"")

    return result


def build_announce(
    identity_priv: bytes,
    identity_pub: bytes = None,
    destination_hash: bytes = None,
    ratchet_priv: bytes = None,
    ratchet_pub: bytes = None,
    full_name: str = "lxmf.delivery",
    app_data: bytes = b"",
) -> bytes:
    """
    Build an ANNOUNCE packet for sharing identity or ratchet key
    """
    import os

    # Get public key, if needed
    identity_pub = identity_pub or public_identity(identity_priv)

    # Get destination hash
    destination_hash = destination_hash or get_identity_destination_hash(
        identity_pub, full_name
    )

    # Build announce data
    public_key = identity_pub  # 64 bytes
    name_hash = sha256(full_name.encode("utf-8"))[:10]
    random_hash = os.urandom(10)

    # Add ratchet if provided
    if not ratchet_pub:
        if ratchet_priv:
            ratchet_pub = public_ratchet(ratchet_priv)
        else:
            ratchet_pub = b""

    if ratchet_pub:
        context_flag = 1
    else:
        ratchet_pub = b""
        context_flag = 0

    # Sign the announce
    signed_data = (
        destination_hash + public_key + name_hash + random_hash + ratchet_pub + app_data
    )
    signature = ed25519_sign(identity_priv[32:], signed_data)

    # Build data field
    data = public_key + name_hash + random_hash
    if ratchet_pub:
        data += ratchet_pub
    data += signature + app_data

    # Build packet
    packet = {
        "header_type": 0,
        "context_flag": context_flag,
        "transport_type": 0,
        "destination_type": DEST_SINGLE,
        "packet_type": PACKET_ANNOUNCE,
        "hops": 0,
        "destination_hash": destination_hash,
        "context": CONTEXT_NONE,
        "data": data,
    }

    return packet_pack(packet)


def build_data(
    plaintext: bytes,
    receiver_identity_pub: bytes,
    receiver_ratchet_pub: bytes,
    full_name: str = "lxmf.delivery",
) -> bytes:
    """
    Build a DATA packet encrypted for a receiver
    receiver_identity_pub: 64-byte identity public key (for addressing)
    receiver_ratchet_pub: 32-byte ratchet public key (for encryption, from ANNOUNCE)
    """
    import os

    # Get receiver's destination hash (for addressing)
    destination_hash = get_identity_destination_hash(receiver_identity_pub, full_name)
    identity_hash = sha256(receiver_identity_pub)[:16]

    # Generate ephemeral key pair for this message
    ephemeral_priv = private_ratchet()
    ephemeral_pub = public_ratchet(ephemeral_priv)

    # Derive encryption keys using ephemeral private and receiver's ratchet public
    shared_secret = x25519_exchange(ephemeral_priv, receiver_ratchet_pub)
    derived_key = hkdf(shared_secret, 64, identity_hash)

    # Split into HMAC key and AES key
    hmac_key = derived_key[:32]
    aes_key = derived_key[32:]

    # Generate random IV and encrypt
    iv = os.urandom(16)
    ciphertext = aes_cbc_encrypt(aes_key, iv, plaintext)

    # Build signed data (IV + ciphertext) and compute HMAC
    signed_data = iv + ciphertext
    message_hmac = hmac_sha256(hmac_key, signed_data)

    # Build data field: ephemeral_pub + IV + ciphertext + HMAC
    data = ephemeral_pub + signed_data + message_hmac

    # Build packet
    packet = {
        "header_type": 0,
        "context_flag": 0,
        "transport_type": 0,
        "destination_type": DEST_SINGLE,
        "packet_type": PACKET_DATA,
        "hops": 0,
        "destination_hash": destination_hash,
        "context": CONTEXT_NONE,
        "data": data,
    }

    return packet_pack(packet)


def build_proof(data_packet_bytes: bytes, sender_identity_priv: bytes) -> bytes:
    """
    Build a PROOF packet for acknowledging a DATA packet
    """
    # Get full message ID from the data packet
    full_message_id = get_message_id(data_packet_bytes)

    # Truncate to 16 bytes for destination hash
    truncated_message_id = full_message_id[:16]

    # Sign the full message ID
    signature = ed25519_sign(sender_identity_priv[32:], full_message_id)

    # Build packet
    packet = {
        "header_type": 0,
        "context_flag": 0,
        "transport_type": 0,
        "destination_type": DEST_SINGLE,
        "packet_type": PACKET_PROOF,
        "hops": 0,
        "destination_hash": truncated_message_id,
        "context": CONTEXT_NONE,
        "data": signature,
    }

    return packet_pack(packet)


def lxmf_parse(
    decrypted_data: bytes, packet_destination_hash: bytes, sender_pub: bytes
) -> Union[bool, dict]:
    """
    Parse and validate an LXMF message from decrypted DATA packet payload

    LXMF format:
    - Bytes 0-15: Source destination hash (16 bytes)
    - Bytes 16-79: Ed25519 signature (64 bytes)
    - Bytes 80+: msgpack [timestamp, destination, content, fields]

    Returns False if invalid, or dict with parsed fields if valid
    """
    if len(decrypted_data) < 80:
        return False

    source_hash = decrypted_data[0:16]
    signature = decrypted_data[16:80]
    msgpack_raw = decrypted_data[80:]

    try:
        # Parse msgpack: [timestamp, destination, content, fields]
        msgpack_data = msgpack.unpackb(msgpack_raw, raw=True)
        if not isinstance(msgpack_data, (list, tuple)) or len(msgpack_data) < 3:
            return False

        timestamp = msgpack_data[0] if len(msgpack_data) > 0 else None
        destination_in_msg = msgpack_data[1] if len(msgpack_data) > 1 else b""
        content = msgpack_data[2] if len(msgpack_data) > 2 else None
        fields = msgpack_data[3] if len(msgpack_data) > 3 else {}

        # Verify LXMF signature
        # message_id = sha256(packet_destination + source_hash + msgpack_raw)
        # signed_data = packet_destination + source_hash + msgpack_raw + message_id
        message_id = sha256(packet_destination_hash + source_hash + msgpack_raw)
        signed_data = packet_destination_hash + source_hash + msgpack_raw + message_id

        if not ed25519_validate(signature, signed_data, sender_pub[32:64]):
            return False

        return {
            "source_hash": source_hash,
            "timestamp": timestamp,
            "content": content,
            "fields": fields,
            "message_id": message_id,
        }
    except Exception:
        return False


def lxmf_build(
    content: bytes,
    source_priv: bytes,
    destination_hash: bytes,
    source_hash: bytes = None,
    timestamp: float = None,
    fields: dict = None,
) -> bytes:
    """
    Build an LXMF message to be encrypted in a DATA packet

    Returns bytes ready for encryption:
    - Bytes 0-15: Source destination hash (16 bytes)
    - Bytes 16-79: Ed25519 signature (64 bytes)
    - Bytes 80+: msgpack [timestamp, destination, content, fields]
    """
    import time

    if timestamp is None:
        timestamp = time.time()
    if fields is None:
        fields = {}
    if source_hash is None:
        source_hash = get_identity_destination_hash(public_identity(source_priv))

    # Build msgpack: [timestamp, destination, content, fields]
    # Note: destination is empty b'' for direct messages
    msgpack_data = [timestamp, b"", content, fields]
    msgpack_raw = msgpack.packb(msgpack_data, use_bin_type=True)

    # Sign: destination + source + msgpack + sha256(destination + source + msgpack)
    message_id = sha256(destination_hash + source_hash + msgpack_raw)
    signed_data = destination_hash + source_hash + msgpack_raw + message_id
    signature = ed25519_sign(source_priv[32:], signed_data)

    # Build LXMF message: source + signature + msgpack
    return source_hash + signature + msgpack_raw
