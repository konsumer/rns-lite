"""
Lightweight Reticulum library for Python
"""

from utils import *

import struct
import msgpack

# Packet types
PACKET_DATA = 0x00
PACKET_ANNOUNCE = 0x01
PACKET_LINKREQUEST = 0x02
PACKET_PROOF = 0x03

# Context types
CONTEXT_NONE = 0x00
CONTEXT_RESOURCE = 0x01
CONTEXT_RESOURCEADV = 0x02
CONTEXT_RESOURCEREQ = 0x03
CONTEXT_RESOURCEHMU = 0x04
CONTEXT_RESOURCEPRF = 0x05
CONTEXT_RESOURCEICL = 0x06
CONTEXT_RESOURCERCL = 0x07
CONTEXT_CACHEREQUEST = 0x08
CONTEXT_REQUEST = 0x09
CONTEXT_RESPONSE = 0x0a
CONTEXT_PATHRESPONSE = 0x0b
CONTEXT_COMMAND = 0x0c
CONTEXT_COMMANDSTATUS = 0x0d
CONTEXT_CHANNEL = 0x0e
CONTEXT_KEEPALIVE = 0xfa
CONTEXT_LINKIDENTIFY = 0xfb
CONTEXT_LINKCLOSE = 0xfc
CONTEXT_LINKPROOF = 0xfd
CONTEXT_LRRTT = 0xfe
CONTEXT_LRPROOF = 0xff

# Destination types
DEST_SINGLE = 0x00
DEST_GROUP = 0x01
DEST_PLAIN = 0x02
DEST_LINK = 0x03

# Transport types
TRANSPORT_BROADCAST = 0
TRANSPORT_TRANSPORT = 1

def build_packet(packet):
    hops = packet.get('hops', 0)
    destination_type = packet.get('destinationType', DEST_SINGLE)
    transport_type = packet.get('transportType', TRANSPORT_BROADCAST)
    packet_type = packet.get('packetType')
    context = packet.get('context')
    transport_id = packet.get('transportId')
    destination_hash = packet.get('destinationHash')
    data = packet.get('data')

    # Determine flags and header structure
    context_flag = 1 if context is not None else 0
    header_type = 1 if transport_id is not None else 0

    flags = (
        (header_type << 6)
        | (context_flag << 5)
        | (transport_type << 4)
        | ((destination_type & 0x03) << 2)
        | (packet_type & 0x03)
    )

    parts = bytearray()
    parts.append(flags)
    parts.append(hops)

    if header_type:
        # [transport_id][destination_hash][context][data]
        parts += transport_id
        parts += destination_hash
        parts.append(context if context is not None else 0)
        if data:
            parts += data
    else:
        # [destination_hash][context][data]
        parts += destination_hash
        parts.append(context if context is not None else 0)
        if data:
            parts += data

    return bytes(parts)

def build_announce(identity_priv_bytes, identity_pub_bytes, ratchet_pub_bytes=None, appdata=None, name="lxmf.delivery"):
    destination_hash = get_destination_hash(identity_pub_bytes, name)

    random_hash = random_bytes(10)
    name_hash = sha256(name.encode('utf-8'))[:10]

    # Default ratchet is encryption key; explicit ratchet if supplied and differs
    enc_pub = identity_pub_bytes[:32]
    ratchet_pub_bytes = ratchet_pub_bytes or enc_pub
    has_explicit_ratchet = ratchet_pub_bytes != enc_pub

    # Get app data (empty if not supplied)
    if appdata is None:
        app_data_bytes = b""
    elif isinstance(appdata, str):
        app_data_bytes = appdata.encode()
    else:
        app_data_bytes = appdata

    # Prepare signed data
    signed_data = concat_bytes(
        destination_hash,
        identity_pub_bytes,
        name_hash,
        random_hash,
        ratchet_pub_bytes if has_explicit_ratchet else b"",
        app_data_bytes,
    )

    signature = ed25519_sign(signed_data, identity_priv_bytes[32:])

    # Order fields
    data_parts = [
        identity_pub_bytes,
        name_hash,
        random_hash,
    ]
    if has_explicit_ratchet:
        data_parts.append(ratchet_pub_bytes)
    data_parts.append(signature)
    if app_data_bytes:
        data_parts.append(app_data_bytes)
    data = concat_bytes(*data_parts)

    packet = {
        'hops': 0,
        'destinationType': DEST_SINGLE,
        'transportType': TRANSPORT_BROADCAST,
        'packetType': PACKET_ANNOUNCE,
        'context': CONTEXT_NONE if has_explicit_ratchet else None,
        'destinationHash': destination_hash,
        'data': data,
    }

    return build_packet(packet)

def build_data(destination_hash, data, context=CONTEXT_NONE, transport_id=None):
    packet = {
        'hops': 0,
        'destinationType': DEST_SINGLE,
        'transportType': TRANSPORT_TRANSPORT if transport_id else TRANSPORT_BROADCAST,
        'packetType': PACKET_DATA,
        'context': context,
        'transportId': transport_id,
        'destinationHash': destination_hash,
        'data': data,
    }
    return build_packet(packet)

def build_lxmf(source_hash, sender_priv_bytes, receiver_pub_bytes, receiver_ratchet_pub, timestamp, title, content, fields):
    # Pack as native str to align with official encoders
    lxmf_content = msgpack.packb([timestamp, title, content, fields], use_bin_type=True)

    destination_hash = get_destination_hash(receiver_pub_bytes, "lxmf.delivery")

    message_id = sha256(concat_bytes(destination_hash, source_hash, lxmf_content))
    message_to_sign = concat_bytes(destination_hash, source_hash, lxmf_content, message_id)

    signature = ed25519_sign(message_to_sign, sender_priv_bytes[32:])
    plaintext = concat_bytes(source_hash, signature, lxmf_content)

    encrypted = message_encrypt(plaintext, receiver_pub_bytes, receiver_ratchet_pub)
    return build_data(destination_hash, encrypted, context=CONTEXT_NONE)

def build_proof(data_packet, identity_priv_bytes):
    # For simplicity, data_packet is a bytes-like packet
    parsed = parse_packet(data_packet)
    packet_hash = parsed['packetHash']
    destination_hash = parsed['destinationHash']

    signing_priv_key = identity_priv_bytes[32:]
    signature = ed25519_sign(packet_hash, signing_priv_key)

    packet = {
        'hops': 0,
        'destinationType': DEST_SINGLE,
        'transportType': TRANSPORT_BROADCAST,
        'packetType': PACKET_PROOF,
        'destinationHash': destination_hash,
        'data': signature,
    }
    return build_packet(packet)

def message_encrypt(plaintext, identity_pub, ratchet):
    identity_hash = sha256(identity_pub)[:16]
    ephemeral_priv = random_bytes(32)
    ephemeral_pub = x25519_public_for_private(ephemeral_priv)

    shared_key = x25519_exchange(ephemeral_priv, ratchet)
    derived_key = hkdf(64, shared_key, identity_hash)
    signing_key = derived_key[:32]
    encryption_key = derived_key[32:]

    iv = random_bytes(16)
    ciphertext_data = aes_cbc_encrypt(encryption_key, iv, plaintext)
    signed_data = concat_bytes(iv, ciphertext_data)
    hmac_val = hmac_sha256(signing_key, signed_data)

    return concat_bytes(ephemeral_pub, iv, ciphertext_data, hmac_val)

def get_destination_hash(identity_pub_bytes, full_name="lxmf.delivery"):
    # Use full 64-byte identity pubkey for hash, then truncate
    identity_hash = sha256(identity_pub_bytes)[:16]
    name_hash = sha256(full_name.encode())[:10]

    addr_hash_material = bytearray(26)
    addr_hash_material[:10] = name_hash
    addr_hash_material[10:] = identity_hash

    return sha256(bytes(addr_hash_material))[:16]

def get_message_id(packet_bytes):
    header_type = (packet_bytes[0] >> 6) & 0b11
    if header_type == 1:
        # header present: skip first 18 bytes, mask first byte
        hashable_part = bytes([packet_bytes[0] & 0b00001111]) + packet_bytes[18:]
    else:
        # short header: skip first 2 bytes, mask first byte
        hashable_part = bytes([packet_bytes[0] & 0b00001111]) + packet_bytes[2:]
    return sha256(hashable_part)

def parse_packet(packet_bytes):
    flags = packet_bytes[0]
    hops = packet_bytes[1]

    header_type = (flags >> 6) & 0x01
    context_flag = (flags >> 5) & 0x01
    transport_type = (flags >> 4) & 0x01
    destination_type = (flags >> 2) & 0x03
    packet_type = flags & 0x03

    DSTLEN = 16

    if header_type:
        transport_id = packet_bytes[2:2+DSTLEN]
        destination_hash = packet_bytes[2+DSTLEN:2+2*DSTLEN]
        context = packet_bytes[2+2*DSTLEN]
        data = packet_bytes[2+2*DSTLEN+1:]
    else:
        transport_id = None
        destination_hash = packet_bytes[2:2+DSTLEN]
        context = packet_bytes[2+DSTLEN]
        data = packet_bytes[2+DSTLEN+1:]

    packet_hash = get_message_id(packet_bytes)

    return {
        'flags': flags,
        'hops': hops,
        'headerType': header_type,
        'contextFlag': context_flag,
        'transportType': transport_type,
        'destinationType': destination_type,
        'packetType': packet_type,
        'transportId': transport_id,
        'destinationHash': destination_hash,
        'context': context,
        'data': data,
        'packetHash': packet_hash,
    }

def parse_announce(packet):
    # packet: dict, as returned by parse_packet
    data = packet['data']
    announce = {}
    announce['valid'] = False

    public_key = data[:64]
    announce['publicKey'] = public_key
    announce['keyPubEncrypt'] = data[:32]
    announce['keyPubSignature'] = data[32:64]
    announce['nameHash'] = data[64:74]
    announce['randomHash'] = data[74:84]

    offset = 84
    if packet['contextFlag']:
        announce['ratchetPub'] = data[offset:offset+32]
        ratchet_for_signing = announce['ratchetPub']
        offset += 32
    else:
        ratchet_for_signing = b""

    announce['signature'] = data[offset:offset+64]
    offset += 64

    if len(data) > offset:
        announce['appData'] = data[offset:]
    else:
        announce['appData'] = b""

    # build data that was signed
    signed_data = concat_bytes(
        packet['destinationHash'],
        public_key,
        announce['nameHash'],
        announce['randomHash'],
        ratchet_for_signing,
        announce['appData'],
    )

    announce['valid'] = ed25519_validate(
        announce['keyPubSignature'],
        announce['signature'],
        signed_data,
    )

    announce['destinationHash'] = packet['destinationHash']
    return announce

def message_decrypt(packet, identity_pub, ratchets):
    identity_hash = sha256(identity_pub)[:16]
    ciphertext_token = packet['data']

    if len(ciphertext_token) < 49:
        return None

    peer_pub_bytes = ciphertext_token[:32]
    # The "rest" is IV (16) + ciphertext + HMAC (last 32)
    rest = ciphertext_token[32:]
    if len(rest) < 48:  # 16 for IV, 32 for HMAC
        return None

    signed_data = rest[:-32]  # IV + ciphertext
    received_hmac = rest[-32:]

    # Now go through ratchets
    for ratchet in ratchets:
        if len(ratchet) != 32:
            continue

        try:
            shared_key = x25519_exchange(ratchet, peer_pub_bytes)
            derived_key = hkdf(64, shared_key, identity_hash)
            signing_key = derived_key[:32]
            encryption_key = derived_key[32:]

            expected_hmac = hmac_sha256(signing_key, signed_data)
            if not equal_bytes(expected_hmac, received_hmac):
                continue

            iv = signed_data[:16]
            ciphertext_data = signed_data[16:]
            decrypted = aes_cbc_decrypt(encryption_key, iv, ciphertext_data)
            return decrypted
        except Exception as e:
            print('ERROR', e)
            continue

    return None

def parse_lxmf(packet, identity_pub, ratchets, sender_pub_key=None):
    plaintext = message_decrypt(packet, identity_pub, ratchets)
    if plaintext is None:
        return None

    try:
        source_hash = plaintext[:16]
        signature = plaintext[16:80]
        raw = plaintext[80:]

        fields = msgpack.unpackb(raw, raw=False)
        timestamp, title, content, field_dict = fields

        lxmf_obj = {
            'sourceHash': source_hash,
            'signature': signature,
            'timestamp': timestamp,
            'title': title.decode() if isinstance(title, bytes) else title,
            'content': content.decode() if isinstance(content, bytes) else content,
            'fields': field_dict,
            'raw': raw,
            'valid': False,
        }

        if sender_pub_key:
            lxmf_obj['valid'] = validate_lxmf(lxmf_obj, packet, sender_pub_key)

        return lxmf_obj
    except Exception as e:
        print("Exception in parse_lxmf:", e)
        return None

def validate_lxmf(lxmf, packet, sender_pub_key):
    message_id = sha256(concat_bytes(packet['destinationHash'], lxmf['sourceHash'], lxmf['raw']))
    message_to_verify = concat_bytes(packet['destinationHash'], lxmf['sourceHash'], lxmf['raw'], message_id)
    return ed25519_validate(
        sender_pub_key[32:],
        lxmf['signature'],
        message_to_verify,
    )

def parse_proof(packet, identity_pub, full_packet_hash):
    signature = packet['data'][:64]
    return ed25519_validate(identity_pub[32:], signature, full_packet_hash)
