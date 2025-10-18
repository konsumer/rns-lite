"""
Lightweight Reticulum library
"""

import sys
from os import urandom
import hashlib
from math import ceil
import time

PACKET_DATA         = 0x00     # Data packets
PACKET_ANNOUNCE     = 0x01     # Announces
PACKET_LINKREQUEST  = 0x02     # Link requests
PACKET_PROOF        = 0x03     # Proofs

CONTEXT_NONE           = 0x00   # Generic data packet
CONTEXT_RESOURCE       = 0x01   # Packet is part of a resource
CONTEXT_RESOURCE_ADV   = 0x02   # Packet is a resource advertisement
CONTEXT_RESOURCE_REQ   = 0x03   # Packet is a resource part request
CONTEXT_RESOURCE_HMU   = 0x04   # Packet is a resource hashmap update
CONTEXT_RESOURCE_PRF   = 0x05   # Packet is a resource proof
CONTEXT_RESOURCE_ICL   = 0x06   # Packet is a resource initiator cancel message
CONTEXT_RESOURCE_RCL   = 0x07   # Packet is a resource receiver cancel message
CONTEXT_CACHE_REQUEST  = 0x08   # Packet is a cache request
CONTEXT_REQUEST        = 0x09   # Packet is a request
CONTEXT_RESPONSE       = 0x0A   # Packet is a response to a request
CONTEXT_PATH_RESPONSE  = 0x0B   # Packet is a response to a path request
CONTEXT_COMMAND        = 0x0C   # Packet is a command
CONTEXT_COMMAND_STATUS = 0x0D   # Packet is a status of an executed command
CONTEXT_CHANNEL        = 0x0E   # Packet contains link channel data
CONTEXT_KEEPALIVE      = 0xFA   # Packet is a keepalive packet
CONTEXT_LINKIDENTIFY   = 0xFB   # Packet is a link peer identification proof
CONTEXT_LINKCLOSE      = 0xFC   # Packet is a link close message
CONTEXT_LINKPROOF      = 0xFD   # Packet is a link packet proof
CONTEXT_LRRTT          = 0xFE   # Packet is a link request round-trip time measurement
CONTEXT_LRPROOF        = 0xFF   # Packet is a link request proof

# Destination types
DEST_SINGLE = 0x00
DEST_GROUP = 0x01
DEST_PLAIN = 0x02
DEST_LINK = 0x03

# Transport types
TRANSPORT_BROADCAST = 0
TRANSPORT_TRANSPORT = 1


# START cpython-specific

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import hmac

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives import serialization
from umsgpack import unpackb, packb

def get_identity_from_bytes(private_identity_bytes):
    """
    Load private keys for encrypt/sign and derive public.
    """
    encryption_private = private_identity_bytes[:32]
    signing_private = private_identity_bytes[32:64]
    encrypt_key = X25519PrivateKey.from_private_bytes(encryption_private)
    encryption_public = encrypt_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw
    )
    sign_key = Ed25519PrivateKey.from_private_bytes(signing_private)
    signing_public = sign_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw
    )
    return {'public': {'encrypt': encryption_public, 'sign': signing_public }, 'private': { 'encrypt': encryption_private, 'sign': signing_private }}

def identity_create():
    """
    Create a full identity (pub/private encrypt/sign.)
    """
    encrypt_key = X25519PrivateKey.generate()
    encryption_private = encrypt_key.private_bytes(encoding=serialization.Encoding.Raw, format=serialization.PrivateFormat.Raw, encryption_algorithm=serialization.NoEncryption())
    encryption_public = encrypt_key.public_key().public_bytes(encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw)
    sign_key = Ed25519PrivateKey.generate()
    signing_private = sign_key.private_bytes(encoding=serialization.Encoding.Raw, format=serialization.PrivateFormat.Raw, encryption_algorithm=serialization.NoEncryption())
    signing_public = sign_key.public_key().public_bytes(encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw)
    return { 'public': { 'encrypt': encryption_public, 'sign': signing_public }, 'private': { 'encrypt': encryption_private, 'sign': signing_private} }

def ratchet_create_new():
    """
    Generate new ratchet private key.
    """
    key = X25519PrivateKey.generate()
    return key.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption()
    )

def ratchet_get_public(private_ratchet):
    """
    Get the public key for ratchet (for use in announces.)
    """
    key = X25519PrivateKey.from_private_bytes(private_ratchet)
    return key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw
    )

def _hmac_sha256(sign_key, data):
    return hmac.new(sign_key, data, hashlib.sha256).digest()

def _aes_cbc_encrypt(encrypt_key, iv, plaintext):
    cipher = Cipher(algorithms.AES(encrypt_key), modes.CBC(iv))
    encryptor = cipher.encryptor()
    return encryptor.update(plaintext) + encryptor.finalize()

def _aes_cbc_decrypt(encrypt_key, iv, ciphertext):
    cipher = Cipher(algorithms.AES(encrypt_key), modes.CBC(iv))
    decryptor = cipher.decryptor()
    return decryptor.update(ciphertext) + decryptor.finalize()

def _ed25519_validate(sign_key_pub, signature, message):
    try:
        pub_key_obj = Ed25519PublicKey.from_public_bytes(sign_key_pub)
        pub_key_obj.verify(signature, message)
        return True
    except Exception as e:
        return False

def _x25519_exchange(private_key, public_key):
    prv_key_obj = X25519PrivateKey.from_private_bytes(private_key)
    pub_key_obj = X25519PublicKey.from_public_bytes(public_key)
    shared_secret = prv_key_obj.exchange(pub_key_obj)
    return shared_secret

def _ed25519_sign(signed_data, sign_key_priv, sign_key_pub):
    sign_key = Ed25519PrivateKey.from_private_bytes(sign_key_priv)
    return sign_key.sign(signed_data)

# END cpython-specific



def _sha256(data):
    return hashlib.sha256(data).digest()

def _hkdf(length=None, derive_from=None, salt=None, context=None):
    hash_len = 32

    if length == None or length < 1:
        raise ValueError("Invalid output key length")

    if derive_from == None or derive_from == "":
        raise ValueError("Cannot derive key from empty input material")

    if salt == None or len(salt) == 0:
        salt = bytes([0] * hash_len)

    if context == None:
        context = b""

    pseudorandom_key = _hmac_sha256(salt, derive_from)

    block = b""
    derived = b""

    for i in range(ceil(length / hash_len)):
        block = _hmac_sha256(
            pseudorandom_key, block + context + bytes([(i + 1) % (0xFF + 1)])
        )
        derived += block

    return derived[:length]


def _pkcs7_unpad(data, bs=16):
    l = len(data)
    n = data[-1]
    if n > bs:
        raise ValueError(f"Cannot unpad, invalid padding length of {n} bytes")
    else:
        return data[: l - n]

def _pkcs7_pad(data, bs=16):
    l = len(data)
    n = bs - l % bs
    v = bytes([n])
    return data + v * n

def get_destination_hash(identity, app_name, *aspects):
    """
    Get the destination-hash (LXMF address) from identity.
    """
    identity_hash = _sha256(identity['public']['encrypt'] + identity['public']['sign'])[:16]
    full_name = app_name
    for aspect in aspects:
        full_name += "." + aspect
    name_hash = _sha256(full_name.encode("utf-8"))[:10]
    addr_hash_material = name_hash + identity_hash
    destination_hash = _sha256(addr_hash_material)[:16]
    return destination_hash

def decode_packet(packet_bytes):
    """
    Extract basic reticulum fields (packet-object) from bytes.
    """
    result = {}
    result["raw"] = packet_bytes

    result["ifac_flag"] = packet_bytes[0] & 0b10000000
    result["header_type"] = packet_bytes[0] & 0b01000000
    
    # is this named wrong?
    result["context_flag"] = packet_bytes[0] & 0b00100000
    
    result["transport_type"] = packet_bytes[0] & 0b00010000
    result["destination_type"] = packet_bytes[0] & 0b00001100
    result["packet_type"] = packet_bytes[0] & 0b00000011
    result["hops"] = packet_bytes[1]
    offset = 2

    addr_count = 2 if result["header_type"] else 1
    addr_size = 16 * addr_count

    result["destination_hash"] = packet_bytes[offset : offset + 16]
    offset += 16

    if result["header_type"]:
        result["source_hash"] = packet_bytes[offset : offset + 16]
        offset += 16
    else:
        result["source_hash"] = None

    result["transport_id"] = packet_bytes[offset]
    offset += 1

    result["data"] = packet_bytes[offset:]
    return result

def encode_packet(packet):
    header_byte = 0

    source_hash = packet.get('source_hash')
    if source_hash:
        packet['header_type'] = 1

    if packet.get('ifac_flag'):
        header_byte |= 0b10000000
    if packet.get('header_type'):
        header_byte |= 0b01000000

    # TODO: I think this is wrong, what I thought was context before is transport_id/transport_type
    has_context = ('context' in packet)
    if has_context:
        packet['context_flag'] = True
    if packet.get('context_flag'):
        header_byte |= 0b00100000

    if packet.get('transport_type'):
        header_byte |= 0b00010000

    destination_type = packet.get('destination_type', 0) & 0b00001100
    header_byte |= destination_type

    packet_type = packet.get('packet_type', 0) & 0b00000011
    header_byte |= packet_type

    out = bytearray()
    out.append(header_byte)
    out.append(packet.get('hops', 0) & 0xFF)

    dest = packet.get('destination_hash', b'')
    if len(dest) != 16:
        raise ValueError("destination_hash must be 16 bytes")
    out += dest

    if source_hash:
        if len(source_hash) != 16:
            raise ValueError("source_hash must be 16 bytes")
        out += source_hash

    if packet.get('context_flag'):
        out.append(packet.get('context', 0) & 0xFF)

    out += packet.get('data', b'')
    return bytes(out)


def build_announce(identity, destination, name='lxmf.delivery', ratchet_pub=None, app_data=None):
    pub_enc = identity['public']['encrypt']
    pub_sig = identity['public']['sign']
    if len(pub_enc) != 32 or len(pub_sig) != 32:
        raise ValueError("Keys must be 32 bytes")

    keys = pub_enc + pub_sig
    name_hash = _sha256(name.encode('utf-8'))[:10]
    random_hash = urandom(10)

    if app_data is None:
        app_data = b''
    elif isinstance(app_data, str):
        app_data = app_data.encode('utf-8')

    # Determine the ratchet key to use
    if ratchet_pub is None or ratchet_pub == pub_enc:
        effective_ratchet = pub_enc
        context_val = 0
    else:
        if len(ratchet_pub) != 32:
            raise ValueError("ratchet_pub must be 32 bytes")
        effective_ratchet = ratchet_pub
        context_val = 1

    # Signature includes: destination + keys + name_hash + random_hash + ratchet + app_data
    signed_data = destination + keys + name_hash + random_hash + effective_ratchet + app_data
    signature = _ed25519_sign(signed_data, identity['private']['sign'], identity['public']['sign'])

    # Payload structure depends on context
    if context_val == 1:
        # Explicit ratchet: keys + name_hash + random_hash + ratchet + signature + app_data
        payload = keys + name_hash + random_hash + effective_ratchet + signature + app_data
    else:
        # Implicit ratchet: keys + name_hash + random_hash + signature + app_data
        payload = keys + name_hash + random_hash + signature + app_data

    pkt = {
        'destination_hash': destination,
        'packet_type': PACKET_ANNOUNCE,
        'destination_type': 0,
        'hops': 0,
        'data': payload,
        'context': context_val,
        'context_flag': True  # Critical: must set this for context byte to be written
    }

    return encode_packet(pkt)

def announce_parse(packet):
    """
    Parse an ANNOUNCE packet (output from decode_packet) into announce-object.
    """
    keysize = 64
    per_keysize = keysize // 2  # 32
    ratchetsize = 32
    name_hash_len = 10
    random_hash_len = 10
    sig_len = 64
    
    data = packet['data']
    out = {'valid': False}
    
    # Extract public keys (first 64 bytes)
    out['key_pub_encrypt'] = data[0:per_keysize]
    out['key_pub_signature'] = data[per_keysize:keysize]
    
    # Extract name_hash and random_hash
    out['name_hash'] = data[keysize:(keysize + name_hash_len)]
    out['random_hash'] = data[(keysize + name_hash_len):(keysize + name_hash_len + random_hash_len)]
    
    context_flag = packet.get('context_flag', 0)
    
    # I am not sure this does what I think
    if context_flag:
        out['ratchet_pub'] = data[(keysize + name_hash_len + random_hash_len):(keysize + name_hash_len + random_hash_len + ratchetsize)]
        out['signature'] = data[(keysize + name_hash_len + random_hash_len + ratchetsize):(keysize + name_hash_len + random_hash_len + ratchetsize + sig_len)]
        
        if len(data) > (keysize + name_hash_len + random_hash_len + ratchetsize + sig_len):
            out['app_data'] = data[(keysize + name_hash_len + random_hash_len + ratchetsize + sig_len):]
        else:
            out['app_data'] = b''
    else:
        out['ratchet_pub'] = out['key_pub_encrypt']
        out['signature'] = data[(keysize + name_hash_len + random_hash_len):(keysize + name_hash_len + random_hash_len + sig_len)]
        
        if len(data) > (keysize + name_hash_len + random_hash_len + sig_len):
            out['app_data'] = data[(keysize + name_hash_len + random_hash_len + sig_len):]
        else:
            out['app_data'] = b''

    
    # Construct signed data
    signed_data = (
        packet['destination_hash'] + 
        out['key_pub_encrypt'] + 
        out['key_pub_signature'] + 
        out['name_hash'] + 
        out['random_hash'] + 
        out['ratchet_pub'] + 
        (out['app_data'] if out['app_data'] else b'')
    )
    
    # Verify signature
    out['valid'] = _ed25519_validate(out['key_pub_signature'], out['signature'], signed_data)

    return out

def get_message_id(packet):
    """
    Get the message-id (used as destination in PROOFs) from a DATA packet (output from decode_packet.)
    """
    header_type = (packet['raw'][0] >> 6) & 0b11
    hashable_part = bytes([packet['raw'][0] & 0b00001111])
    if header_type == 1:
        hashable_part += packet['raw'][18:]
    else:
        hashable_part += packet['raw'][2:]
    return _sha256(hashable_part)

def proof_validate(packet, identity, full_packet_hash):
    """
    Validate a PROOF packet (output from decode_packet.)
    """
    return _ed25519_validate(identity['public']['sign'], packet['data'][0:64], full_packet_hash)

def message_decrypt(packet, identity, ratchets=None):
    """
    Decrypt a DATA message packet using identity's private key and optional ratchets.
    """
    identity_hash = _sha256(identity['public']['encrypt'] + identity['public']['sign'])[:16]

    ciphertext_token = packet.get('data', b'')
    if not ciphertext_token or len(ciphertext_token) <= 49:
        return None
    
    # Extract ephemeral public key and token
    peer_pub_bytes = ciphertext_token[:32]
    ciphertext = ciphertext_token[32:]
    
    # Rest of function stays the same...
    if ratchets:
        for i, ratchet in enumerate(ratchets):
            if len(ratchet) != 32:
                continue
            try:
                shared_key = _x25519_exchange(ratchet, peer_pub_bytes)
                derived_key = _hkdf(
                    length=64,
                    derive_from=shared_key,
                    salt=identity_hash,
                    context=None
                )
                
                signing_key = derived_key[:32] 
                encryption_key = derived_key[32:]
                
                if len(ciphertext) <= 48:
                    continue
                    
                received_hmac = ciphertext[-32:]
                signed_data = ciphertext[:-32]
                expected_hmac = _hmac_sha256(signing_key, signed_data)
                
                if received_hmac != expected_hmac:
                    continue
                    
                iv = ciphertext[:16]
                ciphertext_data = ciphertext[16:-32]
                padded_plaintext = _aes_cbc_decrypt(encryption_key, iv, ciphertext_data)
                plaintext = _pkcs7_unpad(padded_plaintext)
                return plaintext
                
            except Exception:
                continue
    return None


def build_proof(identity, packet, message_id=None):
    """
    Build a PROOF packet in response to a received DATA packet.
    
    Args:
        identity: Your identity dict with private/public keys
        packet: The decoded DATA packet dict (from decode_packet)
        message_id: Optional pre-calculated message ID (32 bytes). If None, will be calculated.
    
    Returns:
        Encoded PROOF packet bytes
    """
    PACKET_PROOF = 0b00000011
    
    # Calculate message_id if not provided
    if message_id is None:
        message_id = get_message_id(packet)
    
    # The destination for the PROOF is the truncated message_id (first 16 bytes)
    proof_destination = message_id[:16]
    
    # Sign the full 32-byte message_id with your signing key
    signature = _ed25519_sign(message_id, identity['private']['sign'], identity['public']['sign'])
    
    # PROOF data format: proof_type + signature
    # proof_type = 0x00 (not 0x01!)
    proof_data = bytes([0x00]) + signature
    
    # Build the PROOF packet - NO context flag!
    pkt = {
        'destination_hash': proof_destination,
        'packet_type': PACKET_PROOF,
        'destination_type': 0,
        'hops': 0,
        'data': proof_data
    }
    
    return encode_packet(pkt)


def build_data(identity, recipient_announce, plaintext, ratchet=None):
    """
    Build an encrypted DATA packet to send to a recipient.
    
    Args:
        identity: Your identity dict with private/public keys
        recipient_announce: The parsed announce dict from announce_parse() containing recipient's keys
        plaintext: The message bytes to encrypt
        ratchet: Your ratchet private key (32 bytes). If None, uses your identity encrypt key.
    
    Returns:
        Encoded DATA packet bytes
    """
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.backends import default_backend
    
    PACKET_DATA = 0b00000000
    
    # Get recipient's identity hash for salt
    recipient_identity_hash = hashlib.sha256(
        recipient_announce['key_pub_encrypt'] + 
        recipient_announce['key_pub_signature']
    ).digest()[:16]
    
    # Use ratchet if provided, otherwise use identity encrypt key
    if ratchet is None:
        ratchet = identity['private']['encrypt']
    
    # Generate ephemeral keypair for this message
    ephemeral_key = X25519PrivateKey.generate()
    ephemeral_pub = ephemeral_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw
    )
    
    # Perform key exchange with recipient's ratchet public key
    shared_key = _x25519_exchange(
        ephemeral_key.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption()
        ),
        recipient_announce['ratchet_pub']
    )
    
    # Derive encryption and signing keys
    derived_key = _hkdf(
        length=64,
        derive_from=shared_key,
        salt=recipient_identity_hash,
        context=None
    )
    
    signing_key = derived_key[:32]
    encryption_key = derived_key[32:]
    
    # Pad plaintext
    padded_plaintext = _pkcs7_pad(plaintext)
    
    # Generate random IV
    iv = urandom(16)
    
    # Encrypt
    ciphertext = _aes_cbc_encrypt(encryption_key, iv, padded_plaintext)
    
    # Create HMAC
    signed_data = iv + ciphertext
    hmac_sig = _hmac_sha256(signing_key, signed_data)
    
    # Build token: version_byte + ephemeral_pub + iv + ciphertext + hmac
    token = bytes([0x00]) + ephemeral_pub + iv + ciphertext + hmac_sig
    
    # Get recipient's destination hash
    recipient_dest = recipient_announce.get('destination_hash')
    if not recipient_dest:
        # If not in announce, calculate it
        recipient_dest = get_destination_hash(
            {
                'public': {
                    'encrypt': recipient_announce['key_pub_encrypt'],
                    'sign': recipient_announce['key_pub_signature']
                }
            },
            "lxmf",
            "delivery"
        )
    
    # Build DATA packet
    pkt = {
        'destination_hash': recipient_dest,
        'packet_type': PACKET_DATA,
        'destination_type': 0,
        'hops': 0,
        'data': token
    }
    
    return encode_packet(pkt)



def build_lxmf_message(my_identity, my_dest, my_ratchet, recipient_announce, message):
    """Build LXMF message"""
    recipient_dest = recipient_announce['destination_hash']
    
    # Prepare message
    timestamp = message.get('timestamp', time.time())
    title = message.get('title', b'')
    if isinstance(title, str):
        title = title.encode('utf-8')
    content = message.get('content', b'')
    if isinstance(content, str):
        content = content.encode('utf-8')
    fields = {k: v for k, v in message.items() 
              if k not in ['timestamp', 'title', 'content']}
    
    payload = [timestamp, title, content, fields]
    packed_payload = packb(payload)
    
    # Calculate hash with destination included
    hashed_part = recipient_dest + my_dest + packed_payload
    message_hash = hashlib.sha256(hashed_part).digest()
    
    # Sign: hashed_part + message_hash
    signed_part = hashed_part + message_hash
    signature = _ed25519_sign(
        signed_part,
        my_identity['private']['sign'],
        my_identity['public']['sign']
    )

    lxmf_message = my_dest + signature + packed_payload
    return build_data(my_identity, recipient_announce, lxmf_message, my_ratchet)


def parse_lxmf_message(plaintext):
    """
    Parse LXMF message from encrypted DATA packet.
    The destination is inferred from the packet, so encrypted payload is:
    source (16) + signature (64) + msgpack
    """
    
    # Structure: source (16) + signature (64) + msgpack
    source_hash = plaintext[0:16]
    signature = plaintext[16:80]
    
    # Msgpack starts at byte 80
    timestamp, title, content, fields = unpackb(plaintext[80:])
    
    # We don't have destination in the encrypted payload - it's inferred from DATA packet
    return {
        **fields,
        'source_hash': source_hash,
        'signature': signature,
        'timestamp': timestamp,
        'title': title,
        'content': content
    }


