# Lightweight Reticulum library
# https://github.com/konsumer/rns-lite

import sys
from os import urandom
import hashlib

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


# micropython has simpler/different hashing & crypto stuff, so we abstract the basic helpers
if sys.implementation.name == "micropython":
    from cryptolib import aes

    # pypi
    import x25519

    # https://ed25519.cr.yp.to/python/ed25519.py
    import ed25519

    # this is slower, but works in micropython
    def get_identity_public(private_identity_bytes):
        encryption_private = private_identity_bytes[:32]
        signing_private = private_identity_bytes[32:64]
        encryption_public = x25519.scalar_base_mult(encryption_private)
        signing_public = ed25519.publickey(signing_private)
        return encryption_public + signing_public

    # HMAC-SHA256 implementation for MicroPython
    def _hmac_sha256(sign_key, data):
        # Standard HMAC construction per RFC 2104
        block_size = 64  # SHA256 block size

        # Adjust key length
        if len(sign_key) > block_size:
            sign_key = hashlib.sha256(sign_key).digest()
        if len(sign_key) < block_size:
            sign_key = sign_key + b"\x00" * (block_size - len(sign_key))

        # Create inner and outer padding
        o_key_pad = bytes(b ^ 0x5C for b in sign_key)
        i_key_pad = bytes(b ^ 0x36 for b in sign_key)

        # HMAC = H(o_key_pad || H(i_key_pad || message))
        inner_hash = hashlib.sha256(i_key_pad + data).digest()
        return hashlib.sha256(o_key_pad + inner_hash).digest()

    # AES-CBC encrypt for MicroPython
    def _aesCbcEncrypt(encrypt_key, iv, plaintext):
        cipher = aes(encrypt_key, 2, iv)  # mode 2 = CBC
        return cipher.encrypt(plaintext)

    # AES-CBC decrypt for MicroPython
    def _aesCbcDecrypt(encrypt_key, iv, ciphertext):
        cipher = aes(encrypt_key, 2, iv)  # mode 2 = CBC
        return cipher.decrypt(ciphertext)

    # Wrapper for ed25519 signature verification.
    def _ed25519_checkvalid(signature, message, public_key):
        try:
            ed25519.checkvalid(signature, message, public_key)
            return True
        except Exception as e:
            return False

else:
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    import hmac

    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
    from cryptography.hazmat.primitives import serialization

    def get_identity_public(private_identity_bytes):
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
        return encryption_public + signing_public

    # wrapped HMAC computation
    def _hmac_sha256(sign_key, data):
        return hmac.new(sign_key, data, hashlib.sha256).digest()

    # wrapped AES CBC encrypt
    def _aesCbcEncrypt(encrypt_key, iv, plaintext):
        cipher = Cipher(algorithms.AES(encrypt_key), modes.CBC(iv))
        encryptor = cipher.encryptor()
        return encryptor.update(plaintext) + encryptor.finalize()

    # wrapped AES CBC decrypt
    def _aesCbcDecrypt(encrypt_key, iv, ciphertext):
        cipher = Cipher(algorithms.AES(encrypt_key), modes.CBC(iv))
        decryptor = cipher.decryptor()
        return decryptor.update(ciphertext) + decryptor.finalize()

# wrapped SHA256 hash
def _sha256(data):
    return hashlib.sha256(data).digest()

# wrapped SHA512 hash
def _sha512(data):
    return hashlib.sha512(data).digest()

# wrapped HKDF
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


def _PKCS7_unpad(data, bs=16):
    l = len(data)
    n = data[-1]
    if n > bs:
        raise ValueError(f"Cannot unpad, invalid padding length of {n} bytes")
    else:
        return data[: l - n]


def _PKCS7_pad(data, bs=16):
    l = len(data)
    n = bs - l % bs
    v = bytes([n])
    return data + v * n

def get_destination_hash(public_identity_bytes, app_name, *aspects):
    identity_hash = _sha256(public_identity_bytes)[:16]
    full_name = app_name
    for aspect in aspects:
        full_name += "." + aspect
    name_hash = _sha256(full_name.encode("utf-8"))[:10]
    addr_hash_material = name_hash + identity_hash
    destination_hash = _sha256(addr_hash_material)[:16]
    return destination_hash


def decode_packet(packet_bytes):
    result = {}
    result["ifac_flag"] = bool(packet_bytes[0] & 0b10000000)
    result["header_type"] = bool(packet_bytes[0] & 0b01000000)
    result["context_flag"] = bool(packet_bytes[0] & 0b00100000)
    result["propagation_type"] = bool(packet_bytes[0] & 0b00010000)
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

    if result["context_flag"]:
        result["context"] = packet_bytes[offset]
        offset += 1
    else:
        result["context"] = None

    result["data"] = packet_bytes[offset:]
    result["raw"] = packet_bytes
    return result

def announce_validate(packet):
    """
    Validate an ANNOUNCE packet.
    """
    data = packet['data']
    dest_hash = packet['destination_hash']
    
    print(f"    Data length: {len(data)}")
    print(f"    Dest hash: {dest_hash.hex()}")
    
    # Search for where the identity hash might be
    print(f"    Searching for identity in data...")
    if dest_hash in data:
        pos = data.index(dest_hash)
        print(f"    Found dest_hash at position: {pos}")
    
    # The signature is always the last 64 bytes
    signature = data[-64:]
    
    # Try different offsets for the crypto material
    # Maybe it's not 148 bytes from the end?
    
    # Let's try: the public key might be at the START (after app_data length prefix?)
    # Or maybe the structure includes the destination hash in the data?
    
    # Parse the first 16 bytes - could be the destination hash
    possible_dest = data[:16]
    print(f"    First 16 bytes: {possible_dest.hex()}")
    
    if possible_dest == dest_hash:
        print(f"    Destination hash is at start of data!")
        # Structure: dest_hash (16) + public_key (64) + name_hash (10) + random_hash (10) + app_data (?) + signature (64)
        public_key = data[16:80]
        name_hash = data[80:90]
        random_hash = data[90:100]
        app_data = data[100:-64]
        signature = data[-64:]
    else:
        # Try: public_key at start
        public_key = data[:64]
        name_hash = data[64:74]
        random_hash = data[74:84]
        app_data = data[84:-64]
        signature = data[-64:]
    
    print(f"    Public key: {public_key.hex()}")
    
    # Try both key orders
    identity_hash_1 = _sha256(public_key)[:16]
    identity_hash_2 = _sha256(public_key[32:] + public_key[:32])[:16]  # swapped
    
    print(f"    Identity (enc+sign): {identity_hash_1.hex()}")
    print(f"    Identity (sign+enc): {identity_hash_2.hex()}")
    
    if identity_hash_1 == dest_hash:
        print(f"    Match with enc+sign order")
        identity_hash = identity_hash_1
        signing_public_key = public_key[32:64]
    elif identity_hash_2 == dest_hash:
        print(f"    Match with sign+enc order")
        identity_hash = identity_hash_2
        signing_public_key = public_key[:32]
    else:
        print(f"    No identity match found")
        return False
    
    # Construct signed data
    signed_data = dest_hash + public_key + name_hash + random_hash + app_data
    
    result = _ed25519_checkvalid(signature, signed_data, signing_public_key)
    print(f"    Signature validation: {result}")
    
    return result

