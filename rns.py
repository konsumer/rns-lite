# Lightweight Reticulum library
# https://github.com/konsumer/rns-lite

import sys
from os import urandom
import hashlib
from math import ceil

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

    # load private keys for encrypt/sign and derive public
    def get_identity_from_bytes(private_identity_bytes):
        encryption_private = private_identity_bytes[:32]
        signing_private = private_identity_bytes[32:64]
        encryption_public = x25519.scalar_base_mult(encryption_private)
        signing_public = ed25519.publickey(signing_private)
        return {'public': { 'encrypt': encryption_public, 'sign': signing_public }, 'private': { 'encrypt': encryption_private, 'sign': signing_private }}

    # create a full identity (pub/private encrypt/sign)
    def identity_create():
        encryption_private = urandom(32)
        signing_private = urandom(32)
        encryption_public = x25519.scalar_base_mult(encryption_private)
        signing_public = ed25519.publickey(signing_private)
        return {'public': { 'encrypt': encryption_public, 'sign': signing_public }, 'private': { 'encrypt': encryption_private, 'sign': signing_private }}

    # generate ratchet private key
    def ratchet_create_new():
        return urandom(32)

    # get the public key for ratchet (for use in announces)
    def ratchet_get_public(private_ratchet):
        return x25519.scalar_base_mult(private_ratchet)

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

    def _aes_cbc_encrypt(encrypt_key, iv, plaintext):
        cipher = aes(encrypt_key, 2, iv)  # mode 2 = CBC
        return cipher.encrypt(plaintext)

    def _aes_cbc_decrypt(encrypt_key, iv, ciphertext):
        cipher = aes(encrypt_key, 2, iv)  # mode 2 = CBC
        return cipher.decrypt(ciphertext)

    def _ed25519_validate(sign_key_pub, signature, message):
        try:
            ed25519.checkvalid(signature, message, sign_key_pub)
            return True
        except Exception as e:
            return False

    def _x25519_exchange(private_key, public_key):
        return x25519.scalar_mult(private_key, public_key)

else:
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    import hmac

    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    from cryptography.hazmat.primitives import serialization

    # load private keys for encrypt/sign and derive public
    def get_identity_from_bytes(private_identity_bytes):
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

    # create a full identity (pub/private encrypt/sign)
    def identity_create():
        encrypt_key = X25519PrivateKey.generate()
        encryption_private = encrypt_key.private_bytes(encoding=serialization.Encoding.Raw, format=serialization.PrivateFormat.Raw, encryption_algorithm=serialization.NoEncryption())
        encryption_public = encrypt_key.public_key().public_bytes(encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw)
        sign_key = Ed25519PrivateKey.generate()
        signing_private = sign_key.private_bytes(encoding=serialization.Encoding.Raw, format=serialization.PrivateFormat.Raw, encryption_algorithm=serialization.NoEncryption())
        signing_public = sign_key.public_key().public_bytes(encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw)
        return { 'public': { 'encrypt': encryption_public, 'sign': signing_public }, 'private': { 'encrypt': encryption_private, 'sign': signing_private} }

    # generate ratchet private key
    def ratchet_create_new():
        key = X25519PrivateKey.generate()
        return key.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption()
        )

    # get the public key for ratchet (for use in announces)
    def ratchet_get_public(private_ratchet):
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

# get the destination-hash (LXMF address) from identity
def get_destination_hash(identity, app_name, *aspects):
    identity_hash = _sha256(identity['public']['encrypt'] + identity['public']['sign'])[:16]
    full_name = app_name
    for aspect in aspects:
        full_name += "." + aspect
    name_hash = _sha256(full_name.encode("utf-8"))[:10]
    addr_hash_material = name_hash + identity_hash
    destination_hash = _sha256(addr_hash_material)[:16]
    return destination_hash

# extract basic reticulum fields
def decode_packet(packet_bytes):
    result = {}
    result["raw"] = packet_bytes

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
    return result

# parse an ANNOUNCE packet (output from decode_packet)
def announce_parse(packet):
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
    
    # Get context_flag (try both possible key names)
    context_flag = packet.get('context_flag', packet.get('context', 0))
    
    # Does this packet have a ratchet pubkey?
    if context_flag == 1:
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

# get the message-id (used as destination in PROOFs) from a DATA packet (output from decode_packet)
def get_message_id(packet):
    header_type = (packet['raw'][0] >> 6) & 0b11
    hashable_part = bytes([packet['raw'][0] & 0b00001111])
    if header_type == 1:
        hashable_part += packet['raw'][18:]
    else:
        hashable_part += packet['raw'][2:]
    return _sha256(hashable_part)

# validate a PROOF packet (output from decode_packet)
def proof_validate(packet, identity, full_packet_hash):
    return _ed25519_validate(identity['public']['sign'], packet['data'][1:65], full_packet_hash)

# decrypt a DATA packet (output from decode_packet)
def message_decrypt(packet, identity, ratchets=None):
    """
    Decrypt a message packet using identity's private key and optional ratchets.
    """
    identity_hash = _sha256(identity['public']['encrypt'] + identity['public']['sign'])[:16]

    ciphertext_token = packet.get('data', b'')
    if not ciphertext_token or len(ciphertext_token) <= 49:
        return None
    
    # Extract ephemeral public key and token
    peer_pub_bytes = ciphertext_token[1:33]
    ciphertext = ciphertext_token[33:]
    
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



