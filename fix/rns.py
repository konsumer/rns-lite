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


def get_pubkeys_from_bytes(public_key):
    """
    Load opaque (no matter the encryption-lib) pubkeys from pubkey-bytes
    """
    enc_pub_key       = X25519PublicKey.from_public_bytes(public_key[:32])
    sig_pub_key       = Ed25519PublicKey.from_public_bytes(public_key[32:])
    return enc_pub_key, sig_pub_key

def get_identity_from_bytes(private_identity_bytes):
    """
    Load opaque (no matter the encryption-lib) private keys from bytes for encrypt/sign and derive public.
    """
    encryption_private = private_identity_bytes[:32]
    signing_private = private_identity_bytes[32:64]
    encrypt_key = X25519PrivateKey.from_private_bytes(encryption_private)
    encryption_public = encrypt_key.public_key()
    sign_key = Ed25519PrivateKey.from_private_bytes(signing_private)
    signing_public = sign_key.public_key()
    return {
        'public': {
            'encrypt': encryption_public,
            'sign': signing_public,
            'bytes': encryption_public.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw) + signing_public.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        },
        'private': {
            'encrypt': encrypt_key,
            'sign': sign_key,
            'bytes': private_identity_bytes
        }
    }

def identity_create():
    """
    Create a full new identity (pub/private encrypt/sign.)
    """
    encrypt_key = X25519PrivateKey.generate()
    sign_key = Ed25519PrivateKey.generate()
    encryption_public = encrypt_key.public_key()
    signing_public = sign_key.public_key()
    return {
        'public': {
            'encrypt': encryption_public,
            'sign': signing_public,
            'bytes': encryption_public.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw) + signing_public.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        },
        'private': {
            'encrypt': encrypt_key,
            'sign': sign_key,
            'bytes': encrypt_key.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption()) + sign_key.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption())
        }
    }


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
    Get the public key for ratchet bytes (for use in announces.)
    """
    key = X25519PrivateKey.from_private_bytes(private_ratchet)
    return key.public_key()

def _ed25519_validate(pub_key_obj, signature, message):
    try:
        pub_key_obj.verify(signature, message)
        return True
    except Exception as e:
        return False

def _x25519_exchange(prv_key_obj, pub_key_obj):
    shared_secret = prv_key_obj.exchange(pub_key_obj)
    return shared_secret

def _ed25519_sign(signed_data, sign_key_priv, sign_key_pub):
    sign_key = Ed25519PrivateKey.from_private_bytes(sign_key_priv)
    return sign_key.sign(signed_data)

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

# END cpython-specific

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

def _sha256(data):
    return hashlib.sha256(data).digest()

def get_destination_hash(identity, full_name='lxmf.delivery'):
    """
    Get the destination-hash (LXMF address) from identity.
    """
    identity_hash = _sha256(identity['public']['bytes'])[:16]
    name_hash = _sha256(full_name.encode("utf-8"))[:10]
    addr_hash_material = name_hash + identity_hash
    destination_hash = _sha256(addr_hash_material)[:16]
    return destination_hash

def get_message_id(packet):
    """
    Get the message-id (used as destination in PROOFs, for example) from a packet (output from packet_unpack.)
    """
    header_type = (packet['raw'][0] >> 6) & 0b11
    hashable_part = bytes([packet['raw'][0] & 0b00001111])
    hashable_part += packet['raw'][2:]
    return _sha256(hashable_part)

def packet_unpack(packet_bytes):
    """
    Phase 1 parsing: basic reticulum packet, that just pulls out header-flags & data
    """
    result = {}
    result["raw"] = packet_bytes
    try:
        result['flags'] = result["raw"][0]
        result['hops']  = result["raw"][1]

        result['header_type']      = (result['flags'] & 0b01000000) >> 6
        result['context_flag']     = (result['flags'] & 0b00100000) >> 5
        result['transport_type']   = (result['flags'] & 0b00010000) >> 4
        result['destination_type'] = (result['flags'] & 0b00001100) >> 2
        result['packet_type']      = (result['flags'] & 0b00000011)

        DST_LEN = 16  # RNS.Reticulum.TRUNCATED_HASHLENGTH//8

        if result['header_type'] == 1:
            result['transport_id'] = result['raw'][2:DST_LEN+2]
            result['destination_hash'] = result['raw'][DST_LEN+2:2*DST_LEN+2]
            result['context'] = ord(result['raw'][2*DST_LEN+2:2*DST_LEN+3])
            result['data'] = result['raw'][2*DST_LEN+3:]
        else:
            result['transport_id'] = None
            result['destination_hash'] = result['raw'][2:DST_LEN+2]
            result['context'] = ord(result['raw'][DST_LEN+2:DST_LEN+3])
            result['data'] = result['raw'][DST_LEN+3:]

        result['packet_hash'] = get_message_id(result)

        return result

    except Exception as e:
        # print(e)
        # malformed packet
        return None

def announce_unpack(packet):
    """
    Phase 2 parsing: verify & pull out the announce-related parts from packet (output from packet_unpack.)
    """
    keysize = 64
    ratchetsize = 32
    name_hash_len = 10
    sig_len = 64
    destination_hash = packet['destination_hash']
    public_key = packet['data'][:keysize]
    
    if packet['context_flag'] == 1:
        name_hash   = packet['data'][keysize:keysize+name_hash_len ]
        random_hash = packet['data'][keysize+name_hash_len:keysize+name_hash_len+10]
        ratchet     = packet['data'][keysize+name_hash_len+10:keysize+name_hash_len+10+ratchetsize]
        signature   = packet['data'][keysize+name_hash_len+10+ratchetsize:keysize+name_hash_len+10+ratchetsize+sig_len]
        app_data    = b""
        if len(packet['data']) > keysize+name_hash_len+10+sig_len+ratchetsize:
            app_data = packet['data'][keysize+name_hash_len+10+sig_len+ratchetsize:]
    else:
        ratchet     = b""
        name_hash   = packet['data'][keysize:keysize+name_hash_len]
        random_hash = packet['data'][keysize+name_hash_len:keysize+name_hash_len+10]
        signature   = packet['data'][keysize+name_hash_len+10:keysize+name_hash_len+10+sig_len]
        app_data    = b""
        if len(packet['data']) > keysize+name_hash_len+10+sig_len:
            app_data = packet['data'][keysize+name_hash_len+10+sig_len:]

    signed_data = destination_hash+public_key+name_hash+random_hash+ratchet+app_data

    if not len(packet['data']) > 64 + 10 + 10 + 64:
        app_data = None

    enc_pub_key, sig_pub_key = get_pubkeys_from_bytes(public_key)

    announce = {
        'app_data': app_data,
        'name_hash': name_hash,
        'public_key': public_key,
        'random_hash': random_hash,
        'ratchet': ratchet,
        'signature': signature,
        'signed_data': signed_data,
        'enc_pub_key': enc_pub_key,
        'sig_pub_key': sig_pub_key,
        'valid': _ed25519_validate(sig_pub_key, signature, signed_data)
    }

    return announce

def proof_validate(packet, sig_pub_key, full_packet_hash):
    """
    Validate a PROOF packet (output from packet_unpack.)
    """
    return _ed25519_validate(sig_pub_key, packet['data'][0:64], full_packet_hash)


def message_decrypt(packet, identity, ratchets=None):
    """
    Decrypt a DATA message packet using identity's private key and optional ratchets.
    """
    identity_hash = _sha256(identity['public']['bytes'])[:16]

    ciphertext_token = packet.get('data', b'')
    if not ciphertext_token or len(ciphertext_token) <= 49:
        return None
    
    # Extract ephemeral public key and token
    peer_pub_bytes = ciphertext_token[:32]
    ciphertext = ciphertext_token[32:]

    # loop over user's ratchets to see if any can decrypt
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
                
            except Exception as e:
                print(e)
                continue
    return None

def build_announce(identity, destination, name='lxmf.delivery', ratchet_pub=None, app_data=None):
    pub_enc = identity['public']['encrypt']
    pub_sig = identity['public']['sign']

    keys = identity['public']['bytes']
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

    return packet_pack(pkt)