# this abstracts all the cpython-specific crypto functions

import hashlib
import hmac
from math import ceil
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives import serialization


# these are key-exchange
def x25519_private_key_generate():
    return X25519PrivateKey.generate()

def x25519_public_from_private(private):
    return private.public_key()

def x25519_private_from_bytes(privateBytes):
    return X25519PrivateKey.from_private_bytes(privateBytes)

def x25519_public_from_bytes(publicBytes):
    return X25519PublicKey.from_public_bytes(publicBytes)

def x25519_exchange(private, public):
    return private.exchange(public)

def x25519_private_to_bytes(private):
    return private.private_bytes_raw()

def x25519_public_to_bytes(public):
    return public.public_bytes_raw()

def encrypt(identityPub, iv, plaintext):
    cipher = Cipher(algorithms.AES(identityPub), modes.CBC(iv))
    encryptor = cipher.encryptor()
    return pkcs7_pad(encryptor.update(plaintext) + encryptor.finalize())

def decrypt(identityPriv, iv, ciphertext):
    cipher = Cipher(algorithms.AES(identityPriv), modes.CBC(iv))
    decryptor = cipher.decryptor()
    return pkcs7_unpad(decryptor.update(ciphertext) + decryptor.finalize())


# these are for signing
def ed25519_private_key_generate():
    return Ed25519PrivateKey.generate()

def ed25519_public_from_private(private):
    return private.public_key()

def ed25519_private_from_bytes(privateBytes):
    return Ed25519PrivateKey.from_private_bytes(privateBytes)

def ed25519_public_from_bytes(publicBytes):
    return Ed25519PublicKey.from_public_bytes(publicBytes)

def ed25519_sign(identityPrivSign, signed_data):
    return identityPrivSign.sign(signed_data)

def ed25519_validate(identityPubSign, signature, message):
    try:
        identityPubSign.verify(signature, message)
        return True
    except Exception as e:
        return False

def ed25519_private_to_bytes(private):
    return private.private_bytes_raw()

def ed25519_public_to_bytes(public):
    return public.public_bytes_raw()


def sha256(data):
    return hashlib.sha256(data).digest()

def pkcs7_unpad(data, bs=16):
    l = len(data)
    n = data[-1]
    if n > bs:
        raise ValueError(f"Cannot unpad, invalid padding length of {n} bytes")
    else:
        return data[: l - n]

def pkcs7_pad(data, bs=16):
    l = len(data)
    n = bs - l % bs
    v = bytes([n])
    return data + v * n

def hmac_sha256(identityPriv, data):
    return hmac.new(identityPriv, data, hashlib.sha256).digest()

def hkdf(length=None, derive_from=None, salt=None, context=None):
    hash_len = 32

    if length == None or length < 1:
        raise ValueError("Invalid output key length")

    if derive_from == None or derive_from == "":
        raise ValueError("Cannot derive key from empty input material")

    if salt == None or len(salt) == 0:
        salt = bytes([0] * hash_len)

    if context == None:
        context = b""

    pseudorandom_key = hmac_sha256(salt, derive_from)
    derived = b""
    block = b""
    derived = b""

    for i in range(ceil(length / hash_len)):
        block = hmac_sha256(
            pseudorandom_key, block + context + bytes([(i + 1) % (0xFF + 1)])
        )
        derived += block

    return derived[:length]
