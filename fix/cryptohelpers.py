# this abstracts all the cpython-specific crypto functions

import hashlib
import hmac
from math import ceil
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives import serialization

def key_from_bytes(private_identity_bytes):
    """
    Load some private-keys (encrypt/sign) from bytes
    """
    return {
        'bytes': private_identity_bytes, # joined privkeys as bytes [encrypt, sign]
        'encrypt': X25519PrivateKey.from_private_bytes(private_identity_bytes[:32]),
        'sign': Ed25519PrivateKey.from_private_bytes(private_identity_bytes[32:64])
    }

def pub_from_bytes(public_identity_bytes):
    """
    Load a pubkey-pair from some bytes
    """
    return {
        'bytes': public_identity_bytes, # joined privkeys as bytes [encrypt, sign]
        'encrypt': X25519PublicKey.from_public_bytes(public_identity_bytes[:32]),
        'sign': Ed25519PublicKey.from_public_bytes(public_identity_bytes[32:64])
    }


def generate_key():
    """
    Generate a new pair of private-keys
    """
    private_encrypt = X25519PrivateKey.generate()
    private_sign = Ed25519PrivateKey.generate()
    b = private_encrypt.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption()) + private_sign.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption())
    return {
        'bytes': b, # joined privkeys as bytes [encrypt, sign]
        'encrypt': private_encrypt,
        'sign': private_sign
    }

def pub_from_key(private_key):
    """
    Get a public key pair from private-keys
    """
    pub_encrypt = private_key['encrypt'].public_key()
    pub_sign = private_key['sign'].public_key()
    b = pub_encrypt.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw) + pub_sign.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return {
        'bytes': b, # joined pubkeys as bytes [encrypt, sign]
        'encrypt': pub_encrypt,
        'sign': pub_sign
    }

def sign(identityPriv, signed_data):
    """
    Use a private-key to sign data
    """
    return identityPriv['sign'].sign(signed_data)

def validate(identityPub, signature, message):
    """
    Use a sign pubkey to validate a signature
    """
    try:
        identityPub['sign'].verify(signature, message)
        return True
    except Exception as e:
        return False

def exchange(private_bytes, peer_pub_bytes):
    """
    Use our private + their public to create a shared secret-key
    """
    # exchnages are mostly done with bytes, so I create the keys on the fly
    prv_key = X25519PrivateKey.from_private_bytes(private_bytes)
    pub_key = X25519PublicKey.from_public_bytes(peer_pub_bytes)
    return prv_key.exchange(pub_key)

def hmac_sha256(identityPriv, data):
    return hmac.new(identityPriv, data, hashlib.sha256).digest()

def encrypt(identityPub, iv, plaintext):
    cipher = Cipher(algorithms.AES(identityPub), modes.CBC(iv))
    encryptor = cipher.encryptor()
    return _pkcs7_pad(encryptor.update(plaintext) + encryptor.finalize())

def decrypt(identityPriv, iv, ciphertext):
    cipher = Cipher(algorithms.AES(identityPriv), modes.CBC(iv))
    decryptor = cipher.decryptor()
    return _pkcs7_unpad(decryptor.update(ciphertext) + decryptor.finalize())

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

    block = b""
    derived = b""

    for i in range(ceil(length / hash_len)):
        block = hmac_sha256(
            pseudorandom_key, block + context + bytes([(i + 1) % (0xFF + 1)])
        )
        derived += block

    return derived[:length]

def sha256(data):
    return hashlib.sha256(data).digest()

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
