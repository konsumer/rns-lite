# Lightweight Reticulum library
# https://github.com/konsumer/rns-lite

import sys
from os import urandom
import hashlib

# micropython has simpler/different hashing & crypto stuff, so we abstract the basic helpers
if sys.implementation.name == "micropython":
    from cryptolib import aes

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

else:
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    import hmac

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

def decode_packet(packet_bytes):
    result = {}
    header1 = packet_bytes[0]
    result["ifac_flag"] = bool(header1 & 0b10000000)
    result["header_type"] = bool(header1 & 0b01000000)
    result["context_flag"] = bool(header1 & 0b00100000)
    result["propagation_type"] = bool(header1 & 0b00010000)
    result["destination_type"] = header1 & 0b00001100
    result["packet_type"] = header1 & 0b00000011
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


def decode_announce(packet):
    """
    Decode an ANNOUNCE packet (output from decode_packet)
    """
    pass


def decode_data(packet, receiverIdentity, ratchets=[]):
    """
    Decrypt a DATA packet (output from decode_packet)
    """
    pass

