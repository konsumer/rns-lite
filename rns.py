# Lightweight Reticulum library
# https://github.com/konsumer/rns-lite

import sys
from os import urandom
import hashlib

# micropython has simpler/different hashing & crypto stuff, so we abstract the basic helpers
if sys.implementation.name == 'micropython':
    from cryptolib import aes
    
    # HMAC-SHA256 implementation for MicroPython
    def _getHmac(sign_key, data):
        # Standard HMAC construction per RFC 2104
        block_size = 64  # SHA256 block size
        
        # Adjust key length
        if len(sign_key) > block_size:
            sign_key = hashlib.sha256(sign_key).digest()
        if len(sign_key) < block_size:
            sign_key = sign_key + b'\x00' * (block_size - len(sign_key))
        
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
    def _getHmac(sign_key, data):
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


def _PKCS7_unpad(data, bs=16):
  l = len(data)
  n = data[-1]
  if n > bs:
    raise ValueError(f"Cannot unpad, invalid padding length of {n} bytes")
  else:
    return data[:l-n]

def _PKCS7_pad(data, bs=16):
  l = len(data)
  n = bs-l%bs
  v = bytes([n])
  return data+v*n

def _split_key(identity=None):
  """
  An identity is 2 private-keys: 16/32 byte-length
  This helper will split that into: sign_key, encrypt_key
  """
  if not isinstance(identity, bytes): raise ValueError("Identity must be bytes")
  if len(identity) != 32 and len(identity) != 64:
    raise ValueError(f"Identity must be 128 or 256 bits, not {len(identity)*8}")
  midpoint = len(identity) // 2
  return (identity[:midpoint], identity[midpoint:])

def token_verify(sign_key, token):
  """
  HMAC verify token-signature
  """
  if not isinstance(token, bytes): raise TypeError("Token must be bytes")
  return token[-32:] == _getHmac(sign_key, token[:-32])

def token_decrypt(identity, token = None):
  """
  AES decrypt a token
  """
  (sign_key, encrypt_key) = _split_key(identity)
  if not token_verify(sign_key, token): raise ValueError("Token HMAC was invalid")
  iv = token[:16]
  plaintext = _aesCbcDecrypt(encrypt_key, iv, token[16:-32])
  return _PKCS7_unpad(plaintext)

def token_encrypt(identity, data = None):
  """
  AES encrypt a token
  """
  (sign_key, encrypt_key) = _split_key(identity)
  if not isinstance(data, bytes): raise TypeError("Token must be bytes")
  iv = urandom(16)
  ciphertext = _aesCbcEncrypt(encrypt_key, iv, _PKCS7_pad(data))
  signed_parts = iv + ciphertext
  return signed_parts + _getHmac(sign_key, signed_parts)



def decode_packet(bytes):
  """
  Decode main parts of a reticulum packet, returns packet dict
  """
  pass

def decode_announce(packet):
  """
  Decode an ANNOUNCE packet (output from decode_packet)
  """
  pass

def decode_data(packet, receiverIdentity, ratchets=[]):
  """
  Decode & decrypt a DATA packet (output from decode_packet)
  """
  pass

def encode_data(packet, whatever):
  """
  Encrypt & encode a DATA packet
  """
  pass

