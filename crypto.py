# this is a central collection of utils you will need in any reticulum implementation

import os
import struct
import hashlib
import hmac
from typing import Optional
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives import serialization

def private_identity():
  """
  Returns a 64-byte private identity: 32 bytes X25519 (encryption), 32 bytes Ed25519 (signing).
  """
  x_sk = X25519PrivateKey.generate()
  ed_sk = Ed25519PrivateKey.generate()

  x_sk_bytes = x_sk.private_bytes(
    encoding=serialization.Encoding.Raw,
    format=serialization.PrivateFormat.Raw,
    encryption_algorithm=serialization.NoEncryption()
  )
  ed_sk_bytes = ed_sk.private_bytes(
    encoding=serialization.Encoding.Raw,
    format=serialization.PrivateFormat.Raw,
    encryption_algorithm=serialization.NoEncryption()
  )
  return x_sk_bytes + ed_sk_bytes

def public_identity(identity_priv_bytes: bytes):
  """
  Returns the public identity for a given private identity (64 bytes).
  Result: 32 bytes X25519 pubkey + 32 bytes Ed25519 pubkey.
  """
  if len(identity_priv_bytes) != 64:
    raise ValueError("identity_priv_bytes must be 64 bytes")
  x_sk_bytes = identity_priv_bytes[:32]
  ed_sk_bytes = identity_priv_bytes[32:]

  x_sk = X25519PrivateKey.from_private_bytes(x_sk_bytes)
  ed_sk = Ed25519PrivateKey.from_private_bytes(ed_sk_bytes)

  x_pk_bytes = x_sk.public_key().public_bytes(
    encoding=serialization.Encoding.Raw,
    format=serialization.PublicFormat.Raw
  )
  ed_pk_bytes = ed_sk.public_key().public_bytes(
    encoding=serialization.Encoding.Raw,
    format=serialization.PublicFormat.Raw
  )
  return x_pk_bytes + ed_pk_bytes

def private_ratchet():
  """
  Returns a random 32-byte ratchet (X25519 private key).
  """
  x_sk = X25519PrivateKey.generate()
  x_sk_bytes = x_sk.private_bytes(
    encoding=serialization.Encoding.Raw,
    format=serialization.PrivateFormat.Raw,
    encryption_algorithm=serialization.NoEncryption()
  )
  return x_sk_bytes

def public_ratchet(x_sk_bytes: bytes):
  """
  Returns X25519 public key for a given 32-byte private ratchet.
  """
  x_sk = X25519PrivateKey.from_private_bytes(x_sk_bytes)
  return x_sk.public_key().public_bytes(
    encoding=serialization.Encoding.Raw,
    format=serialization.PublicFormat.Raw
  )

def sha256(data: bytes) -> bytes:
  return hashlib.sha256(data).digest()

def hmac_sha256(key: bytes, data: bytes) -> bytes:
  return hmac.new(key, data, hashlib.sha256).digest()

def hkdf(ikm: bytes, length: int, salt: Optional[bytes] = None, info: Optional[bytes] = None) -> bytes:
  if length < 1:
    raise ValueError("Invalid output key length")
  if not ikm:
    raise ValueError("Cannot derive key from empty input material")
  salt = salt or b'\x00' * 32
  info = info or b''
  prk = hmac.new(salt, ikm, hashlib.sha256).digest()
  okm = b""
  T = b""
  i = 1
  while len(okm) < length:
    T = hmac.new(prk, T + info + bytes([i]), hashlib.sha256).digest()
    okm += T
    i += 1
  return okm[:length]

def pkcs7_pad(data: bytes, bs: int = 16) -> bytes:
  n = bs - (len(data) % bs)
  return data + bytes([n] * n)

def pkcs7_unpad(data: bytes) -> bytes:
  if len(data) == 0:
    return data
  padding_length = data[-1]
  if not (0 < padding_length <= 16 and padding_length <= len(data)):
    return data
  if data[-padding_length:] != bytes([padding_length]) * padding_length:
    return data
  return data[:-padding_length]

def aes_cbc_encrypt(key: bytes, iv: bytes, plaintext: bytes) -> bytes:
  cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
  encryptor = cipher.encryptor()
  return encryptor.update(pkcs7_pad(plaintext)) + encryptor.finalize()

def aes_cbc_decrypt(key: bytes, iv: bytes, ciphertext: bytes) -> bytes:
  cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
  decryptor = cipher.decryptor()
  return pkcs7_unpad(decryptor.update(ciphertext) + decryptor.finalize())

def ed25519_sign(private_key: bytes, message: bytes) -> bytes:
  return Ed25519PrivateKey.from_private_bytes(private_key).sign(message)

def ed25519_validate(signature: bytes, message: bytes, public_key: bytes) -> bool:
  try:
    Ed25519PublicKey.from_public_bytes(public_key).verify(signature, message)
    return True
  except Exception as e:
    return False

def ed25519_public_for_private(private_key: bytes) -> bytes:
  return Ed25519PrivateKey.from_private_bytes(private_key).public_key().public_bytes_raw()

def x25519_exchange(private_key: bytes, public_key: bytes) -> bytes:
  return X25519PrivateKey.from_private_bytes(private_key).exchange(X25519PublicKey.from_public_bytes(public_key))

def x25519_public_for_private(private_key: bytes) -> bytes:
  return X25519PrivateKey.from_private_bytes(private_key).public_key().public_bytes(
    encoding=serialization.Encoding.Raw,
    format=serialization.PublicFormat.Raw
  )


