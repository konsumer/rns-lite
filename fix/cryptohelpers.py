# this abstracts all the cpython-specific crypto functions

import hashlib
import hmac
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives import serialization

def identity_private_from_bytes(private_identity_bytes):
	"""
	Load some private-keys (encrypt/sign) from bytes
	"""
    return {
    	'bytes': private_identity_bytes, # joined privkeys as bytes [encrypt, sign]
    	'encrypt': X25519PrivateKey.from_private_bytes(private_identity_bytes[:32]),
    	'sign': Ed25519PrivateKey.from_private_bytes(private_identity_bytes[32:64])
    }

def identity_generate():
	private_encrypt = X25519PrivateKey.generate()
    private_sign = Ed25519PrivateKey.generate()
    b = private_encrypt.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption()) + private_sign.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption())
    return {
    	'bytes': b, # joined privkeys as bytes [encrypt, sign]
    	'encrypt': private_encrypt,
		'sign': private_sign
    }

def identity_public_from_private(private_key):
	pub_encrypt = private_key.encrypt.public_key()
	pub_sign = private_key.sign.public_key()
	b = pub_encrypt.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw) + pub_sign.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
	return {
		'bytes': b, # joined pubkeys as bytes [encrypt, sign]
		'encrypt': pub_encrypt,
		'sign': pub_sign
	}

