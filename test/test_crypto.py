import pytest
import os
import sys

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from crypto import (
  private_identity,
  public_identity,
  private_ratchet,
  public_ratchet,
  sha256,
  hmac_sha256,
  hkdf,
  pkcs7_pad,
  pkcs7_unpad,
  aes_cbc_encrypt,
  aes_cbc_decrypt,
  ed25519_sign,
  ed25519_validate,
  ed25519_public_for_private,
  x25519_exchange,
  x25519_public_for_private
)

class TestIdentityKeyGeneration:
  def test_private_identity(self):
    """Test private identity key generation - returns 64 bytes (X25519 + Ed25519)"""
    priv_key = private_identity()
    assert isinstance(priv_key, bytes)
    assert len(priv_key) == 64  # 32 bytes X25519 + 32 bytes Ed25519
    
  def test_public_identity(self):
    """Test public identity key derivation - expects 64 bytes input, returns 64 bytes"""
    priv_key = private_identity()
    pub_key = public_identity(priv_key)
    assert isinstance(pub_key, bytes)
    assert len(pub_key) == 64  # 32 bytes X25519 pub + 32 bytes Ed25519 pub
    
  def test_public_identity_structure(self):
    """Test that public identity contains both X25519 and Ed25519 public keys"""
    priv_key = private_identity()
    x25519_priv = priv_key[:32]  # First 32 bytes
    ed25519_priv = priv_key[32:]  # Last 32 bytes
    
    pub_key = public_identity(priv_key)
    x25519_pub = pub_key[:32]  # First 32 bytes
    ed25519_pub = pub_key[32:]  # Last 32 bytes
    
    # Verify X25519 public key derivation
    expected_x25519_pub = x25519_public_for_private(x25519_priv)
    assert x25519_pub == expected_x25519_pub
    
    # Verify Ed25519 public key derivation
    expected_ed25519_pub = ed25519_public_for_private(ed25519_priv)
    assert ed25519_pub == expected_ed25519_pub
    
  def test_public_identity_with_invalid_input(self):
    """Test public identity with invalid input length"""
    with pytest.raises(Exception):  # Adjust error type as needed
      public_identity(b"too_short")
    with pytest.raises(Exception):
      public_identity(b"too_long" + b"x" * 10)

class TestRatchetKeyGeneration:
  def test_private_ratchet(self):
    """Test private ratchet key generation"""
    priv_key = private_ratchet()
    assert isinstance(priv_key, bytes)
    assert len(priv_key) == 32  # X25519 private key is 32 bytes
    
  def test_public_ratchet(self):
    """Test public ratchet key derivation"""
    priv_key = private_ratchet()
    pub_key = public_ratchet(priv_key)
    assert isinstance(pub_key, bytes)
    assert len(pub_key) == 32  # X25519 public key is 32 bytes
    
  def test_public_ratchet_with_invalid_input(self):
    """Test public ratchet with invalid input"""
    with pytest.raises(Exception):  # or whatever error type is appropriate
      public_ratchet(b"invalid_key_length")

class TestHashFunctions:
  def test_sha256(self):
    """Test SHA256 hash function"""
    data = b"hello world"
    result = sha256(data)
    assert isinstance(result, bytes)
    assert len(result) == 32  # SHA256 produces 32-byte hash
    
    # Test that same input produces same output
    result2 = sha256(data)
    assert result == result2
    
    # Test that different input produces different output
    different_data = b"different"
    different_result = sha256(different_data)
    assert result != different_result
    
  def test_hmac_sha256(self):
    """Test HMAC-SHA256 function"""
    key = b"secret_key"
    data = b"message"
    result = hmac_sha256(key, data)
    assert isinstance(result, bytes)
    assert len(result) == 32  # HMAC-SHA256 produces 32-byte hash
    
    # Test with different key
    different_key = b"different_key"
    different_result = hmac_sha256(different_key, data)
    assert result != different_result
    
    # Test with different data
    different_data = b"different_message"
    different_result2 = hmac_sha256(key, different_data)
    assert result != different_result2

class TestHKDF:
  def test_hkdf(self):
    """Test HKDF function"""
    ikm = b"input_key_material"
    length = 32
    result = hkdf(ikm, length)
    assert isinstance(result, bytes)
    assert len(result) == length
    
  def test_hkdf_with_salt_and_info(self):
    """Test HKDF with salt and info parameters"""
    ikm = b"input_key_material"
    salt = b"salt_value"
    info = b"info_value"
    length = 64
    result = hkdf(ikm, length, salt=salt, info=info)
    assert isinstance(result, bytes)
    assert len(result) == length
    
  def test_hkdf_different_params_produce_different_output(self):
    """Test that different HKDF parameters produce different outputs"""
    ikm1 = b"input1"
    ikm2 = b"input2"
    length = 32
    result1 = hkdf(ikm1, length)
    result2 = hkdf(ikm2, length)
    assert result1 != result2
    
  def test_hkdf_empty_ikm_raises_error(self):
    """Test that empty IKM raises an error"""
    with pytest.raises(ValueError):  # Based on the error seen
      hkdf(b"", 32)

class TestPKCS7Padding:
  def test_pkcs7_pad(self):
    """Test PKCS7 padding"""
    data = b"hello"
    padded = pkcs7_pad(data, 16)
    assert len(padded) % 16 == 0
    assert padded.startswith(data)
    
    # Test with data that's already block-aligned
    aligned_data = b"hello12345678901"  # 16 bytes
    padded_aligned = pkcs7_pad(aligned_data, 16)
    assert len(padded_aligned) == 32  # Should add full block of padding
    
  def test_pkcs7_unpad(self):
    """Test PKCS7 unpadding"""
    original = b"hello"
    padded = pkcs7_pad(original, 16)
    unpadded = pkcs7_unpad(padded)
    assert unpadded == original
    
  def test_pkcs7_pad_unpad_roundtrip(self):
    """Test that pad and unpad are inverses"""
    test_data = [
      b"short",
      b"hello world",
      b"this is a longer message for testing",
      b"",  # empty data
      b"x" * 16,  # exactly one block
      b"x" * 31,  # one byte short of two blocks
    ]
    
    for data in test_data:
      padded = pkcs7_pad(data, 16)
      unpadded = pkcs7_unpad(padded)
      assert unpadded == data

class TestAES:
  def test_aes_cbc_encrypt_decrypt(self):
    """Test AES-CBC encryption and decryption"""
    key = os.urandom(32)  # 256-bit key
    iv = os.urandom(16)   # 128-bit IV
    plaintext = b"hello world, this is a test message!"
    
    ciphertext = aes_cbc_encrypt(key, iv, plaintext)
    decrypted = aes_cbc_decrypt(key, iv, ciphertext)
    
    assert decrypted == plaintext
    
  def test_aes_different_iv_produces_different_ciphertext(self):
    """Test that different IVs produce different ciphertexts"""
    key = os.urandom(32)
    plaintext = b"test message"
    iv1 = os.urandom(16)
    iv2 = os.urandom(16)
    
    ciphertext1 = aes_cbc_encrypt(key, iv1, plaintext)
    ciphertext2 = aes_cbc_encrypt(key, iv2, plaintext)
    
    assert ciphertext1 != ciphertext2
    
  def test_aes_invalid_decryption(self):
    """Test AES decryption with wrong key"""
    key1 = os.urandom(32)
    key2 = os.urandom(32)
    iv = os.urandom(16)
    plaintext = b"test message"
    
    ciphertext = aes_cbc_encrypt(key1, iv, plaintext)
    decrypted = aes_cbc_decrypt(key2, iv, ciphertext)
    
    # The decrypted data should not match the original
    assert decrypted != plaintext

class TestEd25519:
  def test_ed25519_sign_verify(self):
    """Test Ed25519 signing and verification with 32-byte private key"""
    private_key = os.urandom(32)  # 32-byte Ed25519 private key
    public_key = ed25519_public_for_private(private_key)
    message = b"test message for signing"
    
    signature = ed25519_sign(private_key, message)
    is_valid = ed25519_validate(signature, message, public_key)
    
    assert is_valid is True
    
  def test_ed25519_invalid_signature(self):
    """Test Ed25519 verification with invalid signature"""
    private_key1 = os.urandom(32)
    private_key2 = os.urandom(32)
    public_key1 = ed25519_public_for_private(private_key1)
    public_key2 = ed25519_public_for_private(private_key2)
    message = b"test message"
    
    signature = ed25519_sign(private_key1, message)
    is_valid = ed25519_validate(signature, message, public_key2)
    
    assert is_valid is False
    
  def test_ed25519_different_message_invalid(self):
    """Test Ed25519 verification fails with different message"""
    private_key = os.urandom(32)
    public_key = ed25519_public_for_private(private_key)
    message1 = b"original message"
    message2 = b"different message"
    
    signature = ed25519_sign(private_key, message1)
    is_valid = ed25519_validate(signature, message2, public_key)
    
    assert is_valid is False
    
  def test_ed25519_public_for_private(self):
    """Test Ed25519 public key derivation"""
    private_key = os.urandom(32)
    public_key = ed25519_public_for_private(private_key)
    assert isinstance(public_key, bytes)
    assert len(public_key) == 32
    
  def test_ed25519_from_identity_key(self):
    """Test Ed25519 operations using the Ed25519 part of identity key"""
    identity_priv = private_identity()  # 64 bytes: X25519(32) + Ed25519(32)
    ed25519_priv = identity_priv[32:]  # Extract Ed25519 private key (last 32 bytes)
    ed25519_pub = ed25519_public_for_private(ed25519_priv)
    
    # Test signing with the Ed25519 portion of the identity key
    message = b"signed with identity key"
    signature = ed25519_sign(ed25519_priv, message)
    is_valid = ed25519_validate(signature, message, ed25519_pub)
    
    assert is_valid is True
    assert len(ed25519_pub) == 32

class TestX25519:
  def test_x25519_key_exchange(self):
    """Test X25519 key exchange"""
    alice_private = private_ratchet()
    bob_private = private_ratchet()
    
    alice_public = x25519_public_for_private(alice_private)
    bob_public = x25519_public_for_private(bob_private)
    
    # Alice computes shared secret using her private key and Bob's public key
    shared_secret_alice = x25519_exchange(alice_private, bob_public)
    
    # Bob computes shared secret using his private key and Alice's public key
    shared_secret_bob = x25519_exchange(bob_private, alice_public)
    
    # Both should compute the same shared secret
    assert shared_secret_alice == shared_secret_bob
    assert isinstance(shared_secret_alice, bytes)
    assert len(shared_secret_alice) == 32
    
  def test_x25519_public_for_private(self):
    """Test X25519 public key derivation"""
    private_key = private_ratchet()
    public_key = x25519_public_for_private(private_key)
    assert isinstance(public_key, bytes)
    assert len(public_key) == 32
    
  def test_x25519_from_identity_key(self):
    """Test X25519 operations using the X25519 part of identity key"""
    identity_priv = private_identity()  # 64 bytes: X25519(32) + Ed25519(32)
    x25519_priv = identity_priv[:32]  # Extract X25519 private key (first 32 bytes)
    x25519_pub = x25519_public_for_private(x25519_priv)
    
    # Test key exchange with the X25519 portion of the identity key
    other_priv = private_ratchet()
    other_pub = x25519_public_for_private(other_priv)
    
    shared_secret_1 = x25519_exchange(x25519_priv, other_pub)
    shared_secret_2 = x25519_exchange(other_priv, x25519_pub)
    
    assert shared_secret_1 == shared_secret_2
    assert len(shared_secret_1) == 32

# Additional edge case tests
class TestEdgeCases:
  def test_empty_inputs_where_applicable(self):
    """Test functions with empty inputs where it makes sense"""
    # Hash functions with empty data
    empty_hash = sha256(b"")
    assert isinstance(empty_hash, bytes) and len(empty_hash) == 32
    
    # HMAC with empty data
    empty_hmac = hmac_sha256(b"key", b"")
    assert isinstance(empty_hmac, bytes) and len(empty_hmac) == 32
    
    # HKDF with empty IKM should raise error (tested separately)
    # empty_hkdf = hkdf(b"", 32)  # This should raise an error

class TestIdentityKeyStructure:
  """Tests for the dual-purpose identity key structure"""
  
  def test_identity_key_composition(self):
    """Test that identity key contains both X25519 and Ed25519 keys properly"""
    identity_priv = private_identity()
    assert len(identity_priv) == 64
    
    x25519_part = identity_priv[:32]
    ed25519_part = identity_priv[32:]
    
    # Both parts should be 32 bytes each
    assert len(x25519_part) == 32
    assert len(ed25519_part) == 32
    
    # Both parts should be valid private keys for their respective algorithms
    x25519_pub = x25519_public_for_private(x25519_part)
    ed25519_pub = ed25519_public_for_private(ed25519_part)
    
    assert len(x25519_pub) == 32
    assert len(ed25519_pub) == 32
  
  def test_identity_key_consistency(self):
    """Test that public identity derivation is consistent"""
    identity_priv = private_identity()
    pub_identity_1 = public_identity(identity_priv)
    pub_identity_2 = public_identity(identity_priv)
    
    # Should produce the same result
    assert pub_identity_1 == pub_identity_2
    assert len(pub_identity_1) == 64

if __name__ == "__main__":
  pytest.main([__file__])