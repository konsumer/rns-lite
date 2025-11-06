import pytest
import utils as ru

def test_hex_bytes_conversion():
    assert ru.hex_to_bytes('deadbeef') == b'\xde\xad\xbe\xef'
    assert ru.bytes_to_hex(b'\xde\xad\xbe\xef') == 'deadbeef'
    assert ru.hex_to_bytes('') == b''
    assert ru.bytes_to_hex(b'') == ''

def test_random_bytes():
    b1 = ru.random_bytes(32)
    b2 = ru.random_bytes(32)
    assert isinstance(b1, bytes)
    assert len(b1) == 32
    assert b1 != b2

def test_concat_bytes():
    a = b'\x01\x02'
    b = b'\x03'
    c = b'\x04\x05'
    assert ru.concat_bytes(a, b, c) == b'\x01\x02\x03\x04\x05'

def test_equal_bytes():
    a = b'foo'
    b = b'foo'
    c = b'bar'
    assert ru.equal_bytes(a, b)
    assert not ru.equal_bytes(a, c)

def test_msgpack_pack_unpack():
    obj = {'k': 1, 'v': 'hi', 'nested': {'a': 1}}
    packed = ru.msgpack_pack(obj)
    assert ru.msgpack_unpack(packed) == obj

def test_sha256():
    data = b'test'
    h1 = ru.sha256(data)
    h2 = ru.sha256(data)
    assert isinstance(h1, bytes)
    assert h1 == h2
    assert len(h1) == 32

def test_hmac_sha256():
    key = b'\x01' * 32
    data = b'test'
    h1 = ru.hmac_sha256(key, data)
    h2 = ru.hmac_sha256(key, data)
    assert h1 == h2
    assert isinstance(h1, bytes)
    assert len(h1) == 32

def test_hkdf_derivation():
    key = b'\x01' * 32
    salt = b'\x02' * 32
    out = ru.hkdf(64, key, salt)
    assert len(out) == 64
    assert ru.hkdf(32, key, None)
    ctx = b'abc'
    out2 = ru.hkdf(32, key, salt, ctx)
    assert len(out2) == 32
    with pytest.raises(ValueError):
        ru.hkdf(0, key, salt)
    with pytest.raises(ValueError):
        ru.hkdf(32, b'', salt)

def test_pkcs7_padding():
    block = 16
    pads = ru.pkcs7_pad(b'ABC', block)
    assert pads.endswith(bytes([block - 3]))
    unpad = ru.pkcs7_unpad(pads)
    assert unpad == b'ABC'
    assert ru.pkcs7_unpad(b'') == b''

def test_aes_cbc_encrypt_decrypt():
    key = b'\x01' * 32
    iv = b'\x02' * 16
    plain = b'foo bar'
    ct = ru.aes_cbc_encrypt(key, iv, plain)
    pt = ru.aes_cbc_decrypt(key, iv, ct)
    assert pt == plain

def test_ed25519_sign_verify():
    priv = ru.random_bytes(32)
    pub = ru.ed25519_public_for_private(priv)
    msg = b'test'
    sign = ru.ed25519_sign(msg, priv)
    assert len(sign) == 64
    assert ru.ed25519_validate(pub, sign, msg)
    badmsg = b'xx'
    assert not ru.ed25519_validate(pub, sign, badmsg)
    # Corrupt signature
    badsign = bytearray(sign)
    badsign[0] ^= 1
    assert not ru.ed25519_validate(pub, bytes(badsign), msg)

def test_x25519_key_exchange():
    priv1 = ru.random_bytes(32)
    priv2 = ru.random_bytes(32)
    pub1 = ru.x25519_public_for_private(priv1)
    pub2 = ru.x25519_public_for_private(priv2)
    s1 = ru.x25519_exchange(priv1, pub2)
    s2 = ru.x25519_exchange(priv2, pub1)
    assert s1 == s2
    assert len(s1) == 32

