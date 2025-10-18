import sys
from os import urandom
import hashlib
import time
import cryptohelpers as crypto

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

def get_destination_hash(identity, full_name='lxmf.delivery'):
    """
    Get the destination-hash (LXMF address) from identity.
    """
    identity_hash = crypto.sha256(identity['public']['bytes'])[:16]
    name_hash = crypto.sha256(full_name.encode("utf-8"))[:10]
    addr_hash_material = name_hash + identity_hash
    destination_hash = crypto.sha256(addr_hash_material)[:16]
    return destination_hash

def get_message_id(packet):
    """
    Get the message-id (used as destination in PROOFs, for example) from a packet (output from packet_unpack.)
    """
    header_type = (packet['raw'][0] >> 6) & 0b11
    hashable_part = bytes([packet['raw'][0] & 0b00001111])
    hashable_part += packet['raw'][2:]
    return crypto.sha256(hashable_part)


def identity_from_bytes(privatebytes, full_name='lxmf.delivery'):
    """
    Load a complete identity (private/public for encrypt/sign and destination_hash) from private bytes
    """
    identity = {
        'private': {
            'encrypt': crypto.x25519_private_from_bytes(privatebytes[:32]),
            'sign': crypto.ed25519_private_from_bytes(privatebytes[32:64])
        },
        'public': {}
    }
    identity['public']['encrypt'] = crypto.x25519_public_from_private(identity['private']['encrypt'])
    identity['public']['sign'] = crypto.ed25519_public_from_private(identity['private']['sign'])
    identity['private']['bytes'] = crypto.x25519_private_to_bytes(identity['private']['encrypt']) + crypto.ed25519_private_to_bytes(identity['private']['sign'])
    identity['public']['bytes'] = crypto.x25519_public_to_bytes(identity['public']['encrypt']) + crypto.ed25519_public_to_bytes(identity['public']['sign'])
    identity['destination_hash'] = get_destination_hash(identity, full_name)
    return identity


def identity_create(full_name='lxmf.delivery'):
    """
    Build a complete identity (private/public for encrypt/sign and destination_hash)
    """
    return identity_from_bytes(urandom(64), full_name)

def ratchet_create():
    return urandom(32)

def ratchet_public(private):
    return crypto.x25519_public_to_bytes(crypto.x25519_public_from_private(crypto.x25519_private_from_bytes(private)))

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

    announce = {
        'app_data': app_data,
        'name_hash': name_hash,
        'public_key': public_key,
        'random_hash': random_hash,
        'ratchet': ratchet,
        'signature': signature,
        'signed_data': signed_data,
        'valid': crypto.ed25519_validate(crypto.ed25519_public_from_bytes(public_key[32:64]), signature, signed_data)
    }

    return announce

def message_decrypt(packet, identity, ratchets=[]):
    """
    Decrypt a DATA message packet using identity's private key and optional ratchets.
    """
    identity_hash = crypto.sha256(identity['public']['bytes'])[:16]
    ciphertext_token = packet.get('data', b'')
    if not ciphertext_token or len(ciphertext_token) <= 49:
        return None
    
    # Extract ephemeral public key and token
    peer_pub_bytes = ciphertext_token[:32]
    ciphertext = ciphertext_token[32:]

    # loop over user's ratchets to see if any can decrypt
    if ratchets:
        for ratchet in ratchets:
            if len(ratchet) != 32:
                continue
            try:
                shared_key = crypto.x25519_exchange(crypto.x25519_private_from_bytes(ratchet), crypto.x25519_public_from_bytes(peer_pub_bytes))
                derived_key = crypto.hkdf(
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
                expected_hmac = crypto.hmac_sha256(signing_key, signed_data)
                
                if received_hmac != expected_hmac:
                    continue
                    
                iv = ciphertext[:16]
                ciphertext_data = ciphertext[16:-32]
                plaintext = crypto.decrypt(encryption_key, iv, ciphertext_data)
                return plaintext
                
            except Exception as e:
                # print(e)
                continue
    return None

def proof_validate(packet, idenityPub, full_packet_hash):
    """
    Validate a PROOF packet (output from packet_unpack.)
    """
    return crypto.ed25519_validate(idenityPub['public']['sign'], packet['data'][0:64], full_packet_hash)


def build_proof(identity, packet, message_id=None):
    """
    Build a PROOF packet in response to a received DATA packet.
    """
    if message_id is None:
        message_id = get_message_id(packet)
    proof_destination = message_id[:16]
    signature = crypto.ed25519_sign(identity['private']['sign'], message_id)
    proof_data = bytes([0x00]) + signature
    pkt = {
        'destination_hash': proof_destination,
        'packet_type': PACKET_PROOF,
        'destination_type': 0,
        'hops': 0,
        'data': proof_data
    }
    return encode_packet(pkt)

def encode_packet(packet):
    header_byte = 0

    source_hash = packet.get('source_hash')
    if source_hash:
        packet['header_type'] = 1

    if packet.get('ifac_flag'):
        header_byte |= 0b10000000
    if packet.get('header_type'):
        header_byte |= 0b01000000

    # TODO: I think this is wrong, what I thought was context before is transport_id/transport_type
    has_context = ('context' in packet)
    if has_context:
        packet['context_flag'] = True
    if packet.get('context_flag'):
        header_byte |= 0b00100000

    if packet.get('transport_type'):
        header_byte |= 0b00010000

    destination_type = packet.get('destination_type', 0) & 0b00001100
    header_byte |= destination_type

    packet_type = packet.get('packet_type', 0) & 0b00000011
    header_byte |= packet_type

    out = bytearray()
    out.append(header_byte)
    out.append(packet.get('hops', 0) & 0xFF)

    dest = packet.get('destination_hash', b'')
    if len(dest) != 16:
        raise ValueError("destination_hash must be 16 bytes")
    out += dest

    if source_hash:
        if len(source_hash) != 16:
            raise ValueError("source_hash must be 16 bytes")
        out += source_hash

    if packet.get('context_flag'):
        out.append(packet.get('context', 0) & 0xFF)

    out += packet.get('data', b'')
    return bytes(out)

def build_announce(identity, destination, name='lxmf.delivery', ratchet_pub=None, app_data=None):
    pub_enc = identity['public']['encrypt']
    pub_sig = identity['public']['sign']
    keys = identity['public']['bytes']

    name_hash = crypto.sha256(name.encode('utf-8'))[:10]
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
    signature = crypto.ed25519_sign(identity['private']['sign'], signed_data)

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

    return encode_packet(pkt)

