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


def get_identity_from_bytes(privatebytes, full_name='lxmf.delivery'):
    private = crypto.key_from_bytes(privatebytes)
    public = crypto.pub_from_key(private)
    identity = { 'private': private, 'public': public }
    identity['destination_hash'] = get_destination_hash(identity, full_name)
    return identity

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

    peerPub = crypto.pub_from_bytes(public_key)

    announce = {
        'app_data': app_data,
        'name_hash': name_hash,
        'public_key': public_key,
        'random_hash': random_hash,
        'ratchet': ratchet,
        'signature': signature,
        'signed_data': signed_data,
        'valid': crypto.validate(peerPub, signature, signed_data)
    }

    return announce

def message_decrypt(packet, identity, ratchets=None):
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
                shared_key = crypto.exchange(ratchet, peer_pub_bytes)
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
                print(e)
                continue
    return None

def proof_validate(packet, idenityPub, full_packet_hash):
    """
    Validate a PROOF packet (output from packet_unpack.)
    """
    return crypto.validate(idenityPub['public'], packet['data'][0:64], full_packet_hash)