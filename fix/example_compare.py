# this will compare offline parsing with rns and RNS

import rns
import RNS
import umsgpack

# shared data from real clients: [encrypt_key, sign_key]
kA = bytes.fromhex('072ec44973a8dee8e28d230fb4af8fe4')
kB = bytes.fromhex('76a93cda889a8c0a88451e02d53fd8b9')
keys = {
    kA: bytes.fromhex('205131cb9672eaec8a582e8e018307f2428c4aac5e383f12e94939e672b931677763c7398d0b9cb6ef1369d023d8af10b85d80f6579c55a6f528953265c15313'),
    kB: bytes.fromhex('e8c5c096166f3554868de9133b0c55c7abf0318230860a142ea3f84a0aae7759142f6c0b84d9f537ceb2e8e9678fc9fb77caf91e2176278fb4c4f5c3eb7b48cd')
}

ratchets=[
  bytes.fromhex('205cb256c44d4d3939bdc02e2a9667de4214cbcc651bbdc0a318acf7ec68b066'),
  bytes.fromhex('28dd4da561a9bc0cb7d644a4487c01cbe32b01718a21f18905f5611b110a5c45')
]

# output from packet-capture
_traffic = """
ANNOUNCE (072ec44973a8dee8e28d230fb4af8fe4):  2100072ec44973a8dee8e28d230fb4af8fe400a2b9b02fb4749fcf8458762d1be0ae67ff1caa47fb0a52f4c2bd6dd07860a738da50a87f884e6e64aaa70b44d20868144e3e26ffa001c60a7c797dbae5078ece6ec60bc318e2c0f0d90873408275530068de1039e2bb21108b2cbc900b476290ab7867441446db366a70fb8ed1448ca0e889bd65bad6d8654e72661ddc089b06495ab91a57afc5700e095f021aa8cec04f22ba55438efc3ab1e2a91b8d17bd259313f175dff040827fdf1111c88bef501676380b92c40e416e6f6e796d6f75732050656572c0
ANNOUNCE (76a93cda889a8c0a88451e02d53fd8b9):  210076a93cda889a8c0a88451e02d53fd8b90071f199f04d3589ca083c66ff91baed628ee19517ef68eb209827df3a6785cf5b0af43fb0e168176370828fcdc199e5ae2b208b57cf65179ffa8f25733d9d40bc6ec60bc318e2c0f0d908149ad525040068de103b0df6d220011ce9da7559fbd620380501d9e19afce87a6d0c661412f3831cc915dbecabe89ef5a11a359d3757a85280c3ae68a8b6366ed4110be24a408dbe946b2815e0e89f8e49848978122b30e442af83b36cef11d3df69c34189156858560292c40e416e6f6e796d6f75732050656572c0
DATA (76a93cda889a8c0a88451e02d53fd8b9):  000076a93cda889a8c0a88451e02d53fd8b900f549cccf8d574cb520c8f12ea6ea67c4f4ce34f301de611cd942acbfb6933f3f7a025d5b6d6184d04dd0279b8037f1c9c1c1c25defbdd5e62aa8fb04502101014a501b9235e62f823bbdfd4d85e7656d765802f115a01b57b823ae02cc94899ae3a0f94bf7c32f1a73c027e5c95e0dd94c72c833ea75951af517da665eff26bca45e90e2eaa18775e65799ea0b3a977645107850dbfe62bb1f3228b50ac6e775006c4f18d6f3a1474233dc9b13cd95f6a6f581ad0b85de7196ea606d393d35f1
PROOF (2831d76f1a8035638505c132fe5818c1):  03002831d76f1a8035638505c132fe5818c100b90b83a04be319463f930b123b667eaaf64a85e827c34831a032cf72834a1dc58836e1fe4c49e30decab52747da2811db83a4b0b8464aa31e02f2eebbf1dae03
DATA (072ec44973a8dee8e28d230fb4af8fe4):  0000072ec44973a8dee8e28d230fb4af8fe400b2191b23b7506a3325fe288d75a7ab06700f92c710c16a7f55769afb014d753b8cf3187730116905843fb0de9dcec976b121a6425b995f80442819ebe883dab5aa72fb8a9d96849969b073b8e76e4463dc8c0eceba936665c4b62af1c31de32ba3433b6d5bf9ceaf4e08355126af0ef6dd111bdeeefa49434c69aba42160ec3e3698c2a88d96ef940b636dff89f2dbde337ae0fc7cd802de72793458dc3a1966fb0ed28e513dfc77138d53f87875a97a22e11e58191d5ae863de24ff68a3e961
PROOF (d7c0e833f0cbde9f9133cd9e7d508b1a):  0300d7c0e833f0cbde9f9133cd9e7d508b1a00cd00ce237471609d6ef64e427151fed46d9eb71fe6337f6fc530a9f3a55c730f1fd09f82f7d12d1caadbc185b7703f0d9f5db6c792c2dfcdf1eed3111088860c
"""

packets = []
for line in _traffic.strip().split('\n'):
    info, data = line.split(':  ')
    packets.append(bytes.fromhex(data))

# this ANNOUNCE was failing before (from rnsd)
packets.append(bytes.fromhex('01007d62e355cc90ec4e79569d33a8ad6c6b00b05e9bd83282a538be44ec872286cec32de7a8335e29c72fe8e8463ca135565b3a5580d45637aeaf037fe5f608b702a3ca85efcf231c68fbfd852706ac320695e03a09b77ac21b22258e299132c47b0068f2b1de03faecd1a563d18584e2f2b4a4434bd3e9a3fb943fa035cc2205b6f779de118908b7cad82cd4830d3a70ba7c8749af77dafbb6feb4023f988cae05b7ae83210894c2ce68f2b1decb4070000000000000c0'))


# no-side-effects load Packet in RNS
def RNS_packet_unpack(raw):
    """Load a packet from raw bytes without side effects"""
    packet = RNS.Packet.__new__(RNS.Packet)
    packet.raw = raw
    RNS.Packet.unpack(packet)
    packet.rssi = None
    packet.snr = None
    packet.receiving_interface = None
    return packet

# I have to dig into RNS structures more, but this will create same basic shape
# this should be very similar to rns.announce_unpack()
def RNS_get_announce(packet):
    keysize = 64
    ratchetsize = 32
    name_hash_len = 10
    sig_len = 64
    destination_hash = packet.destination_hash
    public_key = packet.data[:keysize]
    if packet.context_flag == 1:
        name_hash   = packet.data[keysize:keysize+name_hash_len ]
        random_hash = packet.data[keysize+name_hash_len:keysize+name_hash_len+10]
        ratchet     = packet.data[keysize+name_hash_len+10:keysize+name_hash_len+10+ratchetsize]
        signature   = packet.data[keysize+name_hash_len+10+ratchetsize:keysize+name_hash_len+10+ratchetsize+sig_len]
        app_data    = b""
        if len(packet.data) > keysize+name_hash_len+10+sig_len+ratchetsize:
            app_data = packet.data[keysize+name_hash_len+10+sig_len+ratchetsize:]
    else:
        ratchet     = b""
        name_hash   = packet.data[keysize:keysize+name_hash_len]
        random_hash = packet.data[keysize+name_hash_len:keysize+name_hash_len+10]
        signature   = packet.data[keysize+name_hash_len+10:keysize+name_hash_len+10+sig_len]
        app_data    = b""
        if len(packet.data) > keysize+name_hash_len+10+sig_len:
            app_data = packet.data[keysize+name_hash_len+10+sig_len:]

    signed_data = destination_hash+public_key+name_hash+random_hash+ratchet+app_data

    if not len(packet.data) > 64 + 10 + 10 + 64:
        app_data = None

    announced_identity = RNS.Identity(create_keys=False)
    announced_identity.load_public_key(public_key)

    enc_pub_bytes     = public_key[:32]
    sig_pub_bytes     = public_key[32:]
    enc_pub_key       = announced_identity.pub
    sig_pub_key       = announced_identity.sig_pub

    announce = {
        'app_data': app_data,
        'name_hash': name_hash,
        'public_key': public_key,
        'random_hash': random_hash,
        'ratchet': ratchet,
        'signature': signature,
        'signed_data': signed_data,
        'enc_pub_bytes': enc_pub_bytes,
        'sig_pub_bytes': sig_pub_bytes,
        'enc_pub_key': enc_pub_key,
        'sig_pub_key': sig_pub_key,
        'valid': False
    }

    try:
        # verify is throw-based and always retuns None
        sig_pub_key.verify(signature, signed_data)
        announce['valid'] = True
    except Exception as e:
        pass


    return announce

rns_messages = {}

def test_rns_packets(p):
    packet = rns.packet_unpack(p)
    

    print("rns")
    print(f"  context: {packet['context']}")
    print(f"  context_flag: {packet['context_flag']}")
    # print(f"  data: {packet['data'].hex()}")
    print(f"  destination_hash: {packet['destination_hash'].hex()}")
    print(f"  destination_type: {packet['destination_type']}")
    print(f"  flags: {packet['flags']}")
    print(f"  header_type: {packet['header_type']}")
    print(f"  hops: {packet['hops']}")
    print(f"  packet_hash: {packet['packet_hash'].hex()}")
    print(f"  packet_type: {packet['packet_type']}")
    print(f"  transport_id: {packet['transport_id']}")
    print(f"  transport_type: {packet['transport_type']}")

    if packet['packet_type'] == rns.PACKET_ANNOUNCE:
        print(f"\n  ANNOUNCE")
        announce = rns.announce_unpack(packet)
        print(f"    app_data: {announce['app_data'].hex()}")
        print(f"    name_hash: {announce['name_hash'].hex()}")
        print(f"    random_hash: {announce['random_hash'].hex()}")
        print(f"    ratchet: {announce['ratchet'].hex()}")
        print(f"    signature: {announce['signature'].hex()}")
        # print(f"    signed_data: {announce['signed_data'].hex()}")
        print(f"    valid: {announce['valid']}")

    if packet['packet_type'] == rns.PACKET_DATA:
        print(f"\n  DATA")
        # store the receiver of the message for PROOF
        rns_messages[ packet['packet_hash'] ] = packet['destination_hash']

        # decrypt
        identity = rns.get_identity_from_bytes(keys[packet['destination_hash']])
        decryptedBytes = rns.message_decrypt(packet, identity, ratchets)
        if decryptedBytes:
            ts, title, content, fields = umsgpack.unpackb(decryptedBytes[80:])
            print(f"    Time: {ts}")
            print(f"    Title: {title}")
            print(f"    Content: {content}")
        else:
            print("    Decryption: Failed")

    if packet['packet_type'] == rns.PACKET_PROOF:
        print(f"\n  PROOF")
        # figure out the right identity of receiver for this packet
        # normally each client would already have  it's own pubkey
        # so you could use destination-id to look up full-message-id
        for full_packet_hash in rns_messages:
            if full_packet_hash.startswith(packet['destination_hash']):
                print(f"    Full Hash: {full_packet_hash.hex()}")
                print(f"    Recipient: {rns_messages[full_packet_hash].hex()}")
                recipient = rns.get_identity_from_bytes(keys[ rns_messages[full_packet_hash] ])
                print(f"    Valid: {rns.proof_validate(packet, recipient['public']['sign'], full_packet_hash)}")
                break
    print("")


def test_RNS_packets(p):
    packet = RNS_packet_unpack(p)
    print("RNS")
    print(f"  context: {packet.context}")
    print(f"  context_flag: {packet.context_flag}")
    # print(f"  data: {packet.data.hex()}")
    print(f"  destination_hash: {packet.destination_hash.hex()}")
    print(f"  destination_type: {packet.destination_type}")
    print(f"  flags: {packet.flags}")
    print(f"  header_type: {packet.header_type}")
    print(f"  hops: {packet.hops}")
    print(f"  packet_hash: {packet.packet_hash.hex()}")
    print(f"  packet_type: {packet.packet_type}")
    print(f"  transport_id: {packet.transport_id}")
    print(f"  transport_type: {packet.transport_type}")

    if packet.packet_type == rns.PACKET_ANNOUNCE:
        print(f"\n  ANNOUNCE")
        announce = RNS_get_announce(packet)
        print(f"    app_data: {announce['app_data'].hex()}")
        print(f"    name_hash: {announce['name_hash'].hex()}")
        print(f"    random_hash: {announce['random_hash'].hex()}")
        print(f"    ratchet: {announce['ratchet'].hex()}")
        print(f"    signature: {announce['signature'].hex()}")
        # print(f"    signed_data: {announce['signed_data'].hex()}")
        print(f"    valid: {announce['valid']}")

    if packet.packet_type == rns.PACKET_DATA:
        print(f"\n  DATA")
        # store the receiver of the message for PROOF
        rns_messages[ packet.packet_hash ] = packet.destination_hash

        # decrypt
        identity = RNS.Identity.from_bytes(keys[packet.destination_hash])
        decryptedBytes = identity.decrypt(packet.data, ratchets=ratchets)
        if decryptedBytes:
            ts, title, content, fields = umsgpack.unpackb(decryptedBytes[80:])
            print(f"    Time: {ts}")
            print(f"    Title: {title}")
            print(f"    Content: {content}")
        else:
            print("    Decryption: Failed")

    if packet.packet_type == rns.PACKET_PROOF:
        print(f"\n  PROOF")
        # figure out the right identity of receiver for this packet
        # normally each client would already have  it's own pubkey
        # so you could use destination-id to look up full-message-id (to see if it's one you sent)
        for full_packet_hash in rns_messages:
            if full_packet_hash.startswith(packet.destination_hash):
                print(f"    Full Hash: {full_packet_hash.hex()}")
                print(f"    Recipient: {rns_messages[full_packet_hash].hex()}")
                recipient = RNS.Identity.from_bytes(keys[rns_messages[full_packet_hash]])
                print(f"    Valid: {recipient.validate(packet.data, full_packet_hash)}")
                break
    print("")



for p in packets:
    test_rns_packets(p)
    test_RNS_packets(p)