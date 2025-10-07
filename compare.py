# this will compare offline-handing with official RNS library

import rns
import RNS
import umsgpack

# shared data from real clients: [encrypt_key, sign_key]
keys = {
    '072ec44973a8dee8e28d230fb4af8fe4': bytes.fromhex('205131cb9672eaec8a582e8e018307f2428c4aac5e383f12e94939e672b931677763c7398d0b9cb6ef1369d023d8af10b85d80f6579c55a6f528953265c15313'),
    '76a93cda889a8c0a88451e02d53fd8b9': bytes.fromhex('e8c5c096166f3554868de9133b0c55c7abf0318230860a142ea3f84a0aae7759142f6c0b84d9f537ceb2e8e9678fc9fb77caf91e2176278fb4c4f5c3eb7b48cd')
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

# no-side-effects load Packet in RNS
def load_RNS_packet(raw):
    """Load a packet from raw bytes without side effects"""
    packet = RNS.Packet.__new__(RNS.Packet)
    packet.raw = raw
    RNS.Packet.unpack(packet)
    packet.rssi = None
    packet.snr = None
    packet.receiving_interface = None
    return packet
    


def test_RNS():
    print("RNS")
    
    # verify I get correct destination addresses
    clientA = RNS.Identity.from_bytes(keys['072ec44973a8dee8e28d230fb4af8fe4'])
    clientA_addr = RNS.Destination.hash(clientA, "lxmf", "delivery")
    print(f"  Client A: {clientA_addr.hex()}")
    clientB = RNS.Identity.from_bytes(keys['76a93cda889a8c0a88451e02d53fd8b9'])
    clientB_addr = RNS.Destination.hash(clientB, "lxmf", "delivery")
    print(f"  Client B: {clientB_addr.hex()}")

    # put the addresses in easier-to-use shape
    recipients = { clientA_addr: clientA, clientB_addr: clientB }

    # track DATA packets that have been sent
    sent_packets = {} 

    for packetBytes in packets:
        print("")
        packet = load_RNS_packet(packetBytes)
        
        # validate ANNOUNCE
        if packet.packet_type == RNS.Packet.ANNOUNCE:
            print(f"  ANNOUNCE to {packet.destination_hash.hex()}")
            if RNS.Identity.validate_announce(packet, True):
                print(f"    Valid: Yes")
            else:
                print(f"    Valid: No")

        # decrypt DATA
        if packet.packet_type == RNS.Packet.DATA:
            print(f"  DATA to {packet.destination_hash.hex()}")

            packet_hash_full = packet.get_hash()  # 32-byte for validation
            packet_hash_truncated = packet_hash_full[:16]  # 16-byte for lookup
            sent_packets[packet_hash_truncated] = (packet.destination_hash, packet_hash_full)
            print(f"    MessageId: {packet_hash_truncated.hex()}")

            identity = recipients[packet.destination_hash]
            decryptedBytes = identity.decrypt(packet.data, ratchets=ratchets)
            ts, title, content, fields = umsgpack.unpackb(decryptedBytes[80:])
            print(f"    Time: {ts}")
            print(f"    Title: {title}")
            print(f"    Content: {content}")
           

        # validate PROOF
        if packet.packet_type == RNS.Packet.PROOF:
            print(f"  PROOF for {packet.destination_hash.hex()}")
            if packet.destination_hash in sent_packets:
                recipient_hash, full_packet_hash = sent_packets[packet.destination_hash]
                identity = recipients[recipient_hash]
                if identity.validate(packet.data, full_packet_hash):
                    print('    Valid: Yes')
                else:
                    print('    Valid: No')
            else:
                print(f"    No Message: {packet.destination_hash.hex()}")

def test_rns():
    print("rns")

    # verify I get correct destination addresses
    clientA = rns.get_identity_from_bytes(keys['072ec44973a8dee8e28d230fb4af8fe4'])
    clientA_addr = rns.get_destination_hash(clientA, "lxmf", "delivery")
    print(f"  Client A: {clientA_addr.hex()}")
    clientB = rns.get_identity_from_bytes(keys['76a93cda889a8c0a88451e02d53fd8b9'])
    clientB_addr = rns.get_destination_hash(clientB, "lxmf", "delivery")
    print(f"  Client B: {clientB_addr.hex()}")

    # put the addresses in easier-to-use shape
    recipients = { clientA_addr: clientA, clientB_addr: clientB }

    # track DATA packets that have been sent
    sent_packets = {} 

    for packetBytes in packets:
        print("")
        packet = rns.decode_packet(packetBytes)
        
        # validate ANNOUNCE
        if packet['packet_type'] == rns.PACKET_ANNOUNCE:
            print(f"  ANNOUNCE to {packet['destination_hash'].hex()}")
            announce = rns.announce_parse(packet)
            ratchet = announce.get('ratchet_pub', None)
            if ratchet:
                print(f'    Ratchet: {ratchet.hex()}')
            if announce['valid']:
                print("    Valid: Yes")
            else:
                print("    Valid: No")


        # decrypt DATA
        if packet['packet_type'] == rns.PACKET_DATA:
            print(f"  DATA to {packet['destination_hash'].hex()}")

            packet_hash_full = rns.get_message_id(packet)  # 32-byte for validation
            packet_hash_truncated = packet_hash_full[:16]  # 16-byte for lookup
            sent_packets[packet_hash_truncated] = (packet['destination_hash'], packet_hash_full)
            print(f"    MessageId: {packet_hash_truncated.hex()}")

            decryptedBytes = rns.message_decrypt(recipients[packet['destination_hash']], packet, ratchets)
            ts, title, content, fields = umsgpack.unpackb(decryptedBytes[80:])
            print(f"    Time: {ts}")
            print(f"    Title: {title}")
            print(f"    Content: {content}")

        # validate PROOF
        if packet['packet_type'] == rns.PACKET_PROOF:
            print(f"  PROOF for {packet['destination_hash'].hex()}")
            if packet['destination_hash'] in sent_packets:
                recipient_hash, full_packet_hash = sent_packets[packet['destination_hash']]
                identity = recipients[recipient_hash]
                if rns.proof_validate(packet, identity, full_packet_hash):
                    print('    Valid: Yes')
                else:
                    print('    Valid: No')
            else:
                print(f"    No Message: {packet['destination_hash'].hex()}")

test_RNS()
test_rns()
