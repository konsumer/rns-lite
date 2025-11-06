import asyncio
import websockets
from rns import *

WS_URL = "wss://signal.konsumer.workers.dev/ws/reticulum"

# State storage
sent_messages = {}
announces = {}

me_priv = private_identity()
me_pub = public_identity(me_priv)
me_dest = get_destination_hash(me_pub)
ratchet_priv = private_ratchet()
ratchet_pub = public_ratchet(ratchet_priv)

async def announce_myself(ws, me_priv, me_pub, ratchet_pub):
    print(f"ANNOUNCE me {bytes_to_hex(me_dest)}")
    pkt = build_announce(me_priv, me_pub, ratchet_pub)
    await ws.send(pkt)

async def main():
    async with websockets.connect(WS_URL) as ws:
        print(f"Connecting to {WS_URL}")
        # Announce every 30 seconds
        async def announce_loop():
            while True:
                await announce_myself(ws, me_priv, me_pub, ratchet_pub)
                await asyncio.sleep(30)
        asyncio.create_task(announce_loop())

        async for msg in ws:
            try:
                packet = parse_packet(msg)
                ptype = packet["packetType"]
                ptypes = {PACKET_ANNOUNCE: "ANNOUNCE", PACKET_DATA: "DATA", PACKET_PROOF: "PROOF"}
                print(ptypes.get(ptype, ptype), bytes_to_hex(packet["destinationHash"]))
                # Handle packet types
                if ptype == PACKET_ANNOUNCE:
                    announce = parse_announce(packet)
                    print("  Valid:", announce["valid"])
                    if announce["valid"]:
                        them_hex = bytes_to_hex(packet["destinationHash"])
                        announces[them_hex] = {**packet, **announce}
                elif ptype == PACKET_DATA:
                    if equal_bytes(me_dest, packet["destinationHash"]):
                        p = parse_lxmf(packet, me_pub, [ratchet_priv])
                        print("  Message ID", bytes_to_hex(packet["packetHash"]))
                        print("  Sending PROOF")
                        proof_pkt = build_proof(msg, me_priv)
                        await ws.send(proof_pkt)
                        if p:
                            source_hash, title, content = p["sourceHash"], p["title"], p["content"]
                            them_hex = bytes_to_hex(source_hash)
                            print("Parse", {"from": them_hex, "title": title, "content": content})
                            # Echo back if have announce for sender
                            if them_hex in announces:
                                print("  Sending Response")
                                receiver_ratchet_pub = announces[them_hex].get("ratchetPub")
                                receiver_pub_bytes = announces[them_hex].get("publicKey")
                                valid = validate_lxmf(p, packet, receiver_pub_bytes)
                                print("  Valid", valid)
                                echo_msg = build_lxmf(
                                    source_hash,
                                    me_priv,
                                    receiver_pub_bytes,
                                    receiver_ratchet_pub,
                                    int(asyncio.get_event_loop().time() * 1000),
                                    "EchoBot",
                                    content,
                                    {}
                                )
                                await ws.send(echo_msg)
                            else:
                                print("  Have not received announce for", them_hex)
                        else:
                            print("  Parse: No")
                    else:
                        print("Not for me")
                elif ptype == PACKET_PROOF:
                    full_packet_hash = sent_messages.get(bytes_to_hex(packet["destinationHash"]))
                    valid = parse_proof(packet, me_pub, full_packet_hash)
                    print("PROOF valid:", valid)
            except Exception as e:
                print("Error", getattr(e, "message", str(e)))

if __name__ == "__main__":
    asyncio.run(main())
