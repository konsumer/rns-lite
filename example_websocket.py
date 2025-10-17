# this is a simple example meant for regular cpython, that uses a websocket

import asyncio
from websockets.asyncio.client import connect
from websockets.exceptions import ConnectionClosed
import rns

uri = "wss://signal.konsumer.workers.dev/ws/reticulum"

me = rns.identity_create()
me_dest = rns.get_destination_hash(me, "lxmf", "delivery")

# this is my ratchet
# normally this would be re-generated periodically (and ANNOUNCEd)
ratchet = rns.ratchet_create_new()
ratchet_pub = rns.ratchet_get_public(ratchet)

# I track annnounces, so I can send a message using their ratchet-pub (in their own ANNOUNCE)
announces = {}

# called periodically to ANNOUNCE myself
async def periodic_announce(websocket, interval=30):
    while True:
        try:
            print(f"Announcing myself: {me_dest.hex()}")
            announceBytes = rns.build_announce(me, me_dest, 'lxmf.delivery', ratchet_pub)
            await websocket.send(announceBytes)
            await asyncio.sleep(interval)
        except ConnectionClosed:
            break


async def handle_announce(packet):
    print(f"ANNOUNCE from {packet['destination_hash'].hex()}")
    announce = rns.announce_parse(packet)
    if announce['valid']:
        dest = packet['destination_hash']
        announces[packet['destination_hash']] = announce
        announces[packet['destination_hash']]['destination_hash'] = packet['destination_hash']
         print("  Valid: Yes")
        print(f"  Saved ({len(announces)}) announce from {packet['destination_hash'].hex()}")
    else:
        print("  Valid: No")


async def handle_proof(packet):
    print(f"PROOF for message {packet['destination_hash'].hex()}")
    ## TODO: check proof?

async def handle_data(packet, websocket):
    message_id = rns.get_message_id(packet)
    print(f"DATA ({message_id.hex()}) for {packet['destination_hash'].hex()}")
    
    # it was for me?
    if packet['destination_hash'] == me_dest:
        # tell them I got it
        print(f"sending PROOF ({message_id.hex()})")
        await websocket.send(rns.build_proof(me, packet, message_id))

        # Decrypt the message
        plaintext = rns.message_decrypt(packet, me, [ratchet])
        if plaintext:
            message = rns.parse_lxmf_message(plaintext)
            content_text = message['content'].decode('utf-8')
            print(f"  From: {message['source_hash'].hex()}")
            print(f"  Title: {message['title'].decode('utf-8')}")
            print(f"  Content: {content_text}")

            # Send reply to sender
            if message['source_hash'] in announces:
                reply = {
                    'title': 'EchoBot',
                    'content': content_text
                } 
                await websocket.send(rns.build_lxmf_message(me, me_dest, ratchet, announces[ message['source_hash'] ], reply))
            else:
                print(f"  Cannot reply - no announce for {message['source_hash'].hex()}")


        else:
            print("  Could not decrypt")


async def handle_incoming(websocket):
    async for message in websocket:
        try:
            packet = rns.decode_packet(message)

            if packet['packet_type'] == rns.PACKET_ANNOUNCE:
                await handle_announce(packet)

            elif packet['packet_type'] == rns.PACKET_PROOF:
                await handle_proof(packet)

            elif packet['packet_type'] == rns.PACKET_DATA:
                await handle_data(packet, websocket)

        except Exception as e:
            print(f"Error handling packet: {e}")
            import traceback
            traceback.print_exc()



async def main():
    print(f"connecting to {uri}")
    async for websocket in connect(uri):
        try:
            # start 2 threads: announce and handle messages
            announce_task = asyncio.create_task(periodic_announce(websocket, interval=30))
            incoming_task = asyncio.create_task(handle_incoming(websocket))
            done, pending = await asyncio.wait(
                [announce_task, incoming_task],
                return_when=asyncio.FIRST_COMPLETED
            )
            # Cancel any remaining tasks
            for task in pending:
                task.cancel()

        except ConnectionClosed:
            continue

if __name__ == "__main__":
    asyncio.run(main())