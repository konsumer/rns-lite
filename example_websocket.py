# this is a simple example meant for regular cpython, that uses a websocket

import asyncio
from websockets.asyncio.client import connect
from websockets.exceptions import ConnectionClosed
import rns

uri = "wss://signal.konsumer.workers.dev/ws/reticulum"

me = rns.identity_create()
me_dest = rns.get_destination_hash(me, "lxmf", "delivery")
ratchet = rns.ratchet_create_new()
ratchet_pub = rns.ratchet_get_public(ratchet)

async def periodic_announce(websocket, interval=30):
    """Send announce every interval seconds"""
    while True:
        try:
            print(f"Announcing myself: {me_dest.hex()}")
            announceBytes = rns.build_announce(me, me_dest, 'lxmf.delivery', ratchet_pub)
            await websocket.send(announceBytes)
            await asyncio.sleep(interval)
        except ConnectionClosed:
            break

async def handle_incoming(websocket):
    async for message in websocket:
        packet = rns.decode_packet(message)
        if packet['packet_type'] == rns.PACKET_ANNOUNCE:
            print(f"ANNOUNCE from {packet['destination_hash'].hex()}")
        elif packet['packet_type'] == rns.PACKET_PROOF:
            print(f"PROOF for message {packet['destination_hash'].hex()}")
        elif packet['packet_type'] == rns.PACKET_DATA:
            message_id = rns.get_message_id(packet)
            print(f"DATA ({message_id.hex()}) for {packet['destination_hash'].hex()}")
            
            # it was for me?
            if packet['destination_hash'] == me_dest:
                # tell them I got it
                print(f"sending PROOF ({message_id.hex()})")
                await websocket.send(rns.build_proof(me, packet, message_id))




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