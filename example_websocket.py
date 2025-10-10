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

async def announce(websocket):
    print(f"announcing myself: {me_dest.hex()}")
    announceBytes = rns.build_announce(me, me_dest, 'lxmf.delivery', ratchet_pub)
    await websocket.send(announceBytes)


async def main():
    print(f"connecting to {uri}")
    async for websocket in connect(uri):
        try:
            await announce(websocket)
            await websocket.close()
            await asyncio.sleep(30)
        except ConnectionClosed:
            continue

if __name__ == "__main__":
    asyncio.run(main())