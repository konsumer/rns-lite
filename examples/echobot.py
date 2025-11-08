import sys
import os
import asyncio
from websockets.asyncio.client import connect

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from rns_lite import *

WS_URL="wss://signal.konsumer.workers.dev/ws/reticulum"

# periodically ANNOUNCE
async def announce_handler(ws, me_priv, me_pub, me_dest, ratchet_priv, ratchet_pub, interval=30):
  while True:
    print(f"ANNOUNCE me {me_dest.hex()}")
    pkt = build_announce(me_priv, ratchet_priv=ratchet_priv, ratchet_pub=ratchet_pub, destination_hash=me_dest)
    await ws.send(pkt)
    await asyncio.sleep(interval)

# handle incoming packets
async def packet_handler(ws, me_priv, me_pub, me_dest, ratchet_priv, ratchet_pub):
  packet_names = {
    PACKET_DATA: 'DATA',
    PACKET_ANNOUNCE: 'ANNOUNCE', 
    PACKET_LINKREQUEST: 'LINKREQUEST',
    PACKET_PROOF: 'PROOF'
  }

  # this will store ANNOUNCE packets, for decrypting DATAs
  announces = {}

  # this will store sent-messages for verifying PROOFs
  sent_messages = {}
  
  async for packet_bytes in ws:
    packet = packet_unpack(packet_bytes)
    print(f"{packet_names[packet['packet_type']]} ({packet['destination_hash'].hex()})")
    try:
      if packet['packet_type'] == PACKET_ANNOUNCE:
        announce = validate_announce(packet)
        if not announce:
          raise ValueError("Invalid ANNOUNCE")
        print("  Valid: True")
        announces[packet['destination_hash']] = announce

      if packet['packet_type'] == PACKET_DATA:
        if packet['destination_hash'] == me_dest:
          data = message_decrypt(packet, me_pub, [ratchet_priv])
          if not data:
            raise ValueError("Invalid DATA - cannot decrypt")
          print(f"  For me: True")

          # Parse LXMF message - need sender's announce for public key
          source_hash = data[0:16]
          sender_announce = announces.get(source_hash)

          if not sender_announce:
            print(f"  Sender {source_hash.hex()[:16]}... not in announces")
            continue

          lxmf = lxmf_parse(data, me_dest, sender_announce['public_key'])
          if not lxmf:
            print(f"  Invalid LXMF message")
            continue

          print(f"  From: {lxmf['source_hash'].hex()}")
          print(f"  Content: {lxmf.get('content', b'(no content)')}")

          # Send PROOF back
          proof_bytes = build_proof(packet_bytes, me_priv)
          await ws.send(proof_bytes)
          print(f"  Sent PROOF")

          # Send echo response DATA back to sender
          if sender_announce['ratchet']:
            try:
              # Build LXMF response message
              response_content = lxmf.get('content', b'')
              lxmf_response = lxmf_build(
                response_content,
                me_priv,
                lxmf['source_hash'],
                source_hash=me_dest
              )

              # Encrypt and send
              response_data = build_data(
                lxmf_response,
                sender_announce['public_key'],
                sender_announce['ratchet']
              )
              await ws.send(response_data)

              # Store sent message for PROOF validation
              response_packet = packet_unpack(response_data)
              sent_messages[response_packet['packet_hash'].hex()] = {
                'packet_bytes': response_data,
                'sender_pub': sender_announce['public_key']
              }
              print(f"  Sent DATA echo to {lxmf['source_hash'].hex()[:16]}...")
            except Exception as e:
              print(f"  Failed to echo: {e}")
          else:
            print(f"  Cannot respond - sender has no ratchet")
        else:
          print("  For me: False")

      if packet['packet_type'] == PACKET_PROOF:
        # Validate PROOF against our sent messages
        truncated_msg_id = packet['destination_hash'].hex()

        # Check if this PROOF is for one of our sent messages
        found = False
        msg_to_delete = None
        for msg_hash, msg_info in sent_messages.items():
          if msg_hash.startswith(truncated_msg_id):
            # Validate the proof
            is_valid = validate_proof(packet, msg_info['sender_pub'], bytes.fromhex(msg_hash))
            print(f"  Valid: {is_valid}")
            if is_valid:
              msg_to_delete = msg_hash
            found = True
            break

        if msg_to_delete:
          del sent_messages[msg_to_delete]

        if not found:
          print("  Not for any of our sent messages")

    except Exception as e:
      print(f"  Failed: {e}")


async def main():
  # setup my identity
  me_priv = private_identity()
  me_pub = public_identity(me_priv)
  me_dest = get_identity_destination_hash(me_pub)
  ratchet_priv = private_ratchet()
  ratchet_pub = public_ratchet(ratchet_priv)

  async for websocket in connect(WS_URL):
    print(f"Connected to {WS_URL}")
    announce_task = asyncio.create_task(announce_handler(websocket, me_priv, me_pub, me_dest, ratchet_priv, ratchet_pub))
    incoming_task = asyncio.create_task(packet_handler(websocket, me_priv, me_pub, me_dest, ratchet_priv, ratchet_pub))
    done, pending = await asyncio.wait([announce_task, incoming_task])

if __name__ == "__main__":
    asyncio.run(main())