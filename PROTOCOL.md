# Simple Chat protocol, version 2

Both apps (desktop `simplechat/`, Android `android/`) implement this. Version 1
(one chat at a time) is not compatible: its handshake magic differs, so a v1
peer is rejected with "uses another version".

## Model

There is no server. Every running app:

- **listens** on TCP (default port 5000) all the time;
- keeps **one link** (an authenticated TCP connection) to each contact that is
  online, so *online* means "we currently have a link to them";
- **announces** itself on the local network over UDP, and listens for others'
  announcements, so contacts are found even when their IP address changes;
- **queues** messages for offline contacts and delivers them when a link comes up.

## LAN announcements (UDP, port 50505)

Every 5 seconds (and at start-up) each app broadcasts one datagram:

    "SCHAT-ANNOUNCE v2\n" + JSON {"pk": "<identity public key, hex>", "port": <TCP port>, "nick": "<nickname>"}

to `255.255.255.255` and to the `/24` broadcast address of its LAN IP.
Announcements are **unauthenticated hints**: anyone can claim any key. That's
harmless, because the address is only used to open a link, and the handshake
proves who is really there. An app ignores its own announcements.

## Link set-up (TCP)

1. **Handshake**: exactly as in v1 (X25519 + Ed25519-signed transcript + HKDF;
   see `simplechat/handshake.py`), with magic `SCHATv2\0`.
2. If the initiator dialled a *known contact*, it checks the peer's identity
   key right away. If it's a different key, the initiator closes the link
   without saying anything. The address now belongs to someone else, or to an
   impostor. Only when the user typed the address themselves is a "key changed"
   warning shown.
3. Both send **NICK** (UTF-8 nickname).
4. **Trust**: an unknown key needs the user to compare fingerprints
   (first contact, or a contact request on the receiving side). A side that
   refuses closes the connection.
5. Both send **READY** with body JSON `{"port": <own listening TCP port>}`, so
   each side learns where to reach the other later.

## Messages on a link

Plaintext of every encrypted frame: `1 byte type | body` (see `channel.py`).

| Type | Name | Body |
|---|---|---|
| 2 | NICK | UTF-8 nickname (also sent later, when it changes) |
| 3 | READY | JSON `{"port"}` |
| 4 | BYE | empty: the app is quitting or removing the contact |
| 5 | PING | empty: sent after 20 s without traffic |
| 6 | PONG | empty: the reply to PING |
| 10–15 | FILE_* | file transfer, unchanged from v1 (online only) |
| 20 | TEXT | JSON `{"id": "<32 hex chars>", "sent": "<ISO time>", "text": "..."}` |
| 21 | ACK | JSON `{"id"}`: "TEXT stored", sent for every TEXT, duplicates included |

- A link with no incoming traffic for 60 s is considered dead and closed.
- **Queued delivery**: a TEXT stays *pending* until its ACK arrives. On every
  new link, all pending TEXTs to that contact are re-sent in order. The
  receiver drops TEXTs whose id it has already stored, but still ACKs them.
- **Duplicate links**: if both sides dial each other at the same moment, two
  links come up. Each side keeps the link whose *initiator* has the smaller
  identity public key (byte-wise) and silently closes the other. Both sides
  apply the same rule, so they agree. To make this rare, when an announcement
  arrives the side with the smaller key dials immediately and the other waits
  3 seconds.
- Dialling an offline contact's last known address is retried every 10 s,
  backing off to 60 s.

## Stored data

- `known_peers.json`: contacts: public key, nickname, known addresses
  (`host:port`), and the last address seen.
- `history/<key>.log`: encrypted, append-only records (format in
  `history.py`). Each record is JSON:
  - `{"k": "msg", "id", "t", "dir": "in"|"out", "who", "text"}`
  - `{"k": "ack", "id"}`: the outgoing message `id` was delivered.

  An outgoing message without an ack record is pending.
