# simplechat

End-to-end encrypted terminal chat between two computers, with file transfer
and encrypted history.

## Build the executable

```sh
sudo pacman -S uv   # once; build.sh needs uv
./build.sh          # downloads a generic Python, installs deps, runs PyInstaller
```

The build deliberately avoids CachyOS's own Python and libraries. Those are
compiled for x86-64-v4 (AVX-512), and a binary built from them dies with
"Illegal instruction" on older CPUs. See the comments in `build.sh` and
`simplechat.spec`.

This produces **`dist/simplechat`**, a single 16 MB file that runs without
Python. Copy it to the other computer.

The binary only runs on the same kind of system it was built on (Linux x86-64
here). It is also tied to this machine's glibc version, so it may not start on
much older distros. For Windows or macOS, run the build on that OS. On Windows,
use the equivalent `pyinstaller --onefile --name simplechat chat.py` command.

## Use

Simple Chat works like a direct-message app, with no server. Your contacts sit
in a sidebar: green ● while you're connected to them, grey ○ when they're
offline. Messages to offline contacts are queued (⏳) and delivered
automatically (✓) when you're both online. Everything is end-to-end
encrypted. The full protocol is described in [PROTOCOL.md](PROTOCOL.md).

```sh
./simplechat                        # the app; reachable on port 5000 while it runs
./simplechat --port 5001            # another port (e.g. a second instance)
./simplechat connect 192.168.1.58   # start, and add a contact by address
```

**Adding someone:**
- People on your Wi-Fi who run Simple Chat appear under **NEARBY**. Pick
  one to add them.
- Or press **Ctrl+A** and type their address.
- Either way, both sides see a fingerprint dialog. **Compare the
  fingerprints by phone or in person** before pressing `y`.
- When someone adds you, you get a *contact request* with the same dialog.

**Staying in touch:** while the app runs, it announces itself on the LAN,
listens for others, and keeps reconnecting to contacts that are offline. A
contact whose IP address changed is found again through the announcements.
Your firewall must allow incoming TCP on your port (`sudo ufw allow 5000/tcp`),
and UDP 50505 for discovery (`sudo ufw allow 50505/udp`).

| Keys | |
|---|---|
| `↑` `↓` `Enter` | pick a contact (or a nearby person, to add them) |
| `Tab` | switch between the contact list and the message box |
| `Enter` | send (queued if the contact is offline) |
| `Ctrl+A` | add a contact by address |
| `Ctrl+O` or `/send <path>` | send a file (online contacts; files go to `./received/`) |
| `Ctrl+N` | change your nickname |
| `Ctrl+D` | remove the selected contact |
| `F1` / `Ctrl+Q` | help / quit (contacts see you go offline) |

Plain commands (no UI): `simplechat fingerprint`, `simplechat peers`,
`simplechat forget <fingerprint-or-name>`.

Data lives in `~/.simplechat/` (override with `--home` or `$SIMPLECHAT_HOME`).

### Code layout

| File | Role |
|---|---|
| `identity.py`, `handshake.py`, `channel.py`, `framing.py` | the cryptography |
| `trust.py`, `history.py`, `conversation.py` | contacts; encrypted message history with queued/delivered state |
| `link.py` | one authenticated connection to one contact (keepalive, acks, files) |
| `discovery.py` | LAN announcements over UDP broadcast |
| `messenger.py` | everything together: listening, dialling, presence, queues (no UI code) |
| `tui.py`, `cli.py` | the Textual interface; command-line arguments |

## Android app

`android/` is a Kotlin/Jetpack Compose app with the same model and protocol:
a contact list with presence, Nearby, contact requests, queued messages, files
and encrypted history. A foreground service keeps you online in the
background (the "Simple Chat is online" notification, with a **Go offline**
button), and incoming messages show up as notifications.

```sh
cd android && ./gradlew installDebug    # or open android/ in Android Studio and press Run
```

- On first launch it asks for **Nearby devices** (Android 17+: needed to reach
  the local network) and **notifications**.
- The phone has no password. Its identity key is sealed by the Android
  Keystore (`data/IdentityStore.kt`).
- `core/` is a line-for-line port of the Python messenger, with no Android code.

## How the crypto works

| Step | Primitive | File |
|---|---|---|
| Identity key (long-term) | Ed25519, encrypted at rest with scrypt + ChaCha20-Poly1305 | `identity.py` |
| Key exchange (per session, forward secret) | X25519, transcript signed with Ed25519 | `handshake.py` |
| Session keys (one per direction) | HKDF-SHA256 | `handshake.py` |
| Messages and files | ChaCha20-Poly1305 with counter nonces (stops tampering, replay and reordering) | `channel.py` |
| Peer verification | Trust-on-first-use fingerprints, like SSH `known_hosts` | `trust.py` |
| History | ChaCha20-Poly1305 per record, key derived from identity | `history.py` |

Each file starts with a comment explaining its part in detail.

## Limits

- Nothing hides *that* two IPs are talking, or how much data they exchange.
- LAN announcements tell everyone on your network that you're running Simple
  Chat, along with your nickname and public key (not your messages).
- Queued messages are only delivered when both of you are online at the same
  time; there's no server to hold them.
- Trust is only as good as your fingerprint check on first contact.
- This is a learning project. It hasn't had a professional security audit.

## Tests

```sh
.venv/bin/pip install pytest pexpect pyte
.venv/bin/python -m pytest                  # crypto, messenger, TUI (Textual pilot), dist/simplechat binary
cd android && ./gradlew testDebugUnitTest   # Kotlin protocol + Kotlin messenger vs the Python messenger
.venv/bin/python tests/android_e2e.py       # the APK in a running emulator vs dist/simplechat
```

The emulator test only ever uses an emulator, never a connected phone, because
it wipes the app's data.
