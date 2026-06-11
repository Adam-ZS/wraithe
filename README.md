# ⚡ WRAITHE — WiFi Pwn Toolkit

> *haunt the spectrum — break the keys*

Wraithe is a modern WiFi penetration testing toolkit built as a cleaner, faster replacement for airgeddon. Focused on WPS attacks, PMKID capture, handshake cracking, and global sweep operations — all from one terminal.

```
╔═══════════════════════════════════════════════════════════════════╗
║                                                                   ║
║    __          _______            _____ _______ _    _ ______     ║
║    \ \        / /  __ \     /\   |_   _|__   __| |  | |  ____|    ║
║     \ \  /\  / /| |__) |   /  \    | |    | |  | |__| | |__       ║
║      \ \/  \/ / |  _  /   / /\ \   | |    | |  |  __  |  __|      ║
║       \  /\  /  | | \ \  / ____ \ _| |_   | |  | |  | | |____     ║
║        \/  \/   |_|  \_\/_/    \_\_____|  |_|  |_|  |_|______|    ║
║                                                                   ║
║                         WIFI PWN TOOLKIT                          ║
║                            by Adam-ZS                             ║
║                                                                   ║
╚═══════════════════════════════════════════════════════════════════╝
```

---

## Features

| Key | Action |
|-----|--------|
| `S` | Scan networks — list all visible APs with signal, channel, encryption |
| `I` | Interface management — set monitor mode, channel hopping |
| `M` | Spoof MAC address |
| `L` | View event log |
| **WPS Attacks** | |
| `W` | WPS menu — attack type recommendations per target |
| `P` | PixieDust attack (reaver) |
| `B` | Bully attack (PixieDust) |
| `O` | OneShot attack (pixiewps) |
| `F` | PIN brute force |
| **Packet Capture** | |
| `H` | Capture WPA handshake |
| `K` | Capture PMKID |
| `D` | Deauth attack (broadcast) |
| `C` | Client deauth (targeted) |
| **Advanced** | |
| `E` | Evil Twin — captive portal credential harvesting |
| `X` | **AutoHack** — 9-step chain: tries WPS Pixie → Bully → OneShot, falls back to PMKID/handshake capture + auto-crack |
| `Y` | **Global WPS Spray** — tries PixieDust mode 1+2 + Bully on ALL visible targets |
| `Z` | **Global Hash Sweep** — bulk PMKID/handshake capture + crack with top 10 passwords |
| `A` | Auto-crack captured handshake |
| `0` / `Ctrl+C` | Exit |

### Quick-Select

Type a target number + command to run instantly:
```
❯ 1 P        # Select target 1, run PixieDust
❯ 3 H        # Select target 3, capture handshake
❯ X          # AutoHack the selected target
```

---

## Requirements

- **Kali Linux** (or any Debian-based with wireless tools)
- **Root access** — Wraithe must run as root for monitor mode
- **Wireless adapter** that supports monitor mode + packet injection

### Packages

```bash
# Core tools (most pre-installed on Kali)
sudo apt install -y aircrack-ng reaver bully hcxdumptool hcxpcapngtool hashcat pixiewps

# Python dependency
sudo pip install pyfiglet --break-system-packages
```

---

## Installation

```bash
git clone https://github.com/Adam-ZS/wraithe.git
cd wraithe
sudo python3 wraithe.py
```

Or just download `wraithe.py` and run it:

```bash
sudo python3 wraithe.py
```

---

## Quick Start

1. **Run it**
   ```bash
   sudo python3 wraithe.py
   ```

2. **Set up monitor mode** — press `I`, select your interface

3. **Scan** — press `S` to find targets

4. **Select a target** — type the number next to it

5. **AutoHack** — press `X` and let it work through WPS → PMKID → handshake

6. **Global spray** — press `Y` to try WPS on every network, or `Z` for bulk hash capture

---

## Tool Structure

```
/opt/wraithe/
├── wraithe.py              # Main entry point + UI
├── modules/
│   ├── crack.py            # Password cracking engine (hashcat wrapper)
│   ├── wps.py              # WPS attack engine (Pixie, PIN, lock check)
│   ├── other.py            # Handshake capture, deauth, PMKID
│   └── evil_twin.py        # Evil Twin captive portal
└── lib/
    ├── interface.py        # Wireless interface management
    └── scanner.py           # Network scanning (airodump-ng wrapper)
```

---

## License

MIT — do what you want. Credit Adam-ZS if you're feeling nice.

---

*For educational purposes and authorized testing only.*
