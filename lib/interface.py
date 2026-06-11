"""
Wraithe - Interface Management Module
Monitor mode, channel hopping, MAC spoofing
"""

import subprocess
import re
import os
import time
import sys

class InterfaceManager:
    def __init__(self, config=None):
        self.config = config or {}
        self.interfaces = []
        self.monitor_interfaces = []
        self.current_interface = None
        self.current_monitor = None

    def get_all_interfaces(self):
        """Detect all wireless interfaces"""
        try:
            result = subprocess.run(
                ['iwconfig'], capture_output=True, text=True, timeout=10
            )
            interfaces = []
            for line in result.stdout.split('\n'):
                if 'IEEE 802.11' in line:
                    iface = line.split()[0]
                    interfaces.append(iface)
            self.interfaces = interfaces
            return interfaces
        except Exception as e:
            return []

    def get_phy_info(self, iface):
        """Get phy index for an interface"""
        try:
            result = subprocess.run(
                ['iw', iface, 'info'], capture_output=True, text=True, timeout=5
            )
            for line in result.stdout.split('\n'):
                if 'wiphy' in line:
                    return line.split()[-1]
        except:
            pass
        return None

    def start_monitor_mode(self, iface=None):
        """Put interface into monitor mode"""
        iface = iface or self.current_interface
        if not iface:
            interfaces = self.get_all_interfaces()
            if not interfaces:
                return None
            iface = interfaces[0]

        phy = self.get_phy_info(iface)
        
        # Kill interfering processes
        subprocess.run(['airmon-ng', 'check', 'kill'], 
                       capture_output=True, text=True, timeout=30)
        
        # Start monitor mode
        result = subprocess.run(
            ['airmon-ng', 'start', iface], 
            capture_output=True, text=True, timeout=15
        )

        # Extract monitor interface name
        mon_iface = None
        for match in re.finditer(r'\(([a-zA-Z0-9]+mon)\)', result.stdout):
            mon_iface = match.group(1)
        
        if not mon_iface:
            # Try common naming
            mon_candidates = [f'{iface}mon', f'{iface}mon0']
            for candidate in mon_candidates:
                r = subprocess.run(['iwconfig'], capture_output=True, text=True, timeout=5)
                if candidate in r.stdout:
                    mon_iface = candidate
                    break
        
        if not mon_iface:
            mon_iface = iface  # fallback
        
        self.current_interface = iface
        self.current_monitor = mon_iface
        return mon_iface

    def stop_monitor_mode(self, mon_iface=None):
        """Stop monitor mode"""
        mon_iface = mon_iface or self.current_monitor
        if mon_iface:
            subprocess.run(['airmon-ng', 'stop', mon_iface],
                          capture_output=True, text=True, timeout=15)
        subprocess.run(['systemctl', 'start', 'NetworkManager'],
                      capture_output=True, text=True, timeout=15)
        self.current_monitor = None

    def set_channel(self, mon_iface, channel):
        """Set interface to specific channel (2.4 or 5GHz)"""
        try:
            # For 5GHz channels, set frequency explicitly
            try:
                ch = int(channel)
                if ch > 14:
                    freq = self._channel_to_freq_5ghz(ch)
                    if freq:
                        return self.set_freq(mon_iface, freq)
            except (ValueError, TypeError):
                pass
            
            subprocess.run(
                ['iw', 'dev', mon_iface, 'set', 'channel', str(channel)],
                capture_output=True, text=True, timeout=5
            )
            return True
        except:
            return False

    @staticmethod
    def _channel_to_freq_5ghz(ch):
        """Convert 5GHz channel number to frequency in MHz"""
        freq_map = {
            32: 5160, 34: 5170, 36: 5180, 38: 5190, 40: 5200, 42: 5210,
            44: 5220, 46: 5230, 48: 5240, 50: 5250, 52: 5260, 54: 5270,
            56: 5280, 58: 5290, 60: 5300, 62: 5310, 64: 5320,
            100: 5500, 102: 5510, 104: 5520, 106: 5530, 108: 5540,
            110: 5550, 112: 5560, 114: 5570, 116: 5580, 118: 5590,
            120: 5600, 122: 5610, 124: 5620, 126: 5630, 128: 5640,
            132: 5660, 134: 5670, 136: 5680, 138: 5690, 140: 5700,
            142: 5710, 144: 5720, 149: 5745, 151: 5755, 153: 5765,
            155: 5775, 157: 5785, 159: 5795, 161: 5805, 163: 5815,
            165: 5825, 167: 5835, 169: 5845, 171: 5855, 173: 5865,
            177: 5885,
        }
        return freq_map.get(ch)

    def set_freq(self, mon_iface, freq):
        """Set frequency (for 5 GHz)"""
        try:
            subprocess.run(
                ['iw', 'dev', mon_iface, 'set', 'freq', str(freq)],
                capture_output=True, text=True, timeout=5
            )
            return True
        except:
            return False

    def hop_channels(self, mon_iface, channels, delay=0.2):
        """Channel hopping in background process"""
        import threading
        
        def _hopper():
            while self._hopping:
                for ch in channels:
                    if not self._hopping:
                        break
                    self.set_channel(mon_iface, ch)
                    time.sleep(delay)
        
        self._hopping = True
        t = threading.Thread(target=_hopper, daemon=True)
        t.start()
        return t

    def stop_hopper(self):
        """Stop channel hopping"""
        self._hopping = False

    def spoof_mac(self, iface, mac=None):
        """Spoof MAC address"""
        if not mac:
            # Generate random MAC
            import random
            mac = "02:%02x:%02x:%02x:%02x:%02x" % (
                random.randint(0, 255),
                random.randint(0, 255),
                random.randint(0, 255),
                random.randint(0, 255),
                random.randint(0, 255),
            )
        
        try:
            subprocess.run(['ifconfig', iface, 'down'], 
                          capture_output=True, text=True, timeout=5)
            subprocess.run(['macchanger', '-m', mac, iface],
                          capture_output=True, text=True, timeout=5)
            subprocess.run(['ifconfig', iface, 'up'],
                          capture_output=True, text=True, timeout=5)
            return mac
        except:
            return None

    def get_channel(self, iface):
        """Get current channel"""
        try:
            result = subprocess.run(
                ['iw', 'dev', iface, 'info'],
                capture_output=True, text=True, timeout=5
            )
            for line in result.stdout.split('\n'):
                if 'channel' in line:
                    parts = line.split()
                    if len(parts) >= 2:
                        return parts[1]
        except:
            pass
        return None

    def cleanup(self):
        """Clean up interfaces"""
        self.stop_hopper()
        if self.current_monitor:
            self.stop_monitor_mode()
