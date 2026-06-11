"""
Wraithe - Scanner Module
Target discovery, airodump-ng wrapper, BSSID/ESSID parsing
"""

import subprocess
import re
import os
import time
import csv
import io
import threading

class Scanner:
    def __init__(self, config=None):
        self.config = config or {}
        self.targets = []
        self._scanning = False

    def scan(self, mon_iface, timeout=15, band='bg'):
        """
        Scan for access points using airodump-ng
        Returns list of target dicts
        """
        if not mon_iface:
            return []

        # Build airodump command
        cmd = ['airodump-ng']
        
        if band == 'a':
            cmd.extend(['--band', 'a'])
        elif band == 'bg':
            cmd.extend(['--band', 'bg'])
        elif band == 'both':
            cmd.extend(['--band', 'abg'])
        
        # Output to temp file to parse
        import tempfile
        tmpdir = tempfile.mkdtemp(prefix='wraithe_scan_')
        output_path = os.path.join(tmpdir, 'scan')
        
        cmd.extend([mon_iface, '-w', output_path, '--output-format', 'csv'])
        
        # Run scan
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )
        
        time.sleep(timeout)
        proc.terminate()
        proc.wait(timeout=5)

        # Parse results
        targets = []
        csv_path = output_path + '-01.csv'
        
        if os.path.exists(csv_path):
            try:
                with open(csv_path, 'r', errors='ignore') as f:
                    content = f.read()
                
                targets = self._parse_airodump_csv(content)
            except Exception as e:
                pass

        # Cleanup
        try:
            for f in os.listdir(tmpdir):
                os.remove(os.path.join(tmpdir, f))
            os.rmdir(tmpdir)
        except:
            pass
        
        self.targets = targets
        return targets

    def _parse_airodump_csv(self, content):
        """Parse airodump-ng CSV output"""
        targets = []
        in_aps = True
        lines = content.split('\n')
        
        for line in lines:
            if not line.strip():
                continue
            if 'Station MAC' in line or 'BSSID' in line and 'First' in line:
                continue
            if 'BSSID' in line and 'Beacons' in line:
                continue
            
            # Split CSV respecting quotes
            try:
                reader = csv.reader(io.StringIO(line))
                for row in reader:
                    if len(row) >= 14:
                        bssid = row[0].strip()
                        if not bssid or bssid == 'BSSID':
                            continue
                        if not re.match(r'([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}', bssid):
                            continue
                        
                        target = {
                            'bssid': bssid.upper(),
                            'essid': row[13].strip().strip(' \t'),
                            'channel': row[3].strip(),
                            'signal': row[8].strip(),
                            'encryption': row[5].strip(),
                            'cipher': row[6].strip(),
                            'auth': row[7].strip(),
                            'power': row[8].strip(),
                            'beacons': row[9].strip(),
                            'data': row[10].strip(),
                            'wps': self._check_wps(bssid.upper()),
                        }
                        
                        # Clean ESSID
                        if target['essid'] == '' or target['essid'].startswith('\\x'):
                            target['essid'] = '<Hidden SSID>'
                        
                        targets.append(target)
            except:
                continue
        
        return targets

    def _check_wps(self, bssid):
        """Quick WPS capability check via wash if available"""
        return '?'  # Unknown until specifically scanned

    def scan_wps(self, mon_iface, timeout=30):
        """
        Scan specifically for WPS-enabled APs using wash
        Returns list of targets with WPS info
        """
        targets = []
        
        try:
            proc = subprocess.Popen(
                ['wash', '-i', mon_iface, '-o', '/tmp/wraithe_wash.txt', '-C'],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL
            )
            time.sleep(timeout)
            proc.terminate()
            proc.wait(timeout=5)
            
            if os.path.exists('/tmp/wraithe_wash.txt'):
                with open('/tmp/wraithe_wash.txt', 'r') as f:
                    content = f.read()
                
                for line in content.split('\n'):
                    if 'WPA' in line or 'WPS' in line:
                        continue
                    parts = line.split()
                    if len(parts) >= 6:
                        bssid = parts[0].strip()
                        if re.match(r'([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}', bssid):
                            target = {
                                'bssid': bssid.upper(),
                                'channel': parts[1].strip(),
                                'signal': parts[2].strip(),
                                'essid': ' '.join(parts[5:]),
                                'wps_lock': parts[4].strip() if len(parts) > 4 else '?',
                                'wps_version': parts[3].strip() if len(parts) > 3 else '?',
                            }
                            targets.append(target)
        except FileNotFoundError:
            pass
        
        return targets

    def scan_with_oneshot(self, mon_iface, timeout=60):
        """Use OneShot's scanning capabilities"""
        targets = []
        try:
            proc = subprocess.Popen(
                ['python3', '/opt/OneShot/oneshot.py', '-i', mon_iface, '--iface-down'],
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True
            )
            
            start = time.time()
            output_lines = []
            import select
            while time.time() - start < timeout:
                readable, _, _ = select.select([proc.stdout], [], [], 1.0)
                if not readable:
                    if proc.poll() is not None:
                        break
                    continue
                line = proc.stdout.readline()
                if not line:
                    break
                output_lines.append(line)
                # Parse WPS targets from OneShot output
                if 'WPS' in line and 'locked' in line.lower():
                    targets.append(line.strip())
            
            proc.terminate()
            proc.wait(timeout=5)
            
            return {'raw': ''.join(output_lines), 'targets': targets}
        except:
            return None

    def get_sorted_targets(self, key='signal'):
        """Return targets sorted by signal strength"""
        def sort_key(t):
            try:
                return -int(t.get(key, 0))
            except:
                return 0
        return sorted(self.targets, key=sort_key)

    def select_target(self, idx=0):
        """Get target by index"""
        if 0 <= idx < len(self.targets):
            return self.targets[idx]
        return None
