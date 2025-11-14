#!/usr/bin/env python3
import socket
import struct
import sys
import argparse
from pathlib import Path
import signal
import time
from datetime import datetime

class SignalHandler:
    def __init__(self):
        self.shutdown_requested = False
        signal.signal(signal.SIGINT, self.signal_handler)
        signal.signal(signal.SIGTERM, self.signal_handler)
    
    def signal_handler(self, signum, frame):
        print(f"\nSignal {signum} received, closing...")
        self.shutdown_requested = True

def decode_xor(data, key):
    if not key:
        return data
    
    key_bytes = key.encode('utf-8')
    key_len = len(key_bytes)
    
    decoded = bytearray()
    for i, byte in enumerate(data):
        decoded_byte = byte ^ key_bytes[i % key_len]
        decoded.append(decoded_byte)
    
    return bytes(decoded)

def format_filename(original_name, client_ip):
    """Format filename with IP and date"""
    # Get current date in DD.MM.YY format
    current_date = datetime.now().strftime("%d.%m.%y")
    
    # Separate name and extension if exists
    original_path = Path(original_name)
    stem = original_path.stem  # Name without extension
    suffix = original_path.suffix  # Extension including the dot
    
    # Create new name: NAME_IP__DATE.ext
    new_name = f"{stem}_{client_ip}__{current_date}{suffix}"
    
    return new_name

def receive_files(host='0.0.0.0', port=7777, xor_key=None):
    signal_handler = SignalHandler()
    
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((host, port))
        s.listen(1)
        # Set socket to non-blocking with timeout
        s.settimeout(1.0)
        
        print(f"Listening on {host}:{port}...")
        print("Press Ctrl+C to stop the server")
        if xor_key:
            print(f"XOR mode activated - Key: '{xor_key}'")
        else:
            print("No XOR decoding mode")
        
        conn = None
        try:
            while not signal_handler.shutdown_requested:
                try:
                    conn, addr = s.accept()
                    conn.settimeout(1.0)  # Timeout for receive operations
                    
                    client_ip = addr[0]  # Extract client IP
                    print(f"Connection established from {addr}")
                    
                    while not signal_handler.shutdown_requested:
                        try:
                            header_data = b''
                            while len(header_data) < 40 and not signal_handler.shutdown_requested:
                                try:
                                    chunk = conn.recv(40 - len(header_data))
                                    if not chunk:
                                        break
                                    header_data += chunk
                                except socket.timeout:
                                    continue
                            
                            if not header_data or len(header_data) < 40:
                                break
                                
                            if signal_handler.shutdown_requested:
                                break
                            
                            original_filename = header_data[:32].decode('utf-8').rstrip('\x00')
                            filesize = struct.unpack('!I', header_data[32:36])[0]
                            checksum = struct.unpack('!I', header_data[36:40])[0]
                            
                            # Format new name with IP and date
                            output_filename = format_filename(original_filename, client_ip)
                            
                            print(f"Receiving: {original_filename} -> {output_filename} ({filesize} bytes)")
                            
                            filedata = b''
                            while len(filedata) < filesize and not signal_handler.shutdown_requested:
                                try:
                                    chunk = conn.recv(min(4096, filesize - len(filedata)))
                                    if not chunk:
                                        break
                                    filedata += chunk
                                except socket.timeout:
                                    continue
                            
                            if signal_handler.shutdown_requested:
                                print("Reception interrupted by user")
                                break
                            
                            if xor_key and filedata:
                                original_size = len(filedata)
                                filedata = decode_xor(filedata, xor_key)
                                print(f"  XOR applied: {original_size} bytes decoded")
                            
                            # Save with the new formatted name
                            with open(output_filename, "wb") as f:
                                f.write(filedata)
                            
                            file_size = Path(output_filename).stat().st_size
                            print(f"Saved: {output_filename} ({file_size} bytes)")
                            
                        except Exception as e:
                            print(f"Error processing file: {e}")
                            break
                    
                    if conn:
                        conn.close()
                        conn = None
                        
                except socket.timeout:
                    # Timeout in accept, check if we need to close
                    continue
                except Exception as e:
                    print(f"Error accepting connection: {e}")
                    if conn:
                        conn.close()
                        conn = None
                    continue
                        
        except Exception as e:
            if not signal_handler.shutdown_requested:
                print(f"Error: {e}")
        
        finally:
            if conn:
                conn.close()
            print("Server closed correctly")

def main():
    parser = argparse.ArgumentParser(description='Receive files with XOR decoding option')
    parser.add_argument('--host', default='0.0.0.0', help='IP address to listen on (default: 0.0.0.0)')
    parser.add_argument('--port', type=int, default=7777, help='Port to listen on (default: 7777)')
    parser.add_argument('--xor-key', help='Key for XOR decoding (optional)')
    
    args = parser.parse_args()
    
    print("=== FILE RECEIVER ===")
    print(f"Host: {args.host}")
    print(f"Port: {args.port}")
    
    if args.xor_key:
        print(f"XOR Key: {args.xor_key}")
        print("Mode: With XOR decoding")
    else:
        print("Mode: No decoding")
    
    print("=" * 30)
    
    try:
        receive_files(args.host, args.port, args.xor_key)
    except Exception as e:
        print(f"Fatal error: {e}")

if __name__ == "__main__":
    main()