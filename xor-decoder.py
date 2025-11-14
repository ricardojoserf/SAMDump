#!/usr/bin/env python3
import argparse
import os

def decode_xor(data, key):
    """Decode data using XOR with the specified key"""
    if not key:
        return data
    
    key_bytes = key.encode('utf-8')
    key_len = len(key_bytes)
    
    decoded = bytearray()
    for i, byte in enumerate(data):
        decoded_byte = byte ^ key_bytes[i % key_len]
        decoded.append(decoded_byte)
    
    return bytes(decoded)

def decode_files(sam_path, system_path, xor_key, output_dir):
    """Decode SAM and SYSTEM files"""
    
    # Read encoded files
    try:
        with open(sam_path, 'rb') as f:
            sam_encoded = f.read()
        
        with open(system_path, 'rb') as f:
            system_encoded = f.read()
    except Exception as e:
        print(f"[-] Error reading files: {e}")
        return False
    
    print(f"[+] Files read:")
    print(f"    SAM: {len(sam_encoded)} bytes")
    print(f"    SYSTEM: {len(system_encoded)} bytes")
    
    # Decode with XOR
    sam_decoded = decode_xor(sam_encoded, xor_key)
    system_decoded = decode_xor(system_encoded, xor_key)
    
    print(f"[+] Files decoded with XOR key: '{xor_key}'")
    
    # Create output directory if it doesn't exist
    os.makedirs(output_dir, exist_ok=True)
    
    # Save decoded files
    sam_output = os.path.join(output_dir, "sam.decoded")
    system_output = os.path.join(output_dir, "system.decoded")
    
    try:
        with open(sam_output, 'wb') as f:
            f.write(sam_decoded)
        
        with open(system_output, 'wb') as f:
            f.write(system_decoded)
        
        print(f"[+] Decoded files saved to:")
        print(f"    {sam_output}")
        print(f"    {system_output}")
        print(f"[+] Final sizes - SAM: {len(sam_decoded)} bytes, SYSTEM: {len(system_decoded)} bytes")
        
        return True
        
    except Exception as e:
        print(f"[-] Error saving decoded files: {e}")
        return False

def main():
    parser = argparse.ArgumentParser(description='SAM and SYSTEM files XOR decoder')
    parser.add_argument('--sam', required=True, help='Path to encoded SAM file')
    parser.add_argument('--system', required=True, help='Path to encoded SYSTEM file')
    parser.add_argument('--xor-key', default='SAMDump2025', 
                       help='XOR key for decoding (default: SAMDump2025)')
    parser.add_argument('--output-dir', default='./decoded',
                       help='Output directory for decoded files (default: ./decoded)')
    
    args = parser.parse_args()
    
    # Verify input files exist
    if not os.path.exists(args.sam):
        print(f"[-] Error: SAM file not found: {args.sam}")
        return
    
    if not os.path.exists(args.system):
        print(f"[-] Error: SYSTEM file not found: {args.system}")
        return
    
    print("=== SAM/SYSTEM DECODER ===")
    print(f"SAM file: {args.sam}")
    print(f"SYSTEM file: {args.system}")
    print(f"XOR key: {args.xor_key}")
    print(f"Output directory: {args.output_dir}")
    print("=" * 40)
    
    # Decode files
    success = decode_files(args.sam, args.system, args.xor_key, args.output_dir)
    
    if success:
        print("\n[+] Decoding completed successfully!")
    else:
        print("\n[-] Error during decoding")

if __name__ == "__main__":
    main()